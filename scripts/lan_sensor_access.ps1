param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Enable", "Disable", "Status")]
    [string]$Action,
    # Addresses of the computers whose sensors may connect, for example 192.168.1.50
    [string[]]$SensorAddress = @(),
    [int]$Port = 8443,
    # Also allow the one-time package download port used by package_sensor.ps1 -Serve
    [switch]$PackageDownload,
    [int]$PackagePort = 8090
)

# Controls which computers on the local network may reach the HTTPS front
# (port 8443) once it is bound to a network address with TLS_BIND_ADDRESS.
#
# Docker Desktop installs a firewall rule that lets every computer on the
# network reach any port it publishes. Windows applies "block" rules before
# "allow" rules, so "Enable" adds a block rule for every address EXCEPT the
# listed sensor computers. Connections from this computer itself (localhost)
# are never affected.
#
# Run "Enable" BEFORE binding the HTTPS front to the network, and "Disable"
# only after it is back on 127.0.0.1. Needs an elevated PowerShell.

$ErrorActionPreference = "Stop"
$BlockRule = "SentinelAI HTTPS front: block other computers"
$PackageBlockRule = "SentinelAI package download: block other computers"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this in a PowerShell window opened with 'Run as administrator'."
    }
}

function ConvertTo-UInt32([System.Net.IPAddress]$Address) {
    $bytes = $Address.GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function ConvertFrom-UInt32([uint32]$Value) {
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]$bytes).ToString()
}

# Every IPv4 address except the allowed ones, as "from-to" ranges.
function Get-BlockedRanges([string[]]$Allowed) {
    $values = @()
    foreach ($item in $Allowed) {
        $parsed = $null
        if (-not [System.Net.IPAddress]::TryParse($item, [ref]$parsed) -or
            $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            throw "Not an IPv4 address: $item"
        }
        $values += [uint32](ConvertTo-UInt32 $parsed)
    }
    $ranges = @()
    [uint64]$start = 0
    foreach ($value in ($values | Sort-Object -Unique)) {
        if ([uint64]$value -gt $start) {
            $ranges += "$(ConvertFrom-UInt32 ([uint32]$start))-$(ConvertFrom-UInt32 ([uint32]($value - 1)))"
        }
        $start = [uint64]$value + 1
    }
    if ($start -le [uint32]::MaxValue) {
        $ranges += "$(ConvertFrom-UInt32 ([uint32]$start))-255.255.255.255"
    }
    return $ranges
}

function Show-Status {
    $rules = Get-NetFirewallRule -DisplayName $BlockRule, $PackageBlockRule -ErrorAction SilentlyContinue
    if (-not $rules) { Write-Host "No SentinelAI network access rules are present."; return }
    foreach ($rule in $rules) {
        $port = ($rule | Get-NetFirewallPortFilter).LocalPort
        $remote = ($rule | Get-NetFirewallAddressFilter).RemoteAddress
        Write-Host "$($rule.DisplayName): port $port, action $($rule.Action), enabled $($rule.Enabled)"
        Write-Host "  blocked ranges: $($remote -join ', ')"
    }
}

if ($Action -eq "Status") { Show-Status; exit 0 }
Assert-Administrator

Get-NetFirewallRule -DisplayName $BlockRule, $PackageBlockRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule

if ($Action -eq "Enable") {
    if ($SensorAddress.Count -eq 0) { throw "Give at least one -SensorAddress." }
    $ranges = Get-BlockedRanges $SensorAddress
    New-NetFirewallRule -DisplayName $BlockRule -Direction Inbound -Action Block -Protocol TCP `
        -LocalPort $Port -RemoteAddress $ranges -Profile Any | Out-Null
    # IPv6 clients are not part of this lab setup: block them all.
    New-NetFirewallRule -DisplayName $BlockRule -Direction Inbound -Action Block -Protocol TCP `
        -LocalPort $Port -RemoteAddress "::/0" -Profile Any | Out-Null
    if ($PackageDownload) {
        New-NetFirewallRule -DisplayName $PackageBlockRule -Direction Inbound -Action Block -Protocol TCP `
            -LocalPort $PackagePort -RemoteAddress $ranges -Profile Any | Out-Null
        # python.exe is not covered by Docker's rule, so the download port also needs an allow rule.
        New-NetFirewallRule -DisplayName $PackageBlockRule -Direction Inbound -Action Allow -Protocol TCP `
            -LocalPort $PackagePort -RemoteAddress $SensorAddress -Profile Any | Out-Null
    }
    Write-Host "Only $($SensorAddress -join ', ') may reach port $Port from the network."
}
else {
    Write-Host "Removed the SentinelAI network access rules."
    Write-Host "Make sure the HTTPS front is bound to 127.0.0.1 again (remove TLS_BIND_ADDRESS)."
}
Show-Status
