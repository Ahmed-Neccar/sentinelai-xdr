param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Enable", "Disable", "Status")]
    [string]$Action,
    [string]$HostOnlyAddress = "192.168.56.1",
    [string]$HostOnlySubnet = "192.168.56.0/24",
    [int]$ApiPort = 8001,
    [int]$PackagePort = 8090
)

# Lab only: lets a VirtualBox guest on the host-only network reach the API,
# which otherwise listens on 127.0.0.1 alone. Nothing is opened on Wi-Fi or
# Ethernet; the firewall rules accept the host-only subnet only.
#
# The connection is plain HTTP. That is acceptable on a host-only network that
# never leaves this computer, and nowhere else. Run "Disable" when finished.
#
# Enable and Disable change system network settings and need an elevated
# (Run as administrator) PowerShell.

$ErrorActionPreference = "Stop"
$ApiRule = "SentinelAI lab sensor API (host-only)"
$PackageRule = "SentinelAI lab sensor package (host-only)"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this in a PowerShell window opened with 'Run as administrator'."
    }
}

function Show-Status {
    Write-Host "Port forwarding:"
    netsh interface portproxy show v4tov4
    Write-Host "Firewall rules:"
    $rules = Get-NetFirewallRule -DisplayName $ApiRule, $PackageRule -ErrorAction SilentlyContinue
    if ($rules) { $rules | Format-Table DisplayName, Enabled, Direction, Action -AutoSize }
    else { Write-Host "  (none)" }
}

if ($Action -eq "Status") {
    Show-Status
    exit 0
}

Assert-Administrator

if ($Action -eq "Enable") {
    $present = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $HostOnlyAddress -ErrorAction SilentlyContinue
    if (-not $present) {
        throw "This computer has no $HostOnlyAddress address. Check the VirtualBox host-only adapter."
    }
    if ($present.InterfaceAlias -match "Wi-?Fi|WLAN") {
        throw "$HostOnlyAddress belongs to '$($present.InterfaceAlias)', which is not a host-only adapter."
    }
    netsh interface portproxy add v4tov4 listenaddress=$HostOnlyAddress listenport=$ApiPort connectaddress=127.0.0.1 connectport=$ApiPort | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not add the port forwarding rule." }
    foreach ($rule in @(@($ApiRule, $ApiPort), @($PackageRule, $PackagePort))) {
        Get-NetFirewallRule -DisplayName $rule[0] -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName $rule[0] -Direction Inbound -Action Allow -Protocol TCP `
            -LocalAddress $HostOnlyAddress -LocalPort $rule[1] -RemoteAddress $HostOnlySubnet | Out-Null
    }
    Write-Host "Enabled. Guests on $HostOnlySubnet can reach http://${HostOnlyAddress}:$ApiPort"
    Write-Host "Run this script with -Action Disable when the test is finished."
}
else {
    netsh interface portproxy delete v4tov4 listenaddress=$HostOnlyAddress listenport=$ApiPort | Out-Null
    Get-NetFirewallRule -DisplayName $ApiRule, $PackageRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Host "Disabled. The API is reachable from this computer only."
}
Show-Status
