param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Setup", "AddComputer", "RemoveComputer", "Status", "Disable")]
    [string]$Action,
    # For AddComputer / RemoveComputer: the other computer's IPv4 address.
    [string]$Address,
    # For Setup: this computer's address on the local network, if it cannot be detected.
    [string]$ServerAddress
)

# One place to let sensors on OTHER computers of the local network connect to
# this SentinelAI server over HTTPS, and to control which computers may.
#
#   Setup           once: certificate for this computer's network address,
#                   firewall closed to everyone, HTTPS front bound to the
#                   network, sensor package built.
#   AddComputer     allow one more computer (by address) to connect.
#   RemoveComputer  stop allowing a computer.
#   Status          show what is allowed and where the server listens.
#   Disable         put everything back on this computer only.
#
# Lab arrangement: the certificate is self-signed and tied to this computer's
# current address, and allowed computers can also open the panel's sign-in
# page. Needs an elevated (Run as administrator) PowerShell, except Status.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$EnvFile = Join-Path $ProjectRoot ".env"
$StateFile = Join-Path $ProjectRoot ".data\remote-sensors.json"
$Certificate = Join-Path $ProjectRoot ".data\tls-lab\localhost.crt"
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$AccessScript = Join-Path $PSScriptRoot "lan_sensor_access.ps1"
$Port = 8443

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this in a PowerShell window opened with 'Run as administrator'."
    }
}

function Test-IPv4([string]$Value) {
    $parsed = $null
    return [System.Net.IPAddress]::TryParse($Value, [ref]$parsed) -and
        $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
        $Value -match '^\d{1,3}(\.\d{1,3}){3}$'
}

function Get-State {
    if (Test-Path -LiteralPath $StateFile) {
        $state = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
        return @{ server = [string]$state.server; computers = @($state.computers | Where-Object { $_ }) }
    }
    return @{ server = ""; computers = @() }
}

function Save-State($State) {
    New-Item -ItemType Directory -Force -Path (Split-Path $StateFile -Parent) | Out-Null
    $json = @{ server = $State.server; computers = @($State.computers) } | ConvertTo-Json
    [IO.File]::WriteAllText($StateFile, $json, (New-Object Text.UTF8Encoding($false)))
}

# The address this computer uses to reach the rest of the network.
function Get-NetworkAddress {
    $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1
    if (-not $route) { throw "No default route found. Give -ServerAddress." }
    $ip = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1
    if (-not $ip) { throw "No IPv4 address found on the default interface. Give -ServerAddress." }
    return $ip.IPAddress
}

# Replace or remove the one non-secret line TLS_BIND_ADDRESS in .env, leaving
# every other line untouched and writing without a byte-order mark.
function Set-BindAddress([string]$Value) {
    if (-not (Test-Path -LiteralPath $EnvFile)) { throw ".env not found at $EnvFile" }
    $lines = @([IO.File]::ReadAllLines($EnvFile) | Where-Object { $_ -notmatch '^\s*TLS_BIND_ADDRESS\s*=' })
    if ($Value) { $lines += "TLS_BIND_ADDRESS=$Value" }
    [IO.File]::WriteAllLines($EnvFile, $lines, (New-Object Text.UTF8Encoding($false)))
}

function Update-Firewall($State) {
    & $AccessScript -Action Enable -SensorAddress @($State.computers) -Port $Port | Out-Null
}

function Restart-Front {
    Push-Location $ProjectRoot
    # docker writes its normal progress to the error stream, which Windows
    # PowerShell turns into a terminating error under "Stop". Judge it by its
    # exit code instead.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        cmd /c "docker compose --profile tls-lab up -d --force-recreate tls-proxy >nul 2>&1"
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
        Pop-Location
    }
    if ($code -ne 0) { throw "docker compose could not restart the HTTPS front (exit code $code)." }
}

function Show-Status {
    $state = Get-State
    $bound = ""
    if (Test-Path -LiteralPath $EnvFile) {
        $line = [IO.File]::ReadAllLines($EnvFile) | Where-Object { $_ -match '^\s*TLS_BIND_ADDRESS\s*=' } | Select-Object -Last 1
        if ($line) { $bound = ($line -split '=', 2)[1].Trim() }
    }
    if ($bound) {
        Write-Host "Remote sensors: ENABLED. Sensors connect to https://$($state.server):$Port"
    }
    else {
        Write-Host "Remote sensors: disabled. The server listens on this computer only."
    }
    if ($state.computers.Count) { Write-Host "Allowed computers: $($state.computers -join ', ')" }
    else { Write-Host "Allowed computers: none" }
    $listening = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty LocalAddress -Unique
    Write-Host "Port $Port listening on: $(if ($listening) { $listening -join ', ' } else { 'nothing' })"
    & $AccessScript -Action Status
}

if ($Action -eq "Status") { Show-Status; exit 0 }
Assert-Administrator
$state = Get-State

switch ($Action) {
    "Setup" {
        if (-not (Test-Path -LiteralPath $Python)) { throw "Project Python environment not found at $Python." }
        $server = if ($ServerAddress) { $ServerAddress } else { Get-NetworkAddress }
        if (-not (Test-IPv4 $server)) { throw "Not an IPv4 address: $server" }
        $state.server = $server
        Write-Host "1/5 Certificate for $server ..."
        & $Python (Join-Path $PSScriptRoot "make_lab_tls_cert.py") --force --name $server --name $env:COMPUTERNAME | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "The certificate could not be created." }
        Write-Host "2/5 Firewall: closed to every computer except the allowed ones ..."
        Update-Firewall $state   # before the port is exposed
        Save-State $state
        Write-Host "3/5 Binding the HTTPS front to the network ..."
        Set-BindAddress "0.0.0.0"
        Restart-Front
        Write-Host "4/5 Building the sensor package ..."
        & (Join-Path $PSScriptRoot "package_sensor.ps1") -Server "https://${server}:$Port" -CaFile $Certificate | Out-Null
        Write-Host "5/5 Done."
        Write-Host ""
        Write-Host "Sensors connect to: https://${server}:$Port"
        Write-Host "Sensor package:     $(Join-Path $ProjectRoot 'dist\sentinel-sensor.zip')"
        Write-Host "No other computer is allowed yet. For each computer:"
        Write-Host "  .\scripts\remote_sensors.ps1 -Action AddComputer -Address <its address>"
        Write-Host "Your browser will warn once more for https://localhost:$Port (new certificate)."
        Write-Host ".env changed (TLS_BIND_ADDRESS): refresh its encrypted backup with .\scripts\backup_env.ps1"
    }
    "AddComputer" {
        if (-not $state.server) { throw "Run -Action Setup first." }
        if (-not (Test-IPv4 $Address)) { throw "Give the other computer's IPv4 address with -Address." }
        if ($Address -eq $state.server) { throw "That is this computer's own address." }
        $state.computers = @(@($state.computers) + $Address | Sort-Object -Unique)
        Update-Firewall $state
        Save-State $state
        Write-Host "Allowed: $Address. On that computer:"
        Write-Host "  1. Install Python 3.12 (tick 'Add to PATH') and Npcap."
        Write-Host "  2. Copy dist\sentinel-sensor.zip there and extract it."
        Write-Host "  3. In the panel: Sensors > Add a sensor computer > download sensor-credentials.json"
        Write-Host "     and put it in the extracted folder."
        Write-Host "  4. In an elevated PowerShell in that folder:"
        Write-Host "       powershell -ExecutionPolicy Bypass -File .\install.ps1"
        Write-Host "       powershell -ExecutionPolicy Bypass -File .\start.ps1"
        Write-Host "       powershell -ExecutionPolicy Bypass -File .\start.ps1 -Interface `"<adapter>`" -AllowIsolation"
    }
    "RemoveComputer" {
        if (-not (Test-IPv4 $Address)) { throw "Give the computer's IPv4 address with -Address." }
        $state.computers = @($state.computers | Where-Object { $_ -ne $Address })
        Update-Firewall $state
        Save-State $state
        Write-Host "No longer allowed: $Address. Revoke its sensor in the panel as well."
    }
    "Disable" {
        Set-BindAddress ""
        Restart-Front               # back on 127.0.0.1 before the firewall rules go
        & $AccessScript -Action Disable | Out-Null
        $state.computers = @()
        Save-State $state
        Write-Host "Disabled. The server listens on this computer only."
        Write-Host ".env changed (TLS_BIND_ADDRESS removed): refresh its encrypted backup."
    }
}
Write-Host ""
Show-Status
