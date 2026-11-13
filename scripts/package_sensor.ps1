param(
    [string]$Server = "http://192.168.56.1:8001",
    # Public certificate of an https:// server with a private or self-signed
    # certificate. It is copied into the package so the sensor can trust it.
    [string]$CaFile,
    [string]$SourceName = "remote-sensor",
    [switch]$Serve,
    [string]$BindAddress = "192.168.56.1",
    [int]$Port = 8090
)

# Builds dist\sentinel-sensor.zip: the sensor program for another machine.
# The package deliberately leaves out sensor\runtime (this machine's sensor
# identity and signing key), logs, the virtual environment and .env, so it
# contains no secrets and the other machine enrolls with its own identity.
# A server certificate given with -CaFile is public and safe to include; its
# private key is never read.
#
# -Serve offers the package over HTTP until Ctrl+C, so the other machine can
# download it with its browser.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$SensorDir = Join-Path $ProjectRoot "sensor"
$Dist = Join-Path $ProjectRoot "dist"
$Stage = Join-Path $Dist "sentinel-sensor"
$Zip = Join-Path $Dist "sentinel-sensor.zip"

if (Test-Path -LiteralPath $Stage) { Remove-Item -LiteralPath $Stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
foreach ($name in @("live_sensor.py", "windows_security.py", "response_actions.py", "requirements.txt", "requirements.lock")) {
    Copy-Item -LiteralPath (Join-Path $SensorDir $name) -Destination $Stage
}

$caArgument = ""
if ($CaFile) {
    $ca = Get-Item -LiteralPath $CaFile
    $content = Get-Content -LiteralPath $ca.FullName -Raw
    if ($content -notmatch "BEGIN CERTIFICATE" -or $content -match "PRIVATE KEY") {
        throw "-CaFile must be a public certificate (PEM) and must not contain a private key."
    }
    Copy-Item -LiteralPath $ca.FullName -Destination (Join-Path $Stage "server-cert.pem")
    $caArgument = "server-cert.pem"
}

$install = @'
# Run once, in the folder where you extracted the package.
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --requirement requirements.lock
Write-Host ""
Write-Host "Installed. Npcap must also be installed (https://npcap.com)."
Write-Host "Next: open PowerShell as administrator and run .\start.ps1"
'@
$start = @'
param(
    [string]$Server = "__SERVER__",
    [string]$Interface,
    [string]$SourceName = "__SOURCE__",
    # Each of these lets this computer apply one kind of approved, time-limited
    # response action. They are refused unless the server address is https://.
    [switch]$AllowIpBlocks,
    [switch]$AllowIsolation,
    [switch]$AllowAccountDisable
)
# Run in a PowerShell opened with "Run as administrator" (packet capture needs it).
# Without -Interface it lists the adapters so you can pick one.
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$Python = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $Python)) { throw "Run .\install.ps1 first." }
if (-not $Interface) {
    & $Python live_sensor.py --list-interfaces
    Write-Host ""
    Write-Host 'Now run:  .\start.ps1 -Interface "<adapter name from the list>"'
    exit 0
}
$Arguments = @("live_sensor.py", "--server", $Server, "--interface", $Interface, "--source-name", $SourceName, "--duration-seconds", "0")
$Ca = "__CA__"
if ($Ca) { $Arguments += @("--ca-file", (Join-Path $PSScriptRoot $Ca)) }
# Put the sensor-credentials.json downloaded from the panel in this folder and
# the sensor signs in with it; without the file it asks for email and password.
$Credentials = Join-Path $PSScriptRoot "sensor-credentials.json"
if (Test-Path -LiteralPath $Credentials) { $Arguments += @("--credentials-file", $Credentials) }
if ($AllowIpBlocks) { $Arguments += "--enforce-blocks" }
if ($AllowIsolation) { $Arguments += "--allow-isolation" }
if ($AllowAccountDisable) { $Arguments += "--allow-account-disable" }
& $Python @Arguments
exit $LASTEXITCODE
'@
Set-Content -LiteralPath (Join-Path $Stage "install.ps1") -Value $install -Encoding utf8
$start = $start.Replace("__SERVER__", $Server).Replace("__SOURCE__", $SourceName).Replace("__CA__", $caArgument)
Set-Content -LiteralPath (Join-Path $Stage "start.ps1") -Value $start -Encoding utf8

if (Test-Path -LiteralPath $Zip) { Remove-Item -LiteralPath $Zip -Force }
Compress-Archive -Path (Join-Path $Stage "*") -DestinationPath $Zip
Remove-Item -LiteralPath $Stage -Recurse -Force
Write-Host "Package written: $Zip"

if ($Serve) {
    $Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    $Share = Join-Path $Dist "share"
    New-Item -ItemType Directory -Force -Path $Share | Out-Null
    Copy-Item -LiteralPath $Zip -Destination $Share -Force
    Write-Host "Download on the other computer: http://${BindAddress}:$Port/sentinel-sensor.zip"
    Write-Host "Press Ctrl+C here when the download has finished."
    & $Python -m http.server $Port --bind $BindAddress --directory $Share
}
