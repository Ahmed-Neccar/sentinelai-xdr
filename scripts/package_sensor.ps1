param(
    [string]$Server = "http://192.168.56.1:8001",
    [switch]$Serve,
    [string]$BindAddress = "192.168.56.1",
    [int]$Port = 8090
)

# Builds dist\sentinel-sensor.zip: the sensor program for a second machine.
# The package deliberately leaves out sensor\runtime (this machine's sensor
# identity and signing key), logs, the virtual environment and .env, so it
# contains no secrets and the other machine enrolls with its own identity.
#
# -Serve offers the package to the host-only network over HTTP until Ctrl+C,
# so a virtual machine can download it with its browser.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$SensorDir = Join-Path $ProjectRoot "sensor"
$Dist = Join-Path $ProjectRoot "dist"
$Stage = Join-Path $Dist "sentinel-sensor"
$Zip = Join-Path $Dist "sentinel-sensor.zip"

if (Test-Path -LiteralPath $Stage) { Remove-Item -LiteralPath $Stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
foreach ($name in @("live_sensor.py", "windows_security.py", "requirements.txt", "requirements.lock")) {
    Copy-Item -LiteralPath (Join-Path $SensorDir $name) -Destination $Stage
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
param([string]$Server = "__SERVER__", [string]$Interface, [string]$SourceName = "vm-win10-sensor")
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
& $Python live_sensor.py --server $Server --interface $Interface --source-name $SourceName --duration-seconds 0
exit $LASTEXITCODE
'@
Set-Content -LiteralPath (Join-Path $Stage "install.ps1") -Value $install -Encoding utf8
Set-Content -LiteralPath (Join-Path $Stage "start.ps1") -Value $start.Replace("__SERVER__", $Server) -Encoding utf8

if (Test-Path -LiteralPath $Zip) { Remove-Item -LiteralPath $Zip -Force }
Compress-Archive -Path (Join-Path $Stage "*") -DestinationPath $Zip
Remove-Item -LiteralPath $Stage -Recurse -Force
Write-Host "Package written: $Zip"

if ($Serve) {
    $Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    $Share = Join-Path $Dist "share"
    New-Item -ItemType Directory -Force -Path $Share | Out-Null
    Copy-Item -LiteralPath $Zip -Destination $Share -Force
    Write-Host "Download in the virtual machine: http://${BindAddress}:$Port/sentinel-sensor.zip"
    Write-Host "Press Ctrl+C here when the download has finished."
    & $Python -m http.server $Port --bind $BindAddress --directory $Share
}
