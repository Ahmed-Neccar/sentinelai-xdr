param(
    [string]$SensorEmail = "sensor-vm@localhost.local",
    [string]$AdminEmail = "admin@localhost.local"
)

# Creates a dedicated ingestion_service account for one additional sensor.
# Run it in your own terminal: it asks for the administrator password and for
# a new sensor password, and stores neither.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Project Python environment not found at $Python."
}
& $Python (Join-Path $PSScriptRoot "create_sensor_account.py") --sensor-email $SensorEmail --admin-email $AdminEmail
exit $LASTEXITCODE
