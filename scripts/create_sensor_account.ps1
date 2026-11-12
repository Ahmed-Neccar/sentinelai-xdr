param(
    [string]$SensorEmail = "sensor-vm@localhost.local",
    [string]$AdminEmail = "admin@localhost.local",
    [ValidateSet("ingestion_service", "analyst", "auditor")]
    [string]$Role = "ingestion_service"
)

# Creates an account through the audited users API, because the panel has no
# user-management screen. The default is a dedicated ingestion_service account
# for one additional sensor; -Role analyst or auditor provisions a person,
# for example before that person signs in with SSO.
#
# Run it in your own terminal: it asks for the administrator password and for
# a new account password, and stores neither.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Project Python environment not found at $Python."
}
& $Python (Join-Path $PSScriptRoot "create_sensor_account.py") --sensor-email $SensorEmail --admin-email $AdminEmail --role $Role
exit $LASTEXITCODE
