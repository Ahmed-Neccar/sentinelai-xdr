param(
    [int]$Files = 8,
    [int]$EventsPerFile = 20000,
    [string]$Output = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "sentinelai-loadtest-report.json"),
    [switch]$KeepStack
)

# Starts a SEPARATE Compose project (own database, volumes and ports), runs the
# synthetic load test against it, and removes it again. The normal deployment on
# 127.0.0.1:8001/8080 is not touched, but it shares this machine's CPU and disk.

# Docker writes progress to stderr; Windows PowerShell 5.1 would treat that as a failure
# under "Stop", so exit codes are checked explicitly instead.
$ErrorActionPreference = "Continue"
$ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Project = "sentinelai-loadtest"
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Bytes = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($Bytes)

$env:POSTGRES_BIND_ADDRESS = "127.0.0.1:15432"
$env:API_BIND_ADDRESS = "127.0.0.1:18001"
$env:SENTINEL_ENV = "development"
$env:SENTINEL_BOOTSTRAP_ADMIN_EMAIL = "loadtest-admin@example.com"
$env:SENTINEL_BOOTSTRAP_ADMIN_PASSWORD = "Lt-" + [Convert]::ToBase64String($Bytes)
$env:LOADTEST_ADMIN_EMAIL = $env:SENTINEL_BOOTSTRAP_ADMIN_EMAIL
$env:LOADTEST_ADMIN_PASSWORD = $env:SENTINEL_BOOTSTRAP_ADMIN_PASSWORD

Push-Location $ProjectRoot
try {
    # Always start from an empty database: the admin password is random per run.
    & docker compose -p $Project down --volumes --remove-orphans | Out-Null
    & docker compose -p $Project up --build -d backend worker
    if ($LASTEXITCODE -ne 0) { throw "The isolated test stack did not start." }
    & $Python (Join-Path $PSScriptRoot "load_test.py") --project $Project --files $Files --events-per-file $EventsPerFile --output $Output
    if ($LASTEXITCODE -ne 0) { throw "The load test did not complete." }
} finally {
    if (-not $KeepStack) { & docker compose -p $Project down --volumes --remove-orphans | Out-Null }
    Pop-Location
    foreach ($Name in "POSTGRES_BIND_ADDRESS", "API_BIND_ADDRESS", "SENTINEL_BOOTSTRAP_ADMIN_EMAIL", "SENTINEL_BOOTSTRAP_ADMIN_PASSWORD", "LOADTEST_ADMIN_EMAIL", "LOADTEST_ADMIN_PASSWORD") {
        Remove-Item "Env:$Name" -ErrorAction SilentlyContinue
    }
}
