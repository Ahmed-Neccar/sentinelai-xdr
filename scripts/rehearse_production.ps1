param(
    # Start in development mode like an existing installation, add some data,
    # run switch_to_production.ps1 against it, and check the data survived.
    [switch]$FromDevelopment,
    [switch]$KeepStack
)

# Starts a SEPARATE Compose project with throwaway secrets, runs checks against
# it in production mode, and removes it again with its volumes. It uses its own
# database and its own ports (API 127.0.0.1:18002) and never reads or changes
# the live stack, its data or the project's .env file.
#
# Without -FromDevelopment it answers "does production mode work?". With it, it
# answers "does switching an existing development installation work?".

$ErrorActionPreference = "Continue"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$Project = "sentinelai-prodcheck"
$Scratch = Join-Path ([IO.Path]::GetTempPath()) ("sentinel-prodcheck-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
$EnvFile = Join-Path $Scratch "rehearsal.env"
$Python = Join-Path $ProjectRoot "sensor\.venv\Scripts\python.exe"
$Api = "127.0.0.1:18002"

function New-Secret([int]$Bytes) {
    $buffer = New-Object byte[] $Bytes
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buffer)
    return $buffer
}
function New-Hex([int]$Bytes) { return -join ((New-Secret $Bytes) | ForEach-Object { $_.ToString("x2") }) }
function New-UrlSafeKey { return [Convert]::ToBase64String((New-Secret 32)).Replace("+", "-").Replace("/", "_") }
function Invoke-Compose([string]$Arguments) {
    cmd /c "docker compose -p $Project --env-file `"$EnvFile`" $Arguments >`"$Scratch\compose.log`" 2>&1"
    return $LASTEXITCODE
}
function Wait-Ready {
    foreach ($attempt in 1..80) {
        try {
            if ((Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://$Api/api/v1/ready").StatusCode -eq 200) { return $true }
        }
        catch { }
        Start-Sleep -Seconds 2
    }
    return $false
}
function Show-BackendLog {
    cmd /c "docker compose -p $Project --env-file `"$EnvFile`" logs --tail 8 backend db-provision 2>&1" |
        ForEach-Object { "$_".Substring(0, [Math]::Min(200, "$_".Length)) }
}

$adminPassword = "Rh-" + (New-Hex 12)
$common = @(
    "SENTINEL_BOOTSTRAP_ADMIN_EMAIL=rehearsal-admin@example.com",
    "SENTINEL_BOOTSTRAP_ADMIN_PASSWORD=$adminPassword",
    "ACCESS_TOKEN_MINUTES=1",
    "API_BIND_ADDRESS=$Api",
    "POSTGRES_BIND_ADDRESS=127.0.0.1:15433"
)
if ($FromDevelopment) {
    # Shaped like an installation that was never hardened: a weak signing key
    # and the Compose default database passwords.
    $lines = @(
        "SENTINEL_ENV=development",
        "SECRET_KEY=weak-key9",
        "SENTINEL_JOB_RUNNER=celery",
        "CORS_ORIGINS=http://127.0.0.1:8080,http://127.0.0.1:5173",
        "CLOUD_CONNECTOR_ENCRYPTION_KEY=$(New-UrlSafeKey)"
    ) + $common
}
else {
    $lines = @(
        "SENTINEL_ENV=production",
        "SECRET_KEY=$(New-Hex 32)",
        "MFA_ENCRYPTION_KEY=$(New-UrlSafeKey)",
        "CLOUD_CONNECTOR_ENCRYPTION_KEY=$(New-UrlSafeKey)",
        "POSTGRES_PASSWORD=$(New-Hex 20)",
        "POSTGRES_APP_PASSWORD=$(New-Hex 20)",
        "POSTGRES_MIGRATOR_PASSWORD=$(New-Hex 20)",
        "CORS_ORIGINS=https://localhost:8443"
    ) + $common
}
$lines | Set-Content -LiteralPath $EnvFile -Encoding ascii

$code = 1
$env:REHEARSAL_API = "http://$Api"
$env:REHEARSAL_ADMIN_EMAIL = "rehearsal-admin@example.com"
$env:REHEARSAL_ADMIN_PASSWORD = $adminPassword
$env:REHEARSAL_TOKEN_MINUTES = "1"
$env:REHEARSAL_SCRATCH = $Scratch
Push-Location $ProjectRoot
try {
    Invoke-Compose "down --volumes --remove-orphans" | Out-Null
    Write-Host ("Starting an isolated stack in " + $(if ($FromDevelopment) { "development" } else { "production" }) + " mode ...")
    # --build: this project has its own images, which must match the current source.
    Invoke-Compose "up --build -d backend worker" | Out-Null
    if (-not (Wait-Ready)) { Show-BackendLog; throw "the API did not become ready" }

    if ($FromDevelopment) {
        & $Python (Join-Path $PSScriptRoot "rehearse_production.py") seed
        if ($LASTEXITCODE -ne 0) { throw "could not create the data to carry over" }
        Write-Host "Running switch_to_production.ps1 against the isolated stack ..."
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "switch_to_production.ps1") `
            -Project $Project -EnvFile $EnvFile -Services "backend worker" -SkipBackup
        if ($LASTEXITCODE -ne 0) { throw "the switch script failed" }
        $mode = (Get-Content -LiteralPath $EnvFile | Where-Object { $_ -cmatch '^SENTINEL_ENV=' })
        Write-Host ("[{0}] the environment file now says {1}" -f $(if ($mode -ceq "SENTINEL_ENV=production") { "ok" } else { "FAIL" }), $mode)
        # The switch keeps its own copy of the old environment file; it holds throwaway values here.
        Get-ChildItem -LiteralPath (Join-Path $ProjectRoot ".data") -Filter "env-before-production-*" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-15) -and (Get-Content -LiteralPath $_.FullName -Raw) -match "rehearsal-admin@example.com" } |
            Remove-Item -Force
    }

    $worker = cmd /c "docker compose -p $Project --env-file `"$EnvFile`" logs --tail 60 worker 2>&1"
    Write-Host ("[{0}] worker started in production mode" -f $(if ("$worker" -match "ready") { "ok" } else { "FAIL" }))
    & $Python (Join-Path $PSScriptRoot "rehearse_production.py")
    $code = $LASTEXITCODE
}
catch { Write-Host "Error: $($_.Exception.Message)" }
finally {
    if (-not $KeepStack) { Invoke-Compose "down --volumes --remove-orphans" | Out-Null }
    Pop-Location
    foreach ($name in "REHEARSAL_API", "REHEARSAL_ADMIN_EMAIL", "REHEARSAL_ADMIN_PASSWORD", "REHEARSAL_TOKEN_MINUTES", "REHEARSAL_SCRATCH") {
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $Scratch -Recurse -Force -ErrorAction SilentlyContinue
}
exit $code
