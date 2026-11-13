param(
    # Only for rehearsals against a separate Compose project. Leave both empty
    # to switch the real stack described by compose.yaml and .env.
    [string]$Project = "",
    [string]$EnvFile = "",
    [string]$Services = "",
    [switch]$SkipBackup
)

# Switches an existing development-mode installation to production mode
# without losing data:
#
#   1. takes a database backup and keeps a copy of the current .env,
#   2. generates new random secrets (they are written to .env and never shown),
#   3. changes the database superuser password to the new one,
#   4. rewrites the affected .env lines and sets SENTINEL_ENV=production,
#   5. rebuilds and restarts the stack, which re-provisions the two service
#      database roles with their new passwords,
#   6. checks the result, and puts everything back if the stack does not come up.
#
# Effects to expect: everyone is signed out (the signing key changes), sensors
# must be restarted, and browsers only keep a session over https or localhost.
# Run it in the project folder. It does not need an elevated PowerShell.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
if (-not $EnvFile) { $EnvFile = Join-Path $ProjectRoot ".env" }
$EnvFile = (Resolve-Path -LiteralPath $EnvFile).Path
$Utf8 = New-Object Text.UTF8Encoding($false)
$compose = "docker compose"
if ($Project) { $compose += " -p $Project" }
$compose += " --env-file `"$EnvFile`""

function Invoke-Compose([string]$Arguments, [string]$Stdin = "") {
    $log = Join-Path ([IO.Path]::GetTempPath()) ("sentinel-switch-" + [Guid]::NewGuid().ToString("N") + ".log")
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        if ($Stdin) { $Stdin | cmd /c "$compose $Arguments >`"$log`" 2>&1" }
        else { cmd /c "$compose $Arguments >`"$log`" 2>&1" }
        $code = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previous }
    $output = if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Raw } else { "" }
    Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
    return @{ code = $code; output = $output }
}

function Get-EnvValue([string[]]$Lines, [string]$Name) {
    foreach ($line in $Lines) {
        if ($line -cmatch "^\s*$([regex]::Escape($Name))\s*=(.*)$") { return $Matches[1].Trim() }
    }
    return $null
}

function Set-EnvValues([string[]]$Lines, [hashtable]$Values) {
    $result = New-Object System.Collections.Generic.List[string]
    $written = @{}
    foreach ($line in $Lines) {
        $name = if ($line -cmatch '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=') { $Matches[1] } else { $null }
        if ($name -and $Values.ContainsKey($name)) {
            if (-not $written.ContainsKey($name)) { $result.Add("$name=$($Values[$name])"); $written[$name] = $true }
        }
        else { $result.Add($line) }
    }
    foreach ($name in ($Values.Keys | Sort-Object)) {
        if (-not $written.ContainsKey($name)) { $result.Add("$name=$($Values[$name])") }
    }
    return $result.ToArray()
}

function New-Bytes([int]$Count) {
    $buffer = New-Object byte[] $Count
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buffer)
    return $buffer
}
function New-Hex([int]$Count) { return -join ((New-Bytes $Count) | ForEach-Object { $_.ToString("x2") }) }
function New-UrlSafeKey { return [Convert]::ToBase64String((New-Bytes 32)).Replace("+", "-").Replace("/", "_") }

function Wait-Api([string]$Address, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            if ((Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://$Address/api/v1/ready").StatusCode -eq 200) { return $true }
        }
        catch { }
        Start-Sleep -Seconds 3
    }
    return $false
}

Push-Location $ProjectRoot
try {
    $original = [IO.File]::ReadAllLines($EnvFile)
    if ((Get-EnvValue $original "SENTINEL_ENV") -ceq "production") {
        Write-Host "This installation is already in production mode. Nothing was changed."
        exit 0
    }
    $api = Get-EnvValue $original "API_BIND_ADDRESS"
    if (-not $api) { $api = "127.0.0.1:8001" }
    if (-not (Wait-Api $api 10)) { throw "The stack is not running and healthy at $api. Start it first." }

    $oldSuperuser = Get-EnvValue $original "POSTGRES_PASSWORD"
    if (-not $oldSuperuser) { $oldSuperuser = "sentinel_dev_only" }   # the Compose default
    $oidc = Get-EnvValue $original "OIDC_CLIENT_SECRET"
    if ($oidc -and $oidc.Length -lt 32) { throw "OIDC_CLIENT_SECRET is shorter than 32 characters; production mode would refuse it." }
    # The application's own placeholder passwords, which production mode rejects.
    # An installation created from the example file may still be using one for
    # its first administrator, and hardening everything else would be pointless
    # while that account opens with a published password.
    $placeholders = @("change-me-now", "replace-with-a-separate-long-random-password")
    $adminEmail = Get-EnvValue $original "SENTINEL_BOOTSTRAP_ADMIN_EMAIL"
    if ($adminEmail) {
        foreach ($candidate in $placeholders) {
            $accepted = $false
            try {
                $body = @{ email = $adminEmail; password = $candidate } | ConvertTo-Json
                Invoke-RestMethod -Method Post -Uri "http://$api/api/v1/auth/login" -ContentType "application/json" -Body $body -TimeoutSec 10 | Out-Null
                $accepted = $true
            }
            catch { }
            if ($accepted) {
                throw "The administrator $adminEmail still signs in with a default password from the example configuration. Change it first (panel: Users > Set password), then run this again. Nothing was changed."
            }
        }
    }

    Write-Host "1/6 Backup ..."
    if (-not $SkipBackup) {
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "backup.ps1") | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "The database backup failed; nothing was changed." }
    }
    $keep = Join-Path $ProjectRoot (".data\env-before-production-" + (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ"))
    New-Item -ItemType Directory -Force -Path (Split-Path $keep -Parent) | Out-Null
    [IO.File]::WriteAllLines($keep, $original, $Utf8)

    Write-Host "2/6 Generating new secrets (not displayed) ..."
    $newSuperuser = New-Hex 24
    # Browsers reach the panel same-origin, so only real https origins are listed.
    $origins = @("https://localhost:8443")
    $state = Join-Path $ProjectRoot ".data\remote-sensors.json"
    if ((Test-Path -LiteralPath $state) -and (Get-EnvValue $original "TLS_BIND_ADDRESS")) {
        $server = (Get-Content -LiteralPath $state -Raw | ConvertFrom-Json).server
        if ($server) { $origins += "https://${server}:8443" }
    }
    $values = @{
        SENTINEL_ENV               = "production"
        SECRET_KEY                 = (New-Hex 48)
        POSTGRES_PASSWORD          = $newSuperuser
        POSTGRES_APP_PASSWORD      = (New-Hex 24)
        POSTGRES_MIGRATOR_PASSWORD = (New-Hex 24)
        CORS_ORIGINS               = ($origins -join ",")
    }
    # The bootstrap password is only read when the database has no users at
    # all, so it is no longer needed, and production mode refuses to start
    # while it holds a placeholder. It is cleared rather than left in the file.
    if (Get-EnvValue $original "SENTINEL_BOOTSTRAP_ADMIN_PASSWORD") { $values["SENTINEL_BOOTSTRAP_ADMIN_PASSWORD"] = "" }
    # Keys that already protect stored data are kept; a new one would make that data unreadable.
    if (-not (Get-EnvValue $original "MFA_ENCRYPTION_KEY")) { $values["MFA_ENCRYPTION_KEY"] = New-UrlSafeKey }
    if (-not (Get-EnvValue $original "CLOUD_CONNECTOR_ENCRYPTION_KEY")) {
        throw "CLOUD_CONNECTOR_ENCRYPTION_KEY is not set. Existing connector credentials were encrypted with a key derived from the old SECRET_KEY and would be lost. Set the key first."
    }

    Write-Host "3/6 Changing the database superuser password ..."
    $sql = "ALTER ROLE sentinel PASSWORD '$newSuperuser';"
    $changed = Invoke-Compose "exec -T postgres psql -v ON_ERROR_STOP=1 -U sentinel -d sentinel -q" $sql
    if ($changed.code -ne 0) { throw "Could not change the database superuser password; nothing else was changed." }

    $switched = $false
    try {
        Write-Host "4/6 Updating .env ..."
        [IO.File]::WriteAllLines($EnvFile, (Set-EnvValues $original $values), $Utf8)

        Write-Host "5/6 Rebuilding and restarting in production mode (a few minutes) ..."
        $target = if ($Services) { $Services } else { "" }
        $up = Invoke-Compose "up --build -d $target"
        if (-not (Wait-Api $api 240)) {
            $logs = Invoke-Compose "logs --tail 12 backend db-provision db-migrate"
            Write-Host $logs.output
            throw "The stack did not become healthy in production mode."
        }
        if (-not $Services) {
            # The lab HTTPS front belongs to a profile and is restarted separately.
            Invoke-Compose "--profile tls-lab up -d --force-recreate tls-proxy" | Out-Null
        }
        $switched = $true
    }
    finally {
        if (-not $switched) {
            Write-Host "Putting the previous configuration back ..."
            [IO.File]::WriteAllLines($EnvFile, $original, $Utf8)
            $back = "ALTER ROLE sentinel PASSWORD '$($oldSuperuser.Replace("'", "''"))';"
            Invoke-Compose "exec -T postgres psql -v ON_ERROR_STOP=1 -U sentinel -d sentinel -q" $back | Out-Null
            Invoke-Compose "up -d $Services" | Out-Null
            if (Wait-Api $api 180) { Write-Host "The stack is running again in its previous mode." }
            else { Write-Host "WARNING: the stack is not healthy. Restore with scripts\restore.ps1 if needed; the previous .env is at $keep" }
        }
    }

    Write-Host "6/6 Checking ..."
    $docs = try { (Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 "http://$api/openapi.json").StatusCode } catch { 404 }
    Write-Host ("  API schema hidden: " + ($docs -eq 404))
    $workers = Invoke-Compose "ps --format `"{{.Service}} {{.Status}}`""
    Write-Host $workers.output.Trim()
    Write-Host ""
    Write-Host "Production mode is on."
    Write-Host "  - Everyone must sign in again; restart the sensor (and its controller)."
    Write-Host "  - The previous .env is kept at $keep . It holds the OLD secrets: delete it once you are satisfied."
    Write-Host "  - .env changed: refresh its encrypted backup with scripts\backup_env.ps1"
}
finally { Pop-Location }
