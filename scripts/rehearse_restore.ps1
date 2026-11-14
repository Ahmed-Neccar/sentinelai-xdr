# Proves that a backup can be restored, without touching the live stack.
#
#   powershell -ExecutionPolicy Bypass -File scripts\rehearse_restore.ps1 [-ManifestPath backups\manifest-....json]
#
# It starts a SEPARATE Compose project (own database, volumes and port 127.0.0.1:15433), checks the
# backup's SHA-256 hashes, restores the database dump and the application-data archive into it,
# compares what came back with the manifest and with the live database, prints how long each step
# took, and removes the project again. It reads the project's backups folder read-only and never
# changes the live stack, its volumes or .env. Without -ManifestPath the newest backup is used.
param(
    [string]$ManifestPath,
    [switch]$KeepStack
)

$ErrorActionPreference = "Continue"
$Root = Split-Path $PSScriptRoot -Parent
$Project = "sentinelai-restorecheck"
$Backups = [System.IO.Path]::GetFullPath((Join-Path $Root "backups"))
$Failed = 0

function Write-Check([bool]$Ok, [string]$Text) {
    if ($Ok) { Write-Host "[ok] $Text" -ForegroundColor Green } else { Write-Host "[FAILED] $Text" -ForegroundColor Red; $script:Failed++ }
}
function Invoke-Compose([string]$Arguments) {
    cmd /c "docker compose -p $Project $Arguments >`"$env:TEMP\restorecheck.log`" 2>&1"
    return $LASTEXITCODE
}
function Invoke-Sql([string]$Sql) {
    $out = $Sql | cmd /c "docker compose -p $Project exec -T postgres psql -U sentinel -d sentinel -tA 2>&1"
    return ($out | Where-Object { $_ -ne "" } | Select-Object -First 1)
}

# -- choose and verify the backup ---------------------------------------------
if (-not $ManifestPath) {
    $latest = Get-ChildItem -LiteralPath $Backups -Filter "manifest-*.json" | Sort-Object Name | Select-Object -Last 1
    if (-not $latest) { throw "No backup manifest found in $Backups" }
    $ManifestPath = $latest.FullName
}
$ManifestPath = [System.IO.Path]::GetFullPath($ManifestPath)
if (-not $ManifestPath.StartsWith($Backups, [System.StringComparison]::OrdinalIgnoreCase)) { throw "Choose a manifest under the project backups folder." }
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
Write-Host "Rehearsing the restore of backup $($manifest.created_at)"
foreach ($entry in @(@{ N = $manifest.database_file; H = $manifest.database_sha256 }, @{ N = $manifest.app_data_file; H = $manifest.app_data_sha256 })) {
    if ([System.IO.Path]::GetFileName($entry.N) -ne $entry.N) { throw "The manifest names an unsafe file." }
    $path = Join-Path $Backups $entry.N
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Check ($hash -eq $entry.H.ToLowerInvariant()) "checksum of $($entry.N)"
}
if ($Failed) { exit 1 }

# -- throw-away stack ------------------------------------------------------------
$bytes = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:POSTGRES_PASSWORD = "rc-" + [Convert]::ToBase64String($bytes).Replace("+", "A").Replace("/", "B").Replace("=", "C")
$env:POSTGRES_BIND_ADDRESS = "127.0.0.1:15433"
$env:POSTGRES_USER = "sentinel"
$env:POSTGRES_DB = "sentinel"
Push-Location $Root
$clock = [Diagnostics.Stopwatch]::StartNew()
try {
    Invoke-Compose "down --volumes --remove-orphans" | Out-Null
    $code = Invoke-Compose "up -d postgres"
    Write-Check ($code -eq 0) "isolated database started"
    $ready = $false
    foreach ($i in 1..60) {
        if ((Invoke-Sql "select 1") -eq "1") { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    Write-Check $ready "isolated database accepts connections"
    if (-not $ready) { throw "database did not become ready" }

    # One line, no double quotes: it travels through cmd.exe into sh inside the container.
    $restoreScript = 'export PGPASSWORD=$POSTGRES_PASSWORD; pg_restore --list $RESTORE_DB_FILE >/dev/null && pg_restore --clean --if-exists --no-owner --no-privileges --single-transaction -h postgres -U $POSTGRES_USER -d $POSTGRES_DB $RESTORE_DB_FILE && tar -tzf $RESTORE_APP_FILE >/dev/null && find /source-data -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + ; tar -xzf $RESTORE_APP_FILE -C /source-data && echo files-restored=$(find /source-data -type f | wc -l)'
    $restoreStart = $clock.Elapsed.TotalSeconds
    # Called directly (not through cmd.exe) so the one-line script keeps its quoting. The error
    # preference is "Continue" here, so Docker's progress on stderr is not treated as a failure.
    $out = & docker compose -p $Project --profile operations run --rm --no-deps -e "RESTORE_DB_FILE=/backups/$($manifest.database_file)" -e "RESTORE_APP_FILE=/backups/$($manifest.app_data_file)" --entrypoint sh restore -ec $restoreScript 2>&1 | ForEach-Object { "$_" }
    $restoreExit = $LASTEXITCODE
    $restoreSeconds = [math]::Round($clock.Elapsed.TotalSeconds - $restoreStart, 1)
    $restoredFiles = $out | Where-Object { $_ -match "files-restored=" } | Select-Object -Last 1
    Write-Check (($restoreExit -eq 0) -and [bool]$restoredFiles) "database and application data restored in $restoreSeconds s"
    if (-not $restoredFiles) { $out | Select-Object -Last 6 | ForEach-Object { Write-Host "     $_" } }
    if ($restoredFiles) { Write-Host "     $restoredFiles" }

    # -- what came back ------------------------------------------------------------
    $version = Invoke-Sql "select version_num from alembic_version"
    $liveVersion = ("select version_num from alembic_version" | cmd /c "docker compose exec -T postgres psql -U sentinel -d sentinel -tA 2>&1" | Select-Object -First 1)
    Write-Check ($version -and $version -eq $liveVersion) "migration level $version (live: $liveVersion)"
    foreach ($table in "users", "security_events", "detections", "cases", "detection_rules", "audit_logs", "sensor_registrations", "cloud_connectors") {
        $restored = Invoke-Sql "select count(*) from $table"
        $live = ("select count(*) from $table" | cmd /c "docker compose exec -T postgres psql -U sentinel -d sentinel -tA 2>&1" | Select-Object -First 1)
        $ok = ($restored -match '^\d+$') -and ([int64]$restored -le [int64]$live) -and ([int64]$restored -gt 0 -or [int64]$live -eq 0)
        Write-Check $ok ("{0,-22} restored {1,8}   live now {2,8}" -f $table, $restored, $live)
    }
    $admins = Invoke-Sql "select count(*) from users u join user_roles ur on ur.user_id = u.id join roles r on r.id = ur.role_id where r.name = 'administrator' and u.is_active"
    Write-Check ($admins -match '^\d+$' -and [int64]$admins -ge 1) "at least one active administrator ($admins)"
}
catch { Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red; $Failed++ }
finally {
    Write-Host ("Total time {0:N1} s (restore step only is the figure to quote; starting Docker adds more)." -f $clock.Elapsed.TotalSeconds)
    if (-not $KeepStack) { Invoke-Compose "down --volumes --remove-orphans" | Out-Null }
    Pop-Location
    foreach ($name in "POSTGRES_PASSWORD", "POSTGRES_BIND_ADDRESS", "POSTGRES_USER", "POSTGRES_DB") { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
}
Write-Host ""
if ($Failed) { Write-Host "$Failed check(s) failed." -ForegroundColor Red; exit 1 }
Write-Host "All checks passed. This proves the dump and archive restore into an empty database; it does not prove the application starts on them or that the .env keys are recoverable." -ForegroundColor Green
exit 0
