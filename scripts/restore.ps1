param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$BackupDirectory = [System.IO.Path]::GetFullPath((Join-Path $ProjectRoot "backups"))
$ManifestFullPath = [System.IO.Path]::GetFullPath($ManifestPath)
$BackupPrefix = $BackupDirectory.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $ManifestFullPath.StartsWith($BackupPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Choose a manifest stored under the project backups directory."
}
if (-not (Test-Path -LiteralPath $ManifestFullPath -PathType Leaf)) {
    throw "Backup manifest was not found: $ManifestFullPath"
}

$Manifest = Get-Content -LiteralPath $ManifestFullPath -Raw | ConvertFrom-Json
foreach ($Name in @($Manifest.database_file, $Manifest.app_data_file)) {
    if ([System.IO.Path]::GetFileName($Name) -ne $Name) {
        throw "The manifest contains an invalid artifact path."
    }
}
$DatabaseFile = Join-Path $BackupDirectory $Manifest.database_file
$AppDataFile = Join-Path $BackupDirectory $Manifest.app_data_file
foreach ($Entry in @(
    @{ Path = $DatabaseFile; Hash = $Manifest.database_sha256 },
    @{ Path = $AppDataFile; Hash = $Manifest.app_data_sha256 }
)) {
    if (-not (Test-Path -LiteralPath $Entry.Path -PathType Leaf)) {
        throw "Backup artifact is missing: $($Entry.Path)"
    }
    $ActualHash = (Get-FileHash -LiteralPath $Entry.Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualHash -ne $Entry.Hash.ToLowerInvariant()) {
        throw "Backup checksum verification failed: $($Entry.Path)"
    }
}

Write-Warning "Restore replaces the current SentinelAI database and uploaded/model files."
$Confirmation = Read-Host "A fresh pre-restore backup will be created. Type RESTORE to continue"
if ($Confirmation -cne "RESTORE") {
    throw "Restore cancelled. No application data was changed."
}

& (Join-Path $PSScriptRoot "backup.ps1")
if ($LASTEXITCODE -ne 0) {
    throw "Could not create the required pre-restore backup. Restore was not started."
}

Push-Location $ProjectRoot
try {
    & docker compose stop backend worker celery-beat frontend
    if ($LASTEXITCODE -ne 0) {
        throw "Could not stop all application services; restore was not started."
    }

    $DatabaseContainerPath = "/backups/$($Manifest.database_file)"
    $AppContainerPath = "/backups/$($Manifest.app_data_file)"
    $RestoreScript = @'
set -eu
pg_restore --list "$RESTORE_DB_FILE" >/dev/null
tar -tzf "$RESTORE_APP_FILE" | awk 'BEGIN { ok=1 } /^\// || /(^|\/)\.\.(\/|$)/ { ok=0 } END { exit !ok }'
export PGPASSWORD="$POSTGRES_PASSWORD"
pg_restore --clean --if-exists --no-owner --no-privileges --single-transaction -h postgres -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$RESTORE_DB_FILE"
find /source-data -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
tar -xzf "$RESTORE_APP_FILE" -C /source-data
'@
    & docker compose --profile operations run --rm --no-deps `
        -e "RESTORE_DB_FILE=$DatabaseContainerPath" `
        -e "RESTORE_APP_FILE=$AppContainerPath" `
        --entrypoint sh restore -ec $RestoreScript
    if ($LASTEXITCODE -ne 0) {
        throw "Restore failed. Application services remain stopped so the data state can be inspected."
    }

    & docker compose up -d backend worker celery-beat frontend
    if ($LASTEXITCODE -ne 0) {
        throw "Data restore succeeded, but application services could not be started."
    }
} finally {
    Pop-Location
}

Write-Output "Restore completed. Check http://127.0.0.1:8001/api/v1/ready and review service logs."
