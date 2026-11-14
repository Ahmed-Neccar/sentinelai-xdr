param(
    [string]$BackupDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) "backups"),
    # Newest backup sets to keep on this computer; older ones are deleted after a verified backup.
    [ValidateRange(3, 1000)]
    [int]$KeepLast = 14
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "backup_alert.ps1")
trap { Send-BackupFailureAlert $_ "backup.ps1"; break }
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ResolvedBackupDirectory = [System.IO.Path]::GetFullPath($BackupDirectory)
New-Item -ItemType Directory -Path $ResolvedBackupDirectory -Force | Out-Null

Push-Location $ProjectRoot
try {
    & docker compose --profile operations run --rm backup
    if ($LASTEXITCODE -ne 0) {
        throw "Compose backup job failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

$Manifest = Get-ChildItem -LiteralPath $ResolvedBackupDirectory -Filter "manifest-*.json" |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
if (-not $Manifest) {
    throw "Backup completed without a manifest in $ResolvedBackupDirectory"
}

$Metadata = Get-Content -LiteralPath $Manifest.FullName -Raw | ConvertFrom-Json
foreach ($Entry in @(
    @{ Name = $Metadata.database_file; Hash = $Metadata.database_sha256 },
    @{ Name = $Metadata.app_data_file; Hash = $Metadata.app_data_sha256 }
)) {
    $Artifact = Join-Path $ResolvedBackupDirectory $Entry.Name
    if (-not (Test-Path -LiteralPath $Artifact -PathType Leaf)) {
        throw "Backup artifact is missing: $Artifact"
    }
    $ActualHash = (Get-FileHash -LiteralPath $Artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualHash -ne $Entry.Hash.ToLowerInvariant()) {
        throw "Backup checksum verification failed: $Artifact"
    }
}

Write-Output "Backup verified from manifest: $($Manifest.FullName)"

# The database backup cannot decrypt MFA secrets or connector credentials without
# the keys in .env. Remind the operator when no current encrypted copy exists.
$EnvFile = Join-Path $ProjectRoot ".env"
if (Test-Path -LiteralPath $EnvFile -PathType Leaf) {
    $EnvBackup = Get-ChildItem -LiteralPath $ResolvedBackupDirectory -Filter "env-*.enc" |
        Sort-Object Name |
        Select-Object -Last 1
    if (-not $EnvBackup) {
        Write-Warning "No encrypted .env backup exists. Run scripts\backup_env.ps1; without .env this backup cannot be fully restored."
    } elseif ((Get-Item -LiteralPath $EnvFile).LastWriteTimeUtc -gt $EnvBackup.LastWriteTimeUtc) {
        Write-Warning ".env changed after its last encrypted backup ($($EnvBackup.Name)). Run scripts\backup_env.ps1 again."
    }
}

Clear-BackupFailure

# Keep the disk from filling: drop the oldest local sets (never the encrypted .env copies).
try {
    & (Join-Path $PSScriptRoot "prune_backups.ps1") -BackupDirectory $ResolvedBackupDirectory -KeepLast $KeepLast
} catch {
    Write-Warning "Old backups could not be pruned: $($_.Exception.Message)"
}

# The HTTPS certificate is self-signed and expires; sensors on other computers drop silently when it does.
try {
    & (Join-Path $PSScriptRoot "check_cert_expiry.ps1") | Out-Host
} catch { }
