param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$')]
    [string]$BucketName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z]{2}(-gov)?-[a-z]+-\d$')]
    [string]$Region,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9+=,.@_-]{1,64}$')]
    [string]$ProfileName
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$CredentialFile = Join-Path $env:USERPROFILE ".aws\sentinelai-backup-credentials"
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Project Python environment not found at $Python. Create the project .venv and install backend requirements first."
}
if (-not (Test-Path -LiteralPath $CredentialFile -PathType Leaf)) {
    throw "Dedicated AWS credentials were not found. Run scripts/configure_aws_backup_profile.ps1 in a private local terminal; never paste the keys into chat."
}
$env:AWS_SHARED_CREDENTIALS_FILE = $CredentialFile

Push-Location $ProjectRoot
try {
    & (Join-Path $PSScriptRoot "backup.ps1")
    if ($LASTEXITCODE -ne 0) { throw "Local backup did not complete; off-site upload was not started." }

    $Manifest = Get-ChildItem -LiteralPath (Join-Path $ProjectRoot "backups") -Filter "manifest-*.json" |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if (-not $Manifest) { throw "No verified local backup manifest was produced." }

    & $Python (Join-Path $PSScriptRoot "upload_offsite_backup.py") `
        --backup-dir (Join-Path $ProjectRoot "backups") `
        --manifest $Manifest.FullName `
        --bucket $BucketName `
        --region $Region `
        --profile $ProfileName
    if ($LASTEXITCODE -ne 0) { throw "Off-site upload failed. The verified local backup remains available." }
} finally {
    Pop-Location
}
