# Writes a passphrase-encrypted copy of .env to backups\env-<timestamp>.enc.
# Run it in your own terminal after creating or changing .env. It asks for a
# passphrase twice and never stores it; keep the passphrase in a password
# manager, separate from the backup files.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Project Python environment not found at $Python."
}
& $Python (Join-Path $PSScriptRoot "env_backup.py") backup
exit $LASTEXITCODE
