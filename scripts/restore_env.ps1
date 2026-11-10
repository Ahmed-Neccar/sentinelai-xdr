param(
    [string]$File,
    [string]$Output
)

# Decrypts an encrypted .env backup into .env.restored (or -Output). It never
# overwrites an existing file; review the result, then rename it to .env.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Project Python environment not found at $Python."
}
$Arguments = @((Join-Path $PSScriptRoot "env_backup.py"), "restore")
if ($File) { $Arguments += @("--file", $File) }
if ($Output) { $Arguments += @("--output", $Output) }
& $Python @Arguments
exit $LASTEXITCODE
