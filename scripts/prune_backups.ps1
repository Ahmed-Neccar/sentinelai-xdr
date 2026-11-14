# Deletes old local backup sets (db-*.dump, app-data-*.tar.gz, manifest-*.json) and keeps
# the newest -KeepLast sets. Encrypted .env copies (env-*.enc) are never touched here.
# Use -WhatIf to see what would go. Sets are matched by their UTC timestamp.
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$BackupDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) "backups"),
    [ValidateRange(3, 1000)]
    [int]$KeepLast = 14
)
$ErrorActionPreference = "Stop"
$dir = [System.IO.Path]::GetFullPath($BackupDirectory)
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { Write-Output "No backup directory."; exit 0 }
$pattern = '^(?:db-(\d{8}T\d{6}Z)\.dump|app-data-(\d{8}T\d{6}Z)\.tar\.gz|manifest-(\d{8}T\d{6}Z)\.json)$'
$files = Get-ChildItem -LiteralPath $dir -File | ForEach-Object {
    $m = [regex]::Match($_.Name, $pattern)
    if ($m.Success) {
        $stamp = ($m.Groups[1].Value + $m.Groups[2].Value + $m.Groups[3].Value)
        [pscustomobject]@{ Stamp = $stamp; File = $_ }
    }
}
# Only a set that has a manifest counts as a usable backup when deciding what to keep.
$complete = $files | Where-Object { $_.File.Name -like "manifest-*" } | ForEach-Object { $_.Stamp } | Sort-Object -Descending -Unique
$keep = @($complete | Select-Object -First $KeepLast)
if ($keep.Count -lt $KeepLast -and $complete.Count -le $KeepLast) { Write-Output "Nothing to prune ($($complete.Count) sets)."; exit 0 }
$oldestKept = $keep[-1]
$removed = 0
foreach ($f in $files) {
    if ($f.Stamp -lt $oldestKept) {
        if ($PSCmdlet.ShouldProcess($f.File.FullName, "Delete old backup file")) {
            Remove-Item -LiteralPath $f.File.FullName -Force
            $removed++
        }
    }
}
Write-Output "Kept the newest $($keep.Count) backup sets (from $oldestKept); removed $removed old files."
