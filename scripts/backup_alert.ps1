# Dot-sourced by backup.ps1 and offsite_backup.ps1. Not run on its own.
#
# On failure: writes backups\LAST_BACKUP_FAILURE.txt (cleared by the next success) and, if
# BACKUP_ALERT_WEBHOOK_URL is set in .env, posts {"text": ...} to that https URL (Slack-compatible).
# The URL is read, never printed. The message holds only the script name, time and error text.
function Get-BackupAlertUrl {
    $envFile = Join-Path (Split-Path $PSScriptRoot -Parent) ".env"
    if (-not (Test-Path -LiteralPath $envFile -PathType Leaf)) { return $null }
    foreach ($line in Get-Content -LiteralPath $envFile) {
        if ($line -cmatch '^\s*BACKUP_ALERT_WEBHOOK_URL\s*=\s*(\S+)\s*$') {
            $value = $Matches[1].Trim('"').Trim("'")
            if ($value -cmatch '^https://') { return $value }
        }
    }
    return $null
}

function Send-BackupFailureAlert {
    param($ErrorRecord, [string]$Source = "backup")
    if ($env:SENTINEL_BACKUP_ALERTED -eq "1") { return }
    $env:SENTINEL_BACKUP_ALERTED = "1"
    $when = [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
    $message = "SentinelAI backup FAILED ($Source) at $when : $($ErrorRecord.Exception.Message)"
    try {
        $dir = Join-Path (Split-Path $PSScriptRoot -Parent) "backups"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dir "LAST_BACKUP_FAILURE.txt") -Value $message -Encoding UTF8
    } catch { }
    $url = Get-BackupAlertUrl
    if ($url) {
        try {
            $body = @{ text = $message } | ConvertTo-Json -Compress
            Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType "application/json; charset=utf-8" -TimeoutSec 20 | Out-Null
        } catch {
            Write-Warning "Could not deliver the backup failure alert to the webhook."
        }
    }
}

function Clear-BackupFailure {
    $marker = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) "backups") "LAST_BACKUP_FAILURE.txt"
    if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue }
}
