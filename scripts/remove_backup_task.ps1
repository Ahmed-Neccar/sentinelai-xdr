$ErrorActionPreference = "Stop"
Unregister-ScheduledTask -TaskName "SentinelAI Daily Backup" -Confirm:$false -ErrorAction SilentlyContinue
Write-Output "SentinelAI Daily Backup scheduled task removed. Existing backup files were left untouched."
