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
$PowerShell = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
if (-not $PowerShell) { $PowerShell = (Get-Command powershell.exe -ErrorAction Stop).Source }
$Script = Join-Path $PSScriptRoot "offsite_backup.ps1"
$Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Script`" -BucketName `"$BucketName`" -Region `"$Region`" -ProfileName `"$ProfileName`""
$Action = New-ScheduledTaskAction -Execute $PowerShell -Argument $Arguments -WorkingDirectory (Split-Path $PSScriptRoot -Parent)
$Trigger = New-ScheduledTaskTrigger -Daily -At 3:00AM
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew
$Principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName "SentinelAI Daily Off-site Backup" -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Creates, verifies, and uploads encrypted SentinelAI backups to the configured private S3 bucket." -Force | Out-Null
Write-Output "Scheduled daily off-site backup for 03:00 local time while this Windows user is signed in and Docker Desktop is available."
