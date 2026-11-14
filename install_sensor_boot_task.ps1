# Runs the sensor itself at boot, before anyone signs in, as SYSTEM (a scheduled task, not a
# Windows service), and restarts it if it stops. Needs an elevated PowerShell.
#
#   .\install_sensor_boot_task.ps1 -Interface "<Npcap adapter name>" [-AllowIpBlocks] [-AllowIsolation] [-AllowAccountDisable]
#       [-WindowsEvents] [-ProcessEvents] [-EndpointEvents]
#   On a computer that is not the server, also add:
#       -Server https://<server-address>:8443 -CaFile .\certs\localhost.crt -CredentialsFile .\sensor-credentials.json
#
# Get the adapter name from the Sensors page or: sensor\.venv\Scripts\python.exe sensor\live_sensor.py --list-interfaces
#
# Do not also start the sensor from the Sensors page while this task runs: two sensors from one
# computer are refused. To control it, use Start/Stop-ScheduledTask 'SentinelAI Sensor (boot)'.
# Isolation notices cannot be shown (a boot session has no desktop), though isolation still works.
#
# Status: written but NOT yet run on a real computer. After installing, restart and check
# sensor\runtime\boot-sensor.log and the Sensors page. Remove with remove_sensor_boot_task.ps1.
param(
    [Parameter(Mandatory = $true)][string]$Interface,
    [string]$Server = 'http://127.0.0.1:8001',
    [string]$CaFile,
    [string]$CredentialsFile,
    [switch]$AllowIpBlocks,
    [switch]$AllowIsolation,
    [switch]$AllowAccountDisable,
    [switch]$WindowsEvents,
    [switch]$ProcessEvents,
    [switch]$EndpointEvents
)
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell (Run as administrator).'
}

$taskName = 'SentinelAI Sensor (boot)'
$root = $PSScriptRoot
$python = Join-Path $root 'sensor\.venv\Scripts\python.exe'
$sensor = Join-Path $root 'sensor\live_sensor.py'
if (-not (Test-Path -LiteralPath $python)) { throw 'Sensor Python environment was not found. Follow sensor\README.md first.' }
if (-not (Test-Path -LiteralPath $sensor)) { throw 'sensor\live_sensor.py was not found.' }
if ($Interface -cmatch '["\r\n]') { throw 'The adapter name contains characters that cannot be used here.' }

$sensorArgs = @("`"$sensor`"", '--server', $Server, '--interface', "`"$Interface`"", '--duration-seconds', '0')
$idFile = Join-Path $root 'sensor\runtime\sensor-id'
if (Test-Path -LiteralPath $idFile) {
    $id = (Get-Content -LiteralPath $idFile -Raw).Trim()
    if ($id -cmatch '^[0-9a-fA-F-]{36}$') { $sensorArgs += @('--sensor-id', $id) }
}
if ($CredentialsFile) { $sensorArgs += @('--credentials-file', "`"$((Resolve-Path -LiteralPath $CredentialsFile).Path)`"") }
else { $sensorArgs += '--use-project-env' }
if ($CaFile) { $sensorArgs += @('--ca-file', "`"$((Resolve-Path -LiteralPath $CaFile).Path)`"") }
if ($AllowIpBlocks) { $sensorArgs += '--enforce-blocks' }
if ($AllowIsolation) { $sensorArgs += '--allow-isolation' }
if ($AllowAccountDisable) { $sensorArgs += '--allow-account-disable' }
if ($WindowsEvents) { $sensorArgs += '--windows-events' }
if ($ProcessEvents) { $sensorArgs += '--process-events' }
if ($EndpointEvents) { $sensorArgs += '--endpoint-events' }

New-Item -ItemType Directory -Path (Join-Path $root 'sensor\runtime') -Force | Out-Null
$log = Join-Path $root 'sensor\runtime\boot-sensor.log'
# cmd.exe is only used to append the sensor's output to a log file.
$cmdLine = '/c ""{0}" {1} >> "{2}" 2>&1"' -f $python, ($sensorArgs -join ' '), $log
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $cmdLine -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings -Description 'Runs the SentinelAI sensor at boot as SYSTEM.' -Force | Out-Null
Write-Host "Installed '$taskName'. It starts at the next boot. To start it now: Start-ScheduledTask -TaskName '$taskName'"
Write-Host "Log: sensor\runtime\boot-sensor.log   Remove with: .\remove_sensor_boot_task.ps1"
