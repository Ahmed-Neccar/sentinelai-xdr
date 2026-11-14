# Removes the boot-time sensor task made by install_sensor_boot_task.ps1. Elevated PowerShell.
$ErrorActionPreference = 'Stop'
$name = 'SentinelAI Sensor (boot)'
if (-not (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)) { Write-Host 'The boot task is not installed.'; exit 0 }
Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $name -Confirm:$false
Write-Host 'Removed. Use .\install_sensor_autostart.ps1 to start the controller at sign-in instead.'
