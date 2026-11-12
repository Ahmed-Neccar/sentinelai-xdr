# Emergency cleanup: removes every Windows Firewall rule that the SentinelAI
# sensor created for an approved IP block ("SentinelAI block <id>") and clears
# the sensor's local record of them. It touches no other firewall rule.
#
# Use it if a block must be lifted and the sensor or the server is not running.
# Needs an elevated (Run as administrator) PowerShell.

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this in a PowerShell window opened with 'Run as administrator'."
}

$rules = @(Get-NetFirewallRule -DisplayName "SentinelAI block *" -ErrorAction SilentlyContinue)
if ($rules.Count -eq 0) {
    Write-Host "No SentinelAI block rules are present."
}
else {
    $rules | ForEach-Object { Write-Host "Removing: $($_.DisplayName) ($($_.Direction))" }
    $rules | Remove-NetFirewallRule
    Write-Host "Removed $($rules.Count) rule(s)."
}

$state = Join-Path (Split-Path $PSScriptRoot -Parent) "sensor\runtime\response-blocks.json"
if (Test-Path -LiteralPath $state) {
    Remove-Item -LiteralPath $state -Force
    Write-Host "Cleared the sensor's local block record."
}
Write-Host "The panel may still show these blocks as applied until the sensor next reports."
