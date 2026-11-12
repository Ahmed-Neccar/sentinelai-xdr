# Emergency cleanup: undoes everything the SentinelAI sensor applied on this
# computer as a response action, without needing the sensor, the server or a
# network connection:
#
#   * removes every Windows Firewall rule it created
#     ("SentinelAI block <id>" and "SentinelAI isolate <id>"),
#   * re-enables the local accounts it recorded as disabled by it,
#   * clears the sensor's local record.
#
# It touches no other firewall rule and no other account. Use it if a block or
# an isolation must be lifted and the sensor or the server is not running.
# Needs an elevated (Run as administrator) PowerShell.

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this in a PowerShell window opened with 'Run as administrator'."
}

$rules = @(Get-NetFirewallRule -DisplayName "SentinelAI block *", "SentinelAI isolate *" -ErrorAction SilentlyContinue)
if ($rules.Count -eq 0) {
    Write-Host "No SentinelAI firewall rules are present."
}
else {
    $rules | ForEach-Object { Write-Host "Removing: $($_.DisplayName) ($($_.Direction))" }
    $rules | Remove-NetFirewallRule
    Write-Host "Removed $($rules.Count) rule(s)."
}

$state = Join-Path (Split-Path $PSScriptRoot -Parent) "sensor\runtime\response-blocks.json"
if (Test-Path -LiteralPath $state) {
    try {
        $records = Get-Content -LiteralPath $state -Raw | ConvertFrom-Json
        foreach ($property in $records.PSObject.Properties) {
            $record = $property.Value
            if ($record.kind -eq "account" -and $record.account -match '^[A-Za-z0-9][A-Za-z0-9._ -]{0,19}$') {
                Enable-LocalUser -Name $record.account
                Write-Host "Re-enabled local account: $($record.account)"
            }
        }
    }
    catch {
        Write-Warning "Could not read the sensor's record to re-enable accounts: $($_.Exception.Message)"
    }
    Remove-Item -LiteralPath $state -Force
    Write-Host "Cleared the sensor's local record."
}
Write-Host "The panel may still show these actions as applied until the sensor next reports."
