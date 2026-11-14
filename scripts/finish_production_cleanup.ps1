# Clears the leftovers of the move to production mode. Run it in an ELEVATED PowerShell:
#
#   powershell -ExecutionPolicy Bypass -File scripts\finish_production_cleanup.ps1
#
# It asks before each step. Add -WhatIf to see what it would do without changing anything.
#
#   1. Deletes .data\env-before-production-* (copies of the old .env with the old weak secrets),
#      but only if an encrypted .env backup newer than .env exists, so a copy of the current
#      keys is safe before the only other copy of any key is removed.
#   2. Deletes the throw-away local Windows account "sentinel-test" (made for the account
#      disable test), if it still exists.
#   3. Removes the three temporary Windows Firewall allow rules from the early setup
#      ("SentinelAI XDR Backend", "SentinelAI XDR Proxy", "SentinelAI Temp HTTP").
#
# It never touches the block rules that keep other computers off the HTTPS port, the stack,
# the database or any backup.
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param()

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated -and -not $WhatIfPreference) {
    throw "Run this from an elevated PowerShell (Run as administrator), or add -WhatIf to preview."
}

# -- 1. old .env copies -------------------------------------------------------
$copies = @(Get-ChildItem -LiteralPath (Join-Path $Root ".data") -Filter "env-before-production-*" -ErrorAction SilentlyContinue)
if (-not $copies.Count) {
    Write-Host "1. No old .env copies found."
}
else {
    $envFile = Join-Path $Root ".env"
    $backup = Get-ChildItem -LiteralPath (Join-Path $Root "backups") -Filter "env-*.enc" -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    if (-not $backup) {
        Write-Warning "1. Skipped: no encrypted .env backup exists. Run scripts\backup_env.ps1 first."
    }
    elseif ((Get-Item -LiteralPath $envFile).LastWriteTimeUtc -gt $backup.LastWriteTimeUtc) {
        Write-Warning "1. Skipped: .env is newer than $($backup.Name). Run scripts\backup_env.ps1 first, then run this again."
    }
    else {
        foreach ($copy in $copies) {
            if ($PSCmdlet.ShouldProcess($copy.FullName, "Delete old .env copy (old secrets)")) {
                Remove-Item -LiteralPath $copy.FullName -Force
                Write-Host "1. Deleted $($copy.Name)"
            }
        }
    }
}

# -- 2. test account ------------------------------------------------------------
$account = Get-LocalUser -Name "sentinel-test" -ErrorAction SilentlyContinue
if (-not $account) {
    Write-Host "2. The account sentinel-test does not exist."
}
elseif ($PSCmdlet.ShouldProcess("local account sentinel-test", "Delete")) {
    Remove-LocalUser -Name "sentinel-test"
    Write-Host "2. Deleted the local account sentinel-test."
}

# -- 3. temporary firewall rules ------------------------------------------------
$names = "SentinelAI XDR Backend", "SentinelAI XDR Proxy", "SentinelAI Temp HTTP"
$rules = @(Get-NetFirewallRule -DisplayName $names -ErrorAction SilentlyContinue)
if (-not $rules.Count) {
    Write-Host "3. The temporary firewall rules are already gone."
}
else {
    foreach ($rule in $rules) {
        if ($PSCmdlet.ShouldProcess($rule.DisplayName, "Remove firewall rule")) {
            Remove-NetFirewallRule -Name $rule.Name
            Write-Host "3. Removed the firewall rule '$($rule.DisplayName)'."
        }
    }
}

Write-Host ""
Write-Host "Done. Check the result with: powershell -ExecutionPolicy Bypass -File scripts\status.ps1"
