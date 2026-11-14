# One-screen health check of this installation. Read-only: it changes nothing and prints no secrets.
#
#   powershell -ExecutionPolicy Bypass -File scripts\status.ps1
#
# Each line is OK, WARN or FAIL. The exit code is 1 when anything FAILed, 0 otherwise.
$ErrorActionPreference = "Continue"
$Root = Split-Path $PSScriptRoot -Parent
$script:Failed = 0
$script:Warned = 0

function Write-Check([string]$Level, [string]$Name, [string]$Detail) {
    if ($Level -eq "FAIL") { $script:Failed++ }
    if ($Level -eq "WARN") { $script:Warned++ }
    $color = @{ OK = "Green"; WARN = "Yellow"; FAIL = "Red" }[$Level]
    Write-Host ("[{0,-4}] {1,-26} {2}" -f $Level, $Name, $Detail) -ForegroundColor $color
}

function Invoke-Docker([string]$Arguments) {
    # Docker writes progress to stderr; cmd keeps Windows PowerShell 5.1 from treating it as an error.
    return (cmd /c "docker $Arguments 2>&1")
}

function Get-EnvValue([string]$Name) {
    $file = Join-Path $Root ".env"
    if (-not (Test-Path -LiteralPath $file)) { return $null }
    foreach ($line in Get-Content -LiteralPath $file) {
        if ($line -cmatch ("^\s*" + [regex]::Escape($Name) + "\s*=\s*(.*)$")) { return $Matches[1].Trim().Trim('"').Trim("'") }
    }
    return $null
}

Write-Host "SentinelAI XDR status - $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host ""

# -- Docker and services ------------------------------------------------------
$docker = Invoke-Docker "version --format {{.Server.Version}}"
if ($LASTEXITCODE -ne 0 -or -not $docker) {
    Write-Check "FAIL" "Docker" "not reachable (is Docker Desktop running?)"
    exit 1
}
Write-Check "OK" "Docker" "server $docker"

Push-Location $Root
try {
    $services = Invoke-Docker "compose ps --format json"
    $running = @{}
    foreach ($line in $services) {
        if ($line -match '^\s*\{') {
            try { $item = $line | ConvertFrom-Json; $running[$item.Service] = $item } catch { }
        }
    }
    foreach ($name in "postgres", "redis", "backend", "worker", "celery-beat", "frontend") {
        if (-not $running.ContainsKey($name)) { Write-Check "FAIL" "service $name" "not running"; continue }
        $state = $running[$name].State
        $health = $running[$name].Health
        if ($state -ne "running") { Write-Check "FAIL" "service $name" $state }
        elseif ($health -and $health -ne "healthy") { Write-Check "WARN" "service $name" "running, health: $health" }
        else { Write-Check "OK" "service $name" "running" }
    }
    if ($running.ContainsKey("tls-proxy")) { Write-Check "OK" "service tls-proxy" "running (HTTPS front)" }
    else { Write-Check "WARN" "service tls-proxy" "not running (HTTPS and SSO on 8443 unavailable)" }
}
finally { Pop-Location }

# -- API readiness, mode and migration level --------------------------------
try {
    $ready = Invoke-RestMethod -UseBasicParsing -TimeoutSec 5 "http://127.0.0.1:8001/api/v1/ready"
    if ($ready.database -and $ready.redis) { Write-Check "OK" "API readiness" "database and Redis available" }
    else { Write-Check "FAIL" "API readiness" ($ready | ConvertTo-Json -Compress) }
}
catch { Write-Check "FAIL" "API readiness" "no answer on 127.0.0.1:8001" }

$mode = Get-EnvValue "SENTINEL_ENV"
if ($mode -eq "production") { Write-Check "OK" "mode" "production" }
elseif ($mode) { Write-Check "WARN" "mode" "$mode (not production)" }
else { Write-Check "WARN" "mode" "SENTINEL_ENV not set" }

$version = Invoke-Docker "compose -f `"$Root\compose.yaml`" exec -T postgres psql -U sentinel -d sentinel -tA -c `"select version_num from alembic_version`""
$version = ($version | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1)
if ($version) { Write-Check "OK" "database migration" "level $version" } else { Write-Check "WARN" "database migration" "could not read" }

try {
    $oidc = Invoke-RestMethod -UseBasicParsing -TimeoutSec 5 "http://127.0.0.1:8001/api/v1/auth/oidc/status"
    if ($oidc.enabled) { Write-Check "OK" "single sign-on" "enabled ($($oidc.origin))" } else { Write-Check "OK" "single sign-on" "not configured" }
}
catch { }

# -- Network exposure ----------------------------------------------------------
foreach ($port in 8001, 8080, 8443, 5432) {
    $listeners = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue
    if (-not $listeners) { continue }
    $addresses = ($listeners | Select-Object -ExpandProperty LocalAddress -Unique) -join ", "
    $loopbackOnly = -not ($listeners | Where-Object { $_.LocalAddress -notin "127.0.0.1", "::1" })
    if ($loopbackOnly -or $port -eq 8443) { Write-Check "OK" "port $port" "listening on $addresses" }
    else { Write-Check "WARN" "port $port" "listening on $addresses (reachable beyond this computer)" }
}
$blocks = Get-NetFirewallRule -DisplayName "SentinelAI*" -ErrorAction SilentlyContinue
if ($blocks) { Write-Check "OK" "firewall rules" "$(@($blocks).Count) SentinelAI rules ($((@($blocks | Where-Object Action -eq 'Block')).Count) block)" }
$old = Get-NetFirewallRule -DisplayName "SentinelAI XDR Backend", "SentinelAI XDR Proxy", "SentinelAI Temp HTTP" -ErrorAction SilentlyContinue
if ($old) { Write-Check "WARN" "old firewall rules" "$(@($old).Count) temporary allow rules still exist; remove them" }

# -- Certificate --------------------------------------------------------------
$cert = Join-Path $Root ".data\tls-lab\localhost.crt"
if (Test-Path -LiteralPath $cert) {
    $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)
    $days = [math]::Floor(($c.NotAfter.ToUniversalTime() - [DateTime]::UtcNow).TotalDays)
    if ($days -lt 0) { Write-Check "FAIL" "HTTPS certificate" "expired $(-$days) days ago" }
    elseif ($days -le 30) { Write-Check "WARN" "HTTPS certificate" "expires in $days days" }
    else { Write-Check "OK" "HTTPS certificate" "valid for $days more days" }
}

# -- Backups ------------------------------------------------------------------
$backups = Join-Path $Root "backups"
if (Test-Path -LiteralPath $backups) {
    $failure = Join-Path $backups "LAST_BACKUP_FAILURE.txt"
    if (Test-Path -LiteralPath $failure) { Write-Check "FAIL" "last backup" ((Get-Content -LiteralPath $failure -Raw).Trim()) }
    $manifest = Get-ChildItem -LiteralPath $backups -Filter "manifest-*.json" | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if ($manifest) {
        $age = [math]::Round(([DateTime]::UtcNow - $manifest.LastWriteTimeUtc).TotalHours, 1)
        if ($age -gt 36) { Write-Check "WARN" "latest local backup" "$age hours old" } else { Write-Check "OK" "latest local backup" "$age hours old" }
    }
    else { Write-Check "WARN" "latest local backup" "none found" }
    $envBackup = Get-ChildItem -LiteralPath $backups -Filter "env-*.enc" | Sort-Object Name | Select-Object -Last 1
    $envFile = Join-Path $Root ".env"
    if (-not $envBackup) { Write-Check "WARN" ".env backup" "no encrypted copy exists (scripts\backup_env.ps1)" }
    elseif ((Test-Path -LiteralPath $envFile) -and (Get-Item -LiteralPath $envFile).LastWriteTimeUtc -gt $envBackup.LastWriteTimeUtc) {
        Write-Check "WARN" ".env backup" ".env changed after $($envBackup.Name); run scripts\backup_env.ps1"
    }
    else { Write-Check "OK" ".env backup" $envBackup.Name }
}
$task = Get-ScheduledTask -TaskName "SentinelAI Daily Off-site Backup" -ErrorAction SilentlyContinue
if ($task) {
    $info = Get-ScheduledTaskInfo -TaskName "SentinelAI Daily Off-site Backup"
    if ($info.LastTaskResult -eq 0) { Write-Check "OK" "off-site backup task" "last run $($info.LastRunTime.ToString('yyyy-MM-dd HH:mm')) succeeded" }
    else { Write-Check "WARN" "off-site backup task" "last result $($info.LastTaskResult) at $($info.LastRunTime.ToString('yyyy-MM-dd HH:mm'))" }
}
else { Write-Check "WARN" "off-site backup task" "not installed" }
if (Test-Path -LiteralPath (Join-Path $Root ".data")) {
    $kept = @(Get-ChildItem -LiteralPath (Join-Path $Root ".data") -Filter "env-before-production-*" -ErrorAction SilentlyContinue)
    if ($kept.Count) { Write-Check "WARN" "old .env copies" "$($kept.Count) copies with the old secrets are still in .data" }
}
if ((Get-EnvValue "BACKUP_ALERT_WEBHOOK_URL")) { Write-Check "OK" "backup failure alert" "webhook configured" }
else { Write-Check "WARN" "backup failure alert" "BACKUP_ALERT_WEBHOOK_URL not set in .env" }

# -- Disk and sensor ----------------------------------------------------------
$drive = Get-PSDrive -Name ($Root.Substring(0, 1)) -ErrorAction SilentlyContinue
if ($drive) {
    $freeGb = [math]::Round($drive.Free / 1GB, 1)
    if ($freeGb -lt 5) { Write-Check "FAIL" "free disk space" "$freeGb GB" } elseif ($freeGb -lt 15) { Write-Check "WARN" "free disk space" "$freeGb GB" } else { Write-Check "OK" "free disk space" "$freeGb GB" }
}
try {
    $client = [Net.Sockets.TcpClient]::new()
    $connect = $client.BeginConnect("127.0.0.1", 8765, $null, $null)
    $up = $connect.AsyncWaitHandle.WaitOne(500) -and $client.Connected
    $client.Dispose()
    if ($up) { Write-Check "OK" "sensor controller" "listening on 127.0.0.1:8765" } else { Write-Check "WARN" "sensor controller" "not running (Sensors page cannot start the sensor)" }
}
catch { }

Write-Host ""
Write-Host "$script:Failed failed, $script:Warned warnings."
if ($script:Failed -gt 0) { exit 1 } else { exit 0 }
