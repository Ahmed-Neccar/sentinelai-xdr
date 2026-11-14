# Reports when the lab HTTPS certificate (and the copy packaged for sensors) expires.
# Read-only. Exit code 0 = fine, 1 = expires within -WarnDays or already expired, 2 = not found.
param(
    [int]$WarnDays = 30,
    [string]$CertificatePath = (Join-Path (Split-Path $PSScriptRoot -Parent) ".data\tls-lab\localhost.crt")
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
    Write-Output "Certificate not found: $CertificatePath"
    exit 2
}
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
$left = [math]::Floor(($cert.NotAfter.ToUniversalTime() - [DateTime]::UtcNow).TotalDays)
$when = $cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'")
if ($left -lt 0) {
    Write-Warning "The HTTPS certificate EXPIRED on $when. Sensors on other computers cannot connect. Run scripts\remote_sensors.ps1 -Action Setup (elevated) and redistribute the sensor package."
    exit 1
} elseif ($left -le $WarnDays) {
    Write-Warning "The HTTPS certificate expires in $left days ($when). Run scripts\remote_sensors.ps1 -Action Setup (elevated) and redistribute the sensor package before then."
    exit 1
}
Write-Output "HTTPS certificate valid for $left more days (until $when)."
exit 0
