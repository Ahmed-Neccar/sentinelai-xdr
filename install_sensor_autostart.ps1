$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""
    )
    exit
}

$taskName = 'SentinelAI Sensor Controller'
$projectRoot = $PSScriptRoot
$pythonw = Join-Path $projectRoot 'sensor\.venv\Scripts\pythonw.exe'
$controller = Join-Path $projectRoot 'sensor\controller.py'
if (-not (Test-Path -LiteralPath $pythonw)) {
    throw 'Sensor Python environment was not found. Follow sensor\README.md to install it first.'
}
if (-not (Test-Path -LiteralPath $controller)) {
    throw 'Sensor controller was not found in the project folder.'
}

$account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $pythonw -Argument "`"$controller`"" -WorkingDirectory $projectRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $account
$taskPrincipal = New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings -Description 'Runs the loopback-only SentinelAI sensor controller for the signed-in user.' -Force | Out-Null

$client = [Net.Sockets.TcpClient]::new()
$controllerAlreadyRunning = $false
try {
    $connect = $client.BeginConnect('127.0.0.1', 8765, $null, $null)
    $controllerAlreadyRunning = $connect.AsyncWaitHandle.WaitOne(500) -and $client.Connected
} catch {
    $controllerAlreadyRunning = $false
} finally {
    $client.Dispose()
}

if ($controllerAlreadyRunning) {
    Write-Host 'Automatic startup is installed. The controller is already running; it will start automatically at your next sign-in.'
} else {
    Start-ScheduledTask -TaskName $taskName
    Write-Host 'Automatic startup is installed and the hidden controller has been started.'
}
Write-Host 'The controller log is in sensor\runtime\controller.log. Remove automatic startup with .\remove_sensor_autostart.ps1.'
