$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""
    )
    exit
}

$python = Join-Path $PSScriptRoot 'sensor\.venv\Scripts\python.exe'
$controller = Join-Path $PSScriptRoot 'sensor\controller.py'
if (-not (Test-Path -LiteralPath $python)) {
    throw 'Sensor Python environment was not found. Follow sensor\README.md to install it first.'
}
if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.env'))) {
    throw 'Project .env file was not found. Start the SentinelAI project setup first.'
}
& $python $controller
