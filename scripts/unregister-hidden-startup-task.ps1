$ErrorActionPreference = "Stop"

$modulePath = Join-Path $PSScriptRoot "CLIProxyAPI.Startup.psm1"
Import-Module $modulePath -Force

$removed = Unregister-CLIProxyAPIHiddenStartupTask

if ($removed) {
    Write-Host "Removed scheduled task: CLIProxyAPI Hidden Startup"
} else {
    Write-Host "Scheduled task not found: CLIProxyAPI Hidden Startup"
}
