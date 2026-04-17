Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$modulePath = Join-Path $PSScriptRoot "CLIProxyAPI.Startup.psm1"
Import-Module $modulePath -Force

$enabled = Enable-CLIProxyAPIHiddenStartupTask
if ($enabled) {
    Write-Host "Enabled scheduled task: $(Get-CLIProxyAPIHiddenStartupTaskName)"
    exit 0
}

Write-Host "Scheduled task not found: $(Get-CLIProxyAPIHiddenStartupTaskName)"
exit 1
