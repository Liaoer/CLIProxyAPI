Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$modulePath = Join-Path $PSScriptRoot "CLIProxyAPI.Startup.psm1"
Import-Module $modulePath -Force

$disabled = Disable-CLIProxyAPIHiddenStartupTask
if ($disabled) {
    Write-Host "Disabled scheduled task: $(Get-CLIProxyAPIHiddenStartupTaskName)"
    exit 0
}

Write-Host "Scheduled task not found: $(Get-CLIProxyAPIHiddenStartupTaskName)"
exit 1
