$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $PSScriptRoot "CLIProxyAPI.Startup.psm1"
Import-Module $modulePath -Force

$task = Register-CLIProxyAPIHiddenStartupTask -RepoRoot $repoRoot

Write-Host "Registered scheduled task: $($task.TaskName)"
Write-Host "It will start CLIProxyAPI silently at user logon."
