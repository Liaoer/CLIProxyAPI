$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $PSScriptRoot "CLIProxyAPI.Startup.psm1"
Import-Module $modulePath -Force

$result = Start-CLIProxyAPIProcess -RepoRoot $repoRoot

if ($result.AlreadyRunning) {
    Write-Host "CLIProxyAPI is already running. PID: $($result.Pid)"
} else {
    Write-Host "CLIProxyAPI started."
    Write-Host "PID: $($result.Pid)"
}

Write-Host "Stdout: $($result.StdoutPath)"
Write-Host "Stderr: $($result.StderrPath)"
Write-Host "URL: $($result.Url)"
