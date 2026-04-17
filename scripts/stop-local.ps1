$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $PSScriptRoot "CLIProxyAPI.Startup.psm1"
Import-Module $modulePath -Force

$result = Stop-CLIProxyAPIProcess -RepoRoot $repoRoot
Write-Host $result.Message

if ($result.State -eq "NoPidFile" -or $result.State -eq "RemovedEmptyPidFile") {
    exit 0
}
