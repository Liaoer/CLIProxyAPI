$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$modulePath = Join-Path $repoRoot "scripts\CLIProxyAPI.Startup.psm1"

Describe "CLIProxyAPI startup automation" {
    It "uses the expected hidden startup task name" {
        Import-Module $modulePath -Force

        Get-CLIProxyAPIHiddenStartupTaskName | Should Be "CLIProxyAPI Hidden Startup"
    }

    It "builds a hidden PowerShell task action for start-local.ps1" {
        Import-Module $modulePath -Force

        $action = Get-CLIProxyAPIHiddenStartupActionSpec -RepoRoot $repoRoot

        $action.Execute | Should Match "powershell.exe$"
        $action.Argument | Should Match "-WindowStyle Hidden"
        $action.Argument | Should Match ([Regex]::Escape((Join-Path $repoRoot "scripts\start-local.ps1")))
    }

    It "builds hidden process start options for cli-proxy-api.exe" {
        Import-Module $modulePath -Force

        $sandbox = Join-Path $env:TEMP ("cliproxyapi-startup-test-" + [Guid]::NewGuid().ToString("N"))
        $null = New-Item -ItemType Directory -Path (Join-Path $sandbox "bin") -Force
        Set-Content -Path (Join-Path $sandbox "config.yaml") -Value "port: 8317"
        Set-Content -Path (Join-Path $sandbox "bin\cli-proxy-api.exe") -Value ""

        try {
            $spec = Get-CLIProxyAPIStartProcessSpec -RepoRoot $sandbox

            $spec.FilePath | Should Be (Join-Path $sandbox "bin\cli-proxy-api.exe")
            $spec.WindowStyle | Should Be "Hidden"
            $spec.ArgumentList[0] | Should Be "--config"
            $spec.ArgumentList[1] | Should Be (Join-Path $sandbox "config.yaml")
            $spec.StdoutPath | Should Be (Join-Path $sandbox ".runtime\cli-proxy-api.stdout.log")
            $spec.StderrPath | Should Be (Join-Path $sandbox ".runtime\cli-proxy-api.stderr.log")
        } finally {
            Remove-Item -Path $sandbox -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It "exports task enable and disable helpers" {
        Import-Module $modulePath -Force

        $commands = Get-Command -Module CLIProxyAPI.Startup |
            Select-Object -ExpandProperty Name

        ($commands -contains "Disable-CLIProxyAPIHiddenStartupTask") | Should Be $true
        ($commands -contains "Enable-CLIProxyAPIHiddenStartupTask") | Should Be $true
    }
}
