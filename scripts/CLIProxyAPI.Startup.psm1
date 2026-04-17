Set-StrictMode -Version Latest

function Resolve-CLIProxyAPIRepoRoot {
    [CmdletBinding()]
    param(
        [string]$RepoRoot
    )

    if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
        return (Split-Path -Parent $PSScriptRoot)
    }

    return [System.IO.Path]::GetFullPath($RepoRoot)
}

function Get-CLIProxyAPIPaths {
    [CmdletBinding()]
    param(
        [string]$RepoRoot
    )

    $resolvedRepoRoot = Resolve-CLIProxyAPIRepoRoot -RepoRoot $RepoRoot
    $binDir = Join-Path $resolvedRepoRoot "bin"
    $runtimeDir = Join-Path $resolvedRepoRoot ".runtime"
    $configPath = Join-Path $resolvedRepoRoot "config.yaml"
    $pidPath = Join-Path $runtimeDir "cli-proxy-api.pid"
    $stdoutPath = Join-Path $runtimeDir "cli-proxy-api.stdout.log"
    $stderrPath = Join-Path $runtimeDir "cli-proxy-api.stderr.log"
    $startScriptPath = Join-Path $resolvedRepoRoot "scripts\start-local.ps1"
    $stopScriptPath = Join-Path $resolvedRepoRoot "scripts\stop-local.ps1"
    $exe = Get-ChildItem -Path $binDir -Recurse -Filter "*.exe" -File -ErrorAction SilentlyContinue |
        Sort-Object -Property FullName |
        Select-Object -First 1

    [pscustomobject]@{
        RepoRoot        = $resolvedRepoRoot
        BinDir          = $binDir
        RuntimeDir      = $runtimeDir
        ConfigPath      = $configPath
        PidPath         = $pidPath
        StdoutPath      = $stdoutPath
        StderrPath      = $stderrPath
        StartScriptPath = $startScriptPath
        StopScriptPath  = $stopScriptPath
        ExePath         = if ($exe) { $exe.FullName } else { $null }
    }
}

function Get-CLIProxyAPIStartProcessSpec {
    [CmdletBinding()]
    param(
        [string]$RepoRoot
    )

    $paths = Get-CLIProxyAPIPaths -RepoRoot $RepoRoot
    if (-not (Test-Path $paths.ConfigPath)) {
        throw "Missing config.yaml at $($paths.ConfigPath)"
    }
    if ([string]::IsNullOrWhiteSpace($paths.ExePath)) {
        throw "No executable found under $($paths.BinDir). Run scripts/install-release.ps1 first."
    }

    [pscustomobject]@{
        FilePath         = $paths.ExePath
        ArgumentList     = @("--config", $paths.ConfigPath)
        WorkingDirectory = $paths.RepoRoot
        StdoutPath       = $paths.StdoutPath
        StderrPath       = $paths.StderrPath
        WindowStyle      = "Hidden"
        PidPath          = $paths.PidPath
        RuntimeDir       = $paths.RuntimeDir
    }
}

function Start-CLIProxyAPIProcess {
    [CmdletBinding()]
    param(
        [string]$RepoRoot
    )

    $spec = Get-CLIProxyAPIStartProcessSpec -RepoRoot $RepoRoot
    $null = New-Item -ItemType Directory -Force -Path $spec.RuntimeDir

    if (Test-Path $spec.PidPath) {
        $existingPid = (Get-Content $spec.PidPath -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
        if (-not [string]::IsNullOrWhiteSpace($existingPid)) {
            $existingProcess = Get-Process -Id $existingPid -ErrorAction SilentlyContinue
            if ($existingProcess) {
                return [pscustomobject]@{
                    AlreadyRunning = $true
                    Pid            = $existingPid
                    StdoutPath     = $spec.StdoutPath
                    StderrPath     = $spec.StderrPath
                    Url            = "http://127.0.0.1:8317"
                }
            }
        }
    }

    $process = Start-Process -FilePath $spec.FilePath `
        -ArgumentList $spec.ArgumentList `
        -WorkingDirectory $spec.WorkingDirectory `
        -RedirectStandardOutput $spec.StdoutPath `
        -RedirectStandardError $spec.StderrPath `
        -WindowStyle Hidden `
        -PassThru

    Set-Content -Path $spec.PidPath -Value $process.Id -NoNewline

    [pscustomobject]@{
        AlreadyRunning = $false
        Pid            = $process.Id
        StdoutPath     = $spec.StdoutPath
        StderrPath     = $spec.StderrPath
        Url            = "http://127.0.0.1:8317"
    }
}

function Stop-CLIProxyAPIProcess {
    [CmdletBinding()]
    param(
        [string]$RepoRoot
    )

    $paths = Get-CLIProxyAPIPaths -RepoRoot $RepoRoot

    if (-not (Test-Path $paths.PidPath)) {
        return [pscustomobject]@{
            State   = "NoPidFile"
            Message = "No PID file found. CLIProxyAPI does not appear to be running."
        }
    }

    $pidValue = (Get-Content $paths.PidPath -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
    if ([string]::IsNullOrWhiteSpace($pidValue)) {
        Remove-Item -Path $paths.PidPath -Force -ErrorAction SilentlyContinue
        return [pscustomobject]@{
            State   = "RemovedEmptyPidFile"
            Message = "Removed empty PID file."
        }
    }

    $process = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
    if ($process) {
        Stop-Process -Id $pidValue -Force
        Remove-Item -Path $paths.PidPath -Force -ErrorAction SilentlyContinue
        return [pscustomobject]@{
            State   = "Stopped"
            Pid     = $pidValue
            Message = "Stopped CLIProxyAPI. PID: $pidValue"
        }
    }

    Remove-Item -Path $paths.PidPath -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        State   = "ProcessNotRunning"
        Pid     = $pidValue
        Message = "Process $pidValue is not running."
    }
}

function Get-CLIProxyAPIHiddenStartupTaskName {
    [CmdletBinding()]
    param()

    return "CLIProxyAPI Hidden Startup"
}

function Get-CLIProxyAPIHiddenStartupActionSpec {
    [CmdletBinding()]
    param(
        [string]$RepoRoot
    )

    $paths = Get-CLIProxyAPIPaths -RepoRoot $RepoRoot
    $powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
    $quotedStartScript = '"' + $paths.StartScriptPath + '"'

    [pscustomobject]@{
        Execute = $powershell
        Argument = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $quotedStartScript"
    }
}

function Get-CLIProxyAPICurrentUserId {
    [CmdletBinding()]
    param()

    return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

function Register-CLIProxyAPIHiddenStartupTask {
    [CmdletBinding()]
    param(
        [string]$RepoRoot
    )

    $taskName = Get-CLIProxyAPIHiddenStartupTaskName
    $actionSpec = Get-CLIProxyAPIHiddenStartupActionSpec -RepoRoot $RepoRoot
    $userId = Get-CLIProxyAPICurrentUserId

    $action = New-ScheduledTaskAction -Execute $actionSpec.Execute -Argument $actionSpec.Argument
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
    $settings = New-ScheduledTaskSettingsSet `
        -Hidden `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew
    $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited

    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "Start CLIProxyAPI silently after Windows logon." `
        -Force | Out-Null

    return Get-ScheduledTask -TaskName $taskName
}

function Unregister-CLIProxyAPIHiddenStartupTask {
    [CmdletBinding()]
    param()

    $taskName = Get-CLIProxyAPIHiddenStartupTaskName
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $task) {
        return $false
    }

    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    return $true
}

function Disable-CLIProxyAPIHiddenStartupTask {
    [CmdletBinding()]
    param()

    $taskName = Get-CLIProxyAPIHiddenStartupTaskName
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $task) {
        return $false
    }

    Disable-ScheduledTask -TaskName $taskName | Out-Null
    return $true
}

function Enable-CLIProxyAPIHiddenStartupTask {
    [CmdletBinding()]
    param()

    $taskName = Get-CLIProxyAPIHiddenStartupTaskName
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $task) {
        return $false
    }

    Enable-ScheduledTask -TaskName $taskName | Out-Null
    return $true
}

Export-ModuleMember -Function @(
    "Disable-CLIProxyAPIHiddenStartupTask",
    "Enable-CLIProxyAPIHiddenStartupTask",
    "Get-CLIProxyAPIHiddenStartupActionSpec",
    "Get-CLIProxyAPIHiddenStartupTaskName",
    "Get-CLIProxyAPIPaths",
    "Get-CLIProxyAPIStartProcessSpec",
    "Register-CLIProxyAPIHiddenStartupTask",
    "Start-CLIProxyAPIProcess",
    "Stop-CLIProxyAPIProcess",
    "Unregister-CLIProxyAPIHiddenStartupTask"
)
