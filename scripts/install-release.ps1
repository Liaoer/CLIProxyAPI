$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$binDir = Join-Path $repoRoot "bin"
$zipPath = Join-Path $env:TEMP "CLIProxyAPI_windows_amd64_latest.zip"

New-Item -ItemType Directory -Force -Path $binDir | Out-Null

$release = Invoke-RestMethod "https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/latest"
$asset = $release.assets | Where-Object { $_.name -like "*_windows_amd64.zip" } | Select-Object -First 1

if (-not $asset) {
    throw "No Windows amd64 release asset found in the latest release."
}

Write-Host "Downloading $($asset.name) ..."
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath

Write-Host "Extracting to $binDir ..."
Expand-Archive -Path $zipPath -DestinationPath $binDir -Force
Remove-Item -Path $zipPath -Force

$exe = Get-ChildItem -Path $binDir -Recurse -Filter "*.exe" | Select-Object -First 1
if (-not $exe) {
    throw "Downloaded release did not contain an executable."
}

Write-Host "Installed: $($exe.FullName)"
