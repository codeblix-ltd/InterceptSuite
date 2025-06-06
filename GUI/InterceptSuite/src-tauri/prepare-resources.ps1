# Pre-build script to prepare native libraries for Tauri bundling
param(
    [string]$BuildConfig = "Release"
)

$ErrorActionPreference = "Stop"

# Get the directory of this script
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$WorkspaceRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $ScriptDir))
$BuildDir = Join-Path $WorkspaceRoot "build"
$TauriDir = $ScriptDir

Write-Host "Preparing native libraries for bundling..." -ForegroundColor Green
Write-Host "Workspace root: $WorkspaceRoot"
Write-Host "Build configuration: $BuildConfig"


Write-Host "Detected platform: Windows"

# Copy Windows libraries
$InterceptDll = Join-Path $BuildDir "$BuildConfig\Intercept.dll"
if (Test-Path $InterceptDll) {
    Copy-Item $InterceptDll $ResourcesDir
    Write-Host "Copied Intercept.dll" -ForegroundColor Green
} else {
    Write-Host "Warning: Intercept.dll not found in $BuildDir\$BuildConfig\" -ForegroundColor Yellow
}

$CryptoDll = Join-Path $BuildDir "$BuildConfig\libcrypto-3-x64.dll"
if (Test-Path $CryptoDll) {
    Copy-Item $CryptoDll $ResourcesDir
    Write-Host "Copied libcrypto-3-x64.dll" -ForegroundColor Green
} else {
    Write-Host "Warning: libcrypto-3-x64.dll not found" -ForegroundColor Yellow
}

$SslDll = Join-Path $BuildDir "$BuildConfig\libssl-3-x64.dll"
if (Test-Path $SslDll) {
    Copy-Item $SslDll $ResourcesDir
    Write-Host "Copied libssl-3-x64.dll" -ForegroundColor Green
} else {
    Write-Host "Warning: libssl-3-x64.dll not found" -ForegroundColor Yellow
}

Write-Host "Native library preparation completed." -ForegroundColor Green
Write-Host "Resources directory contents:"
Get-ChildItem $ResourcesDir | Format-Table Name, Length -AutoSize
