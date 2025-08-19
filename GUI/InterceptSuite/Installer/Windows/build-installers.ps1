# PowerShell script to build NSIS installer only for InterceptSuite Standard Edition
# This script assumes the .NET application is already published
param(
    [string]$OutputDir = "\dist",
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Enable verbose output if requested
if ($Verbose) {
    $VerbosePreference = "Continue"
}

# Script must be run from GUI/InterceptSuite/Installer/Windows directory
$scriptDir = $PSScriptRoot
$projectDir = Split-Path (Split-Path $scriptDir -Parent) -Parent
$projectRoot = Split-Path (Split-Path $projectDir -Parent) -Parent
$installerDir = Split-Path $scriptDir -Parent  # GUI/InterceptSuite/Installer

# Extract version information from .csproj
$getVersionScript = Join-Path $scriptDir "Get-Version.ps1"
if (-not (Test-Path $getVersionScript)) {
    Write-Error "Get-Version.ps1 not found at $getVersionScript"
    exit 1
}

$productVersion = & $getVersionScript "product-version"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Build-NSIS-Installer {
    param([string]$OutputDir)

    Write-Step "Building NSIS installer (User-specific, Self-contained)..."

    $nsisDir = Join-Path $scriptDir "nsis"
    $originalLocation = Get-Location

    try {
        Push-Location $nsisDir

        Write-Host "  Compiling NSIS installer..." -ForegroundColor Gray
        Write-Host "  Using LICENSE from project root: $projectRoot\LICENSE" -ForegroundColor Gray

        # Try to find makensis
        $makensisPath = "makensis.exe"
        $makensisCmd = Get-Command $makensisPath -ErrorAction SilentlyContinue
        if (-not $makensisCmd) {
            $commonPaths = @(
                "${env:ProgramFiles}\NSIS\makensis.exe",
                "${env:ProgramFiles(x86)}\NSIS\makensis.exe"
            )

            foreach ($path in $commonPaths) {
                if (Test-Path $path) {
                    $makensisPath = $path
                    break
                }
            }
        }

        if (-not (Test-Path $makensisPath)) {
            throw "NSIS makensis.exe not found. Please install NSIS."
        }

        & $makensisPath "/DAPP_VERSION=$productVersion" "InterceptSuite-Standard.nsi"
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to compile NSIS installer"
        }

        # Check if output file was created - NSIS creates it in the current directory
        $nsisOutputPath = "InterceptSuite-Standard-$productVersion-Setup.exe"
        $finalOutputPath = Join-Path $installerDir "$OutputDir\InterceptSuite-Standard-$productVersion-x64-Setup.exe"

        if (Test-Path $nsisOutputPath) {
            # Move the file to the unified output directory
            if (!(Test-Path (Join-Path $installerDir $OutputDir))) {
                New-Item -ItemType Directory -Path (Join-Path $installerDir $OutputDir) -Force | Out-Null
            }
            Move-Item $nsisOutputPath $finalOutputPath -Force

            $exeFile = Get-Item $finalOutputPath
            $size = [math]::Round($exeFile.Length / 1MB, 2)
            Write-Success "NSIS installer created: $($exeFile.Name) ($size MB)"
            return $true
        } else {
            throw "NSIS installer file was not created successfully"
        }

    } finally {
        Pop-Location
    }
}

# Main execution
Write-Host "=== NSIS Installer Builder ===" -ForegroundColor Cyan
Write-Host "Product Version: $productVersion" -ForegroundColor Green

# Check if published .NET application exists
$publishDir = Join-Path $projectDir "bin\Release\net9.0\win-x64\publish"
if (-not (Test-Path $publishDir)) {
    Write-Error-Custom "Published .NET application not found at: $publishDir"
    Write-Host "Please run the main build script first or publish the .NET application manually." -ForegroundColor Gray
    exit 1
}

# Check if Intercept.dll exists in publish directory
$interceptDll = Join-Path $publishDir "resource\Intercept.dll"
if (-not (Test-Path $interceptDll)) {
    Write-Error-Custom "Intercept.dll not found in publish directory at: $interceptDll"
    Write-Host "Please ensure the C library is built and copied to the publish directory." -ForegroundColor Gray
    exit 1
}

# Ensure output directory exists
$outputPath = Join-Path $installerDir $OutputDir
if (!(Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    Write-Success "Created output directory: $outputPath"
}

# Build NSIS installer
try {
    $result = Build-NSIS-Installer -OutputDir $OutputDir
    if ($result) {
        Write-Success "NSIS installer build completed successfully!"

        Write-Host ""
        Write-Host "Output files in 'Installer/$OutputDir':" -ForegroundColor Green
        Get-ChildItem $outputPath -Filter "*.exe" -ErrorAction SilentlyContinue | ForEach-Object {
            $size = [math]::Round($_.Length / 1MB, 2)
            Write-Host "  📦 $($_.Name) ($size MB)" -ForegroundColor White
        }
    } else {
        Write-Error-Custom "NSIS installer build failed"
        exit 1
    }
} catch {
    Write-Error-Custom "NSIS installer build failed: $($_.Exception.Message)"
    exit 1
}

Write-Host ""
Write-Host "NSIS installer build completed successfully! 🎉" -ForegroundColor Green
