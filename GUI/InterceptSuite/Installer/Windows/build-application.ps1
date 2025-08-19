# PowerShell script to build NSIS installer for InterceptSuite Standard Edition
# Self-contained deployment - includes .NET runtime but no separate installation required
# Place this script in GUI/InterceptSuite/Installer/Windows/ directory
param(
    [string]$Configuration = "Release",
    [string]$OutputDir = "\dist",  # Changed to point to unified Installer/dist folder
    [switch]$CheckOnly,
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
$assemblyVersion = & $getVersionScript "version"
$productTitle = & $getVersionScript "title"
$productDescription = & $getVersionScript "description"
$companyName = & $getVersionScript "company"
$copyright = & $getVersionScript "copyright"

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ("=" * $Title.Length) -ForegroundColor Cyan
}

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

function Write-Warning-Custom {
    param([string]$Message)
    Write-Host "⚠ $Message" -ForegroundColor Yellow
}

function Test-Prerequisites {
    Write-Step "Checking prerequisites..."
    $allGood = $true

    # Check .NET SDK
    try {
        $dotnetVersion = dotnet --version 2>$null
        Write-Success ".NET SDK version: $dotnetVersion"

        if ($dotnetVersion -match "^9\.") {
            Write-Success ".NET 9.0 SDK detected"
        } else {
            Write-Warning-Custom ".NET 9.0 SDK recommended, found: $dotnetVersion"
        }
    } catch {
        Write-Error-Custom ".NET SDK not found. Please install .NET 9.0 SDK"
        $allGood = $false
    }

    # Check NSIS
    $nsisFound = $false
    try {
        $makensisCmd = Get-Command "makensis.exe" -ErrorAction SilentlyContinue
        if ($makensisCmd) {
            Write-Success "NSIS makensis.exe found at: $($makensisCmd.Source)"
            $nsisFound = $true
        }
    } catch { }

    if (-not $nsisFound) {
        $commonNsisPaths = @(
            "${env:ProgramFiles}\NSIS\makensis.exe",
            "${env:ProgramFiles(x86)}\NSIS\makensis.exe"
        )

        foreach ($path in $commonNsisPaths) {
            if (Test-Path $path) {
                Write-Success "NSIS found at: $path"
                $nsisFound = $true
                break
            }
        }
    }

    if (-not $nsisFound) {
        Write-Error-Custom "NSIS not found. Please install NSIS"
        Write-Host "  Download from: https://nsis.sourceforge.io/" -ForegroundColor Gray
        $allGood = $false
    }

    # Check C build output (Intercept.dll)
    $buildDir = Join-Path $projectDir "..\..\build\Release"
    $interceptDll = "Intercept.dll"

    if (Test-Path $buildDir) {
        Write-Success "Build directory found: $buildDir"

        $dllPath = Join-Path $buildDir $interceptDll
        if (Test-Path $dllPath) {
            $fileInfo = Get-Item $dllPath
            Write-Success "$interceptDll found ($([math]::Round($fileInfo.Length / 1024, 1)) KB)"
        } else {
            Write-Error-Custom "$interceptDll not found"
            Write-Host "  Please build the C libraries first using CMake" -ForegroundColor Gray
            $allGood = $false
        }
    } else {
        Write-Error-Custom "Build directory not found: $buildDir"
        Write-Host "  Please build the C libraries first using CMake" -ForegroundColor Gray
        $allGood = $false
    }

    # Check project file
    $projectFile = Join-Path $projectDir "InterceptSuite.csproj"
    if (Test-Path $projectFile) {
        Write-Success "Project file found: $projectFile"
    } else {
        Write-Error-Custom "Project file not found: $projectFile"
        $allGood = $false
    }

    return $allGood
}

function Copy-Resources {
    Write-Step "Copying C library resources..."

    $buildDir = Join-Path $projectDir "..\..\build\Release"
    $publishResourceDir = Join-Path $projectDir "bin\Release\net9.0\win-x64\publish\resource"

    # Ensure publish resource directory exists
    if (!(Test-Path $publishResourceDir)) {
        New-Item -ItemType Directory -Path $publishResourceDir -Force | Out-Null
        Write-Success "Created publish resource directory: $publishResourceDir"
    }

    # Copy Intercept.dll from C build output to publish resource directory
    $sourcePath = Join-Path $buildDir "Intercept.dll"
    $destPath = Join-Path $publishResourceDir "Intercept.dll"

    if (Test-Path $sourcePath) {
        Copy-Item $sourcePath $destPath -Force
        Write-Success "Copied: Intercept.dll to publish directory"
    } else {
        Write-Warning-Custom "File not found: $sourcePath"
    }

    Write-Success "Resource copy completed"
}

function Clean-BuildOutput {
    Write-Step "Cleaning build output (removing debug and unnecessary files)..."

    $buildOutputDir = Join-Path $projectDir "bin\Release\net9.0\win-x64\publish"

    if (!(Test-Path $buildOutputDir)) {
        Write-Warning-Custom "Build output directory not found: $buildOutputDir"
        return
    }

    # Remove debug and development files
    $unwantedFiles = @("*.pdb", "*.xml", "*.orig", "*.bak", "*.tmp")
    foreach ($pattern in $unwantedFiles) {
        $files = Get-ChildItem -Path $buildOutputDir -Filter $pattern -Recurse -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            Remove-Item $file.FullName -Force
            Write-Success "Removed unwanted file: $($file.Name)"
        }
    }

    # Remove unnecessary obj folders
    $objFolders = Get-ChildItem -Path $buildOutputDir -Name "obj" -Recurse -Directory -ErrorAction SilentlyContinue
    foreach ($objFolder in $objFolders) {
        $objPath = Join-Path $buildOutputDir $objFolder
        Remove-Item $objPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Success "Removed obj folder: $objPath"
    }

    # Note: Keep all Avalonia DLLs - they are needed at runtime
    # Native AOT includes only required dependencies

    Write-Success "Build output cleaned - removed debug files and development artifacts"
}

function Verify-BuildOutput {
    Write-Step "Verifying build output..."

    $buildOutputDir = Join-Path $projectDir "bin\Release\net9.0\win-x64\publish"

    if (!(Test-Path $buildOutputDir)) {
        Write-Error-Custom "Build output directory not found: $buildOutputDir"
        return $false
    }

    $unwantedPatterns = @("*.pdb", "*.xml", "*.orig", "*.bak", "*.tmp", "*.obj")
    $foundUnwanted = $false

    # Check for unwanted file patterns
    foreach ($pattern in $unwantedPatterns) {
        $files = Get-ChildItem -Path $buildOutputDir -Filter $pattern -Recurse -ErrorAction SilentlyContinue
        if ($files.Count -gt 0) {
            $foundUnwanted = $true
            Write-Error-Custom "Found unwanted files matching $pattern"
            foreach ($file in $files) {
                Write-Host "  - $($file.FullName)" -ForegroundColor Red
            }
        }
    }

    if (-not $foundUnwanted) {
        Write-Success "Build output verification passed - no unwanted files found"
    } else {
        Write-Warning "Unwanted files detected in build output. Consider running Clean-BuildOutput again."
    }

    # Check for main executable
    $mainExe = Join-Path $buildOutputDir "InterceptSuite.exe"
    if (Test-Path $mainExe) {
        $fileInfo = Get-Item $mainExe
        $size = [math]::Round($fileInfo.Length / 1MB, 2)
        Write-Success "Main executable found: InterceptSuite.exe ($size MB)"
    } else {
        Write-Error-Custom "Main executable not found: InterceptSuite.exe"
    }

    # Show license status
    $licensePath = Join-Path $projectRoot "LICENSE"
    if (Test-Path $licensePath) {
        Write-Success "LICENSE file found at project root: $licensePath"
    } else {
        Write-Error-Custom "LICENSE file not found at project root: $licensePath"
    }

    return (-not $foundUnwanted)
}

# Main execution
Write-Header "InterceptSuite Standard Edition - Self-Contained Installer Builder"

# Display version information
Write-Step "Version Information"
Write-Host "Product Version: $productVersion" -ForegroundColor Green
Write-Host "Assembly Version: $assemblyVersion" -ForegroundColor Green
Write-Host "Product Title: $productTitle" -ForegroundColor Green
Write-Host "Company: $companyName" -ForegroundColor Green

# If only checking prerequisites
if ($CheckOnly) {
    $prereqResult = Test-Prerequisites
    if ($prereqResult) {
        Write-Success "All prerequisites are satisfied!"
        exit 0
    } else {
        Write-Error-Custom "Some prerequisites are missing."
        exit 1
    }
}

# Check prerequisites
$prereqResult = Test-Prerequisites
if (-not $prereqResult) {
    Write-Error-Custom "Prerequisites check failed. Please install missing components."
    exit 1
}

# Ensure output directory exists (unified Installer output folder)
$outputPath = Join-Path $installerDir $OutputDir
if (!(Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    Write-Success "Created unified output directory: $outputPath"
} else {
    Write-Success "Using unified output directory: $outputPath"
}

# Change to project directory for building
$originalLocation = Get-Location
try {
    Push-Location $projectDir

    # Build .NET application as self-contained (includes runtime)
    Write-Step "Publishing .NET application as self-contained..."
    dotnet publish -r win-x64 -c $Configuration --nologo
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to publish .NET application as self-contained"
    }
    Write-Success ".NET application published successfully (self-contained, no separate runtime installation required)"

    # Copy resources AFTER publish (Intercept.dll from C build)
    Copy-Resources

    # Clean build output AFTER publish to remove unwanted files
    Clean-BuildOutput

    # Verify build output
    $verificationResult = Verify-BuildOutput
    if (-not $verificationResult) {
        Write-Warning-Custom "Build output verification had issues, but continuing with installer creation..."
    }

    # Build NSIS installer is now handled by separate script
    # Use .\build-installer.ps1 to create the installer after this step

    # Summary
    Write-Header "Build Summary"

    Write-Success "InterceptSuite Standard Edition .NET application built successfully!"

    Write-Host ""
    Write-Host "Published application location:" -ForegroundColor Green
    $publishPath = Join-Path $projectDir "bin\Release\net9.0\win-x64\publish"
    Write-Host "  � $publishPath" -ForegroundColor White

    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Run .\build-installer.ps1 to create the installer" -ForegroundColor Gray
    Write-Host "  2. Installer will be created in 'Installer/$OutputDir'" -ForegroundColor Gray

    Write-Host ""
    Write-Host ".NET application build completed successfully! 🎉" -ForegroundColor Green
    Write-Host "Use .\build-installer.ps1 to create the installer." -ForegroundColor Yellow
    exit 0

} finally {
    Pop-Location
}
