#!/usr/bin/env pwsh
# Build script for Windows

param(
    [ValidateSet("Debug", "Release")]
    [string]$BuildType = "Release",

    [string]$VcpkgRoot = $env:VCPKG_INSTALLATION_ROOT
)

# Check if VCPKG_INSTALLATION_ROOT is set
if (-not $VcpkgRoot) {
    Write-Host "VCPKG_INSTALLATION_ROOT environment variable not set."
    Write-Host "Please specify the vcpkg installation path using -VcpkgRoot parameter."
    exit 1
}

# Ensure vcpkg exists
if (-not (Test-Path "$VcpkgRoot/vcpkg.exe")) {
    Write-Host "vcpkg not found at $VcpkgRoot"
    Write-Host "Please ensure vcpkg is installed and the path is correct."
    exit 1
}

# Create build directory if it doesn't exist
if (-not (Test-Path "build")) {
    New-Item -ItemType Directory -Path "build"
}

# Configure with CMake
Write-Host "Configuring with CMake..."
cmake -B build -S . -DCMAKE_BUILD_TYPE=$BuildType -DVCPKG_INSTALLATION_ROOT="$VcpkgRoot"

if ($LASTEXITCODE -ne 0) {
    Write-Host "CMake configuration failed."
    exit 1
}

# Build
Write-Host "Building..."
cmake --build build --config $BuildType

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed."
    exit 1
}


# Copy OpenSSL DLLs from vcpkg if they exist
$BuildOutputDir = "build\$BuildType"

Write-Host "Checking for OpenSSL DLLs in vcpkg..."

# Check multiple possible vcpkg locations
$VcpkgBinPaths = @(
    "$VcpkgRoot\installed\x64-windows\bin",
    "$VcpkgRoot\packages\openssl_x64-windows\bin",
    "$VcpkgRoot\packages\openssl-windows_x64-windows\bin"
    " C:/vcpkg/packages/openssl_x64-windows/bin/"
)

$FoundOpenSSL = $false

foreach ($VcpkgBinDir in $VcpkgBinPaths) {
    Write-Host "Checking: $VcpkgBinDir"

    if (Test-Path $VcpkgBinDir) {
        Write-Host "✅ Directory exists. Looking for OpenSSL DLLs..."

        # List all DLLs for debugging
        $AllDlls = Get-ChildItem "$VcpkgBinDir\*.dll" -ErrorAction SilentlyContinue
        if ($AllDlls) {
            Write-Host "Found DLLs:"
            $AllDlls | ForEach-Object {
                Write-Host "  - $($_.Name)"
            }
        }

        # OpenSSL 3.x naming pattern
        $CryptoDll3 = "$VcpkgBinDir\libcrypto-3-x64.dll"
        $SslDll3 = "$VcpkgBinDir\libssl-3-x64.dll"

        # OpenSSL 1.1.x naming pattern
        $CryptoDll11 = "$VcpkgBinDir\libcrypto-1_1-x64.dll"
        $SslDll11 = "$VcpkgBinDir\libssl-1_1-x64.dll"

        # Try OpenSSL 3.x first
        if ((Test-Path $CryptoDll3) -and (Test-Path $SslDll3)) {
            Write-Host "Found OpenSSL 3.x DLLs, copying to build directory..."
            Copy-Item $CryptoDll3 $BuildOutputDir -Force
            Copy-Item $SslDll3 $BuildOutputDir -Force
            Write-Host "✅ Copied OpenSSL 3.x DLLs from $VcpkgBinDir"
            $FoundOpenSSL = $true
            break
        }
        # Try OpenSSL 1.1.x
        elseif ((Test-Path $CryptoDll11) -and (Test-Path $SslDll11)) {
            Write-Host "Found OpenSSL 1.1.x DLLs, copying to build directory..."
            Copy-Item $CryptoDll11 $BuildOutputDir -Force
            Copy-Item $SslDll11 $BuildOutputDir -Force
            Write-Host "✅ Copied OpenSSL 1.1.x DLLs from $VcpkgBinDir"
            $FoundOpenSSL = $true
            break
        }
        else {
            Write-Host "⚠️ OpenSSL DLLs not found in this directory"
        }
    } else {
        Write-Host "❌ Directory not found: $VcpkgBinDir"
    }
}

if (-not $FoundOpenSSL) {
    Write-Host "⚠️ OpenSSL DLLs not found in any vcpkg location"
    Write-Host "Searched locations:"
    $VcpkgBinPaths | ForEach-Object {
        Write-Host "  - $_"
    }
}

Write-Host "Build completed successfully."
Write-Host "Output library can be found at: build/$BuildType/Intercept.dll"

# Show final build directory contents
Write-Host "Build directory contents:"
Get-ChildItem $BuildOutputDir -Filter "*.dll" | ForEach-Object {
    Write-Host "  - $($_.Name) ($($_.Length) bytes)"
}
