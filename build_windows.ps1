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

Write-Host "Build completed successfully."
Write-Host "Output library can be found at: build/$BuildType/Intercept.dll"
