# Cross-Platform Build Guide for InterceptSuite

This document provides instructions for building the InterceptSuite core library (`Intercept`) on Windows, Linux, and macOS platforms.

## Prerequisites

### All Platforms
- CMake 3.14 or higher
- vcpkg package manager
- OpenSSL 3.0 or higher
- C compiler with C11 support

### Windows
- Visual Studio 2019 or higher
- Windows SDK 10.0 or higher
- PowerShell 5.0 or higher

### Linux
- GCC 8.0 or higher or Clang 6.0 or higher
- POSIX threads library (pthread)
- Development tools (make, pkg-config, etc.)
- CMake 3.14 or higher

#### Installing Dependencies on Ubuntu/Debian:
```bash
sudo apt update
sudo apt install build-essential cmake pkg-config git curl zip unzip tar
```

#### Installing Dependencies on CentOS/RHEL/Fedora:
```bash
# For Fedora/newer RHEL
sudo dnf groupinstall 'Development Tools'
sudo dnf install cmake pkgconfig git curl zip unzip tar

# For older CentOS/RHEL
sudo yum groupinstall 'Development Tools'
sudo yum install cmake pkgconfig git curl zip unzip tar
```

#### Installing Dependencies on Arch/Manjaro:
```bash
sudo pacman -S base-devel cmake pkgconf git curl zip unzip tar
```

### macOS
- Xcode Command Line Tools
- Clang compiler

## Setting Up vcpkg

1. Clone vcpkg repository:
   ```
   git clone https://github.com/microsoft/vcpkg.git
   ```

2. Bootstrap vcpkg:
   - Windows: `.\vcpkg\bootstrap-vcpkg.bat`
   - Linux/macOS: `./vcpkg/bootstrap-vcpkg.sh`

3. Set environment variable (recommended):
   - Windows: `$env:VCPKG_INSTALLATION_ROOT = "path\to\vcpkg"`
   - Linux/macOS: `export VCPKG_INSTALLATION_ROOT=path/to/vcpkg`

## Building the Library

### Windows

1. Open PowerShell in the project directory
2. Run the build script:
   ```powershell
   .\build_windows.ps1 -BuildType Release -VcpkgRoot D:\path\to\vcpkg
   ```

### Linux

1. Open terminal in the project directory
2. Make the build script executable:
   ```bash
   chmod +x build_linux.sh
   ```
3. Run the build script:
   ```bash
   ./build_linux.sh --vcpkg-root=/path/to/vcpkg
   ```

### macOS

1. Open terminal in the project directory
2. Make the build script executable:
   ```bash
   chmod +x build_macos.sh
   ```
3. Run the build script:
   ```bash
   ./build_macos.sh --vcpkg-root=/path/to/vcpkg
   ```

## Output Files

The compiled library will be output to the following locations:

- Windows: `build/Release/Intercept.dll` (or `Debug/Intercept.dll` for debug builds)
- Linux: `build/libIntercept.so`
- macOS: `build/libIntercept.dylib`

On macOS, the library is built as a universal binary supporting both Intel (x86_64) and Apple Silicon (arm64) architectures.

## Integration with C/C++ Projects

Include the following files in your project:
- `include/tls_proxy_dll.h`: Public API declarations
- `include/tls_proxy.h`: Supporting structures and definitions

Link with the appropriate library for your platform:
- Windows: `Intercept.dll` and `Intercept.lib`
- Linux: `libIntercept.so`
- macOS: `libIntercept.dylib`

## Known Platform-Specific Issues

### Windows
- Requires WinSock2 (already linked in the build)
- Requires administrator privileges when intercepting certain system applications

### Linux
- Requires libdl for dynamic loading
- Some distributions may need additional SELinux configuration for traffic interception

### macOS
- On newer macOS versions, additional permissions may be required for traffic interception
- Network Extension entitlements may be required for system-wide interception

## Notes for macOS and Linux Users

The current version of the GUI interface is Windows-only. For macOS and Linux, only the core library is supported, allowing you to:

1. Build your own interface
2. Use command-line tools that utilize the library
3. Integrate the interception capabilities into your custom applications

Future updates will include native GUI interfaces for these platforms.
