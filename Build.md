# Build Guide for InterceptSuite

This guide provides comprehensive instructions for building both the C native library component (DLL/SO/Dylib) and the Rust Tauri GUI application of InterceptSuite.

## Prerequisites

### Required Software

- **Rust** (latest stable version) with:
  - `rustc` compiler
  - `cargo` package manager
- **Node.js** version 18 or higher with npm/yarn
- **Tauri CLI** (`cargo install tauri-cli`)
- **CMake** version 3.14 or higher (for C native library)
- **vcpkg** package manager (for OpenSSL and other C dependencies)
- **Git** (for source control)
- **Platform-specific build tools:**
  - **Windows**: Visual Studio 2022 with C++ Desktop Development workload
  - **Linux**: GCC/Clang, build-essential, libssl-dev
  - **macOS**: Xcode Command Line Tools

### Required Libraries/Dependencies

- **OpenSSL** (installed via vcpkg on all platforms)
- **Rust dependencies** (handled by Cargo)
- **Node.js dependencies** (handled by npm/yarn)

## Project Architecture

The InterceptSuite consists of two main components:

1. **Native Library** (`libIntercept.dll`/`.so`/`.dylib`)
   - Written in C for maximum performance and low-level system access
   - Handles SSL/TLS certificate interception and network operations
   - Cross-platform compatible (Windows, Linux, macOS)

2. **GUI Application**
   - Built with **Tauri + Rust + TypeScript/React**
   - Provides a modern, cross-platform desktop interface
   - Communicates with the native library via FFI (Foreign Function Interface)
   - Hot-reload development support via Tauri's dev server

## Building InterceptSuite

The build process must be done in order: **Native C Library first, then Tauri GUI**

## Step 1: Build the Native C Library

The native library provides the core SSL/TLS interception functionality and must be built before the GUI.

### Setup vcpkg (All Platforms)

vcpkg is used on all platforms for consistent dependency management:

#### Windows

```powershell
# Clone vcpkg repository
git clone https://github.com/Microsoft/vcpkg.git D:/vcpkg

# Navigate to the vcpkg directory
cd D:/vcpkg

# Run the bootstrap script
.\bootstrap-vcpkg.bat

# Integrate vcpkg globally
.\vcpkg integrate install

# Install OpenSSL for x64 architecture
.\vcpkg install openssl:x64-windows
```

#### Linux

```bash
# Clone vcpkg repository
git clone https://github.com/Microsoft/vcpkg.git /var/vcpkg

# Navigate to the vcpkg directory
cd /var/vcpkg

# Run the bootstrap script
./bootstrap-vcpkg.sh

# Install OpenSSL for x64 architecture
./vcpkg install openssl:x64-linux
```

#### macOS

```bash
# Clone vcpkg repository
git clone https://github.com/Microsoft/vcpkg.git /var/vcpkg

# Navigate to the vcpkg directory
cd /var/vcpkg

# Run the bootstrap script
./bootstrap-vcpkg.sh

# Install OpenSSL for ARM64 architecture (Apple Silicon M1/M2/M3)
./vcpkg install openssl:arm64-osx

```

### Build Methods

You can build the native library using either automated scripts or manual CMake commands.

## Windows Build

### Method 1: Using Build Script (Recommended)

The automated build script handles vcpkg setup and native library compilation:

```powershell
# Navigate to project root
cd "InterceptSuite"

# Option A: Using --vcpkg-root parameter
.\build_windows.ps1 --vcpkg-root=D:/vcpkg

# Option B: Set environment variable (if vcpkg is already setup)
$env:VCPKG_INSTALLATION_ROOT = "D:/vcpkg"
.\build_windows.ps1

# Option C: For debug builds
.\build_windows.ps1 --vcpkg-root=D:/vcpkg --debug

```

**What the script does:**
- Validates vcpkg installation
- Configures CMake with proper vcpkg integration
- Install OpenSSL dependencies
- Builds the native C library
- Outputs to `build/Release/libIntercept.dll` or `build/Debug/libIntercept.dll`

### Method 2: Manual CMake Build

For fine-grained control over the build process:

```powershell
# Navigate to project root
cd "InterceptSuite"

# Step 1: Configure CMake with vcpkg toolchain
cmake -B build -S . `
    -DCMAKE_BUILD_TYPE=Release `
    -DVCPKG_INSTALLATION_ROOT=D:/vcpkg `
    -DCMAKE_TOOLCHAIN_FILE=D:/vcpkg/scripts/buildsystems/vcpkg.cmake `
    -G "Visual Studio 17 2022" `
    -A x64

# Step 2: Build the project
cmake --build build --config Release

# Alternative: Build with MSBuild directly
# MSBuild.exe build\InterceptSuite.sln /p:Configuration=Release /p:Platform=x64
```

**For Debug builds:**
```powershell
# Configure for Debug
cmake -B build -S . `
    -DCMAKE_BUILD_TYPE=Debug `
    -DVCPKG_INSTALLATION_ROOT=D:/vcpkg `
    -DCMAKE_TOOLCHAIN_FILE=D:/vcpkg/scripts/buildsystems/vcpkg.cmake `
    -G "Visual Studio 17 2022" `
    -A x64

# Build Debug version
cmake --build build --config Debug
```

**Important Note for Windows**: The native library does not statically link OpenSSL libraries. Instead, it dynamically links to OpenSSL DLLs. CMake is configured to automatically copy the required OpenSSL DLL files (such as `libssl-3-x64.dll` and `libcrypto-3-x64.dll`) from the vcpkg installation to the build folder. This ensures that `libIntercept.dll` can run properly by having all required dependencies in the same directory.


**Build Output Locations:**
- **Release**: `build\Release\libIntercept.dll`
- **Debug**: `build\Debug\libIntercept.dll`

**Troubleshooting Windows Builds:**
- Ensure Visual Studio 2022 with C++ Desktop Development workload is installed
- Verify CMake is in PATH: `cmake --version`
- Check vcpkg integration: `D:\vcpkg\vcpkg integrate install`
- For linker errors, ensure OpenSSL was installed via vcpkg: `D:\vcpkg\vcpkg list openssl`

## Linux Build

### Method 1: Using Build Script (Recommended)

The automated build script handles vcpkg setup and native library compilation:

```bash
# Navigate to project root
cd "InterceptSuite"

# Option A: Using --vcpkg-root parameter
./build_linux.sh --vcpkg-root=/var/vcpkg

# Option B: Set environment variable (if vcpkg is already setup)
export VCPKG_INSTALLATION_ROOT=/var/vcpkg
./build_linux.sh

# Option C: For debug builds
./build_linux.sh --vcpkg-root=/var/vcpkg --debug

```

**What the script does:**
- Validates vcpkg installation and OpenSSL availability
- Installs required system packages (build-essential, cmake)
- Configures CMake with proper vcpkg toolchain integration
- Builds the native C library with OpenSSL dependencies static linked
- Outputs to `build/libIntercept.so`

### Method 2: Manual CMake Build

For fine-grained control over the build process:

```bash
# Navigate to project root
cd "InterceptSuite"

# Step 1: Install required system packages (Ubuntu/Debian)
sudo apt update
sudo apt install build-essential cmake git pkg-config libssl-dev

# Alternative for Red Hat/CentOS/Fedora:
# sudo yum install gcc gcc-c++ cmake git openssl-devel
# sudo dnf install gcc gcc-c++ cmake git openssl-devel

# Step 2: Configure CMake with vcpkg toolchain
cmake -B build -S . \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=/var/vcpkg/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_TARGET_TRIPLET=x64-linux \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

# Step 3: Build the project with parallel jobs
cmake --build build --config Release

# Alternative: Use make directly
# cd build && make -j$(nproc)
```

**For Debug builds:**
```bash
# Configure for Debug with additional debugging symbols
cmake -B build -S . \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_TOOLCHAIN_FILE=/var/vcpkg/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_TARGET_TRIPLET=x64-linux \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_C_FLAGS_DEBUG="-g -O0 -DDEBUG"

# Build Debug version
cmake --build build --config Debug
```

**Build Output Location:** `build/libIntercept.so`

**Platform-Specific Dependencies:**

**Ubuntu/Debian:**
```bash
sudo apt install build-essential cmake git pkg-config curl zip unzip tar
```

**Red Hat/CentOS/Fedora:**
```bash
# CentOS/RHEL 7/8
sudo yum install gcc gcc-c++ cmake3 git pkgconfig curl zip unzip tar

# Fedora
sudo dnf install gcc gcc-c++ cmake git pkgconf curl zip unzip tar
```

**Arch Linux:**
```bash
sudo pacman -S base-devel cmake git curl zip unzip tar
```

**Troubleshooting Linux Builds:**
- Ensure GCC/Clang is installed: `gcc --version` or `clang --version`
- Verify CMake version: `cmake --version` (requires 3.14+)
- Check vcpkg OpenSSL installation: `/var/vcpkg/vcpkg list openssl`
- For permission issues with `/var/vcpkg`, use `sudo` or install to user directory
- If system OpenSSL conflicts, ensure vcpkg toolchain takes precedence

## macOS Build

### Method 1: Using Build Script (Recommended)

The automated build script handles vcpkg setup and native library compilation:

```bash
# Navigate to project root
cd "InterceptSuite"

# Option A: Using --vcpkg-root parameter
./build_macos.sh --vcpkg-root=/var/vcpkg

# Option B: Set environment variable (if vcpkg is already setup)
export VCPKG_INSTALLATION_ROOT=/var/vcpkg
./build_macos.sh

# Option C: For debug builds
./build_macos.sh --vcpkg-root=/var/vcpkg --debug


```

**What the script does:**
- Validates Xcode Command Line Tools installation
- Validates vcpkg installation and OpenSSL availability
- Detects Apple Silicon vs Intel architecture automatically
- Configures CMake with proper vcpkg toolchain integration
- Builds the native C library with OpenSSL dependencies
- Outputs to `build/libIntercept.dylib`

### Method 2: Manual CMake Build

For fine-grained control over the build process:

```bash
# Navigate to project root
cd "InterceptSuite"

cmake -B build -S . \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=/var/vcpkg/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_TARGET_TRIPLET=arm64-osx \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON


# Step 4: Build the project with parallel jobs
cmake --build build --config Release


```

**For Debug builds:**
```bash
# Configure for Debug with additional debugging symbols (Apple Silicon)
cmake -B build -S . \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_TOOLCHAIN_FILE=/var/vcpkg/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_TARGET_TRIPLET=arm64-osx \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_C_FLAGS_DEBUG="-g -O0 -DDEBUG"

# Build Debug version
cmake --build build --config Debug
```

**Build Output Location:** `build/libIntercept.dylib`

**Architecture Detection:**
The build scripts automatically detect your Mac's architecture:

```bash
# Check your Mac's architecture
uname -m
# Output: arm64 (Apple Silicon) or x86_64 (Intel)

# Verify the built library architecture
file build/libIntercept.dylib
# Expected: Mach-O 64-bit dynamically linked shared library arm64
```

**Platform-Specific Dependencies:**

**Required Tools:**
```bash
# Install Xcode Command Line Tools (required)
xcode-select --install

# Alternative: Install full Xcode from App Store (includes Command Line Tools)
```


**Troubleshooting macOS Builds:**

- Verify CMake version: `cmake --version` (requires 3.14+)
- Check vcpkg OpenSSL for correct architecture: `/var/vcpkg/vcpkg list openssl`
- For Apple Silicon Macs, ensure using `arm64-osx` triplet, not `x64-osx`
- If Homebrew OpenSSL conflicts with vcpkg, ensure vcpkg toolchain takes precedence
- For code signing issues in development, add `--codesign-identity -` to CMake flags

### Debug Builds

All platforms support debug builds for development and troubleshooting:

#### Using Build Scripts (Recommended)
```bash
# Windows (PowerShell)
.\build_windows.ps1 --debug --vcpkg-root=D:/vcpkg

# Linux
./build_linux.sh --debug --vcpkg-root=/var/vcpkg

# macOS
./build_macos.sh --debug --vcpkg-root=/var/vcpkg
```

#### Manual CMake Debug Builds

**Windows:**
```powershell
cmake -B build -S . `
    -DCMAKE_BUILD_TYPE=Debug `
    -DVCPKG_INSTALLATION_ROOT=D:/vcpkg `
    -DCMAKE_TOOLCHAIN_FILE=D:/vcpkg/scripts/buildsystems/vcpkg.cmake `
    -G "Visual Studio 17 2022" `
    -A x64
cmake --build build --config Debug --parallel
```

**Linux:**
```bash
cmake -B build -S . \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_TOOLCHAIN_FILE=/var/vcpkg/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_TARGET_TRIPLET=x64-linux \
    -DCMAKE_C_FLAGS_DEBUG="-g -O0 -DDEBUG -fsanitize=address"
cmake --build build --config Debug --parallel $(nproc)
```

**macOS:**
```bash
cmake -B build -S . \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_TOOLCHAIN_FILE=/var/vcpkg/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_TARGET_TRIPLET=arm64-osx \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_C_FLAGS_DEBUG="-g -O0 -DDEBUG"
cmake --build build --config Debug --parallel $(sysctl -n hw.ncpu)
```

#### Debug Build Features

Debug builds include:
- **Debugging symbols** (`-g`) for GDB/LLDB debugging
- **No optimization** (`-O0`) for easier debugging
- **DEBUG macro** defined for conditional debug code
- **Address sanitizer** (Linux) for memory error detection
- **Verbose logging** enabled in the native library
- **Debug assertions** enabled throughout the codebase

#### Environment Variables

All build scripts and manual builds support these environment variables:

```bash
# Primary vcpkg installation directory
export VCPKG_INSTALLATION_ROOT=/var/vcpkg

# Alternative vcpkg root (legacy compatibility)
export VCPKG_ROOT=/var/vcpkg

# Force specific target triplet
export VCPKG_DEFAULT_TRIPLET=x64-linux

# Additional CMake arguments
export CMAKE_ARGS="-DCMAKE_VERBOSE_MAKEFILE=ON"

# Build type override
export BUILD_TYPE=Debug

# Parallel build jobs (auto-detected if not set)
export BUILD_JOBS=8
```

**Windows-specific:**
```powershell
# PowerShell environment variables
$env:VCPKG_INSTALLATION_ROOT = "D:/vcpkg"
$env:VCPKG_DEFAULT_TRIPLET = "x64-windows"
$env:BUILD_TYPE = "Release"
```

## Step 2: Build the Tauri GUI Application

**Prerequisites**: The native C library must be built first (Step 1 above).



## Building the Tauri GUI Application

### Prerequisites Setup

1. **Install Tauri CLI:**

```bash
cargo install tauri-cli
```

2. **Install Node.js dependencies:**

```bash
# Navigate to the GUI directory
cd "InterceptSuite\GUI\InterceptSuite"

# Install frontend dependencies
npm install
# or
yarn install
```

### Development Build

For development with hot-reload:

```bash
# Navigate to the GUI directory
cd "InterceptSuite\GUI\InterceptSuite"

# Start development server
cargo tauri dev
```

This will:
- Start the Rust backend in development mode
- Launch the React frontend with hot-reload
- Open the application window
- Enable debugging features
- Automatically link with the native library built in Step 1

### Production Build

For production builds:

```bash
# Navigate to the GUI directory
cd "InterceptSuite\GUI\InterceptSuite"

# Build the application
cargo tauri build
```

This creates platform-specific installers in `src-tauri/target/release/bundle/`:
- **Windows**: `.exe` and `.msi` installers
- **Linux**: `.deb`, `.rpm`, and `.AppImage` packages
- **macOS**: `.dmg` and `.app` bundles

### Build Configuration

The Tauri build process is configured via `src-tauri/tauri.conf.json`:

```json
{
  "build": {
    "beforeDevCommand": "npm run dev",
    "beforeBuildCommand": "npm run build",
    "devPath": "http://localhost:1420",
    "distDir": "../dist"
  },
  "bundle": {
    "resources": ["resources/*"],
    "externalBin": ["../../../build/libIntercept"]
  }
}
```


## Troubleshooting

### Native Library Export Issues

If you encounter issues with missing exports in the native library, verify that the exports are properly defined in your build configuration. Common exports include:

```c
// Core proxy functions
init_proxy
start_proxy
stop_proxy
set_config

// Callback functions
set_log_callback
set_status_callback
set_connection_callback
set_stats_callback
set_disconnect_callback

// Utility functions
get_system_ips
get_proxy_config
get_proxy_stats

// Interception functions
set_intercept_callback
set_intercept_enabled
set_intercept_direction
respond_to_intercept
```


### Tauri Build Issues

**Node.js version**: Ensure you have Node.js 18+ installed:
```bash
node --version
npm --version
```

**Rust toolchain**: Verify Rust is properly installed:
```bash
rustc --version
cargo --version
```

**Missing Tauri CLI**: Install if needed:
```bash
cargo install tauri-cli
```

**Frontend dependencies**: Clear and reinstall if needed:
```bash
rm -rf node_modules package-lock.json
npm install
```

## Cross-Platform Support

InterceptSuite is designed to be cross-platform:

- **Native Library**: Written in C with platform-specific implementations
- **GUI Application**: Built with Tauri for native performance on all platforms
- **Supported Platforms**: Windows, Linux, and macOS

### Platform-Specific Notes

**Windows**:
- Uses WinAPI for system integration
- Requires Visual Studio 2022 build tools
- Dependencies managed via vcpkg

**Linux**:
- Uses POSIX APIs
- Requires build-essential tools
- Dependencies managed via vcpkg
- Supports multiple package formats (.deb, .rpm, .AppImage)

**macOS**:
- Uses BSD/Darwin APIs
- Requires Xcode Command Line Tools
- Dependencies managed via vcpkg

## Testing the Build

After building both components, verify the build was successful:

### 1. Verify Native Library Build

**Windows:**
```powershell
# Check if the DLL was created
Test-Path "build\Release\libIntercept.dll"
# Should return: True

# Check DLL dependencies
dumpbin /dependents build\Release\libIntercept.dll

# Verify exports are available
dumpbin /exports build\Release\libIntercept.dll | Select-String "init_proxy|start_proxy|stop_proxy"
```

**Linux:**
```bash
# Check if the shared library was created
ls -la build/libIntercept.so

# Check library dependencies
ldd build/libIntercept.so

# Verify exports are available
nm -D build/libIntercept.so | grep -E "init_proxy|start_proxy|stop_proxy"

# Check library architecture
file build/libIntercept.so
```

**macOS:**
```bash
# Check if the dylib was created
ls -la build/libIntercept.dylib

# Check library dependencies
otool -L build/libIntercept.dylib

# Verify exports are available
nm -D build/libIntercept.dylib | grep -E "init_proxy|start_proxy|stop_proxy"

# Check library architecture
file build/libIntercept.dylib
lipo -info build/libIntercept.dylib
```

### 2. Run the development GUI

Start the development version to test integration:

```bash
cd "InterceptSuite\GUI\InterceptSuite"
cargo tauri dev
```

**Expected behavior:**
- Application window opens without errors
- Native library loads successfully (check console for loading messages)
- GUI components render properly
- Proxy configuration interface is accessible

### 3. Test core functionality

In the development GUI:

1. **Configuration Test:**
   - Open proxy settings
   - Set a valid port (e.g., 8080)
   - Configure certificate settings

2. **Proxy Start Test:**
   - Click "Start Proxy"
   - Verify proxy starts without errors
   - Check status indicators

3. **Connection Test:**
   - Configure a client application to use the proxy
   - Make a test HTTPS connection
   - Verify interception works in the application logs

### 4. Test the production build

Build and test the production version:

```bash
# Build production version
cd "InterceptSuite\GUI\InterceptSuite"
cargo tauri build

# Test the generated installer/package
# Windows: Run the .exe or .msi installer from src-tauri/target/release/bundle/
# Linux: Install the .deb/.rpm package or run .AppImage
# macOS: Open the .dmg and install the .app
```

### 5. Verify functionality in production

After installing the production build:

1. **Launch the application**
2. **Configure proxy settings** (port, certificates, etc.)
3. **Start the proxy server**
4. **Configure a client application** to use the proxy (e.g., browser with proxy settings)
5. **Make test connections** and verify that:
   - Connections are successfully intercepted
   - Certificate handling works correctly
   - Logs are properly recorded
   - Performance is acceptable

### 6. Performance verification

Monitor the application during use:

```bash
# Windows - Task Manager or Resource Monitor
# Linux - htop, top, or system monitor
htop

# macOS - Activity Monitor or terminal
top -pid $(pgrep InterceptSuite)
```

**Expected performance characteristics:**
- **Memory usage**: < 100MB for typical workloads
- **CPU usage**: < 5% when idle, < 20% under load
- **Network latency**: < 50ms additional latency introduced by proxy
- **Throughput**: Should handle 100+ concurrent connections without degradation

## Development Workflow

For active development:

1. **Start the development server:**
```bash
cd "InterceptSuite\GUI\InterceptSuite"
cargo tauri dev
```

2. **Make changes to:**
   - **Frontend**: React/TypeScript files in `src/`
   - **Backend**: Rust files in `src-tauri/src/`
   - **Native Library**: C files in project root

3. **The development server will automatically:**
   - Reload frontend changes instantly
   - Rebuild Rust backend when needed
   - Require manual rebuild for C library changes

4. **Test changes:**
   - Use browser dev tools for frontend debugging
   - Use `cargo tauri dev` console for backend logs
   - Use system debugger for native library issues
