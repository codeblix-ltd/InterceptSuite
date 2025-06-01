# Cross-Platform Build Guide for InterceptSuite

This document provides instructions for building the InterceptSuite core library (`Intercept`) on Windows, Linux, and macOS platforms.

## ✅ Cross-Platform Build Status

- **Linux (POSIX)**: ✅ Successfully building and linking
- **Windows**: ✅ Previously working (needs verification after changes)
- **macOS**: 🔄 Should work with Linux POSIX implementation

## Recent Cross-Platform Fixes Completed

The following major issues have been resolved to enable cross-platform compilation:

### 1. Platform Header Syntax Fixes
- Fixed malformed `#include` directives and macro definitions in `platform.h`
- Separated multiple statements that were incorrectly combined on single lines
- Added proper POSIX thread types (`THREAD_HANDLE`, `THREAD_RETURN_TYPE`)

### 2. Socket Type Abstraction
- Implemented `socket_t` typedef for cross-platform socket handling
- Windows: `typedef SOCKET socket_t;`
- POSIX: `typedef int socket_t;`

### 3. Error Handling Unification
- Replaced all direct `WSAGetLastError()` calls with `GET_SOCKET_ERROR()` macro
- Added `GET_LAST_ERROR()` macro for non-socket errors
- Maps Windows error functions to POSIX `errno` appropriately

### 4. Thread Management Abstraction
- Fixed `CREATE_THREAD` macro implementation
- Added `INVALID_THREAD_ID` constant for proper thread comparison
- Replaced `NULL` thread comparisons with portable `INVALID_THREAD_ID` checks

### 5. Event System Simplification
- Simplified complex POSIX event macros that were causing compilation errors
- Implemented basic event system abstraction compatible with both platforms

### 6. Duplicate Symbol Resolution
- Removed duplicate `print_openssl_error()` function definition from `tls_utils.c`
- Function is now properly defined only in `cert_utils.c` with declaration in `cert_utils.h`

## Cross-Platform Implementation Details

The InterceptSuite library has been designed to work seamlessly across Windows, Linux, and macOS by using platform abstraction techniques:

### Platform Detection
Platform detection is handled in `platform.h`:
- Windows is detected using `_WIN32` or `_WIN64` macros
- When either macro is defined, `INTERCEPT_WINDOWS` is defined for internal use
- POSIX systems (Linux/macOS) use separate implementations for platform-specific features

### Abstracted System Calls
The following areas have been abstracted for cross-platform compatibility:

1. **Socket Handling**:
   - Windows uses Winsock2 (`SOCKET` type, `closesocket()`, etc.)
   - POSIX systems use standard BSD sockets (`int` descriptor, `close()`)
   - Error handling maps between `WSAGetLastError()` and `errno`/`strerror()`

2. **Thread Management**:
   - Windows: `CreateThread()`, `WaitForSingleObject()`, `CloseHandle()`
   - POSIX: `pthread_create()`, `pthread_join()`, `pthread_mutex` family

3. **Synchronization Primitives**:
   - Windows: `CRITICAL_SECTION`, `CreateEvent()`, `SetEvent()`, etc.
   - POSIX: `pthread_mutex_t`, `pthread_cond_t`

4. **Socket Timeouts**:
   - Windows: `DWORD` milliseconds timeout with `setsockopt()`
   - POSIX: `struct timeval` with seconds/microseconds for `setsockopt()`

5. **Error Handling**:
   - Windows: `WSAGetLastError()` with error code
   - POSIX: `errno` with `strerror()` for human-readable messages

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

## Platform-Specific Implementation Details

The library uses platform detection via preprocessor directives to ensure compatibility across Windows, Linux, and macOS:

```c
#if defined(_WIN32) || defined(_WIN64)
    #define INTERCEPT_WINDOWS
#endif
```

### Socket Operations
- **Windows**: Uses WinSock2 API with `SOCKET` type and `WSAGetLastError()` for errors
- **Linux/macOS**: Uses POSIX socket API with `int` type and `errno`/`strerror()` for errors

### Thread Management
- **Windows**: Uses Win32 thread API with `CreateThread()` and thread handles
- **Linux/macOS**: Uses POSIX thread API with `pthread_create()` and `pthread_join()`

### Socket Timeouts
- **Windows**: Uses `DWORD` type with milliseconds
```c
DWORD timeout = 60000;  // 60 seconds in milliseconds
```
- **Linux/macOS**: Uses `struct timeval` with seconds and microseconds
```c
struct timeval timeout;
timeout.tv_sec = 60;    // 60 seconds
timeout.tv_usec = 0;
```

### Synchronization Primitives
- **Windows**: Uses critical sections, events, and `WaitForSingleObject()`
- **Linux/macOS**: Uses pthread mutexes, condition variables, and timed waits

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

## Building on Linux

### Prerequisites
- Ubuntu/Debian: `sudo apt-get install build-essential cmake git`
- vcpkg package manager installed
- OpenSSL development headers

### Build Process
```bash
# Using the provided build script
./build_linux.sh --vcpkg-root=/path/to/vcpkg

# Or manually with CMake
mkdir -p build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
make -j4
```

### Successful Build Output
The Linux build now successfully produces:
- `libIntercept.so` - Shared library (approximately 8.4MB)
- All cross-platform abstractions working correctly
- No duplicate symbol errors
- Only minor format warnings (non-critical)
