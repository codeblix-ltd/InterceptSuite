# TLS Project Setup Guide

This guide provides detailed instructions for setting up and building the TLS project with vcpkg for dependency management.

## Prerequisites

Before you can build and run this project, you need to install:

1. **CMake** (3.14 or higher):
   - Download from [cmake.org/download](https://cmake.org/download/)
   - During installation, select the option to add CMake to the system PATH

2. **A C compiler**:
   - For Windows, install Visual Studio with C/C++ development tools
   - Or install the Build Tools for Visual Studio

3. **vcpkg** (Already installed at D:/vcpkg):
   - Make sure vcpkg is properly integrated with your system

## Build Instructions

### Step 1: Set up the build environment

CMake is already installed at `C:\Program Files\CMake\bin`, so we can use it directly. The project is designed to automatically find vcpkg in common installation locations, but you can also specify it manually.

```powershell
# Create a build directory
if (-not (Test-Path -Path "d:\Windows TLS\build")) {
    New-Item -ItemType Directory -Path "d:\Windows TLS\build"
}

# Navigate to the build directory
Set-Location -Path "d:\Windows TLS\build"

# Configure the project with CMake (auto-detect vcpkg)
& "C:\Program Files\CMake\bin\cmake.exe" ..

# OR specify vcpkg location explicitly if needed
# & "C:\Program Files\CMake\bin\cmake.exe" .. -DVCPKG_INSTALLATION_ROOT="D:/vcpkg"

# OR use the traditional method
# & "C:\Program Files\CMake\bin\cmake.exe" .. -DCMAKE_TOOLCHAIN_FILE="D:/vcpkg/scripts/buildsystems/vcpkg.cmake"

# Build the project
& "C:\Program Files\CMake\bin\cmake.exe" --build .
```

### Using the Project with Visual Studio

If you prefer using Visual Studio:

1. Open Visual Studio
2. Select "Open a local folder" and navigate to your project folder
3. Right-click on CMakeLists.txt and select "Configure Cache"
4. To configure with vcpkg, go to Project > CMake Settings
5. Add the following entry to CMake Command Arguments:
   `-DCMAKE_TOOLCHAIN_FILE="D:/vcpkg/scripts/buildsystems/vcpkg.cmake"`

### Adding Dependencies with vcpkg

1. Install a package with vcpkg:
```powershell
& "C:\Program Files\vcpkg\vcpkg.exe" install [package-name]
```

2. Update your CMakeLists.txt to include the package:
```cmake
find_package([Package] REQUIRED)
target_link_libraries(tls_app PRIVATE [Package]::[Library])
```

## Common Dependencies You Might Want to Add

Here are some common dependencies you might want to add to your project:

### OpenSSL

```powershell
& "D:\vcpkg\vcpkg.exe" install openssl:x64-windows
```

Then update CMakeLists.txt:
```cmake
find_package(OpenSSL REQUIRED)
target_link_libraries(tls_app PRIVATE OpenSSL::SSL OpenSSL::Crypto)
```

### libcurl

```powershell
& "D:\vcpkg\vcpkg.exe" install curl:x64-windows
```

Then update CMakeLists.txt:
```cmake
find_package(CURL REQUIRED)
target_link_libraries(tls_app PRIVATE CURL::libcurl)
```

## Project Structure

- `include/` - Header files
- `src/` - Source files
- `test/` - Test files
- `CMakeLists.txt` - CMake build configuration
- `.vscode/` - VS Code configuration files
