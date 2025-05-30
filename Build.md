# Build Guide for InterceptSuite

This guide provides comprehensive instructions for building both the C DLL component and the C# GUI application of the Windows InterceptSuite.

## Prerequisites

### Required Software

- **Visual Studio 2022** (Community, Professional, or Enterprise) with:
  - C++ Desktop Development workload
  - .NET Desktop Development workload
  - Windows 10/11 SDK
- **CMake** version 3.14 or higher
- **vcpkg** package manager (for OpenSSL dependency)
- **Git** (for source control)
- **PowerShell** 5.1 or higher

### Required Libraries/Dependencies

- **OpenSSL** (installed via vcpkg, version 3.x)
- **.NET 8.0 SDK** for the C# GUI application

## Building the C DLL (Intercept.dll)

### Setup vcpkg

If you haven't already installed vcpkg, follow these steps:

```powershell
# Clone vcpkg repository
git clone https://github.com/microsoft/vcpkg.git D:/vcpkg

# Navigate to the vcpkg directory
cd D:/vcpkg

# Run the bootstrap script
.\bootstrap-vcpkg.bat

# Integrate vcpkg with Visual Studio
.\vcpkg integrate install

# Install OpenSSL for x64 architecture
.\vcpkg install openssl:x64-windows
```

### Build the DLL using CMake

1. **Configure the build:**

```powershell
# Navigate to the project root
cd "D:\Windows TLS"

# Configure CMake
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DVCPKG_INSTALLATION_ROOT=D:/vcpkg
```

2. **Build the project:**

```powershell
# Build the solution
cmake --build build --config Release
```

3. **Verify the build output:**

After successful compilation, you should find these files in the `build\Release` directory:
- `Intercept.dll` - The main DLL
- `Intercept.lib` - Import library for the DLL
- `libcrypto-3-x64.dll` - OpenSSL crypto library
- `libssl-3-x64.dll` - OpenSSL SSL library

### Building for Debug

For debug builds, use the following commands:

```powershell
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug -DVCPKG_INSTALLATION_ROOT=D:/vcpkg
cmake --build build --config Debug
```

The debug output will be located in `build\Debug`.

## Building the C# GUI Application

### Using Visual Studio

1. Open Visual Studio 2022
2. Open the solution `D:\Windows TLS\GUI\InterceptSuite\InterceptSuite.csproj`
3. Select the build configuration (Debug or Release)
4. Build the solution (Build > Build Solution or F6)

### Using Command Line

You can also build the C# GUI application using the .NET CLI:

```powershell
# Navigate to the GUI project directory
cd "D:\Windows TLS\GUI\InterceptSuite"

# Build the project
dotnet build -c Release
```

## Creating a Complete Package

To create a complete package with both the DLL and GUI:

```powershell
# First build the C DLL
cd "D:\Windows TLS"
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DVCPKG_INSTALLATION_ROOT=D:/vcpkg
cmake --build build --config Release

# Then build and publish the C# application
cd "D:\Windows TLS\GUI\InterceptSuite"
dotnet publish -c Release -r win-x64 --self-contained false -o "..\..\publish"
```

This will create a complete package in the `D:\Windows TLS\publish` directory.

## Troubleshooting

### DLL Export Issues

If you encounter issues with missing exports in the DLL, verify that `tls_proxy.def` includes all required exports:

```
EXPORTS
init_proxy
start_proxy
stop_proxy
set_config
set_log_callback
set_status_callback
set_connection_callback
set_stats_callback
set_disconnect_callback
get_system_ips
get_proxy_config
get_proxy_stats
set_intercept_callback
set_intercept_enabled
set_intercept_direction
respond_to_intercept
OPENSSL_Applink
```

### OpenSSL DLL Issues

If you encounter issues with OpenSSL DLLs not being found:

1. Check that the OpenSSL DLLs (`libcrypto-3-x64.dll` and `libssl-3-x64.dll`) are present in the same directory as `Intercept.dll`.
2. Make sure you're using the correct architecture (x64) for all components.
3. Consider adding the OpenSSL bin directory to your system PATH.

### .NET Framework Version Issues

Ensure that you have .NET 8.0 SDK installed. You can verify this by running:

```powershell
dotnet --list-sdks
```

## Cross-Platform Considerations

The C/C++ DLL component is specifically designed for Windows and uses Windows-specific APIs. The C# GUI also targets Windows only. This is not a cross-platform application.

## Test Procedure

After building both components:

1. Run the GUI application from `D:\Windows TLS\publish\InterceptSuite.exe`
2. Configure the proxy settings
3. Start the proxy server
4. Configure your client application to use the proxy
5. Verify that the connections are successfully intercepted
