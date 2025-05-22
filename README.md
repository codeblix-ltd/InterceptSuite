# Windows TLS MITM Proxy

A TLS/SSL Man-in-the-Middle proxy written in C that intercepts and displays encrypted HTTPS traffic in plaintext. This tool allows you to inspect encrypted communications between clients and servers by acting as a transparent proxy.

## Prerequisites

- CMake (3.14 or higher)
- A C compiler (MSVC, GCC, or Clang)
- vcpkg (installed anywhere on your system)

## Building the Project

### Using CMake

1. Create a build directory:
```powershell
mkdir build
cd build
```

2. Configure the project with CMake:
```powershell
# Automatic vcpkg detection (recommended)
cmake ..

# OR specify vcpkg location explicitly
cmake .. -DVCPKG_INSTALLATION_ROOT=D:/path/to/vcpkg

# OR use the traditional method
cmake .. -DCMAKE_TOOLCHAIN_FILE=D:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
```

3. Build the project:
```powershell
cmake --build .
```

## Dependency Management with vcpkg

This project includes a `vcpkg.json` file that specifies required dependencies. There are two ways to use it:

1. **Manifest Mode** (recommended):
   - The project will automatically download and build dependencies
   - Just run CMake as described above

2. **Classic Mode**:
   - Install dependencies manually with vcpkg:
   ```
   vcpkg install openssl
   ```

### Using VS Code

1. Install the C/C++ and CMake Tools extensions
2. Open the project folder in VS Code
3. Configure the CMake Tools extension to use the vcpkg toolchain file
4. Build the project using the CMake Tools extension

## Adding Dependencies

1. Install packages with vcpkg:
```powershell
vcpkg install [package-name]
```

2. Add the required packages to your CMakeLists.txt:
```cmake
find_package([Package] REQUIRED)
target_link_libraries(tls_app PRIVATE [Package]::[Library])
```

## Project Structure

- `include/` - Header files
- `src/` - Source files
- `test/` - Test files
- `CMakeLists.txt` - CMake build configuration

## Usage

1. **Set up the CA Certificate**:
   - When you first run the application, it will generate a CA certificate and key (`myCA.pem` and `myCA.key`)
   - Import `myCA.pem` into your browser or system's trusted certificate store
   - This allows the proxy to generate trusted certificates on-the-fly for intercepted HTTPS connections

2. **Run the Proxy**:
   ```powershell
   ./tls_app
   ```
   
3. **Configure Client Applications**:
   - Set up your system or browser to use a SOCKS5 proxy at `127.0.0.1:4444`
   - You can use tools like Proxifier, ProxyCap, or browser extensions to redirect traffic

4. **View Decrypted Traffic**:
   - All intercepted TLS/SSL traffic will be displayed in the console in plaintext
   - Traffic is formatted to show both the direction and content of communications

## Features

- SOCKS5 proxy implementation for transparent interception
- Dynamic SSL/TLS certificate generation for any domain
- Support for both plaintext and binary data visualization
- Cross-platform compatibility (Windows, Linux, macOS)
- Minimal dependencies (OpenSSL and standard libraries)

## Security Notice

This tool is designed for educational purposes, debugging, and security testing. Using it to intercept communications without proper authorization may be illegal and unethical. Always ensure you have permission to monitor network traffic before using this tool.
