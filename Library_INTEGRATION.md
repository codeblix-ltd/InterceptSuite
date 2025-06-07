# Library Integration Guide

This guide explains how to integrate the InterceptSuite native library into your own applications across Windows, Linux, and macOS platforms.

## Available Library Files

The InterceptSuite TLS MITM Proxy is available as a cross-platform native library that you can integrate into your own applications. After building the project following the instructions in [Build.md](Build.md), you can find the library files in:

**Windows:**
- Debug build: `build\Debug\libIntercept.dll`
- Release build: `build\Release\libIntercept.dll`

**Linux:**
- Debug build: `build/libIntercept.so`
- Release build: `build/libIntercept.so`

**macOS:**
- Debug build: `build/libIntercept.dylib`
- Release build: `build/libIntercept.dylib`

## Dependencies

**Windows:** The library requires the following dependencies to be present in the same directory:
- `libcrypto-3-x64.dll` (OpenSSL cryptographic library)
- `libssl-3-x64.dll` (OpenSSL SSL/TLS library)

**Linux/macOS:** OpenSSL libraries are statically linked into the shared library (.so/.dylib), so no additional dependencies are required at runtime.

## Integration

Include the `tls_proxy_dll.h` header file (located in the `include` folder) to access the TLS proxy functionality. The library provides:
- Cross-platform TLS interception and inspection
- Dynamic certificate generation and management
- SOCKS5 proxy functionality with real-time monitoring
- Real-time event callbacks for logging and monitoring
- Traffic interception with modification capabilities
- Certificate export functionality for trust establishment

The library uses platform-specific macros for proper symbol visibility and calling conventions across Windows, Linux, and macOS.

## API Overview

The InterceptSuite library provides the following exported functions:

### Core Proxy Functions
- `start_proxy()` - Start the proxy server (also initializes proxy subsystems)
- `stop_proxy()` - Stop the proxy server
- `set_config()` - Configure proxy settings (bind address, port, log file, verbose mode)

### Configuration and Status Functions
- `get_system_ips()` - Retrieve system network interfaces
- `get_proxy_config()` - Get current proxy configuration and running status
- `get_intercept_config()` - Get current interception configuration and status

### Callback Registration Functions
- `set_log_callback()` - Set callback for log events (provides full proxy history data, including all incoming and outgoing data flows with timestamps)
- `set_status_callback()` - Set callback for status messages, error notifications, and debug logs (shown in status bar of GUI)
- `set_connection_callback()` - Set callback for new connections (displays TCP connections with unique connection IDs for tracking)
- `set_disconnect_callback()` - Set callback for connection termination
- `set_intercept_callback()` - Set callback for traffic interception

### Traffic Interception Functions
- `set_intercept_enabled()` - Enable/disable traffic interception (0=disabled, 1=enabled)
- `set_intercept_direction()` - Set interception direction (0=none, 1=client→server, 2=server→client, 3=both)
- `respond_to_intercept()` - Respond to intercepted traffic (forward original, drop, or forward modified data)

### Certificate Management Functions
- `export_certificate()` - Export CA certificate and private key to specified directory

## Function Signatures

```c
// Core proxy functions
typedef bool intercept_bool_t;  // On Windows: BOOL, On Linux/macOS: bool
INTERCEPT_API intercept_bool_t start_proxy(void);
INTERCEPT_API void stop_proxy(void);
INTERCEPT_API intercept_bool_t set_config(const char* bind_addr, int port, const char* log_file, int verbose_mode);

// System information
INTERCEPT_API int get_system_ips(char* buffer, int buffer_size);

// Configuration structures and getters
typedef struct {
    char bind_addr[64];       /* Binding IP address */
    int port;                 /* Proxy port */
    char log_file[256];       /* Log file path */
    int verbose_mode;         /* Verbose logging enabled (1) or disabled (0) */
    int is_running;           /* Proxy status: running (1) or stopped (0) */
} proxy_config_t;
INTERCEPT_API proxy_config_t get_proxy_config(void);

typedef struct {
    int is_enabled;           /* Interception enabled (1) or disabled (0) */
    int direction;            /* Direction: None (0), Client->Server (1), Server->Client (2), Both (3) */
} intercept_status_t;
INTERCEPT_API intercept_status_t get_intercept_config(void);

// Callback function types
typedef void (*log_callback_t)(const char* timestamp, int connection_id, int packet_id, const char* src_ip, const char* dst_ip, int dst_port, const char* message_type, const char* data);
typedef void (*status_callback_t)(const char* message);
typedef void (*connection_callback_t)(const char* client_ip, int client_port, const char* target_host, int target_port, int connection_id);
typedef void (*disconnect_callback_t)(int connection_id, const char* reason);
typedef void (*intercept_callback_t)(int connection_id, const char* direction, const char* src_ip, const char* dst_ip, int dst_port, const unsigned char* data, int data_length, int packet_id);

// Callback registration functions
INTERCEPT_API void set_log_callback(log_callback_t callback);
INTERCEPT_API void set_status_callback(status_callback_t callback);
INTERCEPT_API void set_connection_callback(connection_callback_t callback);
INTERCEPT_API void set_disconnect_callback(disconnect_callback_t callback);
INTERCEPT_API void set_intercept_callback(intercept_callback_t callback);

// Interception control functions
INTERCEPT_API void set_intercept_enabled(int enabled);
INTERCEPT_API void set_intercept_direction(int direction);
INTERCEPT_API void respond_to_intercept(int connection_id, int action, const unsigned char* modified_data, int modified_length);

// Certificate export function
INTERCEPT_API intercept_bool_t export_certificate(const char* output_directory, int export_type);
```

### Interception Response Actions

When using `respond_to_intercept()`, the `action` parameter can be:
- **0 (INTERCEPT_ACTION_FORWARD)** - Forward the original data unchanged
- **1 (INTERCEPT_ACTION_DROP)** - Drop the connection
- **2 (INTERCEPT_ACTION_MODIFY)** - Forward modified data (must provide modified_data and modified_length)

### Certificate Export Types

When using `export_certificate()`, the `export_type` parameter can be:
- **0** - Export certificate (PEM to DER format)
- **1** - Export private key (PEM copy)

## Example Usage

### C Example

```c
#include "tls_proxy_dll.h"
#include <stdio.h>
#include <stdlib.h>

// Callback functions
void log_callback(const char* timestamp, int connection_id, int packet_id, const char* src_ip, const char* dst_ip, int dst_port, const char* message_type, const char* data) {
    printf("[%s] ID:%d PKT:%d %s -> %s:%d [%s] %s\n", timestamp, connection_id, packet_id, src_ip, dst_ip, dst_port, message_type, data);
}

void status_callback(const char* message) {
    printf("[STATUS] %s\n", message);
}

void connection_callback(const char* client_ip, int client_port, const char* target_host, int target_port, int connection_id) {
    printf("[CONNECTION] ID: %d, %s:%d -> %s:%d\n", connection_id, client_ip, client_port, target_host, target_port);
}

void disconnect_callback(int connection_id, const char* reason) {
    printf("[DISCONNECT] ID: %d, Reason: %s\n", connection_id, reason);
}

void intercept_callback(int connection_id, const char* direction, const char* src_ip, const char* dst_ip,
                        int dst_port, const unsigned char* data, int data_length, int packet_id) {
    printf("[INTERCEPT] ID: %d, PKT: %d, Direction: %s, %s -> %s:%d, %d bytes\n",
           connection_id, packet_id, direction, src_ip, dst_ip, dst_port, data_length);

    // Example: Forward the original data unchanged (action 0)
    respond_to_intercept(connection_id, 0, NULL, 0);

    // Example: To modify data and forward it (action 2):
    // respond_to_intercept(connection_id, 2, modified_data, modified_length);

    // Example: To drop the connection (action 1):
    // respond_to_intercept(connection_id, 1, NULL, 0);
}

int main() {
    // Register all callbacks
    set_log_callback(log_callback);
    set_status_callback(status_callback);
    set_connection_callback(connection_callback);
    set_disconnect_callback(disconnect_callback);
    set_intercept_callback(intercept_callback);

    // Configure and start the proxy
    if (!set_config("0.0.0.0", 8443, "intercept.log", 1)) {
        printf("Failed to set configuration\n");
        return 1;
    }

    // Enable interception for all traffic (both directions)
    set_intercept_enabled(1); // 1 = enabled
    set_intercept_direction(0); // 0 = both directions

    if (!start_proxy()) {
        printf("Failed to start proxy\n");
        return 1;
    }

    printf("Proxy running on port 8443. Press Enter to stop...\n");
    getchar();

    // Export CA certificate before stopping
    if (export_certificate("./certificates", 0)) {
        printf("CA certificate exported successfully\n");
    }

    // Clean up
    stop_proxy();

    return 0;
}
```

## Building Applications with the InterceptSuite Library

### Prerequisites

Before integrating the library, ensure you have built it following the instructions in [Build.md](Build.md). The library must be built for your target platform.

### Platform-Specific Integration

#### Windows

**Using Visual Studio:**
1. Add the `include` directory to your project's include paths
2. Link against the library:
   - Add `libIntercept.lib` (import library) to your project's additional dependencies
   - Or use `#pragma comment(lib, "libIntercept.lib")` in your source code
3. Ensure runtime dependencies are available:
   - `libIntercept.dll` must be in your application's directory or system PATH
   - OpenSSL DLLs: `libssl-3-x64.dll` and `libcrypto-3-x64.dll`

**Using MinGW/MSYS2:**
```bash
gcc -o myapp myapp.c -I./include -L./build/Release -lIntercept
```

#### Linux

**Using GCC:**
```bash
gcc -o myapp myapp.c -I./include -L./build -lIntercept -lpthread
```

**Using CMake (recommended):**
```cmake
find_library(INTERCEPT_LIB Intercept HINTS ${CMAKE_SOURCE_DIR}/build)
target_link_libraries(myapp ${INTERCEPT_LIB})
target_include_directories(myapp PRIVATE ${CMAKE_SOURCE_DIR}/include)
```

#### macOS

**Using Clang:**
```bash
clang -o myapp myapp.c -I./include -L./build -lIntercept
```

**For universal binaries (Intel + Apple Silicon):**
```bash
clang -arch x86_64 -arch arm64 -o myapp myapp.c -I./include -L./build -lIntercept
```

### Runtime Requirements

#### Windows
- `libIntercept.dll` must be accessible via application directory or system PATH
- OpenSSL dependencies: `libssl-3-x64.dll` and `libcrypto-3-x64.dll`
- Visual C++ Redistributable (if built with MSVC)

#### Linux
- `libIntercept.so` must be accessible via LD_LIBRARY_PATH or standard library paths
- OpenSSL libraries are statically linked (no additional runtime dependencies)
- Ensure proper file permissions for certificate generation

#### macOS
- `libIntercept.dylib` must be accessible via DYLD_LIBRARY_PATH or standard library paths
- OpenSSL libraries are statically linked (no additional runtime dependencies)
- Code signing may be required for distribution

### Library Path Configuration

For development and testing, you can set environment variables to locate the library:

**Windows (PowerShell):**
```powershell
$env:PATH += ";D:\Windows TLS\build\Release"
```

**Linux/macOS (Bash):**
```bash
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/path/to/Windows TLS/build"  # Linux
export DYLD_LIBRARY_PATH="$DYLD_LIBRARY_PATH:/path/to/Windows TLS/build"  # macOS
```

### Integration Notes

- Always call `stop_proxy()` before application exit to ensure proper cleanup
- Callback functions are called from internal threads - ensure thread safety
- The library handles certificate generation automatically, but requires write permissions
- For production use, consider implementing proper error handling for all API calls
- Memory management for callback data is handled internally - do not free callback parameters

## Troubleshooting

### Common Integration Issues

#### Library Loading Errors

**"Cannot load library" or "DLL not found":**
- Ensure the library file is in the correct location
- Check that all dependencies are available (OpenSSL DLLs on Windows)
- Verify the architecture matches (x64 library with x64 application)
- On Linux/macOS, check file permissions and executable bit

**"Undefined symbol" errors:**
- Verify you're linking against the correct library version
- Ensure the header file matches the library version
- Check that all required dependencies are linked

#### Runtime Issues

**Proxy fails to start:**
- Check if the port is already in use
- Verify sufficient privileges (may need elevated permissions)
- Ensure the bind address is valid for your system
- Check firewall settings that might block the proxy port

**Certificate generation failures:**
- Verify write permissions in the working directory
- Check available disk space
- Ensure OpenSSL libraries are properly loaded

**Callback functions not being called:**
- Verify callbacks are set before calling `start_proxy()`
- Ensure callback function signatures match exactly
- Check that the callback functions are not being garbage collected (C#)

#### Platform-Specific Issues

**Windows:**
- If using MinGW, ensure compatible runtime libraries
- Visual Studio version compatibility with library build
- Windows Defender or antivirus blocking the proxy

**Linux:**
- SELinux policies might prevent network operations
- Check that required network capabilities are available
- Ensure the library was built with the same compiler/libc version

**macOS:**
- Gatekeeper may block unsigned libraries
- System Integrity Protection (SIP) restrictions
- Architecture mismatch (Intel vs. Apple Silicon)

### Debug Tips

1. **Enable verbose logging** by setting `verbose_mode = 1` in `set_config()`
2. **Check return values** of all API functions for error indication
3. **Use status callbacks** to monitor internal library state
4. **Test with minimal examples** before integrating into larger applications
5. **Verify network connectivity** with basic proxy tools first

### Getting Help

If you encounter issues not covered here:
1. Check the [main README](README.md) for known limitations
2. Review the build logs for any compilation warnings
3. Test with the provided example applications
4. Ensure you're using the latest version of the library
