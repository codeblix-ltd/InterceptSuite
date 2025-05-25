# DLL Integration Guide

This guide explains how to integrate the TLS MITM Proxy DLL into your own applications.

## Available DLL Files

The TLS MITM Proxy is available as a DLL that you can integrate into your own applications. After building the project, you can find the DLL files in:

- Debug build: `build-dll\Debug\tls_proxy.dll`
- Release build: `build-dll\Release\tls_proxy.dll`

## Integration

Include the `tls_proxy_dll.h` header file to access the TLS proxy functionality including:
- TLS interception and inspection
- Certificate generation and management
- SOCKS5 proxy functionality

## API Overview

See the TLS Proxy API in the `tls_proxy_dll.h` header file for complete documentation of available functions.

## Example Usage

### Using the TLS Proxy DLL

```c
#include "tls_proxy_dll.h"
#include <stdio.h>

void log_callback(const char* timestamp, const char* src_ip, const char* dst_ip, int dst_port, const char* type, const char* data) {
    printf("[%s] %s -> %s:%d [%s] %s\n", timestamp, src_ip, dst_ip, dst_port, type, data);
}

void status_callback(const char* message) {
    printf("[STATUS] %s\n", message);
}

int main() {
    // Initialize the proxy
    if (!init_proxy()) {
        printf("Failed to initialize proxy\n");
        return 1;
    }

    // Set callbacks
    set_log_callback(log_callback);
    set_status_callback(status_callback);

    // Configure proxy
    if (!set_config("127.0.0.1", 4433, "tls_proxy.log")) {
        printf("Failed to set configuration\n");
        return 1;
    }

    // Start the proxy
    if (!start_proxy()) {
        printf("Failed to start proxy\n");
        return 1;
    }

    printf("TLS proxy running on 127.0.0.1:4433. Press Enter to stop.\n");
    getchar();

    // Clean up
    stop_proxy();

    return 0;
}
```

## API Documentation

For complete API documentation, see the [USAGE_GUIDE.md](USAGE_GUIDE.md) file included with the distribution.

## Building an Application with the DLL

### Using Visual Studio

1. Add `tls_proxy.lib` to your project's additional dependencies
2. Add the include directory to your project's include paths
3. Make sure `tls_proxy.dll` is in your application's path or in a system path

### Using GCC

```bash
gcc -o myapp myapp.c -I./include -L./build-dll/Debug -ltls_proxy
```

## Runtime Requirements

- `tls_proxy.dll` must be in the application's path or a system path
- OpenSSL DLLs must be available (`libssl-3-x64.dll` and `libcrypto-3-x64.dll`)
