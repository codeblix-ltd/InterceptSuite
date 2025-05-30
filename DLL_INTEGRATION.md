# DLL Integration Guide

This guide explains how to integrate the Intercept Suite DLL into your own applications.

## Available DLL Files

The TLS MITM Proxy is available as a DLL that you can integrate into your own applications. After building the project, you can find the DLL files in:

- Debug build: `build\Debug\Intercept.dll`
- Release build: `build\Release\Intercept.dll`

## Dependencies

The DLL requires the following dependencies to be present in the same directory:
- `libcrypto-3-x64.dll` (OpenSSL)
- `libssl-3-x64.dll` (OpenSSL)

## Integration

Include the `tls_proxy_dll.h` header file (located in the `include` folder) to access the TLS proxy functionality including:
- TLS interception and inspection
- Certificate generation and management
- SOCKS5 proxy functionality
- Real-time event callbacks

## API Overview

The Intercept DLL provides the following key functionality:

### Core Functions
- `start_proxy()` - Start the proxy server
- `stop_proxy()` - Stop the proxy server
- `set_config()` - Configure proxy settings (address, port, logging)
- `get_system_ips()` - Retrieve system network interfaces
- `get_proxy_config()` - Get current proxy configuration
- `get_proxy_stats()` - Get proxy statistics

### Callback Registration
- `set_log_callback()` - Set callback for log events (provides full proxy history data, including all incoming and outgoing data flows with timestamps)
- `set_status_callback()` - Set callback for status messages, error notifications, and debug logs (shown in the status bar of the GUI application)
- `set_connection_callback()` - Set callback for new connections (displays TCP connections in the Connections tab of the GUI with unique connection IDs for tracking)
- `set_disconnect_callback()` - Set callback for connection termination
- `set_stats_callback()` - Set callback for proxy statistics (provides real-time updates on total connections, active connections, and total bytes transferred)

- `set_intercept_callback()` - Set callback for traffic interception

### Traffic Interception
- `set_intercept_enabled()` - Enable/disable interception
- `set_intercept_direction()` - Set interception direction (client→server, server→client, both)
- `respond_to_intercept()` - Forward intercepted data (original or modified)

## Example Usage

### C Example

```c
#include "tls_proxy_dll.h"
#include <stdio.h>
#include <stdlib.h>

// Callback functions
void log_callback(const char* timestamp, const char* src_ip, const char* dst_ip, int dst_port, const char* type, const char* data) {
    printf("[%s] %s -> %s:%d [%s] %s\n", timestamp, src_ip, dst_ip, dst_port, type, data);
}

void status_callback(const char* message) {
    printf("[STATUS] %s\n", message);
}

void connection_callback(const char* client_ip, int client_port, const char* target_host, int target_port, int connection_id) {
    printf("[CONNECTION] ID: %d, %s:%d -> %s:%d\n", connection_id, client_ip, client_port, target_host, target_port);
}

void stats_callback(int total_connections, int active_connections, int total_bytes_transferred) {
    printf("[STATS] Total: %d, Active: %d, Bytes: %d\n", total_connections, active_connections, total_bytes_transferred);

    // Parameters received:
    // - total_connections: The cumulative number of connections handled since proxy startup
    // - active_connections: The current number of open connections being managed by the proxy
    // - total_bytes_transferred: The total bytes transferred through the proxy since startup
}

void disconnect_callback(int connection_id, const char* reason) {
    printf("[DISCONNECT] ID: %d, Reason: %s\n", connection_id, reason);
}

void intercept_callback(int connection_id, const char* direction, const char* src_ip, const char* dst_ip,
                        int dst_port, const unsigned char* data, int data_length) {
    printf("[INTERCEPT] ID: %d, Direction: %s, %s -> %s:%d, %d bytes\n",
           connection_id, direction, src_ip, dst_ip, dst_port, data_length);

    // Simply forward the original data (action 0 = Forward original)
    respond_to_intercept(connection_id, 0, NULL, 0);
}

int main() {
    // Register all callbacks
    set_log_callback(log_callback);
    set_status_callback(status_callback);
    set_connection_callback(connection_callback);
    set_stats_callback(stats_callback);
    set_disconnect_callback(disconnect_callback);
    set_intercept_callback(intercept_callback);

    // Configure and start the proxy
    if (!set_config("0.0.0.0", 8443, "intercept.log", 1)) {
        printf("Failed to set configuration\n");
        return 1;
    }

    // Enable interception for all traffic
    set_intercept_enabled(1); // 1 = enabled
    set_intercept_direction(0); // 0 = both directions

    if (!start_proxy()) {
        printf("Failed to start proxy\n");
        return 1;
    }

    printf("Proxy running on port 8443. Press Enter to stop...\n");
    getchar();

    // Clean up
    stop_proxy();

    return 0;
}
```

### C# Example

```csharp
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

class InterceptExample
{
    // DLL imports
    [DllImport("Intercept.dll", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool start_proxy();

    [DllImport("Intercept.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern void stop_proxy();

    [DllImport("Intercept.dll", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool set_config(
        [MarshalAs(UnmanagedType.LPStr)] string bind_addr,
        int port,
        [MarshalAs(UnmanagedType.LPStr)] string log_file,
        int verbose_mode);

    [DllImport("Intercept.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern void set_intercept_enabled(int enabled);

    [DllImport("Intercept.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern void set_intercept_direction(int direction);

    [DllImport("Intercept.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern void respond_to_intercept(int connection_id, int action, byte[] modified_data, int modified_length);

    // Callback delegates
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void LogCallbackDelegate(
        [MarshalAs(UnmanagedType.LPStr)] string timestamp,
        [MarshalAs(UnmanagedType.LPStr)] string src_ip,
        [MarshalAs(UnmanagedType.LPStr)] string dst_ip,
        int dst_port,
        [MarshalAs(UnmanagedType.LPStr)] string message_type,
        [MarshalAs(UnmanagedType.LPStr)] string data);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void InterceptCallbackDelegate(
        int connection_id,
        [MarshalAs(UnmanagedType.LPStr)] string direction,
        [MarshalAs(UnmanagedType.LPStr)] string src_ip,
        [MarshalAs(UnmanagedType.LPStr)] string dst_ip,
        int dst_port,
        IntPtr data,
        int data_length);

    [DllImport("Intercept.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern void set_log_callback(LogCallbackDelegate callback);

    [DllImport("Intercept.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern void set_intercept_callback(InterceptCallbackDelegate callback);

    // Keep references to prevent garbage collection
    static LogCallbackDelegate _logCallback;
    static InterceptCallbackDelegate _interceptCallback;

    static void Main(string[] args)
    {
        // Set up callbacks
        _logCallback = LogCallback;
        _interceptCallback = InterceptCallback;

        set_log_callback(_logCallback);
        set_intercept_callback(_interceptCallback);

        // Configure and start proxy
        if (!set_config("0.0.0.0", 8443, "intercept.log", 1))
        {
            Console.WriteLine("Failed to set proxy configuration");
            return;
        }

        // Enable interception
        set_intercept_enabled(1);
        set_intercept_direction(0); // Both directions

        if (!start_proxy())
        {
            Console.WriteLine("Failed to start proxy");
            return;
        }

        Console.WriteLine("Proxy running on port 8443. Press Enter to stop...");
        Console.ReadLine();

        // Cleanup
        stop_proxy();
    }

    // Callback implementations
    static void LogCallback(string timestamp, string srcIp, string dstIp, int dstPort, string messageType, string data)
    {
        Console.WriteLine($"[{timestamp}] {srcIp} -> {dstIp}:{dstPort} [{messageType}] {data}");
    }

    static void InterceptCallback(int connectionId, string direction, string srcIp, string dstIp, int dstPort, IntPtr dataPtr, int dataLength)
    {
        Console.WriteLine($"Intercepted: {connectionId}, {direction}, {srcIp} -> {dstIp}:{dstPort}, {dataLength} bytes");

        // Example: Extract data and optionally modify it
        byte[] originalData = new byte[dataLength];
        Marshal.Copy(dataPtr, originalData, 0, dataLength);

        // Example: Forward original data without modification (action 0)
        respond_to_intercept(connectionId, 0, null, 0);

        // Example: To modify data and forward it (action 2):
        // respond_to_intercept(connectionId, 2, modifiedData, modifiedData.Length);

        // Example: To drop the connection (action 1):
        // respond_to_intercept(connectionId, 1, null, 0);
    }
}
```


## Building an Application with the DLL

### Using Visual Studio

1. Add `Intercept.lib` to your project's additional dependencies
2. Add the include directory to your project's include paths
3. Make sure `Intercept.dll` and OpenSSL DLLs are in your application's path or in a system path

### Using GCC

```bash
gcc -o myapp myapp.c -I./include -L./build/Release -lIntercept
```

## Runtime Requirements

- `Intercept.dll` must be in the application's path or a system path
- OpenSSL DLLs must be available (`libssl-3-x64.dll` and `libcrypto-3-x64.dll`)
