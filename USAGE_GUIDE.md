# TLS MITM Proxy DLL Usage Guide

## Overview
The TLS MITM Proxy DLL provides a full-featured MITM proxy for intercepting and inspecting TLS traffic.

This guide explains how to use the TLS proxy capabilities to intercept and analyze encrypted traffic.

## System Requirements
- Windows 8.1/10/11 or Windows Server 2012 R2 and later
- Microsoft Visual C++ Redistributable for Visual Studio 2022
- OpenSSL dependencies (included in the package)

## Basic Integration Steps
1. Include the header file in your project: `#include "tls_proxy_dll.h"`
2. Link against the import library `tls_proxy.lib`
3. Ensure the DLL `tls_proxy.dll` is in your application's path
4. Call the initialization functions as described below

## DLL Location
For development, the DLL can be found at:
- Debug build: `build-dll\Debug\tls_proxy.dll`
- Release build: `build-dll\Release\tls_proxy.dll`

## API Reference

### Initialization and Cleanup

#### `BOOL init_proxy(void)`
Initializes the TLS proxy subsystem. This must be called before any other functions.

```c
// Example:
if (!init_proxy()) {
    printf("Failed to initialize TLS proxy\n");
    return 1;
}
```

#### `BOOL start_proxy(void)`
Starts the TLS proxy server based on the current configuration.

```c
// Example:
if (!start_proxy()) {
    printf("Failed to start proxy server\n");
    return 1;
}
```

#### `void stop_proxy(void)`
Stops the TLS proxy server.

```c
// Example:
stop_proxy();
```

### Configuration

#### `BOOL set_config(const char* bind_addr, int port, const char* log_file)`
Configures the TLS proxy server.

- **Parameters:**
  - `bind_addr`: IP address to bind the proxy to (e.g., "127.0.0.1")
  - `port`: Port number for the proxy to listen on (e.g., 4433)
  - `log_file`: Path to log file for storing proxy logs (e.g., "tls_proxy.log")

```c
// Example:
if (!set_config("127.0.0.1", 4433, "tls_proxy.log")) {
    printf("Failed to configure proxy\n");
    return 1;
}
```



### Notifications

#### `void set_log_callback(log_callback_t callback)`
Registers a callback to receive detailed log messages from intercepted traffic.

- **Parameters:**
  - `callback`: Function pointer with signature:
    ```c
    void (*log_callback_t)(const char* timestamp, const char* src_ip, const char* dst_ip, int dst_port, const char* message_type, const char* data);
    ```

```c
// Example:
void log_callback(const char* timestamp, const char* src_ip, const char* dst_ip, int dst_port, const char* message_type, const char* data) {
    printf("[%s] %s -> %s:%d [%s] %s\n", timestamp, src_ip, dst_ip, dst_port, message_type, data);
}

set_log_callback(log_callback);
```

#### `void set_status_callback(status_callback_t callback)`
Registers a callback to receive status messages.

- **Parameters:**
  - `callback`: Function pointer with signature:
    ```c
    void (*status_callback_t)(const char* message);
    ```

```c
// Example:
void status_callback(const char* message) {
    printf("[STATUS] %s\n", message);
}

set_status_callback(status_callback);
```

### System Information

#### `int get_system_ips(char* buffer, int buffer_size)`
Retrieves available network interfaces and their IP addresses.

- **Parameters:**
  - `buffer`: Buffer to store comma-separated list of IP addresses
  - `buffer_size`: Size of the buffer in bytes
- **Returns:** Number of bytes written to buffer, or 0 on failure

```c
// Example:
char ip_buffer[1024];
int bytes_written = get_system_ips(ip_buffer, sizeof(ip_buffer));
if (bytes_written > 0) {
    printf("Available IPs: %s\n", ip_buffer);
}
```

#### `BOOL get_proxy_config(char* bind_addr, int* port, char* log_file)`
Retrieves the current proxy configuration.

- **Parameters:**
  - `bind_addr`: Buffer to store the bind address (should be at least 256 bytes)
  - `port`: Pointer to store the port number
  - `log_file`: Buffer to store the log file path (should be at least 256 bytes)
- **Returns:** TRUE on success, FALSE on failure

```c
// Example:
char bind_addr[256];
int port;
char log_file[256];
if (get_proxy_config(bind_addr, &port, log_file)) {
    printf("Proxy config: %s:%d, log: %s\n", bind_addr, port, log_file);
}
```

#### `BOOL get_proxy_stats(int* connections, int* bytes_transferred)`
Retrieves current proxy statistics.

- **Parameters:**
  - `connections`: Pointer to store the number of active connections
  - `bytes_transferred`: Pointer to store the total bytes transferred
- **Returns:** TRUE on success, FALSE on failure

```c
// Example:
int connections, bytes_transferred;
if (get_proxy_stats(&connections, &bytes_transferred)) {
    printf("Stats: %d connections, %d bytes transferred\n", connections, bytes_transferred);
}
```

## Real-time Event Callbacks

The TLS Proxy DLL provides real-time event callbacks for monitoring proxy activity without polling. These callbacks are invoked automatically when events occur.

### Connection Events

#### `void set_connection_callback(connection_callback_t callback)`
Sets a callback function that is called when a new connection is established.

- **Callback signature:** `void (*connection_callback_t)(const char* client_ip, int client_port, const char* target_host, int target_port, int connection_id)`
- **Parameters:**
  - `client_ip`: IP address of the connecting client
  - `client_port`: Port of the connecting client
  - `target_host`: Target hostname being accessed
  - `target_port`: Target port being accessed
  - `connection_id`: Unique identifier for this connection

```c
// Example connection callback
void on_connection(const char* client_ip, int client_port, 
                   const char* target_host, int target_port, int connection_id) {
    printf("New connection %d: %s:%d -> %s:%d\n", 
           connection_id, client_ip, client_port, target_host, target_port);
}

// Set the callback
set_connection_callback(on_connection);
```

#### `void set_stats_callback(stats_callback_t callback)`
Sets a callback function that is called when statistics are updated.

- **Callback signature:** `void (*stats_callback_t)(int total_connections, int active_connections, int total_bytes_transferred)`
- **Parameters:**
  - `total_connections`: Total number of connections handled
  - `active_connections`: Currently active connections
  - `total_bytes_transferred`: Total bytes transferred through the proxy

```c
// Example stats callback
void on_stats_update(int total_connections, int active_connections, int total_bytes_transferred) {
    printf("Stats: %d total, %d active, %d bytes transferred\n", 
           total_connections, active_connections, total_bytes_transferred);
}

// Set the callback
set_stats_callback(on_stats_update);
```

#### `void set_disconnect_callback(disconnect_callback_t callback)`
Sets a callback function that is called when a connection is closed.

- **Callback signature:** `void (*disconnect_callback_t)(int connection_id, const char* reason)`
- **Parameters:**
  - `connection_id`: Unique identifier for the connection that was closed
  - `reason`: Reason for disconnection (e.g., "Connection closed", "SOCKS5 handshake failed")

```c
// Example disconnect callback
void on_disconnect(int connection_id, const char* reason) {
    printf("Connection %d closed: %s\n", connection_id, reason);
}

// Set the callback
set_disconnect_callback(on_disconnect);
```

### Complete Example with Callbacks

```c
#include <stdio.h>
#include <windows.h>
#include "tls_proxy_dll.h"

// Callback functions
void on_connection(const char* client_ip, int client_port, 
                   const char* target_host, int target_port, int connection_id) {
    printf("[CONNECT] %d: %s:%d -> %s:%d\n", 
           connection_id, client_ip, client_port, target_host, target_port);
}

void on_stats_update(int total_connections, int active_connections, int total_bytes_transferred) {
    printf("[STATS] Total: %d, Active: %d, Bytes: %d\n", 
           total_connections, active_connections, total_bytes_transferred);
}

void on_disconnect(int connection_id, const char* reason) {
    printf("[DISCONNECT] %d: %s\n", connection_id, reason);
}

void on_status(const char* message) {
    printf("[STATUS] %s\n", message);
}

int main() {
    // Initialize proxy
    if (!init_proxy()) {
        printf("Failed to initialize proxy\n");
        return 1;
    }

    // Set up all callbacks
    set_connection_callback(on_connection);
    set_stats_callback(on_stats_update);
    set_disconnect_callback(on_disconnect);
    set_status_callback(on_status);

    // Configure and start proxy
    if (!set_config("127.0.0.1", 4433, "proxy.log")) {
        printf("Failed to configure proxy\n");
        return 1;
    }

    if (!start_proxy()) {
        printf("Failed to start proxy\n");
        return 1;
    }

    printf("Proxy running with real-time callbacks. Press Enter to stop...\n");
    getchar();

    stop_proxy();
    return 0;
}
```

## Language Integration Examples

### C/C++

```c
// Basic usage in C
#include <stdio.h>
#include <windows.h>
#include "tls_proxy_dll.h"

// Link with tls_proxy.lib

int main() {
    // Initialize the proxy
    if (!init_proxy()) {
        printf("Failed to initialize TLS proxy\n");
        return 1;
    }

    // Configure the proxy to listen on localhost:4433
    const char* bind_addr = "127.0.0.1";
    int port = 4433;
    const char* log_file = "tls_proxy.log";

    if (!set_config(bind_addr, port, log_file)) {
        printf("Failed to configure proxy\n");
        return 1;
    }

    // Start the proxy
    if (!start_proxy()) {
        printf("Failed to start proxy server\n");
        return 1;
    }

    printf("TLS proxy started and listening on %s:%d\n", bind_addr, port);
    printf("Configure your application to use this proxy address\n");
    printf("Press Enter to stop...\n");
    getchar();


    // Stop the proxy and clean up
    stop_proxy();
    printf("Proxy stopped\n");

    return 0;
}
```

### Python

```python
# Using the TLS Proxy DLL from Python
import ctypes
from ctypes import c_bool, c_char_p, c_int, WINFUNCTYPE
import time

# Define callback types
LOG_CALLBACK = WINFUNCTYPE(None, c_char_p, c_char_p, c_char_p, c_int, c_char_p, c_char_p)
STATUS_CALLBACK = WINFUNCTYPE(None, c_char_p)

# Load the DLL
tls_proxy = ctypes.CDLL("path/to/tls_proxy.dll")

# Define function prototypes
tls_proxy.init_proxy.restype = c_bool
tls_proxy.start_proxy.restype = c_bool
tls_proxy.stop_proxy.restype = None
tls_proxy.set_config.argtypes = [c_char_p, c_int, c_char_p]
tls_proxy.set_config.restype = c_bool
tls_proxy.set_log_callback.argtypes = [LOG_CALLBACK]
tls_proxy.set_status_callback.argtypes = [STATUS_CALLBACK]
tls_proxy.get_system_ips.argtypes = [c_char_p, c_int]
tls_proxy.get_system_ips.restype = c_int

# Callback functions
def log_callback(timestamp, src_ip, dst_ip, dst_port, msg_type, data):
    ts = timestamp.decode() if timestamp else "N/A"
    src = src_ip.decode() if src_ip else "N/A"
    dst = dst_ip.decode() if dst_ip else "N/A"
    typ = msg_type.decode() if msg_type else "N/A"
    dat = data.decode() if data else "N/A"
    print(f"[{ts}] {src} -> {dst}:{dst_port} [{typ}] {dat}")

def status_callback(message):
    msg = message.decode() if message else "N/A"
    print(f"[STATUS] {msg}")

# Register callbacks
log_cb = LOG_CALLBACK(log_callback)
status_cb = STATUS_CALLBACK(status_callback)

# Initialize proxy
if tls_proxy.init_proxy():
    print("TLS Proxy initialized successfully")

    # Set callbacks
    tls_proxy.set_log_callback(log_cb)
    tls_proxy.set_status_callback(status_cb)

    # Get available IP addresses
    buffer_size = 1024
    buffer = ctypes.create_string_buffer(buffer_size)
    bytes_written = tls_proxy.get_system_ips(buffer, buffer_size)

    if bytes_written > 0:
        ips = buffer.value.decode().split(',')
        print("Available IP addresses:")
        for i, ip in enumerate(ips):
            print(f"{i+1}. {ip}")

        # Use localhost for this example
        bind_addr = "127.0.0.1"
        port = 4433
        log_file = "tls_proxy.log"

        # Configure and start proxy
        if tls_proxy.set_config(bind_addr.encode(), port, log_file.encode()):
            print(f"Proxy configured to listen on {bind_addr}:{port}")

            if tls_proxy.start_proxy():
                print(f"TLS Proxy started successfully on {bind_addr}:{port}")
                print("Press Ctrl+C to stop...")
                try:
                    # Keep proxy running until interrupted
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("Stopping proxy...")
                finally:
                    # Clean up
                    tls_proxy.stop_proxy()
                    print("Proxy stopped")
            else:
                print("Failed to start proxy")
    else:
        print("Failed to get system IP addresses")
else:
    print("Failed to initialize TLS proxy")
```

### C#

```csharp
// Using the TLS Proxy DLL from C#
using System;
using System.Runtime.InteropServices;
using System.Threading;

class TLSProxyExample
{
    // Log callback delegate
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void LogCallbackDelegate(
        [MarshalAs(UnmanagedType.LPStr)] string timestamp,
        [MarshalAs(UnmanagedType.LPStr)] string sourceIP,
        [MarshalAs(UnmanagedType.LPStr)] string destIP,
        int destPort,
        [MarshalAs(UnmanagedType.LPStr)] string messageType,
        [MarshalAs(UnmanagedType.LPStr)] string data);

    // Status callback delegate
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void StatusCallbackDelegate(
        [MarshalAs(UnmanagedType.LPStr)] string message);

    // DLL imports
    [DllImport("tls_proxy.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool init_proxy();

    [DllImport("tls_proxy.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool start_proxy();

    [DllImport("tls_proxy.dll")]
    public static extern void stop_proxy();

    [DllImport("tls_proxy.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool set_config(
        [MarshalAs(UnmanagedType.LPStr)] string bindAddr,
        int port,
        [MarshalAs(UnmanagedType.LPStr)] string logFile);

    [DllImport("tls_proxy.dll")]
    public static extern void set_log_callback(LogCallbackDelegate callback);    [DllImport("tls_proxy.dll")]
    public static extern void set_status_callback(StatusCallbackDelegate callback);

    [DllImport("tls_proxy.dll")]
    public static extern int get_system_ips(
        [MarshalAs(UnmanagedType.LPStr)] byte[] buffer,
        int bufferSize);

    [DllImport("tls_proxy.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool get_proxy_config(
        [MarshalAs(UnmanagedType.LPStr)] byte[] bindAddr,
        ref int port,
        [MarshalAs(UnmanagedType.LPStr)] byte[] logFile);

    [DllImport("tls_proxy.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool get_proxy_stats(
        ref int connections,
        ref int bytesTransferred);

    static void Main()
    {
        // Callbacks
        LogCallbackDelegate logCallback = (timestamp, srcIp, dstIp, dstPort, msgType, data) => {
            Console.WriteLine($"[{timestamp}] {srcIp} -> {dstIp}:{dstPort} [{msgType}] {data}");
        };

        StatusCallbackDelegate statusCallback = (message) => {
            Console.WriteLine($"[STATUS] {message}");
        };

        // Initialize proxy
        if (!init_proxy())
        {
            Console.WriteLine("Failed to initialize TLS proxy");
            return;
        }

        try
        {
            // Set callbacks
            set_log_callback(logCallback);
            set_status_callback(statusCallback);

            // Configure proxy to listen on localhost:4433
            string bindAddr = "127.0.0.1";
            int port = 4433;
            string logFile = "tls_proxy.log";

            if (set_config(bindAddr, port, logFile))
            {
                Console.WriteLine($"Proxy configured to listen on {bindAddr}:{port}");

                // Start the proxy
                if (start_proxy())
                {
                    Console.WriteLine($"TLS proxy started successfully on {bindAddr}:{port}");
                    Console.WriteLine("Press any key to stop the proxy...");

                    // Display stats periodically
                    var statsThread = new Thread(() => {
                        int connections = 0;
                        int bytesTransferred = 0;

                        while (true)
                        {
                            if (get_proxy_stats(ref connections, ref bytesTransferred))
                            {
                                Console.WriteLine($"Current stats: {connections} connections, {bytesTransferred} bytes transferred");
                            }
                            Thread.Sleep(5000); // Update every 5 seconds
                        }
                    });

                    statsThread.IsBackground = true;
                    statsThread.Start();

                    // Wait for user input to stop
                    Console.ReadKey();

                    // Stop the proxy
                    stop_proxy();
                    Console.WriteLine("Proxy stopped");
                }
                else
                {
                    Console.WriteLine("Failed to start proxy");
                }
            }            else
            {
                Console.WriteLine("Failed to configure proxy");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
```

## Troubleshooting

### Common Issues

1. **DLL Loading Failure**
   - Ensure the DLL is in your application's path or use an absolute path when loading
   - Check for missing dependencies with tools like Dependency Walker

2. **Initialization Failure**
   - Make sure OpenSSL DLLs (libssl-3-x64.dll, libcrypto-3-x64.dll) are available
   - Check the Windows event log for detailed error messages

3. **Common Configuration Errors**
   - Verify that the port you're trying to bind to isn't already in use
   - Ensure the IP address is valid for your system

4. **Binding Failures**
   - Check that the port is not already in use by another application
   - Ensure the IP address is valid and exists on the system

5. **Certificate Issues**
   - Verify that myCA.pem and myCA.key are present in the working directory
   - If missing, the DLL will generate new ones, but they won't be trusted by browsers
   - Import the CA certificate into your browser's trusted certificate store

6. **Proxy Connection Issues**
   - Ensure client applications are configured to use the correct proxy address and port
   - Check firewall settings that might block the proxy connections
   - Verify the proxy is actually started before connecting clients

## Security Considerations

- Use this tool only in controlled environments with proper authorization
- This software is designed for development, testing, and educational purposes only
- Intercepting encrypted traffic without consent may violate privacy laws and regulations
- Always inform users when TLS interception is active

## Version Information

This documentation applies to TLS MITM Proxy DLL version 1.0.0.
Last updated: May 25, 2025.
