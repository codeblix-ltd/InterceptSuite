#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>

#define LIBRARY_PATH "../build/libIntercept.dylib"

// Function pointer types (matching the DLL interface)
typedef int (*get_proxy_config_func)(char* bind_addr, int* port, char* log_file, int* verbose_mode);
typedef int (*get_proxy_stats_func)(int* connections, int* bytes_transferred);
typedef int (*get_system_ips_func)(char* ip_buffer, int buffer_size);
typedef int (*set_config_func)(const char* bind_addr, int port, const char* log_file, int verbose_mode);
typedef int (*start_proxy_func)(void);
typedef int (*stop_proxy_func)(void);

// Callback function pointer types
typedef void (*stats_callback_func)(int total_connections, int active_connections, int total_bytes);
typedef void (*connection_callback_func)(const char* client_ip, int client_port, const char* target_host, int target_port, int connection_id);
typedef void (*disconnect_callback_func)(int connection_id);
typedef void (*log_callback_func)(const char* timestamp, const char* level, const char* message, const char* data);

typedef int (*set_stats_callback_func)(stats_callback_func callback);
typedef int (*set_connection_callback_func)(connection_callback_func callback);
typedef int (*set_disconnect_callback_func)(disconnect_callback_func callback);
typedef int (*set_log_callback_func)(log_callback_func callback);

// Test callback functions
void test_stats_callback(int total_connections, int active_connections, int total_bytes) {
    printf("📊 Stats Callback: Total=%d, Active=%d, Bytes=%d\n", total_connections, active_connections, total_bytes);
}

void test_connection_callback(const char* client_ip, int client_port, const char* target_host, int target_port, int connection_id) {
    printf("🔗 Connection Callback: %s:%d -> %s:%d (ID: %d)\n", client_ip, client_port, target_host, target_port, connection_id);
}

void test_disconnect_callback(int connection_id) {
    printf("🔌 Disconnect Callback: Connection ID %d closed\n", connection_id);
}

void test_log_callback(const char* timestamp, const char* level, const char* message, const char* data) {
    printf("📝 Log Callback [%s] %s: %s\n", timestamp, level, message);
    if (data && strlen(data) > 0) {
        printf("    Data: %.100s%s\n", data, strlen(data) > 100 ? "..." : "");
    }
}

int main() {
    printf("=== macOS TLS Intercept Library Test ===\n");
    printf("Platform: macOS (ARM64)\n");
    printf("Library: %s\n\n", LIBRARY_PATH);

    // Check if library file exists
    if (access(LIBRARY_PATH, F_OK) != 0) {
        printf("✗ Library file does not exist: %s\n", LIBRARY_PATH);
        printf("  Please build the library first using: ./build_macos.sh\n");
        return 1;
    }

    // Load the library
    void* lib = dlopen(LIBRARY_PATH, RTLD_LAZY);
    if (!lib) {
        printf("✗ Failed to load library: %s\n", dlerror());
        return 1;
    }
    printf("✓ Successfully loaded library: %s\n\n", LIBRARY_PATH);

    // Get function pointers
    get_proxy_config_func get_proxy_config = (get_proxy_config_func)dlsym(lib, "get_proxy_config");
    get_proxy_stats_func get_proxy_stats = (get_proxy_stats_func)dlsym(lib, "get_proxy_stats");
    get_system_ips_func get_system_ips = (get_system_ips_func)dlsym(lib, "get_system_ips");
    set_config_func set_config = (set_config_func)dlsym(lib, "set_config");
    start_proxy_func start_proxy = (start_proxy_func)dlsym(lib, "start_proxy");
    stop_proxy_func stop_proxy = (stop_proxy_func)dlsym(lib, "stop_proxy");

    // Get callback setter functions
    set_stats_callback_func set_stats_callback = (set_stats_callback_func)dlsym(lib, "set_stats_callback");
    set_connection_callback_func set_connection_callback = (set_connection_callback_func)dlsym(lib, "set_connection_callback");
    set_disconnect_callback_func set_disconnect_callback = (set_disconnect_callback_func)dlsym(lib, "set_disconnect_callback");
    set_log_callback_func set_log_callback = (set_log_callback_func)dlsym(lib, "set_log_callback");

    // Check critical functions
    if (!get_proxy_config || !get_proxy_stats || !get_system_ips || !set_config) {
        printf("✗ Failed to get critical function pointers from library\n");
        printf("  get_proxy_config: %p\n", get_proxy_config);
        printf("  get_proxy_stats: %p\n", get_proxy_stats);
        printf("  get_system_ips: %p\n", get_system_ips);
        printf("  set_config: %p\n", set_config);
        dlclose(lib);
        return 1;
    }
    printf("✓ Successfully loaded all critical function pointers\n");

    // Check optional functions (callbacks and proxy control)
    printf("✓ Optional functions loaded:\n");
    printf("  start_proxy: %s\n", start_proxy ? "✓" : "✗");
    printf("  stop_proxy: %s\n", stop_proxy ? "✓" : "✗");
    printf("  set_stats_callback: %s\n", set_stats_callback ? "✓" : "✗");
    printf("  set_connection_callback: %s\n", set_connection_callback ? "✓" : "✗");
    printf("  set_disconnect_callback: %s\n", set_disconnect_callback ? "✓" : "✗");
    printf("  set_log_callback: %s\n", set_log_callback ? "✓" : "✗");
    printf("\n");

    // Test 1: Get current proxy configuration
    printf("Test 1: Getting proxy configuration...\n");
    char bind_addr[256] = {0};
    int port = 0;
    char log_file[512] = {0};
    int verbose_mode = 0;

    int result = get_proxy_config(bind_addr, &port, log_file, &verbose_mode);

    if (result) {
        printf("✓ Successfully retrieved proxy configuration:\n");
        printf("  Bind Address: %s\n", bind_addr[0] ? bind_addr : "Not set");
        printf("  Port: %d\n", port);
        printf("  Log File: %s\n", log_file[0] ? log_file : "Not set");
        printf("  Verbose Mode: %s\n", verbose_mode ? "Enabled" : "Disabled");
    } else {
        printf("✗ Failed to retrieve proxy configuration\n");
    }
    printf("\n");

    // Test 2: Get proxy statistics
    printf("Test 2: Getting proxy statistics...\n");
    int connections = 0;
    int bytes_transferred = 0;

    result = get_proxy_stats(&connections, &bytes_transferred);

    if (result) {
        printf("✓ Successfully retrieved proxy statistics:\n");
        printf("  Total Connections: %d\n", connections);
        printf("  Bytes Transferred: %d\n", bytes_transferred);
    } else {
        printf("✗ Failed to retrieve proxy statistics\n");
    }
    printf("\n");

    // Test 3: Get system network interfaces
    printf("Test 3: Getting system network interfaces...\n");
    char ip_buffer[1024] = {0};
    int ip_count = get_system_ips(ip_buffer, sizeof(ip_buffer));

    if (ip_count > 0) {
        printf("✓ Successfully retrieved %d network interface(s):\n", ip_count);
        printf("  IPs: %s\n", ip_buffer);
    } else {
        printf("✗ Failed to retrieve network interfaces (returned: %d)\n", ip_count);
    }
    printf("\n");

    // Test 4: Test configuration setting
    printf("Test 4: Testing configuration setting...\n");
    result = set_config("127.0.0.1", 8080, "/tmp/intercept_test.log", 1);

    if (result) {
        printf("✓ Successfully set proxy configuration\n");

        // Verify the configuration was set
        memset(bind_addr, 0, sizeof(bind_addr));
        memset(log_file, 0, sizeof(log_file));
        port = 0;
        verbose_mode = 0;

        if (get_proxy_config(bind_addr, &port, log_file, &verbose_mode)) {
            printf("  Verified configuration:\n");
            printf("    Bind Address: %s\n", bind_addr);
            printf("    Port: %d\n", port);
            printf("    Log File: %s\n", log_file);
            printf("    Verbose Mode: %s\n", verbose_mode ? "Enabled" : "Disabled");
        }
    } else {
        printf("✗ Failed to set proxy configuration\n");
    }
    printf("\n");

    // Test 5: Test callback registration
    printf("Test 5: Testing callback registration...\n");
    if (set_stats_callback && set_connection_callback && set_disconnect_callback && set_log_callback) {
        printf("  Registering callbacks...\n");

        if (set_stats_callback(test_stats_callback)) {
            printf("  ✓ Stats callback registered\n");
        } else {
            printf("  ✗ Failed to register stats callback\n");
        }

        if (set_connection_callback(test_connection_callback)) {
            printf("  ✓ Connection callback registered\n");
        } else {
            printf("  ✗ Failed to register connection callback\n");
        }

        if (set_disconnect_callback(test_disconnect_callback)) {
            printf("  ✓ Disconnect callback registered\n");
        } else {
            printf("  ✗ Failed to register disconnect callback\n");
        }

        if (set_log_callback(test_log_callback)) {
            printf("  ✓ Log callback registered\n");
        } else {
            printf("  ✗ Failed to register log callback\n");
        }
    } else {
        printf("  ⚠️  Callback functions not available in this library build\n");
    }
    printf("\n");

    // Test 6: Test proxy start/stop (if available)
    if (start_proxy && stop_proxy) {
        printf("Test 6: Testing proxy start/stop...\n");

        printf("  Starting proxy...\n");
        result = start_proxy();
        if (result) {
            printf("  ✓ Proxy started successfully\n");

            // Let it run for a moment
            printf("  Running for 2 seconds...\n");
            sleep(2);

            printf("  Stopping proxy...\n");
            result = stop_proxy();
            if (result) {
                printf("  ✓ Proxy stopped successfully\n");
            } else {
                printf("  ✗ Failed to stop proxy\n");
            }
        } else {
            printf("  ✗ Failed to start proxy\n");
        }
    } else {
        printf("Test 6: Proxy control functions not available\n");
    }
    printf("\n");

    printf("=== Test Complete ===\n");

    // Clean up
    dlclose(lib);
    printf("✓ Library unloaded successfully\n");

    return 0;
}