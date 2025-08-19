#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Platform detection and includes
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #define IS_WINDOWS 1
    #define LIBRARY_NAME "../build/release/Intercept.dll"
    #define LOAD_LIBRARY(name) LoadLibrary(name)
    #define GET_FUNCTION(lib, name) GetProcAddress(lib, name)
    #define FREE_LIBRARY(lib) FreeLibrary(lib)
    typedef HMODULE library_handle_t;
#else
    #include <dlfcn.h>
    #define IS_WINDOWS 0
    #define LIBRARY_NAME "../build/libIntercept.so"
    #define LOAD_LIBRARY(name) dlopen(name, RTLD_LAZY)
    #define GET_FUNCTION(lib, name) dlsym(lib, name)
    #define FREE_LIBRARY(lib) dlclose(lib)
    typedef void* library_handle_t;
#endif

// Function pointer types (matching the DLL interface)
typedef struct {
    char bind_addr[64];       /* Binding IP address */
    int port;                 /* Proxy port */
    int verbose_mode;         /* Verbose logging enabled (1) or disabled (0) */
    int is_running;           /* Proxy status: running (1) or stopped (0) */
} proxy_config_t;

typedef proxy_config_t (*get_proxy_config_func)(void);
typedef int (*get_proxy_stats_func)(int* connections, int* bytes_transferred);
typedef int (*get_system_ips_func)(char* ip_buffer, int buffer_size);
typedef int (*set_config_func)(const char* bind_addr, int port, int verbose_mode);

int main() {
    printf("=== Cross-Platform TLS Intercept Library Test ===\n");
    printf("Platform: %s\n", IS_WINDOWS ? "Windows" : "Linux");
    printf("Library: %s\n\n", LIBRARY_NAME);

    // Load the library
    library_handle_t lib = LOAD_LIBRARY(LIBRARY_NAME);
    if (!lib) {
#ifdef _WIN32
        printf("✗ Failed to load library: %s (Error: %lu)\n", LIBRARY_NAME, GetLastError());
#else
        printf("✗ Failed to load library: %s (Error: %s)\n", LIBRARY_NAME, dlerror());
#endif
        return 1;
    }
    printf("✓ Successfully loaded library: %s\n\n", LIBRARY_NAME);

    // Get function pointers
    get_proxy_config_func get_proxy_config = (get_proxy_config_func)GET_FUNCTION(lib, "get_proxy_config");
    get_proxy_stats_func get_proxy_stats = (get_proxy_stats_func)GET_FUNCTION(lib, "get_proxy_stats");
    get_system_ips_func get_system_ips = (get_system_ips_func)GET_FUNCTION(lib, "get_system_ips");
    set_config_func set_config = (set_config_func)GET_FUNCTION(lib, "set_config");

    if (!get_proxy_config || !get_proxy_stats || !get_system_ips || !set_config) {
        printf("✗ Failed to get function pointers from library\n");
        FREE_LIBRARY(lib);
        return 1;
    }
    printf("✓ Successfully loaded all function pointers\n\n");    // Test 1: Get current proxy configuration
    printf("Test 1: Getting proxy configuration...\n");

    proxy_config_t config = get_proxy_config();

    printf("✓ Successfully retrieved proxy configuration:\n");
    printf("  Bind Address: %s\n", config.bind_addr[0] ? config.bind_addr : "Not set");
    printf("  Port: %d\n", config.port);
    printf("  Log File: %s\n", config.log_file[0] ? config.log_file : "Not set");
    printf("  Verbose Mode: %s\n", config.verbose_mode ? "Enabled" : "Disabled");
    printf("  Proxy Status: %s\n", config.is_running ? "Running" : "Stopped");

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
    result = set_config("127.0.0.1", 8080, "test.log", 1);

    if (result) {
        printf("✓ Successfully set proxy configuration\n");        // Verify the configuration was set
        proxy_config_t config = get_proxy_config();
        printf("  Verified configuration:\n");
        printf("    Bind Address: %s\n", config.bind_addr);
        printf("    Port: %d\n", config.port);
        printf("    Log File: %s\n", config.log_file);
        printf("    Verbose Mode: %s\n", config.verbose_mode ? "Enabled" : "Disabled");
        printf("    Proxy Status: %s\n", config.is_running ? "Running" : "Stopped");
    } else {
        printf("✗ Failed to set proxy configuration\n");
    }

    printf("\n=== Test Complete ===\n");

    // Clean up
    FREE_LIBRARY(lib);
    printf("✓ Library unloaded successfully\n");

    return 0;
}
