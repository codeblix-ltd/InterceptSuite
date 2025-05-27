/*
 * TLS MITM Proxy - DLL Interface
 *
 * Provides DLL exports for controlling the TLS MITM proxy functionality.
 */

#include "../include/tls_proxy.h"
#include "../include/cert_utils.h"
#include "../include/socks5.h"
#include "../include/tls_utils.h"
#include "../include/utils.h"
#include "../include/tls_proxy_dll.h"

#ifdef _WIN32
#include <iphlpapi.h>
#include <time.h>
#pragma comment(lib, "iphlpapi.lib")
#endif

/* Global server instance */
server_thread_t g_server = {0};

/* Global CA certificate and key */
X509 *ca_cert = NULL;
EVP_PKEY *ca_key = NULL;

/* Global callback functions */
static log_callback_t g_log_callback = NULL;
static status_callback_t g_status_callback = NULL;
static connection_callback_t g_connection_callback = NULL;
static stats_callback_t g_stats_callback = NULL;
static disconnect_callback_t g_disconnect_callback = NULL;

/* Statistics */
static int g_total_connections = 0;
static int g_total_bytes = 0;

/* DLL entry point */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            /* Initialize with default settings */
            init_config();
            break;

        case DLL_PROCESS_DETACH:
            /* Clean up */
            cleanup_winsock();
            cleanup_openssl();
            break;
    }
    return TRUE;
}

/* Exported functions */

__declspec(dllexport) BOOL start_proxy(void) {
    send_status_update("Starting proxy initialization...");

    /* Initialize Winsock */
    send_status_update("Initializing Winsock...");
    if (!init_winsock()) {
        send_status_update("ERROR: Failed to initialize Winsock");
        return FALSE;
    }
    send_status_update("Winsock initialized successfully");

    /* Initialize OpenSSL */
    send_status_update("Initializing OpenSSL...");
    if (!init_openssl()) {
        send_status_update("ERROR: Failed to initialize OpenSSL");
        cleanup_winsock();
        return FALSE;
    }
    send_status_update("OpenSSL initialized successfully");

    /* Load or generate CA certificate */
    send_status_update("Loading or generating CA certificate...");
    if (!load_or_generate_ca_cert()) {
        send_status_update("ERROR: Failed to load or generate CA certificate");
        cleanup_openssl();
        cleanup_winsock();
        return FALSE;
    }
    send_status_update("Proxy initialization completed successfully");

    /* Start proxy server */
    /* Initialize critical section */
    InitializeCriticalSection(&g_server.cs);
    g_server.should_stop = 0;
    g_server.thread_handle = NULL;

    /* Create server socket */
    socket_t server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        DeleteCriticalSection(&g_server.cs);
        return FALSE;
    }

    /* Allow socket reuse */
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        close_socket(server_sock);
        DeleteCriticalSection(&g_server.cs);
        return FALSE;
    }

    /* Bind socket */
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, config.bind_addr, &(server_addr.sin_addr)) != 1) {
        close_socket(server_sock);
        DeleteCriticalSection(&g_server.cs);
        return FALSE;
    }
    server_addr.sin_port = htons(config.port);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        close_socket(server_sock);
        DeleteCriticalSection(&g_server.cs);
        return FALSE;
    }

    /* Start listening */
    if (listen(server_sock, SOMAXCONN) == SOCKET_ERROR) {
        close_socket(server_sock);
        DeleteCriticalSection(&g_server.cs);
        return FALSE;
    }

    /* Set socket to non-blocking mode */
    unsigned long nonBlocking = 1;
    if (ioctlsocket(server_sock, FIONBIO, &nonBlocking) != 0) {
        close_socket(server_sock);
        DeleteCriticalSection(&g_server.cs);
        return FALSE;
    }

    /* Store server socket in global state */
    g_server.server_sock = server_sock;

    /* Start server thread */
    g_server.thread_handle = (HANDLE)_beginthreadex(NULL, 0, run_server_thread, NULL, 0, NULL);
    if (g_server.thread_handle == NULL) {
        close_socket(server_sock);
        DeleteCriticalSection(&g_server.cs);
        return FALSE;
    }

    return TRUE;
}

__declspec(dllexport) void stop_proxy(void) {
    /* Signal thread to stop */
    EnterCriticalSection(&g_server.cs);
    g_server.should_stop = 1;
    LeaveCriticalSection(&g_server.cs);

    /* Close socket to break accept() */
    if (g_server.server_sock != INVALID_SOCKET) {
        shutdown(g_server.server_sock, SD_BOTH);
        close_socket(g_server.server_sock);
        g_server.server_sock = INVALID_SOCKET;
    }

    /* Wait for thread to finish */
    if (g_server.thread_handle) {
        WaitForSingleObject(g_server.thread_handle, 5000);
        CloseHandle(g_server.thread_handle);
        g_server.thread_handle = NULL;
    }

    /* Delete critical section */
    DeleteCriticalSection(&g_server.cs);
}

__declspec(dllexport) BOOL set_config(const char* bind_addr, int port, const char* log_file, int verbose_mode) {
    if (!bind_addr || port <= 0 || port > 65535 || !log_file) {
        return FALSE;
    }

    /* Validate IP address */
    if (!validate_ip_address(bind_addr)) {
        return FALSE;
    }

    /* Update configuration */
    strncpy(config.bind_addr, bind_addr, sizeof(config.bind_addr) - 1);
    config.port = port;
    strncpy(config.log_file, log_file, sizeof(config.log_file) - 1);
    config.verbose = verbose_mode;

    return TRUE;
}

/* Winsock initialization and cleanup */
int init_winsock(void) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 0;
    }
    return 1;
}

void cleanup_winsock(void) {
    WSACleanup();
}

/* Server thread function */
THREAD_RETURN_TYPE WINAPI run_server_thread(void* arg) {
    socket_t server_sock = g_server.server_sock;
    client_info* client;
    THREAD_HANDLE thread_id;

    while (!g_server.should_stop) {
        /* Prepare for select() */
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(server_sock, &readfds);        /* Set timeout for select */
        tv.tv_sec = 1;  /* Check should_stop flag every second */
        tv.tv_usec = 0;

        /* Wait for connection with timeout */
        int ret = select(0, &readfds, NULL, NULL, &tv);
        if (ret == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEINTR) {
                fprintf(stderr, "Select failed: %d\n", WSAGetLastError());
            }
            continue;
        }

        if (ret == 0) {
            /* Timeout - check should_stop flag */
            continue;
        }

        /* Accept connection */
        client = (client_info*)malloc(sizeof(client_info));
        if (!client) {
            continue;
        }

        socklen_t client_len = sizeof(client->client_addr);
        client->client_sock = accept(server_sock, (struct sockaddr*)&client->client_addr, &client_len);
        if (client->client_sock == INVALID_SOCKET) {
            free(client);
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                fprintf(stderr, "Failed to accept connection: %d\n", WSAGetLastError());
            }
            continue;
        }

        /* Set client socket to blocking mode for normal operation */
        unsigned long nonBlocking = 0;
        if (ioctlsocket(client->client_sock, FIONBIO, &nonBlocking) != 0) {
            close_socket(client->client_sock);
            free(client);
            continue;
        }

        /* Create thread to handle client */
        CREATE_THREAD(thread_id, handle_client, client);
        if (thread_id != NULL) {
            CloseHandle(thread_id);
        } else {
            close_socket(client->client_sock);
            free(client);
        }
    }

    THREAD_RETURN;
}

/* Helper function to send status updates */
void send_status_update(const char* message) {
    if (g_status_callback && message) {
        g_status_callback(message);
    }
}

/* Helper function to send log entries */
void send_log_entry(const char* src_ip, const char* dst_ip, int dst_port, const char* msg_type, const char* data) {
    if (g_log_callback && src_ip && dst_ip && msg_type && data) {
        char timestamp[64];
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

        g_log_callback(timestamp, src_ip, dst_ip, dst_port, msg_type, data);
    }
}

/* Helper function to send connection notifications */
void send_connection_notification(const char* client_ip, int client_port, const char* target_host, int target_port, int connection_id) {
    g_total_connections++;
    if (g_connection_callback && client_ip && target_host) {
        g_connection_callback(client_ip, client_port, target_host, target_port, connection_id);
    }

    /* Update statistics callback */
    if (g_stats_callback) {
        g_stats_callback(g_total_connections, 0, g_total_bytes); /* active_connections = 0 for now */
    }
}

/* Helper function to send disconnect notifications */
void send_disconnect_notification(int connection_id, const char* reason) {
    if (g_disconnect_callback && reason) {
        g_disconnect_callback(connection_id, reason);
    }
}

/* Set callback functions */
__declspec(dllexport) void set_log_callback(log_callback_t callback) {
    g_log_callback = callback;
}

__declspec(dllexport) void set_status_callback(status_callback_t callback) {
    g_status_callback = callback;
}

__declspec(dllexport) void set_connection_callback(connection_callback_t callback) {
    g_connection_callback = callback;
}

__declspec(dllexport) void set_stats_callback(stats_callback_t callback) {
    g_stats_callback = callback;
}

__declspec(dllexport) void set_disconnect_callback(disconnect_callback_t callback) {
    g_disconnect_callback = callback;
}

/* Get system IP addresses */
__declspec(dllexport) int get_system_ips(char* buffer, int buffer_size) {
    if (!buffer || buffer_size <= 0) return 0;

    buffer[0] = '\0';
    int offset = 0;

    // Add localhost and 0.0.0.0 (any interface)
    offset += snprintf(buffer + offset, buffer_size - offset, "127.0.0.1;0.0.0.0;");

    // Get adapter info
    ULONG adapter_info_size = 0;
    if (GetAdaptersInfo(NULL, &adapter_info_size) == ERROR_BUFFER_OVERFLOW) {
        PIP_ADAPTER_INFO adapter_info = (PIP_ADAPTER_INFO)malloc(adapter_info_size);
        if (adapter_info && GetAdaptersInfo(adapter_info, &adapter_info_size) == NO_ERROR) {
            PIP_ADAPTER_INFO adapter = adapter_info;
            while (adapter && offset < buffer_size - 20) {
                if (adapter->Type == MIB_IF_TYPE_ETHERNET || adapter->Type == IF_TYPE_IEEE80211) {
                    PIP_ADDR_STRING addr = &adapter->IpAddressList;
                    while (addr && offset < buffer_size - 20) {
                        if (strcmp(addr->IpAddress.String, "0.0.0.0") != 0) {
                            offset += snprintf(buffer + offset, buffer_size - offset, "%s;", addr->IpAddress.String);
                        }
                        addr = addr->Next;
                    }
                }
                adapter = adapter->Next;
            }
            free(adapter_info);
        }
    }

    return offset;
}

/* Get current proxy configuration */
__declspec(dllexport) BOOL get_proxy_config(char* bind_addr, int* port, char* log_file) {
    if (!bind_addr || !port || !log_file) return FALSE;
    strcpy(bind_addr, config.bind_addr);
    *port = config.port;
    strcpy(log_file, config.log_file);

    return TRUE;
}

/* Get proxy statistics */
__declspec(dllexport) BOOL get_proxy_stats(int* connections, int* bytes_transferred) {
    if (!connections || !bytes_transferred) return FALSE;

    *connections = g_total_connections;
    *bytes_transferred = g_total_bytes;

    return TRUE;
}

/* Process enumeration functionality has been removed as it was only needed for WinDivert */
