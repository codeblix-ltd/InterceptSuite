/*
 * TLS MITM Proxy - Main Entry Point
 *
 * This is the main entry point for the TLS MITM proxy application.
 * It initializes the necessary components and starts the proxy server.
 */

#include "../include/tls_proxy.h"
#include "../include/cert_utils.h"
#include "../include/socks5.h"
#include "../include/tls_utils.h"
#include "../include/utils.h"

/* Additional Windows headers for console handling */
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

/* Function prototypes */
int init_winsock(void);
void cleanup_winsock(void);
int start_proxy_server(void);

/* Winsock initialization and cleanup */
int init_winsock(void) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "Failed to initialize Winsock\n");
        return 0;
    }
    return 1;
}

void cleanup_winsock(void) {
    WSACleanup();
}

/* Start the proxy server */
int start_proxy_server(void) {
    socket_t server_sock;
    struct sockaddr_in server_addr;
    client_info *client;
    THREAD_HANDLE thread_id;
    int ret;    // Create the server socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        fprintf(stderr, "Failed to create socket: %d\n", WSAGetLastError());
        return 0;
    }

    // Allow socket reuse
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) != 0) {
        fprintf(stderr, "Failed to set SO_REUSEADDR: %d\n", WSAGetLastError());
        // Continue anyway, not critical
    }

    // Set TCP keepalive to detect dead connections
    DWORD keepAlive = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepAlive, sizeof(keepAlive)) != 0) {
        fprintf(stderr, "Failed to set SO_KEEPALIVE: %d\n", WSAGetLastError());
        // Continue anyway, not critical
    }

    // Set a reasonable timeout
    DWORD timeout = 60000;  // 60 seconds
    if (setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) != 0 ||
        setsockopt(server_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) != 0) {
        fprintf(stderr, "Failed to set socket timeout: %d\n", WSAGetLastError());
        // Continue anyway, not critical
    }    // Bind the socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;

    // Convert IP string to binary representation
    if (inet_pton(AF_INET, config.bind_addr, &(server_addr.sin_addr)) != 1) {
        fprintf(stderr, "Failed to convert bind address: %s\n", config.bind_addr);
        close_socket(server_sock);
        return 0;
    }
    server_addr.sin_port = htons(config.port);

    ret = bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (ret == SOCKET_ERROR) {
        fprintf(stderr, "Failed to bind socket to %s:%d: %d\n",
                config.bind_addr, config.port, WSAGetLastError());
        close_socket(server_sock);
        return 0;
    }

    // Log successful bind
    log_message("Successfully bound to %s:%d", config.bind_addr, config.port);// Listen for connections
    ret = listen(server_sock, SOMAXCONN);
    if (ret == SOCKET_ERROR) {
        fprintf(stderr, "Failed to listen on socket: %d\n", WSAGetLastError());
        close_socket(server_sock);
        return 0;
    }


    if (config.verbose) {
        printf("   - SOCKS5 Proxy: %s:%d\n", config.bind_addr, config.port);
        fflush(stdout);
    }    if (config.verbose && config.log_fp) {
        printf("   - Log file: %s\n", config.log_file);
        fflush(stdout);
    }    if (config.verbose) {
        printf("===========================================================================\n");
        fflush(stdout);
        printf("[*] MITM proxy listening on %s:%d\n", config.bind_addr, config.port);
        fflush(stdout);
    }

    // Set socket to non-blocking mode
    unsigned long nonBlocking = 1;
    if (ioctlsocket(server_sock, FIONBIO, &nonBlocking) != 0) {
        fprintf(stderr, "Failed to set socket to non-blocking mode\n");
        close_socket(server_sock);
        return 0;
    }

    // Main server loop
    while (1) {
        // Prepare for select() call
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(server_sock, &readfds);

        // Wait for 1 second
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        // Check if socket is ready for reading (connection available)
        int ready = select((int)server_sock + 1, &readfds, NULL, NULL, &tv);

        if (ready < 0) {
            // Error in select()
            fprintf(stderr, "Select error: %d\n", WSAGetLastError());
            SLEEP(1000);
            continue;
        }

        if (ready == 0) {
            // Timeout (no connection available)
            continue;
        }

        // Connection available, allocate client info
        client = (client_info*)malloc(sizeof(client_info));
        if (!client) {
            fprintf(stderr, "Memory allocation failed\n");
            SLEEP(1000);
            continue;
        }        // Accept the connection
        socklen_t addr_len = sizeof(client->client_addr);
        client->client_sock = accept(server_sock, (struct sockaddr*)&client->client_addr, &addr_len);

        if (client->client_sock == INVALID_SOCKET) {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
                if (config.verbose) {
                    fprintf(stderr, "Failed to accept connection: %d\n", error);
                }
            }
            free(client);
            continue;
        }

        // Set client socket back to blocking mode for normal operation
        nonBlocking = 0;
        if (ioctlsocket(client->client_sock, FIONBIO, &nonBlocking) != 0) {
            if (config.verbose) {
                fprintf(stderr, "Failed to set socket to blocking mode: %d\n", WSAGetLastError());
            }
            // This is important so we'll close the socket if we can't set to blocking mode
            close_socket(client->client_sock);
            free(client);
            continue;
        }

        // Set TCP_NODELAY to improve performance (disable Nagle's algorithm)
        DWORD nodelay = 1;
        if (setsockopt(client->client_sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay)) != 0) {
            if (config.verbose) {
                fprintf(stderr, "Failed to set TCP_NODELAY: %d\n", WSAGetLastError());
            }
            // Continue anyway, not critical
        }

        // Set reasonable buffer sizes
        int recvBufSize = 65536;  // 64KB
        int sendBufSize = 65536;  // 64KB
        setsockopt(client->client_sock, SOL_SOCKET, SO_RCVBUF, (const char*)&recvBufSize, sizeof(recvBufSize));
        setsockopt(client->client_sock, SOL_SOCKET, SO_SNDBUF, (const char*)&sendBufSize, sizeof(sendBufSize));

        if (config.verbose) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(client->client_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
            printf("\n[*] Accepted connection from %s:%d\n",
                   ip_str,
                   ntohs(client->client_addr.sin_port));
        }        // Create a thread to handle the client
        CREATE_THREAD(thread_id, handle_client, client);
        // Detach thread for better performance - thread will clean up its own resources
        if (thread_id != NULL) {
            CloseHandle(thread_id);
        } else {
            // Thread creation failed, clean up client
            if (config.verbose) {
                fprintf(stderr, "Failed to create thread for client\n");
            }
            close_socket(client->client_sock);
            free(client);
        }
    }

    // Cleanup (this code is never reached in this simple server)
    close_socket(server_sock);
    return 1;
}

/* Global CA certificate and key */
X509 *ca_cert = NULL;
EVP_PKEY *ca_key = NULL;

/* Main entry point */
int main(int argc, char *argv[]) {
    /* Parse command line arguments */
    if (!parse_arguments(argc, argv)) {
        print_usage(argv[0]);
        return 1;
    }

    /* Check if help was requested */
    if (config.help_requested) {
        print_usage(argv[0]);
        return 0;
    }

    /* Validate the provided IP address */
    if (!validate_ip_address(config.bind_addr)) {
        fprintf(stderr, "Error: '%s' is not a valid IP address on this system.\n", config.bind_addr);
        fprintf(stderr, "Use --help to see usage information.\n");
        return 1;
    }

    /* Initialize Windows Sockets */
    if (config.verbose) {
        printf("Initializing Winsock...\n");
        fflush(stdout);
    }
    if (!init_winsock()) {
        fprintf(stderr, "Failed to initialize Winsock\n");
        fflush(stderr);
        return 1;
    }
    if (config.verbose) {
        printf("Winsock initialized successfully\n");
        fflush(stdout);
    }

    /* Initialize OpenSSL */
    if (config.verbose) {
        printf("Initializing OpenSSL...\n");
        fflush(stdout);
    }
    if (!init_openssl()) {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        cleanup_winsock();
        return 1;
    }
    if (config.verbose) {
        printf("OpenSSL initialized successfully\n");
        fflush(stdout);
    }

    /* Load or generate CA certificate */
    if (config.verbose) {
        printf("Loading or generating CA certificate...\n");
        fflush(stdout);
    }
    if (!load_or_generate_ca_cert()) {
        fprintf(stderr, "Failed to load or generate CA certificate\n");
        cleanup_openssl();
        cleanup_winsock();
        return 1;
    }
    if (config.verbose) {
        printf("CA certificate ready\n");
        fflush(stdout);
    }    /* Open the log file if specified */
    if (strlen(config.log_file) > 0) {
        if (!open_log_file()) {
            fprintf(stderr, "Warning: Failed to open log file, continuing without logging\n");
        } else if (config.verbose) {
            printf("Logging to file: %s\n", config.log_file);
        }
    }

    /* Print table header immediately in non-verbose mode */
    if (!config.verbose) {
        printf("\n%-15s | %-15s | %-5s | %s\n", "Source IP", "Dest IP", "Port", "Message");
        printf("---------------|----------------|-------|---------------------------\n");
    }

    /* Start the proxy server */
    if (config.verbose) {
        printf("Starting proxy server...\n");
        fflush(stdout);
    }
    if (!start_proxy_server()) {
        fprintf(stderr, "Failed to start proxy server\n");
        close_log_file();
        cleanup_openssl();
        cleanup_winsock();
        return 1;
    }

    /* This is reached when Ctrl+C is pressed or server is stopped */
    close_log_file();
    cleanup_openssl();
    cleanup_winsock();
    return 0;
}
