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

/* Additional Windows headers for console handling */
#include <windows.h>
#include <io.h>
#include <fcntl.h>

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
    int ret;

    // Create the server socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        fprintf(stderr, "Failed to create socket\n");
        return 0;
    }

    // Allow socket reuse
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    // Bind the socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
    server_addr.sin_port = htons(PROXY_PORT);

    ret = bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (ret == SOCKET_ERROR) {
        fprintf(stderr, "Failed to bind socket\n");
        close_socket(server_sock);
        return 0;
    }

    // Listen for connections
    ret = listen(server_sock, 5);
    if (ret == SOCKET_ERROR) {
        fprintf(stderr, "Failed to listen on socket\n");
        close_socket(server_sock);
        return 0;
    }

    printf("\nTLS MITM Proxy - Intercepts TLS traffic and displays it in plaintext\n");
    fflush(stdout);
    printf("===========================================================================\n");
    fflush(stdout);
    printf("1. Ensure the CA certificate has been added to your system/browser trust store\n");
    fflush(stdout);
    printf("   - CA Certificate: %s\n", CA_CERT_FILE);
    fflush(stdout);
    printf("2. Configure your system to use this proxy:\n");
    fflush(stdout);
    printf("   - SOCKS5 Proxy: 127.0.0.1:%d\n", PROXY_PORT);
    fflush(stdout);
    printf("   - Use a tool like ProxyCap, Proxifier, etc. to redirect traffic\n");
    fflush(stdout);
    printf("3. All intercepted traffic will be displayed in plaintext\n");
    fflush(stdout);
    printf("===========================================================================\n");
    fflush(stdout);
    printf("[*] MITM proxy listening on 127.0.0.1:%d\n", PROXY_PORT);
    fflush(stdout);

    // Main server loop
    while (1) {
        client = (client_info*)malloc(sizeof(client_info));
        if (!client) {
            fprintf(stderr, "Memory allocation failed\n");
            continue;
        }

        socklen_t addr_len = sizeof(client->client_addr);
        client->client_sock = accept(server_sock, (struct sockaddr*)&client->client_addr, &addr_len);

        if (client->client_sock == INVALID_SOCKET) {
            fprintf(stderr, "Failed to accept connection\n");
            free(client);
            continue;
        }        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client->client_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
        printf("\n[*] Accepted connection from %s:%d\n",
               ip_str,
               ntohs(client->client_addr.sin_port));

        // Create a thread to handle the client
        CREATE_THREAD(thread_id, handle_client, client);
        // Detach thread and let it clean up itself
        CloseHandle(thread_id);
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
    /* Initialize Windows Sockets */
    printf("Initializing Winsock...\n");
    fflush(stdout);
    if (!init_winsock()) {
        fprintf(stderr, "Failed to initialize Winsock\n");
        fflush(stderr);
        return 1;
    }
    printf("Winsock initialized successfully\n");
    fflush(stdout);

    /* Initialize OpenSSL */
    printf("Initializing OpenSSL...\n");
    fflush(stdout);
    if (!init_openssl()) {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        cleanup_winsock();
        return 1;
    }
    printf("OpenSSL initialized successfully\n");
    fflush(stdout);

    /* Load or generate CA certificate */
    printf("Loading or generating CA certificate...\n");
    fflush(stdout);
    if (!load_or_generate_ca_cert()) {
        fprintf(stderr, "Failed to load or generate CA certificate\n");
        cleanup_openssl();
        cleanup_winsock();
        return 1;
    }
    printf("CA certificate ready\n");
    fflush(stdout);

    /* Start the proxy server */
    printf("Starting proxy server...\n");
    fflush(stdout);
    if (!start_proxy_server()) {
        fprintf(stderr, "Failed to start proxy server\n");
        cleanup_openssl();
        cleanup_winsock();
        return 1;
    }

    /* This is reached when Ctrl+C is pressed or server is stopped */
    cleanup_openssl();
    cleanup_winsock();
    return 0;
}
