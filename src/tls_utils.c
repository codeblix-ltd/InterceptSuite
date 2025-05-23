/*
 * TLS MITM Proxy - Data Processing Utilities Implementation
 */

#include "../include/tls_utils.h"
#include "../include/cert_utils.h"
#include "../include/socks5.h"
#include "../include/utils.h"
#include <ctype.h>  /* For isprint() */

/*
 * Print OpenSSL error messages
 */
static void print_openssl_error(void) {
    unsigned long err;
    while ((err = ERR_get_error())) {
        char *str = ERR_error_string(err, NULL);
        fprintf(stderr, "OpenSSL Error: %s\n", str);
    }
}

/*
 * Pretty print intercepted data in table format
 */
void pretty_print_data(const char *direction, const unsigned char *data, int len,
                     const char *src_ip, const char *dst_ip, int dst_port) {    char message[BUFFER_SIZE] = {0};

    // In non-verbose mode, filter protocol handshake messages
    if (!config.verbose) {
        // Only display data that appears to be actual content
        // Skip TLS protocol messages which are typically small
        if (len < 5) {
            // Skip very small protocol messages in non-verbose mode
            return;
        }

        // Check if the data appears to be TLS handshake or protocol messages
        // Most application data is either text or larger binary chunks
        if (len < 20 && !isprint(data[0])) {
            // Likely a TLS protocol message, skip in non-verbose mode
            return;
        }
    }

    // Format the message content
    if (len > 0) {
        // Check if the data appears to be text
        int is_text = 1;
        for (int i = 0; i < len && i < 100; i++) {
            if (data[i] != 0 && (data[i] < 32 || data[i] > 126)) {
                // ASCII control characters or non-ASCII characters
                // that are not space, newline, tab, etc.
                if (data[i] != '\r' && data[i] != '\n' && data[i] != '\t') {
                    is_text = 0;
                    break;
                }
            }
        }

        if (is_text) {
            // Limit text length to avoid buffer overflow
            int copy_len = (len > 1024) ? 1024 : len;
            snprintf(message, sizeof(message), "[Text] %.*s%s",
                     copy_len, data, (copy_len < len) ? "...(truncated)" : "");
        } else {
            // For binary data, show a shortened hex representation
            snprintf(message, sizeof(message), "[Binary] ");
            int hex_len = (len > 32) ? 32 : len;
            char *msg_ptr = message + strlen(message);
            size_t remaining = sizeof(message) - strlen(message) - 1;

            for (int i = 0; i < hex_len && remaining > 3; i++) {
                int bytes_written = snprintf(msg_ptr, remaining, "%02x ", data[i]);
                msg_ptr += bytes_written;
                remaining -= bytes_written;
            }

            if (hex_len < len && remaining > 12) {
                snprintf(msg_ptr, remaining, "...(truncated)");
            }
        }
    } else {
        strncpy(message, "[Empty]", sizeof(message) - 1);
    }
      // Print table header occasionally (only in verbose mode)
    // In non-verbose mode, the header is printed once at startup
    static int counter = 0;
    if (config.verbose && counter++ % 20 == 0) {
        printf("\n%-15s | %-15s | %-5s | %s\n", "Source IP", "Dest IP", "Port", "Message");
        printf("---------------|----------------|-------|---------------------------\n");
    }
      // Print the message in table format
    printf("%-15s | %-15s | %-5d | %s\n", src_ip, dst_ip, dst_port, message);

    // Log to file if configured
    if (config.log_fp) {
        fprintf(config.log_fp, "%-15s | %-15s | %-5d | %s\n",
                src_ip, dst_ip, dst_port, message);
        fflush(config.log_fp);
    }
}

/*
 * Forward data between SSL connections
 */
void forward_data(SSL *src, SSL *dst, const char *direction, const char *src_ip, const char *dst_ip, int dst_port) {
    unsigned char buffer[BUFFER_SIZE];
    int len;
    int fd;
    fd_set readfds;
    struct timeval tv;
    int ret;
    int activity_timeout = 0;

    // Validate parameters
    if (!src || !dst || !direction || !src_ip || !dst_ip) {
        fprintf(stderr, "Invalid parameters passed to forward_data\n");
        return;
    }

    // Add exception handling with OpenSSL's error queue
    ERR_clear_error(); // Clear any previous errors

    // Get the socket file descriptor from the SSL
    fd = SSL_get_fd(src);
    if (fd < 0) {
        fprintf(stderr, "Error getting socket fd from SSL\n");
        print_openssl_error();
        return;
    }

    // Log start of data forwarding
    if (config.verbose) {
        printf("Starting data forwarding: %s -> %s:%d\n", src_ip, dst_ip, dst_port);
    }

    while (1) {
        // Set up the select() call with a timeout
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);

        // Set a 1 second timeout to allow for more responsive termination
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        ret = select(fd + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            fprintf(stderr, "select() error\n");
            break;
        } else if (ret == 0) {
            // Timeout occurred, continue waiting but increment timeout counter
            activity_timeout++;

            // If we've been idle for over 60 seconds in non-verbose mode, exit
            // In verbose mode, we might want to wait longer
            if (!config.verbose && activity_timeout > 60) {
                if (config.verbose) {
                    printf("Connection idle timeout (%s)\n", direction);
                }
                break;
            }
            continue;
        }

        // Reset timeout counter when there's activity
        activity_timeout = 0;

        // Data is available to read
        len = SSL_read(src, buffer, sizeof(buffer));
        if (len <= 0) {
            int error = SSL_get_error(src, len);
            if (error == SSL_ERROR_ZERO_RETURN) {
                // Connection closed cleanly
                if (config.verbose) {
                    printf("Connection closed by peer (%s)\n", direction);
                }
            }
            else if (error == SSL_ERROR_SYSCALL && ERR_peek_error() == 0) {
                // This is usually just the client closing the connection abruptly
                if (config.verbose) {
                    printf("Connection closed abruptly (%s)\n", direction);
                }
            }
            else if (error == SSL_ERROR_SSL &&
                    ERR_GET_REASON(ERR_peek_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
                // Common case: unexpected EOF (client closed connection)
                if (config.verbose) {
                    printf("Connection closed by peer with unexpected EOF (%s)\n", direction);
                }
                ERR_clear_error(); // Clear the error queue
            }
            else {
                fprintf(stderr, "SSL_read error in %s: %d\n", direction, error);
                print_openssl_error();
            }
            break;
        }        // Print the intercepted data
        pretty_print_data(direction, buffer, len, src_ip, dst_ip, dst_port);

        // Forward to the destination
        int written = SSL_write(dst, buffer, len);
        if (written <= 0) {
            int error = SSL_get_error(dst, written);
            if (error == SSL_ERROR_ZERO_RETURN ||
               (error == SSL_ERROR_SYSCALL && ERR_peek_error() == 0)) {
                printf("Peer closed connection while writing (%s)\n", direction);
            } else {
                fprintf(stderr, "SSL_write error in %s\n", direction);
                print_openssl_error();
            }
            break;
        }
    }
}

/*
 * Thread function for forwarding data
 */
THREAD_RETURN_TYPE forward_data_thread(void *arg) {
    if (arg == NULL) {
        fprintf(stderr, "Error: NULL argument passed to forward_data_thread\n");
        THREAD_RETURN;
    }

    forward_info *info = (forward_info *)arg;

    // Validate all pointers and parameters before using them
    if (info->src && info->dst &&
        info->direction && strlen(info->direction) > 0 &&
        info->src_ip && strlen(info->src_ip) > 0 &&
        info->dst_ip && strlen(info->dst_ip) > 0) {

        forward_data(info->src, info->dst, info->direction, info->src_ip, info->dst_ip, info->dst_port);
    } else {
        fprintf(stderr, "Error: Invalid parameters in forward_data_thread\n");
    }

    // Free the allocated structure
    free(info);
    THREAD_RETURN;
}

/*
 * Handle a client connection
 */
THREAD_RETURN_TYPE handle_client(void *arg) {
    if (!arg) {
        fprintf(stderr, "Error: NULL argument passed to handle_client\n");
        THREAD_RETURN;
    }

    client_info *client = (client_info*)arg;
    socket_t client_sock = client->client_sock;
    socket_t server_sock = INVALID_SOCKET;
    SSL_CTX *server_ctx = NULL;
    SSL_CTX *client_ctx = NULL;
    SSL *server_ssl = NULL;
    SSL *client_ssl = NULL;
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    THREAD_HANDLE thread_id;
    char target_host[MAX_HOSTNAME_LEN];
    char client_ip[MAX_IP_ADDR_LEN];
    char server_ip[MAX_IP_ADDR_LEN];
    int target_port;
    int ret;

    // Get client IP address as string
    inet_ntop(AF_INET, &(client->client_addr.sin_addr), client_ip, MAX_IP_ADDR_LEN);    // Set socket options for better compatibility
    DWORD timeout = 120000;  // 120 seconds timeout
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    // TCP keepalive to detect dead connections
    DWORD keepAlive = 1;
    setsockopt(client_sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepAlive, sizeof(keepAlive));

    // Handle the SOCKS5 handshake
    memset(target_host, 0, sizeof(target_host));
    if (!handle_socks5_handshake(client_sock, target_host, &target_port)) {
        if (config.verbose) {
            fprintf(stderr, "Failed to handle SOCKS5 handshake\n");
        }
        goto cleanup;
    }

    if (config.verbose) {
        printf("\nIntercepting connection to %s:%d\n", target_host, target_port);
    }    // Generate certificate for the target host
    if (!generate_cert_for_host(target_host, &cert, &key)) {
        fprintf(stderr, "Failed to generate certificate for %s\n", target_host);
        goto cleanup;
    }

    // Create server context (for client -> proxy)
    server_ctx = create_server_ssl_context();
    if (!server_ctx) {
        fprintf(stderr, "Failed to create server SSL context\n");
        goto cleanup;
    }

    // Use the generated certificate and key
    if (SSL_CTX_use_certificate(server_ctx, cert) != 1) {
        fprintf(stderr, "Failed to use certificate\n");
        print_openssl_error();
        goto cleanup;
    }

    if (SSL_CTX_use_PrivateKey(server_ctx, key) != 1) {
        fprintf(stderr, "Failed to use private key\n");
        print_openssl_error();
        goto cleanup;
    }

    if (SSL_CTX_check_private_key(server_ctx) != 1) {
        fprintf(stderr, "Private key does not match certificate\n");
        print_openssl_error();
        goto cleanup;
    }    // Create server SSL object and attach to client socket
    if (config.verbose) {
        printf("Performing TLS handshake with client...\n");
    }
    server_ssl = SSL_new(server_ctx);
    if (!server_ssl) {
        fprintf(stderr, "Failed to create server SSL object\n");
        print_openssl_error();
        goto cleanup;
    }

    SSL_set_fd(server_ssl, (int)client_sock);

    ret = SSL_accept(server_ssl);
    if (ret != 1) {
        fprintf(stderr, "Failed to perform TLS handshake with client: %d\n",
                SSL_get_error(server_ssl, ret));
        print_openssl_error();
        goto cleanup;
    }    // Connect to the real server
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        fprintf(stderr, "Failed to create socket for server connection: %d\n", WSAGetLastError());
        goto cleanup;
    }
      // Set server socket options
    DWORD server_timeout = 60000;  // 60 seconds timeout
    if (setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&server_timeout, sizeof(server_timeout)) != 0 ||
        setsockopt(server_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&server_timeout, sizeof(server_timeout)) != 0) {
        if (config.verbose) {
            fprintf(stderr, "Warning: Failed to set server socket timeout: %d\n", WSAGetLastError());
        }
    }

    // Resolve hostname
    struct hostent *host = gethostbyname(target_host);
    if (!host) {
        fprintf(stderr, "Failed to resolve hostname %s: %d\n", target_host, WSAGetLastError());
        goto cleanup;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, host->h_addr, host->h_length);
    server_addr.sin_port = htons(target_port);

    // Get server IP as string
    inet_ntop(AF_INET, &(server_addr.sin_addr), server_ip, MAX_IP_ADDR_LEN);

    if (config.verbose) {
        printf("Connecting to real server at %s:%d...\n", target_host, target_port);
    }

    // Log connection attempt
    log_message("Connecting to server %s (%s):%d", target_host, server_ip, target_port);

    ret = connect(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (ret == SOCKET_ERROR) {
        int error = WSAGetLastError();
        fprintf(stderr, "Failed to connect to server %s:%d: %d\n",
                target_host, target_port, error);
        log_message("Connection to %s:%d failed with error %d", target_host, target_port, error);
        goto cleanup;
    }

    // Set TCP_NODELAY for better performance
    int nodelay = 1;
    setsockopt(server_sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));

    // Create client context (for proxy -> server)
    client_ctx = create_client_ssl_context();
    if (!client_ctx) {
        fprintf(stderr, "Failed to create client SSL context\n");
        goto cleanup;
    }    // Create client SSL object and attach to server socket
    if (config.verbose) {
        printf("Performing TLS handshake with server...\n");
    }
    client_ssl = SSL_new(client_ctx);
    if (!client_ssl) {
        fprintf(stderr, "Failed to create client SSL object\n");
        print_openssl_error();
        goto cleanup;
    }

    SSL_set_fd(client_ssl, (int)server_sock);

    // Set Server Name Indication (SNI)
    SSL_set_tlsext_host_name(client_ssl, target_host);

    ret = SSL_connect(client_ssl);
    if (ret != 1) {
        fprintf(stderr, "Failed to perform TLS handshake with server: %d\n",
                SSL_get_error(client_ssl, ret));
        print_openssl_error();
        goto cleanup;
    }    if (config.verbose) {
        printf("TLS MITM established! Intercepting traffic between client and %s:%d\n",
               target_host, target_port);
    }
    // Create a thread to forward data from client to server
    forward_info *client_to_server = (forward_info*)malloc(sizeof(forward_info));
    if (!client_to_server) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }    client_to_server->src = server_ssl;
    client_to_server->dst = client_ssl;
    strncpy(client_to_server->direction, "client->server", sizeof(client_to_server->direction)-1);
    client_to_server->direction[sizeof(client_to_server->direction)-1] = '\0';
    strncpy(client_to_server->src_ip, client_ip, MAX_IP_ADDR_LEN-1);
    strncpy(client_to_server->dst_ip, server_ip, MAX_IP_ADDR_LEN-1);
    client_to_server->dst_port = target_port;

    // Log connection info
    log_message("Established connection: %s -> %s:%d", client_ip, server_ip, target_port);    // Create a second thread for server->client direction
    forward_info *server_to_client = (forward_info*)malloc(sizeof(forward_info));
    if (!server_to_client) {
        fprintf(stderr, "Memory allocation failed\n");
        free(client_to_server); // Don't leak memory
        goto cleanup;
    }    server_to_client->src = client_ssl;
    server_to_client->dst = server_ssl;
    strncpy(server_to_client->direction, "server->client", sizeof(server_to_client->direction)-1);
    server_to_client->direction[sizeof(server_to_client->direction)-1] = '\0';
    strncpy(server_to_client->src_ip, server_ip, MAX_IP_ADDR_LEN-1);
    strncpy(server_to_client->dst_ip, client_ip, MAX_IP_ADDR_LEN-1);
    server_to_client->dst_port = ntohs(client->client_addr.sin_port);

    // Make sure strings are null-terminated
    client_to_server->src_ip[MAX_IP_ADDR_LEN-1] = '\0';
    client_to_server->dst_ip[MAX_IP_ADDR_LEN-1] = '\0';
    server_to_client->src_ip[MAX_IP_ADDR_LEN-1] = '\0';
    server_to_client->dst_ip[MAX_IP_ADDR_LEN-1] = '\0';

    // Start both forwarding threads
    THREAD_HANDLE thread_id2;
    CREATE_THREAD(thread_id, forward_data_thread, client_to_server);
    CREATE_THREAD(thread_id2, forward_data_thread, server_to_client);

    // Wait for both threads to finish
    if (thread_id != NULL) JOIN_THREAD(thread_id);
    if (thread_id2 != NULL) JOIN_THREAD(thread_id2);

    if (config.verbose) {
        printf("Connection to %s:%d closed\n", target_host, target_port);
    }

cleanup:
    // Log connection closure
    if (target_host[0] != '\0') {
        log_message("Closing connection to %s:%d", target_host, target_port);
    } else {
        log_message("Closing SOCKS5 connection (target unknown)");
    }

    // Clear any OpenSSL errors before cleanup
    ERR_clear_error();

    // Cleanup SSL objects in the correct order
    if (server_ssl) {
        SSL_shutdown(server_ssl);
        SSL_free(server_ssl);
        server_ssl = NULL;
    }

    if (client_ssl) {
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        client_ssl = NULL;
    }

    // Free SSL contexts
    if (server_ctx) {
        SSL_CTX_free(server_ctx);
        server_ctx = NULL;
    }

    if (client_ctx) {
        SSL_CTX_free(client_ctx);
        client_ctx = NULL;
    }

    // Free X509 and key
    if (cert) {
        X509_free(cert);
        cert = NULL;
    }

    if (key) {
        EVP_PKEY_free(key);
        key = NULL;
    }

    // Close sockets safely
    if (server_sock != INVALID_SOCKET) {
        close_socket(server_sock);
        server_sock = INVALID_SOCKET;
    }

    if (client_sock != INVALID_SOCKET) {
        close_socket(client_sock);
        client_sock = INVALID_SOCKET;
    }

    // Free client info struct - only free once and null the pointer
    if (client) {
        free(client);
        client = NULL;
    }

    THREAD_RETURN;
}
