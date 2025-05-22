/*
 * TLS MITM Proxy - Data Processing Utilities Implementation
 */

#include "../include/tls_utils.h"
#include "../include/cert_utils.h"
#include "../include/socks5.h"

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
 * Pretty print intercepted data
 */
void pretty_print_data(const char *direction, const unsigned char *data, int len) {
    printf("\n%s\n", "========================================");
    printf("[%s] Length: %d bytes\n", direction, len);
    printf("%s\n", "========================================");

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
        printf("[Text content]\n");
        // Print the text, limiting to a reasonable length
        int print_len = len > 1024 ? 1024 : len;
        printf("%.*s\n", print_len, data);
        if (print_len < len) {
            printf("... (truncated)\n");
        }
    }
    else {
        printf("[Binary content]\n");
        // Print hexdump, limiting to a reasonable length
        int print_len = len > 256 ? 256 : len;
        for (int i = 0; i < print_len; i++) {
            printf("%02x ", data[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
        if (print_len < len) {
            printf("... (truncated)\n");
        }
    }

    printf("%s\n\n", "========================================");
}

/*
 * Forward data between SSL connections
 */
void forward_data(SSL *src, SSL *dst, const char *direction) {
    unsigned char buffer[BUFFER_SIZE];
    int len;

    while (1) {
        len = SSL_read(src, buffer, sizeof(buffer));

        if (len <= 0) {
            int error = SSL_get_error(src, len);
            if (error == SSL_ERROR_ZERO_RETURN) {
                // Connection closed cleanly
                printf("Connection closed by peer (%s)\n", direction);
            }
            else if (error == SSL_ERROR_SYSCALL && ERR_peek_error() == 0) {
                // This is usually just the client closing the connection abruptly
                printf("Connection closed abruptly (%s)\n", direction);
            }
            else if (error == SSL_ERROR_SSL &&
                    ERR_GET_REASON(ERR_peek_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
                // Common case: unexpected EOF (client closed connection)
                printf("Connection closed by peer with unexpected EOF (%s)\n", direction);
                ERR_clear_error(); // Clear the error queue
            }
            else {
                fprintf(stderr, "SSL_read error in %s: %d\n", direction, error);
                print_openssl_error();
            }
            break;
        }

        // Print the intercepted data
        pretty_print_data(direction, buffer, len);

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
    forward_info *info = (forward_info *)arg;
    forward_data(info->src, info->dst, info->direction);
    free(info); // Free the allocated structure
    THREAD_RETURN;
}

/*
 * Handle a client connection
 */
THREAD_RETURN_TYPE handle_client(void *arg) {
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
    int target_port;
    int ret;

    // Handle the SOCKS5 handshake
    memset(target_host, 0, sizeof(target_host));
    if (!handle_socks5_handshake(client_sock, target_host, &target_port)) {
        fprintf(stderr, "Failed to handle SOCKS5 handshake\n");
        goto cleanup;
    }

    printf("\nIntercepting connection to %s:%d\n", target_host, target_port);

    // Generate certificate for the target host
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
    }

    // Create server SSL object and attach to client socket
    printf("Performing TLS handshake with client...\n");
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
    }

    // Connect to the real server
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        fprintf(stderr, "Failed to create socket for server connection\n");
        goto cleanup;
    }

    struct hostent *host = gethostbyname(target_host);
    if (!host) {
        fprintf(stderr, "Failed to resolve hostname %s\n", target_host);
        goto cleanup;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, host->h_addr, host->h_length);
    server_addr.sin_port = htons(target_port);

    printf("Connecting to real server at %s:%d...\n", target_host, target_port);
    ret = connect(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (ret == SOCKET_ERROR) {
        fprintf(stderr, "Failed to connect to server: %d\n", WSAGetLastError());
        goto cleanup;
    }

    // Create client context (for proxy -> server)
    client_ctx = create_client_ssl_context();
    if (!client_ctx) {
        fprintf(stderr, "Failed to create client SSL context\n");
        goto cleanup;
    }

    // Create client SSL object and attach to server socket
    printf("Performing TLS handshake with server...\n");
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
    }

    printf("TLS MITM established! Intercepting traffic between client and %s:%d\n",
           target_host, target_port);

    // Create a thread to forward data from client to server
    forward_info *client_to_server = (forward_info*)malloc(sizeof(forward_info));
    if (!client_to_server) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }
    client_to_server->src = server_ssl;
    client_to_server->dst = client_ssl;
    client_to_server->direction = "client->server";

    // Start forwarding data in both directions
    CREATE_THREAD(thread_id, forward_data_thread, client_to_server);
    forward_data(client_ssl, server_ssl, "server->client");

    // Wait for the other thread to finish
    JOIN_THREAD(thread_id);

    printf("Connection to %s:%d closed\n", target_host, target_port);

cleanup:
    if (server_ssl) SSL_free(server_ssl);
    if (client_ssl) SSL_free(client_ssl);
    if (server_ctx) SSL_CTX_free(server_ctx);
    if (client_ctx) SSL_CTX_free(client_ctx);
    if (cert) X509_free(cert);
    if (key) EVP_PKEY_free(key);

    if (client_sock != INVALID_SOCKET) close_socket(client_sock);
    if (server_sock != INVALID_SOCKET) close_socket(server_sock);

    free(client);
    THREAD_RETURN;
}
