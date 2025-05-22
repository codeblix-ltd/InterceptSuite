/*
 * TLS MITM Proxy - Intercepts TLS traffic and displays it in plaintext
 *
 * This proxy intercepts TLS connections between clients and servers,
 * performs TLS handshakes with both sides, and shows the decrypted traffic.
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <process.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "libssl.lib")
    #pragma comment(lib, "libcrypto.lib")
    typedef SOCKET socket_t;
    typedef unsigned int socklen_t;
    #define THREAD_RETURN_TYPE unsigned __stdcall
    #define THREAD_RETURN return 0
    #define close_socket(s) closesocket(s)
    #define THREAD_HANDLE HANDLE
    #define CREATE_THREAD(handle, func, arg) handle = (HANDLE)_beginthreadex(NULL, 0, func, arg, 0, NULL)
    #define JOIN_THREAD(handle) WaitForSingleObject(handle, INFINITE); CloseHandle(handle)
    #define SLEEP(ms) Sleep(ms)

    // Declaration for OPENSSL_Applink
    void **__cdecl OPENSSL_Applink(void);
#else
    #include <unistd.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <pthread.h>
    typedef int socket_t;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define THREAD_RETURN_TYPE void*
    #define THREAD_RETURN return NULL
    #define close_socket(s) close(s)
    #define THREAD_HANDLE pthread_t
    #define CREATE_THREAD(handle, func, arg) pthread_create(&handle, NULL, func, arg)
    #define JOIN_THREAD(handle) pthread_join(handle, NULL)
    #define SLEEP(ms) usleep(ms * 1000)
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>

#define PROXY_PORT 4444
#define BUFFER_SIZE 16384
#define MAX_HOSTNAME_LEN 256
#define CERT_EXPIRY_DAYS 365
#define CA_CERT_FILE "myCA.pem"
#define CA_KEY_FILE "myCA.key"

/* Define SSL error reason codes if not available */
#ifndef SSL_R_UNEXPECTED_EOF_WHILE_READING
#define SSL_R_UNEXPECTED_EOF_WHILE_READING 0x14A
#endif

typedef struct {
    socket_t client_sock;
    struct sockaddr_in client_addr;
} client_info;

typedef struct {
    socket_t client_sock;
    socket_t server_sock;
    SSL *client_ssl;
    SSL *server_ssl;
    char target_host[MAX_HOSTNAME_LEN];
    int target_port;
} connection_info;

// Structure to pass data to the forwarding thread
typedef struct {
    SSL *src;
    SSL *dst;
    const char *direction;
} forward_info;

// Global CA certificate and key
X509 *ca_cert = NULL;
EVP_PKEY *ca_key = NULL;

// Function prototypes
int init_openssl(void);
void cleanup_openssl(void);
int load_or_generate_ca_cert(void);
int generate_cert_for_host(const char *hostname, X509 **cert, EVP_PKEY **key);
int handle_socks5_handshake(socket_t client_sock, char *target_host, int *target_port);
THREAD_RETURN_TYPE handle_client(void *arg);
THREAD_RETURN_TYPE forward_data_thread(void *arg);
void forward_data(SSL *src, SSL *dst, const char *direction);
void pretty_print_data(const char *direction, const unsigned char *data, int len);
void print_openssl_error(void);
SSL_CTX *create_server_ssl_context(void);
SSL_CTX *create_client_ssl_context(void);

int main(void) {
    socket_t server_sock;
    struct sockaddr_in server_addr;
    client_info *client;
    THREAD_HANDLE thread_id;
    int ret;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "Failed to initialize Winsock\n");
        return 1;
    }
#endif

    // Initialize OpenSSL
    if (!init_openssl()) {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        return 1;
    }

    // Load or generate CA certificate and key
    if (!load_or_generate_ca_cert()) {
        fprintf(stderr, "Failed to load or generate CA certificate\n");
        cleanup_openssl();
        return 1;
    }

    // Create the server socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        fprintf(stderr, "Failed to create socket\n");
        cleanup_openssl();
        return 1;
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
        cleanup_openssl();
        return 1;
    }

    // Listen for connections
    ret = listen(server_sock, 5);
    if (ret == SOCKET_ERROR) {
        fprintf(stderr, "Failed to listen on socket\n");
        close_socket(server_sock);
        cleanup_openssl();
        return 1;
    }

    printf("\nTLS MITM Proxy - Intercepts TLS traffic and displays it in plaintext\n");
    printf("===========================================================================\n");
    printf("1. Ensure the CA certificate has been added to your system/browser trust store\n");
    printf("   - CA Certificate: %s\n", CA_CERT_FILE);
    printf("2. Configure your system to use this proxy:\n");
    printf("   - SOCKS5 Proxy: 127.0.0.1:%d\n", PROXY_PORT);
    printf("   - Use a tool like ProxyCap, Proxifier, etc. to redirect traffic\n");
    printf("3. All intercepted traffic will be displayed in plaintext\n");
    printf("===========================================================================\n");
    printf("[*] MITM proxy listening on 127.0.0.1:%d\n", PROXY_PORT);

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
        }

        printf("\n[*] Accepted connection from %s:%d\n",
               inet_ntoa(client->client_addr.sin_addr),
               ntohs(client->client_addr.sin_port));

        // Create a thread to handle the client
        CREATE_THREAD(thread_id, handle_client, client);
#ifdef _WIN32
        // In Windows, we detach the thread and let it clean up itself
        CloseHandle(thread_id);
#else
        // In POSIX, we detach the thread
        pthread_detach(thread_id);
#endif
    }

    // Cleanup (this code is never reached in this simple server)
    close_socket(server_sock);
    cleanup_openssl();

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}

int init_openssl(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#else
    OPENSSL_init_ssl(0, NULL);
#endif

#ifdef _WIN32
    // Initialize the OPENSSL_Applink functionality (defined in applink.c)
    OPENSSL_Applink();
#endif

    return 1;
}

void cleanup_openssl(void) {
    if (ca_cert) X509_free(ca_cert);
    if (ca_key) EVP_PKEY_free(ca_key);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ERR_free_strings();
    EVP_cleanup();
#endif
}

void print_openssl_error(void) {
    unsigned long err;
    while ((err = ERR_get_error())) {
        char *str = ERR_error_string(err, NULL);
        fprintf(stderr, "OpenSSL Error: %s\n", str);
    }
}

int load_or_generate_ca_cert(void) {
    FILE *cert_file = fopen(CA_CERT_FILE, "r");
    FILE *key_file = fopen(CA_KEY_FILE, "r");

    if (cert_file && key_file) {
        // Load existing CA cert and key
        printf("Loading existing CA cert and key from %s and %s\n", CA_CERT_FILE, CA_KEY_FILE);
        ca_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
        fclose(cert_file);

        ca_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
        fclose(key_file);

        if (ca_cert && ca_key) {
            return 1; // Successfully loaded
        }

        // If we got here, something failed
        if (ca_cert) X509_free(ca_cert);
        if (ca_key) EVP_PKEY_free(ca_key);
        ca_cert = NULL;
        ca_key = NULL;
    }

    // Generate new CA cert and key
    printf("Generating new CA cert and key\n");

    // Generate key
    ca_key = EVP_PKEY_new();
    if (!ca_key) {
        print_openssl_error();
        return 0;
    }

    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!rsa) {
        print_openssl_error();
        EVP_PKEY_free(ca_key);
        ca_key = NULL;
        return 0;
    }

    if (!EVP_PKEY_assign_RSA(ca_key, rsa)) {
        print_openssl_error();
        RSA_free(rsa);
        EVP_PKEY_free(ca_key);
        ca_key = NULL;
        return 0;
    }

    // Generate cert
    ca_cert = X509_new();
    if (!ca_cert) {
        print_openssl_error();
        EVP_PKEY_free(ca_key);
        ca_key = NULL;
        return 0;
    }

    // Set version, serial number, validity
    X509_set_version(ca_cert, 2); // X509v3
    ASN1_INTEGER_set(X509_get_serialNumber(ca_cert), 1);

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(ca_cert), 0); // Valid from now
    X509_gmtime_adj(X509_get_notAfter(ca_cert), 60 * 60 * 24 * 365 * 10); // Valid for 10 years

    // Set public key and issuer/subject
    X509_set_pubkey(ca_cert, ca_key);

    X509_NAME *name = X509_get_subject_name(ca_cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"TLS MITM Proxy CA", -1, -1, 0);
    X509_set_issuer_name(ca_cert, name);

    // Add extensions
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, ca_cert, ca_cert, NULL, NULL, 0);

    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:TRUE");
    if (!ext) {
        print_openssl_error();
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        ca_cert = NULL;
        ca_key = NULL;
        return 0;
    }

    X509_add_ext(ca_cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Sign the certificate
    if (!X509_sign(ca_cert, ca_key, EVP_sha256())) {
        print_openssl_error();
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        ca_cert = NULL;
        ca_key = NULL;
        return 0;
    }

    // Write to files
    cert_file = fopen(CA_CERT_FILE, "w");
    key_file = fopen(CA_KEY_FILE, "w");

    if (cert_file && key_file) {
        PEM_write_X509(cert_file, ca_cert);
        PEM_write_PrivateKey(key_file, ca_key, NULL, NULL, 0, NULL, NULL);

        fclose(cert_file);
        fclose(key_file);

        printf("CA cert and key written to %s and %s\n", CA_CERT_FILE, CA_KEY_FILE);
        printf("IMPORTANT: Install this CA cert in your system/browser certificate store!\n");

        return 1;
    }

    fprintf(stderr, "Failed to write CA cert and key to files\n");
    if (cert_file) fclose(cert_file);
    if (key_file) fclose(key_file);

    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);
    ca_cert = NULL;
    ca_key = NULL;

    return 0;
}

int generate_cert_for_host(const char *hostname, X509 **cert_out, EVP_PKEY **key_out) {
    X509 *cert;
    EVP_PKEY *key;
    X509_NAME *name;

    printf("Generating certificate for %s\n", hostname);

    // Generate key
    key = EVP_PKEY_new();
    if (!key) {
        print_openssl_error();
        return 0;
    }

    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!rsa) {
        print_openssl_error();
        EVP_PKEY_free(key);
        return 0;
    }

    if (!EVP_PKEY_assign_RSA(key, rsa)) {
        print_openssl_error();
        RSA_free(rsa);
        EVP_PKEY_free(key);
        return 0;
    }

    // Generate cert
    cert = X509_new();
    if (!cert) {
        print_openssl_error();
        EVP_PKEY_free(key);
        return 0;
    }

    // Set version, serial number, validity
    X509_set_version(cert, 2); // X509v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)time(NULL));

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0); // Valid from now
    X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * CERT_EXPIRY_DAYS); // Valid for a year

    // Set public key
    X509_set_pubkey(cert, key);

    // Set subject name
    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)hostname, -1, -1, 0);

    // Set issuer name (from CA cert)
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    // Add Subject Alternative Name extension
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);

    char san[MAX_HOSTNAME_LEN + 8];
    sprintf(san, "DNS:%s", hostname);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
    if (!ext) {
        print_openssl_error();
        X509_free(cert);
        EVP_PKEY_free(key);
        return 0;
    }

    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Sign the certificate with our CA key
    if (!X509_sign(cert, ca_key, EVP_sha256())) {
        print_openssl_error();
        X509_free(cert);
        EVP_PKEY_free(key);
        return 0;
    }

    *cert_out = cert;
    *key_out = key;

    return 1;
}

SSL_CTX *create_server_ssl_context(void) {
    SSL_CTX *ctx;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ctx = SSL_CTX_new(SSLv23_server_method());
#else
    ctx = SSL_CTX_new(TLS_server_method());
#endif

    if (!ctx) {
        print_openssl_error();
        return NULL;
    }

    // Allow all SSL/TLS protocols
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    return ctx;
}

SSL_CTX *create_client_ssl_context(void) {
    SSL_CTX *ctx;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ctx = SSL_CTX_new(SSLv23_client_method());
#else
    ctx = SSL_CTX_new(TLS_client_method());
#endif

    if (!ctx) {
        print_openssl_error();
        return NULL;
    }

    // Disable certificate verification for outbound connections
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

int handle_socks5_handshake(socket_t client_sock, char *target_host, int *target_port) {
    unsigned char buffer[512];
    int received;
    unsigned char reply[10] = {0};

    // Receive the initial greeting
    received = recv(client_sock, (char*)buffer, 2, 0);
    if (received != 2) {
        fprintf(stderr, "Failed to receive SOCKS5 greeting\n");
        return 0;
    }

    if (buffer[0] != 5) { // SOCKS5 version
        fprintf(stderr, "Unsupported SOCKS version: %d\n", buffer[0]);
        return 0;
    }

    int nmethods = buffer[1];
    received = recv(client_sock, (char*)buffer, nmethods, 0);
    if (received != nmethods) {
        fprintf(stderr, "Failed to receive auth methods\n");
        return 0;
    }

    // Send auth method choice (no auth)
    reply[0] = 5; // SOCKS5
    reply[1] = 0; // No auth
    if (send(client_sock, (char*)reply, 2, 0) != 2) {
        fprintf(stderr, "Failed to send auth method choice\n");
        return 0;
    }

    // Receive connection request
    received = recv(client_sock, (char*)buffer, 4, 0);
    if (received != 4) {
        fprintf(stderr, "Failed to receive connection request\n");
        return 0;
    }

    if (buffer[0] != 5) { // SOCKS5 version
        fprintf(stderr, "Unsupported SOCKS version: %d\n", buffer[0]);
        return 0;
    }

    if (buffer[1] != 1) { // Only support CONNECT command
        fprintf(stderr, "Unsupported command: %d\n", buffer[1]);
        return 0;
    }

    int atyp = buffer[3];
    if (atyp == 1) {
        // IPv4 address
        received = recv(client_sock, (char*)buffer, 4, 0);
        if (received != 4) {
            fprintf(stderr, "Failed to receive IPv4 address\n");
            return 0;
        }

        // Convert IPv4 address to string
        sprintf(target_host, "%d.%d.%d.%d", buffer[0], buffer[1], buffer[2], buffer[3]);
    }
    else if (atyp == 3) {
        // Domain name
        received = recv(client_sock, (char*)buffer, 1, 0);
        if (received != 1) {
            fprintf(stderr, "Failed to receive domain name length\n");
            return 0;
        }

        int domain_len = buffer[0];
        received = recv(client_sock, (char*)buffer, domain_len, 0);
        if (received != domain_len) {
            fprintf(stderr, "Failed to receive domain name\n");
            return 0;
        }

        // Copy domain name to target_host
        memcpy(target_host, buffer, domain_len);
        target_host[domain_len] = '\0';
    }
    else if (atyp == 4) {
        // IPv6 address
        // For simplicity, we'll just read the 16 bytes and not try to convert them to a string
        received = recv(client_sock, (char*)buffer, 16, 0);
        if (received != 16) {
            fprintf(stderr, "Failed to receive IPv6 address\n");
            return 0;
        }

        sprintf(target_host, "IPv6"); // Placeholder
        fprintf(stderr, "IPv6 addresses are not fully supported\n");
    }
    else {
        fprintf(stderr, "Unsupported address type: %d\n", atyp);
        return 0;
    }

    // Receive port
    received = recv(client_sock, (char*)buffer, 2, 0);
    if (received != 2) {
        fprintf(stderr, "Failed to receive port\n");
        return 0;
    }

    *target_port = (buffer[0] << 8) | buffer[1];

    // Send success response
    memset(reply, 0, sizeof(reply));
    reply[0] = 5; // SOCKS5
    reply[1] = 0; // Success
    reply[2] = 0; // Reserved
    reply[3] = 1; // IPv4
    // IP address (all zeros for 0.0.0.0)
    // Port (all zeros)

    if (send(client_sock, (char*)reply, 10, 0) != 10) {
        fprintf(stderr, "Failed to send success response\n");
        return 0;
    }

    return 1;
}

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

THREAD_RETURN_TYPE forward_data_thread(void *arg) {
    forward_info *info = (forward_info *)arg;
    forward_data(info->src, info->dst, info->direction);
    free(info); // Free the allocated structure
    THREAD_RETURN;
}

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
        fprintf(stderr, "Failed to connect to server: %d\n",
#ifdef _WIN32
                WSAGetLastError()
#else
                errno
#endif
        );
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
    }    printf("TLS MITM established! Intercepting traffic between client and %s:%d\n",
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