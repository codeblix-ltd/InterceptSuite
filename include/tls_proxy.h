/*
 * TLS MITM Proxy - Main Header
 *
 * Defines common structures, constants and function declarations
 * for the TLS intercept proxy.
 */

#ifndef TLS_PROXY_H
#define TLS_PROXY_H

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>

/* OpenSSL Applink reference */
void **__cdecl OPENSSL_Applink(void);

/* Constants */
#define PROXY_PORT 4444
#define BUFFER_SIZE 16384
#define MAX_HOSTNAME_LEN 256
#define CERT_EXPIRY_DAYS 365
#define CA_CERT_FILE "myCA.pem"
#define CA_KEY_FILE "myCA.key"

/* Windows-specific defines and typedefs */
typedef SOCKET socket_t;
typedef unsigned int socklen_t;
#define THREAD_RETURN_TYPE unsigned __stdcall
#define THREAD_RETURN return 0
#define close_socket(s) closesocket(s)
#define THREAD_HANDLE HANDLE
#define CREATE_THREAD(handle, func, arg) handle = (HANDLE)_beginthreadex(NULL, 0, func, arg, 0, NULL)
#define JOIN_THREAD(handle) WaitForSingleObject(handle, INFINITE); CloseHandle(handle)
#define SLEEP(ms) Sleep(ms)

/* Define SSL error reason codes if not available */
#ifndef SSL_R_UNEXPECTED_EOF_WHILE_READING
#define SSL_R_UNEXPECTED_EOF_WHILE_READING 0x14A
#endif

/* Structures */
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

typedef struct {
    SSL *src;
    SSL *dst;
    const char *direction;
} forward_info;

/* Global certificate references */
extern X509 *ca_cert;
extern EVP_PKEY *ca_key;

/* Function prototypes */
int init_winsock(void);
void cleanup_winsock(void);
int start_proxy_server(void);

#endif /* TLS_PROXY_H */
