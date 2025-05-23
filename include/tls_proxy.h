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
#include <iphlpapi.h>  /* For IP address validation */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>

/* OpenSSL Applink reference */
void **__cdecl OPENSSL_Applink(void);

/* Default Constants */
#define DEFAULT_PROXY_PORT 4444
#define DEFAULT_BIND_ADDR "127.0.0.1"
#define DEFAULT_LOGFILE "tls_proxy.log"
#define BUFFER_SIZE 16384
/* Only define MAX_HOSTNAME_LEN if not already defined */
#ifndef MAX_HOSTNAME_LEN
#define MAX_HOSTNAME_LEN 256
#endif
#define MAX_FILEPATH_LEN 512
#define MAX_IP_ADDR_LEN 46  /* Max length for IPv6 addresses */
#define CERT_EXPIRY_DAYS 365
#define CA_CERT_FILE "myCA.pem"
#define CA_KEY_FILE "myCA.key"

/* Windows-specific defines and typedefs */
typedef SOCKET socket_t;
/* Only define socklen_t if not already defined in system headers */
#ifndef _SOCKLEN_T_DEFINED
typedef unsigned int socklen_t;
#endif
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
    char direction[32]; /* Use a char array instead of string pointer */
    char src_ip[MAX_IP_ADDR_LEN];
    char dst_ip[MAX_IP_ADDR_LEN];
    int dst_port;
} forward_info;

/* Configuration structure */
typedef struct {
    int port;                       /* Port to listen on */
    char bind_addr[MAX_IP_ADDR_LEN];/* IP address to bind to */
    char log_file[MAX_FILEPATH_LEN];/* Path to log file */
    FILE *log_fp;                   /* Log file pointer */
    int help_requested;             /* Flag for help display */
    int verbose;                    /* Flag for verbose output */
} proxy_config;

/* Global certificate references */
extern X509 *ca_cert;
extern EVP_PKEY *ca_key;

/* Global configuration */
extern proxy_config config;

/* Function prototypes */
int init_winsock(void);
void cleanup_winsock(void);
int start_proxy_server(void);
void print_usage(const char *program_name);
int parse_arguments(int argc, char *argv[]);
int validate_ip_address(const char *ip_addr);
void log_message(const char *format, ...);
void close_log_file(void);

#endif /* TLS_PROXY_H */
