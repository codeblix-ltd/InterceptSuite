/*
 * TLS MITM Proxy - Certificate Utilities
 *
 * Functions for handling TLS certificates, creating and using
 * a CA certificate, and generating per-domain certificates.
 * Enhanced with ALPN and HTTP/2 support.
 * HTTP/S is not the goal of InterceptSuite, InterceptSuite is designed for non HTTP protocol
 * Adding HTTP/HTTP2 support allows intercepting application with non HTTP and HTTP protocol use instead of proxy raise error due to lack of alpn
 */

#ifndef CERT_UTILS_H
#define CERT_UTILS_H

#include "../proxy/tls_proxy.h"

/* Function prototypes */
int init_openssl(void);
void cleanup_openssl(void);
int load_or_generate_ca_cert(void);
int generate_cert_for_host(const char *hostname, X509 **cert, EVP_PKEY **key);
void print_openssl_error(void);

/* SSL Context creation */
SSL_CTX *create_server_ssl_context(void);
SSL_CTX *create_client_ssl_context(void);

/* ALPN and HTTP/2 support */
SSL_CTX *create_client_ssl_context_with_alpn(void);
SSL_CTX *create_server_ssl_context_with_alpn(X509 *cert, EVP_PKEY *key);
int alpn_select_callback(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                        const unsigned char *in, unsigned int inlen, void *arg);

/* File utility functions */
char* read_file_to_memory(const char* filename, long* file_size);
int write_memory_to_file(const char* filename, const char* data, size_t data_size);

/* Certificate cache management */
void init_cert_cache(void);
void cleanup_cert_cache(void);

/* Certificate regeneration */
int regenerate_ca_certificate(void);

#endif /* CERT_UTILS_H */
