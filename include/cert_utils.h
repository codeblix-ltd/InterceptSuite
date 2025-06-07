/*
 * TLS MITM Proxy - Certificate Utilities
 *
 * Functions for handling TLS certificates, creating and using
 * a CA certificate, and generating per-domain certificates.
 */

#ifndef CERT_UTILS_H
#define CERT_UTILS_H

#include "tls_proxy.h"

/* Function prototypes */
int init_openssl(void);
void cleanup_openssl(void);
int load_or_generate_ca_cert(void);
int generate_cert_for_host(const char *hostname, X509 **cert, EVP_PKEY **key);
void print_openssl_error(void);

/* SSL Context creation */
SSL_CTX *create_server_ssl_context(void);
SSL_CTX *create_client_ssl_context(void);

/* File utility functions */
char* read_file_to_memory(const char* filename, long* file_size);
int write_memory_to_file(const char* filename, const char* data, size_t data_size);

#endif /* CERT_UTILS_H */
