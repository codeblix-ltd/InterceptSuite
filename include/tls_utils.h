/*
 * TLS MITM Proxy - Data Processing Utilities
 *
 * Functions for handling data forwarding between client and server,
 * including pretty printing of the intercepted data.
 */

#ifndef TLS_UTILS_H
#define TLS_UTILS_H

#include "tls_proxy.h"

/* Function prototypes */
void forward_data(SSL *src, SSL *dst, const char *direction, const char *src_ip, const char *dst_ip, int dst_port);
THREAD_RETURN_TYPE forward_data_thread(void *arg);
void pretty_print_data(const char *direction, const unsigned char *data, int len, const char *src_ip, const char *dst_ip, int dst_port);
THREAD_RETURN_TYPE handle_client(void *arg);

#endif /* TLS_UTILS_H */
