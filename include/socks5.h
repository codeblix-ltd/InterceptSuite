/*
 * TLS MITM Proxy - SOCKS5 Protocol Handler
 *
 * Functions for handling the SOCKS5 protocol to receive connection
 * target information from clients.
 */

#ifndef SOCKS5_H
#define SOCKS5_H

#include "tls_proxy.h"

/* Function prototypes */
int handle_socks5_handshake(socket_t client_sock, char *target_host, int *target_port);

#endif /* SOCKS5_H */
