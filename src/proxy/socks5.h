/*
 * TLS MITM Proxy - SOCKS5 Protocol Handler
 *
 * Functions for handling the SOCKS5 protocol to receive connection
 * target information from clients.
 */

#ifndef SOCKS5_H
#define SOCKS5_H

#include "../tls/proxy/tls_proxy.h"

/* SOCKS5 Protocol Constants (RFC 1928) */
// SOCKS version
#define SOCKS5_VERSION             0x05

// Authentication methods
#define SOCKS5_AUTH_NONE           0x00
#define SOCKS5_AUTH_GSSAPI         0x01
#define SOCKS5_AUTH_USERNAME_PASS  0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE  0xFF

// Command types
#define SOCKS5_CMD_CONNECT         0x01
#define SOCKS5_CMD_BIND            0x02
#define SOCKS5_CMD_UDP_ASSOCIATE   0x03

// Address types
#define SOCKS5_ADDR_IPV4           0x01
#define SOCKS5_ADDR_DOMAIN         0x03
#define SOCKS5_ADDR_IPV6           0x04

// Reply codes
#define SOCKS5_REPLY_SUCCESS       0x00
#define SOCKS5_REPLY_GENERAL_FAIL  0x01
#define SOCKS5_REPLY_CONN_DENIED   0x02
#define SOCKS5_REPLY_NET_UNREACH   0x03
#define SOCKS5_REPLY_HOST_UNREACH  0x04
#define SOCKS5_REPLY_CONN_REFUSED  0x05
#define SOCKS5_REPLY_TTL_EXPIRED   0x06
#define SOCKS5_REPLY_CMD_NOTSUP    0x07
#define SOCKS5_REPLY_ADDR_NOTSUP   0x08

/* Special return codes for handle_socks5_handshake */
#define SOCKS5_RESULT_TCP_CONNECT  1  // Normal TCP CONNECT - proceed with TCP connection
#define SOCKS5_RESULT_UDP_ASSOCIATE 2  // UDP ASSOCIATE - keep control connection alive
#define SOCKS5_RESULT_ERROR        0  // Error - close connection

/* Function prototypes */
int handle_socks5_handshake(socket_t client_sock, char *target_host, int *target_port);

#endif /* SOCKS5_H */
