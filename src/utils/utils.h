/*
 * InterceptSuite - Utility Functions Header
 *
 * Defines utility functions for the TLS MITM proxy,
 * including logging, command line parsing, and IP validation.
 */

#ifndef UTILS_H
#define UTILS_H

#include "../tls/proxy/tls_proxy.h"

/* Function prototypes */
void init_config(void);
int validate_ip_address(const char *ip_addr);
void log_message(const char *format, ...);

/* Packet ID management */
int get_next_packet_id(void);

/* Socket error handling */
const char* get_socket_error_description(int error_code);

/* Proxy configuration functions */
INTERCEPT_API intercept_bool_t set_config(const char *bind_addr, int port, int verbose_mode);
INTERCEPT_API proxy_config_t get_proxy_config(void);
INTERCEPT_API int get_system_ips(char *buffer, int buffer_size);

/* Safe string copy helper function */
static void safe_strncpy(char* dest, size_t dest_size, const char* src) {
#ifdef _MSC_VER
    strncpy_s(dest, dest_size, src, _TRUNCATE);
#else
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
#endif
}

#endif /* UTILS_H */
