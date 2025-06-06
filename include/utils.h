/*
 * InterceptSuite - Utility Functions Header
 *
 * Defines utility functions for the TLS MITM proxy,
 * including logging, command line parsing, and IP validation.
 */

#ifndef UTILS_H
#define UTILS_H

#include "tls_proxy.h"

/* Function prototypes */
void init_config(void);
int validate_ip_address(const char *ip_addr);
int open_log_file(void);
void close_log_file(void);
void log_message(const char *format, ...);

/* Callback helper functions - implemented in main.c */
void send_status_update(const char* message);

#endif /* UTILS_H */
