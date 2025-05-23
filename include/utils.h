/*
 * TLS MITM Proxy - Utility Functions Header
 *
 * Defines utility functions for the TLS MITM proxy,
 * including logging, command line parsing, and IP validation.
 */

#ifndef UTILS_H
#define UTILS_H

#include "tls_proxy.h"

/* Function prototypes */
void init_config(void);
void print_usage(const char *program_name);
int parse_arguments(int argc, char *argv[]);
int validate_ip_address(const char *ip_addr);
int open_log_file(void);
void close_log_file(void);
void log_message(const char *format, ...);

#endif /* UTILS_H */
