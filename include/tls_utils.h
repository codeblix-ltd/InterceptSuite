/*
 * TLS MITM Proxy - Data Processing Utilities
 *
 * Functions for handling data forwarding between client and server,
 * including pretty printing of the intercepted data.
 */

#ifndef TLS_UTILS_H
#define TLS_UTILS_H

#include "tls_proxy.h"

/* Protocol type detection */
#define PROTOCOL_TLS       1
#define PROTOCOL_HTTP      2
#define PROTOCOL_PLAIN_TCP 3

/* Function prototypes */
int detect_protocol(socket_t sock);
void forward_data(SSL *src, SSL *dst, const char *direction, const char *src_ip, const char *dst_ip, int dst_port, int connection_id);
void forward_tcp_data(socket_t src, socket_t dst, const char *direction, const char *src_ip, const char *dst_ip, int dst_port, int connection_id);
THREAD_RETURN_TYPE forward_data_thread(void *arg);
THREAD_RETURN_TYPE forward_tcp_thread(void *arg);
void pretty_print_data(const char *direction, const unsigned char *data, int len, const char *src_ip, const char *dst_ip, int dst_port,int connection_id, int packet_id);
THREAD_RETURN_TYPE handle_client(void *arg);

/* Callback helper functions - implemented in main.c */
void send_log_entry(const char* src_ip, const char* dst_ip, int dst_port, const char* message_type, const char* data);
void send_status_update(const char* message);

/* Interception support functions */
int should_intercept_data(const char* direction, int connection_id);
int wait_for_intercept_response(intercept_data_t* intercept_data);
void send_intercept_data(int connection_id, const char* direction, const char* src_ip, const char* dst_ip, int dst_port, const unsigned char* data, int data_length, int packet_id);

#endif /* TLS_UTILS_H */
