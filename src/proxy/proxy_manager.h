/*
 * TLS MITM Proxy - Proxy Manager Header
 *
 * Contains declarations for proxy server management functionality.
 */

#ifndef PROXY_MANAGER_H
#define PROXY_MANAGER_H

#include "../platform/platform.h"
#include "../tls/proxy/tls_proxy.h"
#include "../tls/proxy/tls_proxy_dll.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Helper function to check if port is available */
int is_port_available(const char* bind_addr, int port);

/* Initialize proxy components */
INTERCEPT_API void init_proxy_components(void);

/* Start the proxy server */
INTERCEPT_API proxy_start_result_t start_proxy(void);

/* Stop the proxy server */
INTERCEPT_API void stop_proxy(void);

/* Server thread function */
THREAD_RETURN_TYPE THREAD_CALL run_server_thread(void * arg);

/* Network subsystem initialization and cleanup */
int init_winsock(void);
void cleanup_winsock(void);

/* Helper functions for status and notifications */
void send_status_update(const char * message);
void send_log_entry(const char * src_ip, const char * dst_ip, int dst_port,
    const char * direction, const unsigned char * data, int data_length,
    const char * msg_type, int connection_id, int packet_id);
void send_connection_notification(const char * client_ip, int client_port,
    const char * target_host, int target_port, int connection_id);
void send_disconnect_notification(int connection_id, const char * reason);

#ifdef __cplusplus
}
#endif

#endif /* PROXY_MANAGER_H */
