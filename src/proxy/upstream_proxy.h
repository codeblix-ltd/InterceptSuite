/*
 * Intercept Suite - Upstream Proxy Support
 *
 * Defines structures and functions for routing traffic through upstream proxies.
 * Supports both HTTP CONNECT and SOCKS5 upstream proxies.
 */

#ifndef UPSTREAM_PROXY_H
#define UPSTREAM_PROXY_H

#include "../platform/platform.h"
#include "../tls/proxy/tls_proxy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum lengths for upstream proxy configuration */
#define UPSTREAM_PROXY_MAX_HOST 256
#define UPSTREAM_PROXY_MAX_USERNAME 128
#define UPSTREAM_PROXY_MAX_PASSWORD 128

/* Upstream proxy types */
typedef enum {
    UPSTREAM_PROXY_NONE = 0,
    UPSTREAM_PROXY_HTTP = 1,    /* HTTP CONNECT proxy - HTTP/HTTPS/WebSocket only */
    UPSTREAM_PROXY_SOCKS5 = 2   /* SOCKS5 proxy - All TCP/UDP traffic */
} upstream_proxy_type_t;

/* Upstream proxy configuration */
typedef struct {
    int enabled;                                           /* 0 = disabled, 1 = enabled */
    upstream_proxy_type_t type;                           /* Proxy type */
    char host[UPSTREAM_PROXY_MAX_HOST];                   /* Proxy server hostname/IP */
    int port;                                             /* Proxy server port */
    char username[UPSTREAM_PROXY_MAX_USERNAME];           /* Optional username for authentication */
    char password[UPSTREAM_PROXY_MAX_PASSWORD];           /* Optional password for authentication */
    int use_auth;                                         /* 0 = no auth, 1 = use username/password */
} upstream_proxy_config_t;

/* Global upstream proxy configuration */
extern upstream_proxy_config_t g_upstream_proxy_config;

/* API Functions for configuration */
INTERCEPT_API void set_upstream_proxy_enabled(int enabled);
INTERCEPT_API void set_upstream_proxy_type(upstream_proxy_type_t type);
INTERCEPT_API void set_upstream_proxy_host(const char* host);
INTERCEPT_API void set_upstream_proxy_port(int port);
INTERCEPT_API void set_upstream_proxy_auth(const char* username, const char* password);
INTERCEPT_API void disable_upstream_proxy_auth(void);
INTERCEPT_API upstream_proxy_config_t* get_upstream_proxy_config(void);

/* Convenience function to set all upstream proxy settings at once */
INTERCEPT_API int configure_upstream_proxy(upstream_proxy_type_t type, const char* host, int port,
                                          const char* username, const char* password);

/* Connection functions */
socket_t connect_through_upstream_proxy(const char* target_host, int target_port);
int should_use_upstream_proxy(const char* target_host, int target_port);

/* Protocol-specific connection functions */
socket_t connect_through_http_proxy(const char* target_host, int target_port);
socket_t connect_through_socks5_proxy(const char* target_host, int target_port);

/* UDP support for SOCKS5 */
int setup_socks5_udp_associate(socket_t* control_sock, struct sockaddr_in* udp_relay_addr);
int send_udp_through_socks5(socket_t udp_sock, const struct sockaddr_in* relay_addr,
                           const char* target_host, int target_port,
                           const unsigned char* data, int data_len);
int should_use_upstream_proxy_udp(const char* target_host, int target_port);

/* Utility functions */
int is_http_traffic(int target_port);
int is_websocket_traffic(const char* target_host, int target_port);
void init_upstream_proxy_config(void);

#ifdef __cplusplus
}
#endif

#endif /* UPSTREAM_PROXY_H */