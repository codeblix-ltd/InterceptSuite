#ifndef UDP_RELAY_H
#define UDP_RELAY_H

#include "../platform/platform.h"
#include "../tls/proxy/tls_proxy.h"

#ifdef __cplusplus
extern "C" {
#endif

// UDP relay server structure
typedef struct {
    socket_t socket;
    THREAD_HANDLE thread_handle;
    mutex_t cs;
    int should_stop;
    char bind_addr[MAX_IP_ADDR_LEN];
    int port;
} udp_relay_server_t;

// Function prototypes
int start_udp_relay_server(const char* bind_addr, int port);
void stop_udp_relay_server(void);
THREAD_RETURN_TYPE THREAD_CALL udp_relay_thread(void* param);
int handle_udp_packet(socket_t sock, struct sockaddr_in* client_addr,
                     const char* data, int data_len);
int parse_socks5_udp_request(const char* data, int data_len,
                           char* target_host, int* target_port,
                           const char** payload, int* payload_len);

// Message type detection function (shared with TCP)
const char* detect_message_type(const unsigned char* data, int len);

#ifdef __cplusplus
}
#endif

#endif /* UDP_RELAY_H */
