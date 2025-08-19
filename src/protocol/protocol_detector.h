/*
 * Protocol Detection Utilities
 *
 * Functions for detecting different protocols from network traffic.
 * Enhanced with ALPN and HTTP/2 support.
 */

#ifndef PROTOCOL_DETECTOR_H
#define PROTOCOL_DETECTOR_H

#include "../platform/platform.h"
#include <openssl/ssl.h>

/* Protocol type definitions */
#define PROTOCOL_TLS 1
#define PROTOCOL_HTTP 2
#define PROTOCOL_PLAIN_TCP 3
#define PROTOCOL_HTTP2 4

/* HTTP/2 frame types */
#define HTTP2_FRAME_DATA          0x0
#define HTTP2_FRAME_HEADERS       0x1
#define HTTP2_FRAME_PRIORITY      0x2
#define HTTP2_FRAME_RST_STREAM    0x3
#define HTTP2_FRAME_SETTINGS      0x4
#define HTTP2_FRAME_PUSH_PROMISE  0x5
#define HTTP2_FRAME_PING          0x6
#define HTTP2_FRAME_GOAWAY        0x7
#define HTTP2_FRAME_WINDOW_UPDATE 0x8
#define HTTP2_FRAME_CONTINUATION  0x9

/* Function prototypes */
int detect_protocol(socket_t sock);
const char* get_negotiated_protocol(SSL *ssl);
const char* get_http2_frame_type_name(uint8_t frame_type);
void process_http2_frame(const char *data, int length, const char *direction, 
                        const char *src_ip, const char *dst_ip, int dst_port, 
                        int connection_id, int packet_id);
void process_http11_data(const char *data, int length, const char *direction,
                        const char *src_ip, const char *dst_ip, int dst_port,
                        int connection_id, int packet_id);

#endif /* PROTOCOL_DETECTOR_H */
