/*
 * Protocol Detection Utilities Implementation
 *
 * Functions for detecting different protocols from network traffic.
 * Enhanced with ALPN and HTTP/2 support.
 */

#include "protocol_detector.h"
#include "../tls/proxy/tls_proxy.h"
#include "../utils/utils.h"
#include <time.h>

/* External variables from utils.c */
extern proxy_config config;

/* External callback functions from main.c */
extern void send_log_entry(const char *src_ip, const char *dst_ip, int dst_port,
                          const char *direction, const unsigned char *data, int data_length,
                          const char *msg_type, int connection_id, int packet_id);

/* External packet ID counter */
extern int g_packet_id_counter;

/*
 * Detect protocol based on first bytes of data
 * Uses universal detection approach that works with any protocol
 *
 * Returns:
 *   PROTOCOL_TLS - If connection starts with TLS handshake
 *   PROTOCOL_PLAIN_TCP - For all other protocols (including HTTP, PostgreSQL, SMTP, etc)
 *
 * Note: This function no longer identifies HTTP separately.
 *
 */
int detect_protocol(socket_t sock) {
    unsigned char peek_buffer[8] = {0};
    int bytes_peeked;
    
    // Set a short timeout for protocol detection to avoid blocking
    fd_set readfds;
    struct timeval timeout;
    
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    timeout.tv_sec = 2;  // 2 second timeout
    timeout.tv_usec = 0;
    
    // Check if data is available for reading
    int ready = select((int)(sock + 1), &readfds, NULL, NULL, &timeout);
    if (ready <= 0) {
        // No data available within timeout period - default to plain TCP
        return PROTOCOL_PLAIN_TCP;
    }

    // Peek at the first few bytes without removing them from the buffer
    bytes_peeked = recv(sock, (char *)peek_buffer, sizeof(peek_buffer), MSG_PEEK);

    if (bytes_peeked <= 0) {
        // Error or connection closed - default to plain TCP
        return PROTOCOL_PLAIN_TCP;
    }

    // Check for TLS handshake
    // TLS handshake starts with 0x16 (handshake message) followed by 0x03 (SSL/TLS version)
    if (bytes_peeked >= 3 && peek_buffer[0] == 0x16 &&
        (peek_buffer[1] == 0x03 || peek_buffer[1] == 0x02 || peek_buffer[1] == 0x01)) {
        return PROTOCOL_TLS;
    }

    // For all other protocols (including HTTP, PostgreSQL, SMTP, etc.)
    // Return PROTOCOL_PLAIN_TCP and handle potential TLS upgrades later
    return PROTOCOL_PLAIN_TCP;
}

/*
 * Get the negotiated protocol from an SSL connection
 */
const char* get_negotiated_protocol(SSL *ssl) {
    if (!ssl) {
        return "unknown";
    }

    const unsigned char *proto;
    unsigned int proto_len;
    SSL_get0_alpn_selected(ssl, &proto, &proto_len);

    if (proto && proto_len > 0) {
        if (proto_len == 2 && memcmp(proto, "h2", 2) == 0) {
            return "HTTP/2";
        } else if (proto_len == 8 && memcmp(proto, "http/1.1", 8) == 0) {
            return "HTTP/1.1";
        } else {
            // Return a limited-length protocol name for safety
            static char proto_buffer[32];
            int copy_len = proto_len < sizeof(proto_buffer) - 1 ? proto_len : sizeof(proto_buffer) - 1;
            memcpy(proto_buffer, proto, copy_len);
            proto_buffer[copy_len] = '\0';
            return proto_buffer;
        }
    }

    return "TLS";
}

/*
 * Get human-readable name for HTTP/2 frame type
 */
const char* get_http2_frame_type_name(uint8_t frame_type) {
    switch (frame_type) {
        case HTTP2_FRAME_DATA: return "DATA";
        case HTTP2_FRAME_HEADERS: return "HEADERS";
        case HTTP2_FRAME_PRIORITY: return "PRIORITY";
        case HTTP2_FRAME_RST_STREAM: return "RST_STREAM";
        case HTTP2_FRAME_SETTINGS: return "SETTINGS";
        case HTTP2_FRAME_PUSH_PROMISE: return "PUSH_PROMISE";
        case HTTP2_FRAME_PING: return "PING";
        case HTTP2_FRAME_GOAWAY: return "GOAWAY";
        case HTTP2_FRAME_WINDOW_UPDATE: return "WINDOW_UPDATE";
        case HTTP2_FRAME_CONTINUATION: return "CONTINUATION";
        default: return "UNKNOWN";
    }
}

/*
 * Process HTTP/2 frame data for display in GUI
 */
void process_http2_frame(const char *data, int length, const char *direction,
                        const char *src_ip, const char *dst_ip, int dst_port,
                        int connection_id, int packet_id) {
    if (length < 9) {
        if (config.verbose) {
            log_message("%s: HTTP/2 frame too short (%d bytes)", direction, length);
        }
        return;
    }

    // Parse HTTP/2 frame header (9 bytes)
    uint32_t frame_length = (data[0] << 16) | (data[1] << 8) | data[2];
    uint8_t frame_type = data[3];
    uint8_t flags = data[4];
    uint32_t stream_id = ((data[5] & 0x7F) << 24) | (data[6] << 16) | (data[7] << 8) | data[8];

    const char *frame_type_name = get_http2_frame_type_name(frame_type);

    // Send to GUI for protocol-aware display
    send_log_entry(src_ip, dst_ip, dst_port, direction,
                  (unsigned char*)data, length, frame_type_name, connection_id, packet_id);
}

/*
 * Process HTTP/1.1 data for display in GUI
 */
void process_http11_data(const char *data, int length, const char *direction,
                        const char *src_ip, const char *dst_ip, int dst_port,
                        int connection_id, int packet_id) {
    // Basic HTTP/1.1 processing
    char first_line[256] = {0};
    const char *line_end = strstr(data, "\r\n");

    const char *msg_type = "HTTP";

    if (line_end && (line_end - data) < sizeof(first_line) - 1) {
        memcpy(first_line, data, line_end - data);

        // Determine more specific message type based on first line
        if (strncmp(first_line, "GET ", 4) == 0 || strncmp(first_line, "POST ", 5) == 0 ||
            strncmp(first_line, "PUT ", 4) == 0 || strncmp(first_line, "DELETE ", 7) == 0) {
            msg_type = "HTTP Request";
        } else if (strncmp(first_line, "HTTP/", 5) == 0) {
            msg_type = "HTTP Response";
        }
    } else {
        msg_type = "HTTP Data";
    }

    // Send to GUI
    send_log_entry(src_ip, dst_ip, dst_port, direction,
                  (unsigned char*)data, length, msg_type, connection_id, packet_id);
}
