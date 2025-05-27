/*
 * TLS MITM Proxy - Data Processing Utilities Implementation
 */

#include "../include/tls_utils.h"
#include "../include/cert_utils.h"
#include "../include/socks5.h"
#include "../include/utils.h"
#include <ctype.h>  /* For isprint() */

/* External callback functions from main.c */
extern void send_log_entry(const char* src_ip, const char* dst_ip, int dst_port, const char* message_type, const char* data);
extern void send_status_update(const char* message);
extern void send_connection_notification(const char* client_ip, int client_port, const char* target_host, int target_port, int connection_id);
extern void send_disconnect_notification(int connection_id, const char* reason);

/* Global connection ID counter */
static int g_connection_id_counter = 0;

/*
 * Print OpenSSL error messages
 */
static void print_openssl_error(void) {
    unsigned long err;
    while ((err = ERR_get_error())) {
        char *str = ERR_error_string(err, NULL);
        fprintf(stderr, "OpenSSL Error: %s\n", str);
    }
}

/*
 * Pretty print intercepted data in table format
 */
void pretty_print_data(const char *direction, const unsigned char *data, int len,
                     const char *src_ip, const char *dst_ip, int dst_port) {    char message[BUFFER_SIZE] = {0};    // In non-verbose mode, filter protocol handshake messages more intelligently
    if (!config.verbose) {
        // Skip very small messages that are likely TLS protocol overhead
        if (len < 3) {
            return;
        }        // For messages between 3-10 bytes, check if they look like TLS protocol messages
        // TLS protocol messages typically have specific patterns
        if (len <= 10) {
            // Check for common TLS record type markers (should be filtered)
            if (len >= 1 && (data[0] == 0x14 || data[0] == 0x15 || data[0] == 0x16 || data[0] == 0x17)) {
                // This looks like a TLS record header, skip it
                if (config.verbose) {
                    char debug_msg[256];
                    snprintf(debug_msg, sizeof(debug_msg), "[DEBUG] Filtered TLS protocol message (%s): len=%d, type=0x%02x", direction, len, data[0]);
                    send_status_update(debug_msg);
                }
                return;
            }

            // For very short messages, be more permissive with text content
            int printable_chars = 0;
            for (int i = 0; i < len; i++) {
                if (isprint(data[i]) || data[i] == '\r' || data[i] == '\n' || data[i] == '\t') {
                    printable_chars++;
                }
            }

            // If less than 70% of characters are printable, it's likely protocol data
            if (printable_chars < (len * 0.7)) {
                if (config.verbose) {
                    char debug_msg[256];
                    snprintf(debug_msg, sizeof(debug_msg), "[DEBUG] Filtered low-printable message (%s): len=%d, printable=%d/%d", direction, len, printable_chars, len);
                    send_status_update(debug_msg);
                }
                return;
            }
        }
    }

    // Format the message content
    ////// Need to works on this part show better representation of data, support to binary ---> string/ASCII conversion
    if (len > 0) {
        // Check if the data appears to be text
        int is_text = 1;
        for (int i = 0; i < len && i < 100; i++) {
            if (data[i] != 0 && (data[i] < 32 || data[i] > 126)) {
                // ASCII control characters or non-ASCII characters
                // that are not space, newline, tab, etc.
                if (data[i] != '\r' && data[i] != '\n' && data[i] != '\t') {
                    is_text = 0;
                    break;
                }
            }
        }        if (is_text) {
            // Limit text length to avoid buffer overflow
            int copy_len = (len > 1024) ? 1024 : len;
            snprintf(message, sizeof(message), "%.*s%s",
                     copy_len, data, (copy_len < len) ? "...(truncated)" : "");
        } else {
            // For binary data, show a shortened hex representation
            message[0] = '\0'; // Start with empty string
            int hex_len = (len > 32) ? 32 : len;
            char *msg_ptr = message;
            size_t remaining = sizeof(message) - 1;

            for (int i = 0; i < hex_len && remaining > 3; i++) {
                int bytes_written = snprintf(msg_ptr, remaining, "%02x ", data[i]);
                msg_ptr += bytes_written;
                remaining -= bytes_written;
            }

            if (hex_len < len && remaining > 12) {
                snprintf(msg_ptr, remaining, "...(truncated)");
            }
        }    } else {
        strncpy(message, "", sizeof(message) - 1);    }

    // Determine message type for the callback
    const char* message_type;
    if (len == 0) {
        message_type = "Empty";
    } else {
        // Check if the data appears to be text
        int is_text = 1;
        for (int i = 0; i < len && i < 100; i++) {
            if (data[i] != 0 && (data[i] < 32 || data[i] > 126)) {
                // ASCII control characters or non-ASCII characters
                // that are not space, newline, tab, etc.
                if (data[i] != '\r' && data[i] != '\n' && data[i] != '\t') {
                    is_text = 0;
                    break;
                }
            }
        }
        message_type = is_text ? "Text" : "Binary";
    }

    // Send to callback instead of printf
    send_log_entry(src_ip, dst_ip, dst_port, message_type, message);

    // Log to file if configured
    if (config.log_fp) {
        fprintf(config.log_fp, "%-15s | %-15s | %-5d | %s\n",
                src_ip, dst_ip, dst_port, message);
        fflush(config.log_fp);
    }
}

/*
 * Forward data between SSL connections
 */
void forward_data(SSL *src, SSL *dst, const char *direction, const char *src_ip, const char *dst_ip, int dst_port, int connection_id) {
    unsigned char buffer[BUFFER_SIZE];
    int len;
    int fd;
    fd_set readfds;
    struct timeval tv;
    int ret;
    int activity_timeout = 0;

    // Comprehensive parameter validation
    if (!src || !dst || !direction || !src_ip || !dst_ip) {
        send_status_update("Error: Invalid parameters passed to forward_data");
        return;
    }

    // Validate SSL objects are properly initialized
    if (SSL_get_fd(src) == -1 || SSL_get_fd(dst) == -1) {
        send_status_update("Error: SSL objects not properly initialized");
        return;
    }

    // Check SSL state before proceeding
    if (SSL_get_state(src) != TLS_ST_OK || SSL_get_state(dst) != TLS_ST_OK) {
        if (config.verbose) {
            char status_msg[256];
            snprintf(status_msg, sizeof(status_msg), "Warning: SSL connection not in OK state (%s)", direction);
            send_status_update(status_msg);
        }
    }

    // Add exception handling with OpenSSL's error queue
    ERR_clear_error(); // Clear any previous errors

    // Get the socket file descriptor from the SSL with validation
    fd = SSL_get_fd(src);
    if (fd < 0) {
        send_status_update("Error: Failed to get socket fd from SSL");
        print_openssl_error();
        return;
    }

    // Validate the socket is still valid
    int socket_error = 0;
    socklen_t len_opt = sizeof(socket_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&socket_error, &len_opt) != 0 || socket_error != 0) {
        if (config.verbose) {
            char status_msg[256];
            snprintf(status_msg, sizeof(status_msg), "Socket error detected before forwarding (%s): %d", direction, socket_error);
            send_status_update(status_msg);
        }
        return;
    }

    // Log start of data forwarding
    if (config.verbose) {
        char status_msg[256];
        snprintf(status_msg, sizeof(status_msg), "Starting data forwarding: %s -> %s:%d", src_ip, dst_ip, dst_port);
        send_status_update(status_msg);
    }

    while (1) {
        // Set up the select() call with a timeout
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);

        // Set a 1 second timeout to allow for more responsive termination
        tv.tv_sec = 1;
        tv.tv_usec = 0;        ret = select((int)(fd + 1), &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            send_status_update("Error: select() failed in data forwarding");
            break;
        } else if (ret == 0) {
            // Timeout occurred, continue waiting but increment timeout counter
            activity_timeout++;

            // If we've been idle for over 60 seconds in non-verbose mode, exit
            // In verbose mode, we might want to wait longer
            if (!config.verbose && activity_timeout > 60) {
                if (config.verbose) {
                    char status_msg[256];
                    snprintf(status_msg, sizeof(status_msg), "Connection idle timeout (%s)", direction);
                    send_status_update(status_msg);
                }
                break;
            }
            continue;
        }

        // Reset timeout counter when there's activity
        activity_timeout = 0;

        // Additional SSL state validation before read
        if (!SSL_is_init_finished(src)) {
            send_status_update("Error: SSL handshake not completed for source");
            break;
        }

        // Data is available to read - perform SSL_read with additional error handling
        ERR_clear_error(); // Clear error queue before operation
        len = SSL_read(src, buffer, sizeof(buffer));
        if (len <= 0) {
            int error = SSL_get_error(src, len);

            if (error == SSL_ERROR_ZERO_RETURN) {
                // Connection closed cleanly
                if (config.verbose) {
                    char status_msg[256];
                    snprintf(status_msg, sizeof(status_msg), "Connection closed by peer (%s)", direction);
                    send_status_update(status_msg);
                }
            }
            else if (error == SSL_ERROR_SYSCALL) {
                unsigned long ssl_err = ERR_peek_error();
                if (ssl_err == 0) {
                    // System call error without OpenSSL error - usually connection closed
                    if (config.verbose) {
                        char status_msg[256];
                        snprintf(status_msg, sizeof(status_msg), "Connection closed abruptly (%s)", direction);
                        send_status_update(status_msg);
                    }
                } else {
                    // Actual system error
                    char error_msg[256];
                    snprintf(error_msg, sizeof(error_msg), "SSL_read system error in %s: %d", direction, error);
                    send_status_update(error_msg);
                    print_openssl_error();
                }
            }
            else if (error == SSL_ERROR_SSL &&
                    ERR_GET_REASON(ERR_peek_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
                // Common case: unexpected EOF (client closed connection)
                if (config.verbose) {
                    char status_msg[256];
                    snprintf(status_msg, sizeof(status_msg), "Connection closed by peer with unexpected EOF (%s)", direction);
                    send_status_update(status_msg);
                }
                ERR_clear_error(); // Clear the error queue
            }
            else if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                // Non-blocking operation would block - continue loop
                continue;
            }
            else {
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "SSL_read error in %s: %d", direction, error);
                send_status_update(error_msg);
                print_openssl_error();
            }
            break;
        }

        // Print the intercepted data
        pretty_print_data(direction, buffer, len, src_ip, dst_ip, dst_port);

        // Additional SSL state validation before write
        if (!SSL_is_init_finished(dst)) {
            send_status_update("Error: SSL handshake not completed for destination");
            break;
        }

        // Forward to the destination with retry mechanism
        int bytes_written = 0;
        int total_written = 0;

        while (total_written < len) {
            ERR_clear_error(); // Clear error queue before operation
            bytes_written = SSL_write(dst, buffer + total_written, len - total_written);

            if (bytes_written <= 0) {
                int error = SSL_get_error(dst, bytes_written);

                if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
                    // Non-blocking operation would block - wait a bit and retry
                    SLEEP(10);
                    continue;
                }
                else if (error == SSL_ERROR_ZERO_RETURN ||
                        (error == SSL_ERROR_SYSCALL && ERR_peek_error() == 0)) {
                    char status_msg[256];
                    snprintf(status_msg, sizeof(status_msg), "Peer closed connection while writing (%s)", direction);
                    send_status_update(status_msg);
                } else {
                    char error_msg[256];
                    snprintf(error_msg, sizeof(error_msg), "SSL_write error in %s: %d", direction, error);
                    send_status_update(error_msg);
                    print_openssl_error();
                }
                return; // Exit the function on write error
            }

            total_written += bytes_written;
        }
    }
}

/*
 * Forward data between plain TCP sockets (non-TLS)
 */
void forward_tcp_data(socket_t src, socket_t dst, const char *direction, const char *src_ip, const char *dst_ip, int dst_port, int connection_id) {
    unsigned char buffer[BUFFER_SIZE];
    int len;
    fd_set readfds;
    struct timeval tv;
    int ret;
    int activity_timeout = 0;

    // Validate parameters
    if (src == INVALID_SOCKET || dst == INVALID_SOCKET || !direction || !src_ip || !dst_ip) {
        send_status_update("Error: Invalid parameters passed to forward_tcp_data");
        return;
    }

    // Log start of TCP data forwarding
    if (config.verbose) {
        char status_msg[256];
        snprintf(status_msg, sizeof(status_msg), "Starting TCP data forwarding: %s -> %s:%d", src_ip, dst_ip, dst_port);
        send_status_update(status_msg);
    }

    while (1) {
        // Set up the select() call with a timeout
        FD_ZERO(&readfds);
        FD_SET(src, &readfds);

        // Set a 1 second timeout
        tv.tv_sec = 1;
        tv.tv_usec = 0;        ret = select((int)(src + 1), &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            send_status_update("Error: select() failed in TCP data forwarding");
            break;
        } else if (ret == 0) {
            // Timeout occurred
            activity_timeout++;

            // If idle for too long, exit
            if (!config.verbose && activity_timeout > 60) {
                if (config.verbose) {
                    char status_msg[256];
                    snprintf(status_msg, sizeof(status_msg), "TCP connection idle timeout (%s)", direction);
                    send_status_update(status_msg);
                }
                break;
            }
            continue;
        }

        // Reset timeout counter when there's activity
        activity_timeout = 0;

        // Data is available to read
        len = recv(src, (char*)buffer, sizeof(buffer), 0);
        if (len <= 0) {
            if (len == 0) {
                // Connection closed cleanly
                if (config.verbose) {
                    char status_msg[256];
                    snprintf(status_msg, sizeof(status_msg), "TCP connection closed by peer (%s)", direction);
                    send_status_update(status_msg);
                }
            } else {
                // Error
                if (config.verbose) {
                    char status_msg[256];
                    snprintf(status_msg, sizeof(status_msg), "TCP recv error (%s): %d", direction, WSAGetLastError());
                    send_status_update(status_msg);
                }
            }
            break;
        }

        // Print the intercepted data
        pretty_print_data(direction, buffer, len, src_ip, dst_ip, dst_port);

        // Forward to the destination
        int sent = 0;
        while (sent < len) {
            int written = send(dst, (char*)buffer + sent, len - sent, 0);
            if (written <= 0) {
                if (config.verbose) {
                    char status_msg[256];
                    snprintf(status_msg, sizeof(status_msg), "TCP send error (%s): %d", direction, WSAGetLastError());
                    send_status_update(status_msg);
                }
                return;
            }
            sent += written;
        }
    }
}

/*
 * Detect protocol type (TLS, HTTP, or other TCP)
 * Returns PROTOCOL_TLS, PROTOCOL_HTTP, or PROTOCOL_PLAIN_TCP
 */
int detect_protocol(socket_t sock) {
    unsigned char peek_buffer[8] = {0};
    int bytes_peeked;

    // Peek at the first few bytes without removing them from the buffer
    bytes_peeked = recv(sock, (char*)peek_buffer, sizeof(peek_buffer), MSG_PEEK);

    if (bytes_peeked <= 0) {
        // Error or connection closed
        return PROTOCOL_PLAIN_TCP; // Default to plain TCP
    }

    // Check for TLS handshake
    // TLS handshake starts with 0x16 (handshake message) followed by 0x03 (SSL/TLS version)
    if (bytes_peeked >= 3 && peek_buffer[0] == 0x16 &&
        (peek_buffer[1] == 0x03 || peek_buffer[1] == 0x02 || peek_buffer[1] == 0x01)) {
        return PROTOCOL_TLS;
    }

    // Check for HTTP
    if (bytes_peeked >= 4) {
        // Check for common HTTP methods at the start
        if ((peek_buffer[0] == 'G' && peek_buffer[1] == 'E' && peek_buffer[2] == 'T' && peek_buffer[3] == ' ') ||
            (peek_buffer[0] == 'P' && peek_buffer[1] == 'O' && peek_buffer[2] == 'S' && peek_buffer[3] == 'T') ||
            (peek_buffer[0] == 'H' && peek_buffer[1] == 'E' && peek_buffer[2] == 'A' && peek_buffer[3] == 'D') ||
            (peek_buffer[0] == 'P' && peek_buffer[1] == 'U' && peek_buffer[2] == 'T' && peek_buffer[3] == ' ') ||
            (peek_buffer[0] == 'D' && peek_buffer[1] == 'E' && peek_buffer[2] == 'L' && peek_buffer[3] == 'E')) {
            return PROTOCOL_HTTP;
        }

        // Check for HTTP response
        if ((peek_buffer[0] == 'H' && peek_buffer[1] == 'T' && peek_buffer[2] == 'T' && peek_buffer[3] == 'P')) {
            return PROTOCOL_HTTP;
        }
    }

    // Otherwise assume plain TCP
    return PROTOCOL_PLAIN_TCP;
}

/*
 * Thread function for forwarding SSL data
 */
THREAD_RETURN_TYPE forward_data_thread(void *arg) {
    if (arg == NULL) {
        fprintf(stderr, "Error: NULL argument passed to forward_data_thread\n");
        THREAD_RETURN;
    }

    forward_info *info = (forward_info *)arg;

    // Validate all pointers and parameters
    if (info->src && info->dst &&
        info->direction && strlen(info->direction) > 0 &&
        info->src_ip && strlen(info->src_ip) > 0 &&
        info->dst_ip && strlen(info->dst_ip) > 0) {

        forward_data(info->src, info->dst, info->direction, info->src_ip, info->dst_ip, info->dst_port, info->connection_id);
    } else {
        fprintf(stderr, "Error: Invalid parameters in forward_data_thread\n");
    }

    // Free the allocated structure
    free(info);
    THREAD_RETURN;
}

/*
 * Thread function for forwarding TCP data
 */
THREAD_RETURN_TYPE forward_tcp_thread(void *arg) {
    if (arg == NULL) {
        fprintf(stderr, "Error: NULL argument passed to forward_tcp_thread\n");
        THREAD_RETURN;
    }

    forward_tcp_info *info = (forward_tcp_info *)arg;

    // Validate all parameters
    if (info->src != INVALID_SOCKET && info->dst != INVALID_SOCKET &&
        info->direction && strlen(info->direction) > 0 &&
        info->src_ip && strlen(info->src_ip) > 0 &&
        info->dst_ip && strlen(info->dst_ip) > 0) {

        forward_tcp_data(info->src, info->dst, info->direction, info->src_ip, info->dst_ip, info->dst_port, info->connection_id);
    } else {
        fprintf(stderr, "Error: Invalid parameters in forward_tcp_thread\n");
    }

    // Free the allocated structure
    free(info);
    THREAD_RETURN;
}

/*
 /*
 * Forward data between SSL connections (with protocol detection)
 */
void forward_data_with_detection(SSL *src, SSL *dst, const char *src_ip, const char *dst_ip, int dst_port, int connection_id) {
    unsigned char buffer[BUFFER_SIZE];
    int len;
    int fd;
    fd_set readfds;
    struct timeval tv;
    int ret;
    int activity_timeout = 0;

    // Enhanced parameter validation
    if (!src || !dst || !src_ip || !dst_ip) {
        send_status_update("Error: Invalid parameters passed to forward_data_with_detection");
        return;
    }

    // Validate SSL objects are properly initialized
    if (SSL_get_fd(src) == -1 || SSL_get_fd(dst) == -1) {
        send_status_update("Error: SSL objects not properly initialized in detection");
        return;
    }

    // Check SSL state before proceeding
    if (SSL_get_state(src) != TLS_ST_OK || SSL_get_state(dst) != TLS_ST_OK) {
        if (config.verbose) {
            char status_msg[256];
            snprintf(status_msg, sizeof(status_msg), "Warning: SSL connection not in OK state (with detection)");
            send_status_update(status_msg);
        }
    }

    // Get the socket file descriptor from the SSL with validation
    fd = SSL_get_fd(src);
    if (fd < 0) {
        send_status_update("Error: Failed to get socket fd from SSL");
        print_openssl_error();
        return;
    }

    // Validate the socket is still valid
    int socket_error = 0;
    socklen_t len_opt = sizeof(socket_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&socket_error, &len_opt) != 0 || socket_error != 0) {
        if (config.verbose) {
            char status_msg[256];
            snprintf(status_msg, sizeof(status_msg), "Socket error detected in detection: %d", socket_error);
            send_status_update(status_msg);
        }
        return;
    }

    // Log start of data forwarding
    if (config.verbose) {
        char status_msg[256];
        snprintf(status_msg, sizeof(status_msg), "Starting data forwarding with detection: %s -> %s:%d", src_ip, dst_ip, dst_port);
        send_status_update(status_msg);
    }

    while (1) {
        // Set up the select() call with a timeout
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);

        // Set a 1 second timeout to allow for more responsive termination
        tv.tv_sec = 1;
        tv.tv_usec = 0;        ret = select((int)(fd + 1), &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            send_status_update("Error: select() failed in data forwarding with detection");
            break;
        } else if (ret == 0) {
            // Timeout occurred, continue waiting but increment timeout counter
            activity_timeout++;

            // If we've been idle for over 60 seconds in non-verbose mode, exit
            // In verbose mode, we might want to wait longer
            if (!config.verbose && activity_timeout > 60) {
                if (config.verbose) {
                    char status_msg[256];
                    snprintf(status_msg, sizeof(status_msg), "Connection idle timeout (with detection)");
                    send_status_update(status_msg);
                }
                break;
            }
            continue;
        }        // Reset timeout counter when there's activity
        activity_timeout = 0;

        // Additional SSL state validation before read
        if (!SSL_is_init_finished(src)) {
            send_status_update("Error: SSL handshake not completed for source (with detection)");
            break;
        }

        // Data is available to read - perform SSL_read with additional error handling
        ERR_clear_error(); // Clear error queue before operation
        len = SSL_read(src, buffer, sizeof(buffer));
        if (len <= 0) {
            int error = SSL_get_error(src, len);

            if (error == SSL_ERROR_ZERO_RETURN) {
                // Connection closed cleanly
                if (config.verbose) {
                    char status_msg[256];
                    snprintf(status_msg, sizeof(status_msg), "Connection closed by peer (with detection)");
                    send_status_update(status_msg);
                }
            }
            else if (error == SSL_ERROR_SYSCALL) {
                unsigned long ssl_err = ERR_peek_error();
                if (ssl_err == 0) {
                    // System call error without OpenSSL error - usually connection closed
                    if (config.verbose) {
                        char status_msg[256];
                        snprintf(status_msg, sizeof(status_msg), "Connection closed abruptly (with detection)");
                        send_status_update(status_msg);
                    }
                } else {
                    // Actual system error
                    char error_msg[256];
                    snprintf(error_msg, sizeof(error_msg), "SSL_read system error in detection: %d", error);
                    send_status_update(error_msg);
                    print_openssl_error();
                }
            }
            else if (error == SSL_ERROR_SSL &&
                    ERR_GET_REASON(ERR_peek_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
                // Common case: unexpected EOF (client closed connection)
                if (config.verbose) {
                    char status_msg[256];
                    snprintf(status_msg, sizeof(status_msg), "Connection closed by peer with unexpected EOF (with detection)");
                    send_status_update(status_msg);
                }
                ERR_clear_error(); // Clear the error queue
            }
            else if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                // Non-blocking operation would block - continue loop
                continue;
            }
            else {
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "SSL_read error in data forwarding with detection: %d", error);
                send_status_update(error_msg);
                print_openssl_error();
            }
            break;
        }

        // Print the intercepted data
        pretty_print_data("??", buffer, len, src_ip, dst_ip, dst_port);

        // Additional SSL state validation before write
        if (!SSL_is_init_finished(dst)) {
            send_status_update("Error: SSL handshake not completed for destination (with detection)");
            break;
        }        // Detect protocol and handle accordingly
        int protocol = detect_protocol(fd);
        if (protocol == PROTOCOL_TLS) {
            // Forward as TLS with retry mechanism
            int bytes_written = 0;
            int total_written = 0;

            while (total_written < len) {
                ERR_clear_error(); // Clear error queue before operation
                bytes_written = SSL_write(dst, buffer + total_written, len - total_written);

                if (bytes_written <= 0) {
                    int error = SSL_get_error(dst, bytes_written);

                    if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
                        // Non-blocking operation would block - wait a bit and retry
                        SLEEP(10);
                        continue;
                    }
                    else if (error == SSL_ERROR_ZERO_RETURN ||
                            (error == SSL_ERROR_SYSCALL && ERR_peek_error() == 0)) {
                        char status_msg[256];
                        snprintf(status_msg, sizeof(status_msg), "Peer closed connection while writing (with detection)");
                        send_status_update(status_msg);                    } else {
                        char error_msg[256];
                        snprintf(error_msg, sizeof(error_msg), "SSL_write error in data forwarding with detection");
                        send_status_update(error_msg);
                        print_openssl_error();
                    }
                    break; // Exit the while loop on write error
                }

                total_written += bytes_written;
            }
        } else if (protocol == PROTOCOL_HTTP) {
            // For HTTP, we might want to handle differently in the future
            // For now, just forward as TCP
            forward_tcp_data(fd, SSL_get_fd(dst), "??", src_ip, dst_ip, dst_port, connection_id);
        } else {
            // Plain TCP, forward directly
            forward_tcp_data(fd, SSL_get_fd(dst), "??", src_ip, dst_ip, dst_port, connection_id);
        }
    }
}

/*
 * Thread function for forwarding data with protocol detection
 */
THREAD_RETURN_TYPE forward_data_with_detection_thread(void *arg) {
    if (arg == NULL) {
        fprintf(stderr, "Error: NULL argument passed to forward_data_with_detection_thread\n");
        THREAD_RETURN;
    }

    forward_info *info = (forward_info *)arg;

    // Validate all pointers and parameters before using them
    if (info->src && info->dst &&
        info->direction && strlen(info->direction) > 0 &&
        info->src_ip && strlen(info->src_ip) > 0 &&
        info->dst_ip && strlen(info->dst_ip) > 0) {

        forward_data_with_detection(info->src, info->dst, info->src_ip, info->dst_ip, info->dst_port, info->connection_id);
    } else {
        fprintf(stderr, "Error: Invalid parameters in forward_data_with_detection_thread\n");
    }

    // Free the allocated structure
    free(info);
    THREAD_RETURN;
}

/*
 * Handle a client connection
 */
THREAD_RETURN_TYPE handle_client(void *arg) {
    if (!arg) {
        fprintf(stderr, "Error: NULL argument passed to handle_client\n");
        THREAD_RETURN;
    }

    client_info *client = (client_info*)arg;
    socket_t client_sock = client->client_sock;
    socket_t server_sock = INVALID_SOCKET;
    SSL_CTX *server_ctx = NULL;
    SSL_CTX *client_ctx = NULL;
    SSL *server_ssl = NULL;
    SSL *client_ssl = NULL;
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    THREAD_HANDLE thread_id;
    char target_host[MAX_HOSTNAME_LEN];
    char client_ip[MAX_IP_ADDR_LEN];
    char server_ip[MAX_IP_ADDR_LEN];
    int target_port;
    int ret;
    int connection_id;
    int protocol_type;

    // Generate unique connection ID
    connection_id = ++g_connection_id_counter;

    // Get client IP address as string
    inet_ntop(AF_INET, &(client->client_addr.sin_addr), client_ip, MAX_IP_ADDR_LEN);

    // Set socket options for better compatibility
    DWORD timeout = 120000;  // 120 seconds timeout
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    // TCP keepalive to detect dead connections
    DWORD keepAlive = 1;
    setsockopt(client_sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepAlive, sizeof(keepAlive));

    // Handle the SOCKS5 handshake
    memset(target_host, 0, sizeof(target_host));
    if (!handle_socks5_handshake(client_sock, target_host, &target_port)) {
        if (config.verbose) {
            fprintf(stderr, "Failed to handle SOCKS5 handshake\n");
        }
        send_disconnect_notification(connection_id, "SOCKS5 handshake failed");
        goto cleanup;
    }

    // Notify about new connection
    send_connection_notification(client_ip, ntohs(client->client_addr.sin_port), target_host, target_port, connection_id);

    if (config.verbose) {
        printf("\nIntercepting connection to %s:%d\n", target_host, target_port);
    }

    // Connect to the real server before deciding protocol type
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        fprintf(stderr, "Failed to create socket for server connection: %d\n", WSAGetLastError());
        goto cleanup;
    }

    // Set server socket options
    DWORD server_timeout = 60000;  // 60 seconds timeout
    if (setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&server_timeout, sizeof(server_timeout)) != 0 ||
        setsockopt(server_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&server_timeout, sizeof(server_timeout)) != 0) {
        if (config.verbose) {
            fprintf(stderr, "Warning: Failed to set server socket timeout: %d\n", WSAGetLastError());
        }
    }

    // Resolve hostname
    struct hostent *host = gethostbyname(target_host);
    if (!host) {
        fprintf(stderr, "Failed to resolve hostname %s: %d\n", target_host, WSAGetLastError());
        goto cleanup;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, host->h_addr, host->h_length);
    server_addr.sin_port = htons(target_port);

    // Get server IP as string
    inet_ntop(AF_INET, &(server_addr.sin_addr), server_ip, MAX_IP_ADDR_LEN);

    if (config.verbose) {
        printf("Connecting to real server at %s:%d...\n", target_host, target_port);
    }

    // Log connection attempt
    log_message("Connecting to server %s (%s):%d", target_host, server_ip, target_port);

    ret = connect(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (ret == SOCKET_ERROR) {
        int error = WSAGetLastError();
        fprintf(stderr, "Failed to connect to server %s:%d: %d\n",
                target_host, target_port, error);
        log_message("Connection to %s:%d failed with error %d", target_host, target_port, error);
        goto cleanup;
    }    // Set TCP_NODELAY for better performance
    int nodelay = 1;
    setsockopt(server_sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));    // Detect protocol type (TLS, HTTP, or plain TCP)
    protocol_type = detect_protocol(client_sock);

    if (protocol_type == PROTOCOL_TLS) {
        // TLS handling path
        if (config.verbose) {
            printf("Detected TLS protocol, proceeding with TLS interception\n");
        }
        send_status_update("Proceeding with TLS interception");

        // Generate certificate for the target host
        if (!generate_cert_for_host(target_host, &cert, &key)) {
            fprintf(stderr, "Failed to generate certificate for %s\n", target_host);
            goto cleanup;
        }

        // Create server context (for client -> proxy)
        server_ctx = create_server_ssl_context();
        if (!server_ctx) {
            fprintf(stderr, "Failed to create server SSL context\n");
            goto cleanup;
        }

        // Use the generated certificate and key
        if (SSL_CTX_use_certificate(server_ctx, cert) != 1 ||
            SSL_CTX_use_PrivateKey(server_ctx, key) != 1 ||
            SSL_CTX_check_private_key(server_ctx) != 1) {
            fprintf(stderr, "Failed to set up SSL certificate\n");
            print_openssl_error();
            goto cleanup;
        }

        // Create server SSL object and attach to client socket
        if (config.verbose) {
            printf("Performing TLS handshake with client...\n");
        }

        // Additional validation before creating SSL object
        if (!server_ctx) {
            fprintf(stderr, "Error: server_ctx is NULL when creating SSL object\n");
            goto cleanup;
        }

        server_ssl = SSL_new(server_ctx);
        if (!server_ssl) {
            fprintf(stderr, "Failed to create server SSL object\n");
            print_openssl_error();
            goto cleanup;
        }

        // Validate socket before setting fd
        if (client_sock == INVALID_SOCKET) {
            fprintf(stderr, "Error: Invalid client socket for SSL\n");
            SSL_free(server_ssl);
            server_ssl = NULL;
            goto cleanup;
        }

        // Set socket with error checking
        if (SSL_set_fd(server_ssl, (int)client_sock) != 1) {
            fprintf(stderr, "Failed to set client socket fd for SSL\n");
            print_openssl_error();
            SSL_free(server_ssl);
            server_ssl = NULL;
            goto cleanup;
        }

        // Clear OpenSSL error queue before handshake
        ERR_clear_error();

        ret = SSL_accept(server_ssl);

        if (ret != 1) {
            int ssl_error = SSL_get_error(server_ssl, ret);
            unsigned long error_reason = ERR_peek_error();

            fprintf(stderr, "Failed to perform TLS handshake with client: %d (reason: 0x%lx)\n",
                    ssl_error, ERR_GET_REASON(error_reason));
            print_openssl_error();

            // Log more friendly message for common certificate errors
            if (ERR_GET_REASON(error_reason) == SSL_R_TLSV1_ALERT_BAD_CERTIFICATE ||
                ERR_GET_REASON(error_reason) == SSL_R_CERTIFICATE_VERIFY_FAILED ||
                error_reason == SSL_R_TLSV1_ALERT_BAD_CERTIFICATE ||
                error_reason == SSL_R_CERTIFICATE_VERIFY_FAILED) {
                send_status_update("TLS handshake failed: Client rejected our certificate");
                log_message("Certificate was rejected by client. Consider importing myCA.pem into client's trust store");
            } else {
                char error_str[256] = {0};
                ERR_error_string_n(error_reason, error_str, sizeof(error_str));
                log_message("TLS handshake failed with error: %s", error_str);
                send_status_update("TLS handshake failed - falling back to direct forwarding");
            }

            // Properly clean up TLS resources since we're falling back to TCP
            if (server_ssl) {
                SSL_shutdown(server_ssl);  // Properly shutdown SSL connection
                SSL_free(server_ssl);
                server_ssl = NULL;
            }
            if (server_ctx) {
                SSL_CTX_free(server_ctx);
                server_ctx = NULL;
            }

            // Instead of failing, let's fall back to direct TCP forwarding for this connection
            protocol_type = PROTOCOL_PLAIN_TCP;

            // Clean up the remaining TLS resources we won't need
            if (cert) {
                X509_free(cert);
                cert = NULL;
            }
            if (key) {
                EVP_PKEY_free(key);
                key = NULL;
            }

            // Continue with non-TLS handling
        }

    // Create client context (for proxy -> server) - only if still doing TLS
    if (protocol_type == PROTOCOL_TLS) {
        client_ctx = create_client_ssl_context();
        if (!client_ctx) {
            fprintf(stderr, "Failed to create client SSL context\n");
            goto cleanup;
        }

        // Create client SSL object and attach to server socket
        if (config.verbose) {
            printf("Performing TLS handshake with server...\n");
        }

        // Additional validation before creating client SSL object
        if (!client_ctx) {
            fprintf(stderr, "Error: client_ctx is NULL when creating SSL object\n");
            goto cleanup;
        }

        client_ssl = SSL_new(client_ctx);
        if (!client_ssl) {
            fprintf(stderr, "Failed to create client SSL object\n");
            print_openssl_error();
            goto cleanup;
        }

        // Validate server socket before setting fd
        if (server_sock == INVALID_SOCKET) {
            fprintf(stderr, "Error: Invalid server socket for SSL\n");
            SSL_free(client_ssl);
            client_ssl = NULL;
            goto cleanup;
        }

        // Set socket with error checking
        if (SSL_set_fd(client_ssl, (int)server_sock) != 1) {
            fprintf(stderr, "Failed to set server socket fd for SSL\n");
            print_openssl_error();
            SSL_free(client_ssl);
            client_ssl = NULL;
            goto cleanup;
        }

        // Set Server Name Indication (SNI) with validation
        if (target_host && strlen(target_host) > 0) {
            if (SSL_set_tlsext_host_name(client_ssl, target_host) != 1) {
                if (config.verbose) {
                    fprintf(stderr, "Warning: Failed to set SNI hostname\n");
                    print_openssl_error();
                }
            }
        }

        // Clear OpenSSL error queue before handshake
        ERR_clear_error();

        ret = SSL_connect(client_ssl);
        if (ret != 1) {
            int ssl_error = SSL_get_error(client_ssl, ret);
            fprintf(stderr, "Failed to perform TLS handshake with server: %d\n", ssl_error);
            print_openssl_error();

            // Fall back to TCP if server handshake fails
            send_status_update("Server TLS handshake failed - falling back to TCP");
            protocol_type = PROTOCOL_PLAIN_TCP;

            // Clean up client SSL resources
            if (client_ssl) {
                SSL_shutdown(client_ssl);
                SSL_free(client_ssl);
                client_ssl = NULL;
            }
            if (client_ctx) {
                SSL_CTX_free(client_ctx);
                client_ctx = NULL;
            }
        }
    }
    if (config.verbose) {
        printf("TLS MITM established! Intercepting traffic between client and %s:%d\n",
               target_host, target_port);
    }
    // Create a thread to forward data from client to server
    forward_info *client_to_server = (forward_info*)malloc(sizeof(forward_info));
    if (!client_to_server) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }    client_to_server->src = server_ssl;
    client_to_server->dst = client_ssl;
    strncpy(client_to_server->direction, "client->server", sizeof(client_to_server->direction)-1);
    client_to_server->direction[sizeof(client_to_server->direction)-1] = '\0';
    strncpy(client_to_server->src_ip, client_ip, MAX_IP_ADDR_LEN-1);
    strncpy(client_to_server->dst_ip, server_ip, MAX_IP_ADDR_LEN-1);
    client_to_server->dst_port = target_port;
    client_to_server->connection_id = connection_id;

    // Log connection info
    log_message("Established connection: %s -> %s:%d", client_ip, server_ip, target_port);    // Create a second thread for server->client direction
    forward_info *server_to_client = (forward_info*)malloc(sizeof(forward_info));
    if (!server_to_client) {
        fprintf(stderr, "Memory allocation failed\n");
        free(client_to_server); // Don't leak memory
        goto cleanup;
    }    server_to_client->src = client_ssl;
    server_to_client->dst = server_ssl;
    strncpy(server_to_client->direction, "server->client", sizeof(server_to_client->direction)-1);
    server_to_client->direction[sizeof(server_to_client->direction)-1] = '\0';
    strncpy(server_to_client->src_ip, server_ip, MAX_IP_ADDR_LEN-1);
    strncpy(server_to_client->dst_ip, client_ip, MAX_IP_ADDR_LEN-1);
    server_to_client->dst_port = ntohs(client->client_addr.sin_port);
    server_to_client->connection_id = connection_id;

    // Make sure strings are null-terminated
    client_to_server->src_ip[MAX_IP_ADDR_LEN-1] = '\0';
    client_to_server->dst_ip[MAX_IP_ADDR_LEN-1] = '\0';
    server_to_client->src_ip[MAX_IP_ADDR_LEN-1] = '\0';
    server_to_client->dst_ip[MAX_IP_ADDR_LEN-1] = '\0';

    // Start both forwarding threads
    THREAD_HANDLE thread_id2;
    CREATE_THREAD(thread_id, forward_data_thread, client_to_server);
    CREATE_THREAD(thread_id2, forward_data_thread, server_to_client);

    // Wait for both threads to finish    if (thread_id != NULL) JOIN_THREAD(thread_id);
    if (thread_id2 != NULL) JOIN_THREAD(thread_id2);    if (config.verbose) {
        printf("Connection to %s:%d closed\n", target_host, target_port);
    }
    }
    else if (protocol_type == PROTOCOL_HTTP || protocol_type == PROTOCOL_PLAIN_TCP) {
        // Non-TLS handling path (HTTP or plain TCP)
        if (protocol_type == PROTOCOL_HTTP) {
            if (config.verbose) {
                printf("Detected HTTP protocol, forwarding as plain TCP\n");
            }
            send_status_update("Forwarding HTTP traffic");
        } else {
            if (config.verbose) {
                printf("Detected plain TCP protocol\n");
            }
            send_status_update("Forwarding plain TCP traffic");
        }

        if (config.verbose) {
            printf("Setting up direct TCP forwarding between client and %s:%d\n", target_host, target_port);
        }

        // Create TCP forwarding info structs
        forward_tcp_info *client_to_server = (forward_tcp_info*)malloc(sizeof(forward_tcp_info));
        if (!client_to_server) {
            fprintf(stderr, "Memory allocation failed\n");
            goto cleanup;
        }

        client_to_server->src = client_sock;
        client_to_server->dst = server_sock;
        strncpy(client_to_server->direction, "client->server", sizeof(client_to_server->direction)-1);
        client_to_server->direction[sizeof(client_to_server->direction)-1] = '\0';
        strncpy(client_to_server->src_ip, client_ip, MAX_IP_ADDR_LEN-1);
        strncpy(client_to_server->dst_ip, server_ip, MAX_IP_ADDR_LEN-1);
        client_to_server->dst_port = target_port;
        client_to_server->connection_id = connection_id;

        // Create a second TCP info struct for server->client direction
        forward_tcp_info *server_to_client = (forward_tcp_info*)malloc(sizeof(forward_tcp_info));
        if (!server_to_client) {
            fprintf(stderr, "Memory allocation failed\n");
            free(client_to_server); // Don't leak memory
            goto cleanup;
        }

        server_to_client->src = server_sock;
        server_to_client->dst = client_sock;
        strncpy(server_to_client->direction, "server->client", sizeof(server_to_client->direction)-1);
        server_to_client->direction[sizeof(server_to_client->direction)-1] = '\0';
        strncpy(server_to_client->src_ip, server_ip, MAX_IP_ADDR_LEN-1);
        strncpy(server_to_client->dst_ip, client_ip, MAX_IP_ADDR_LEN-1);
        server_to_client->dst_port = ntohs(client->client_addr.sin_port);
        server_to_client->connection_id = connection_id;

        // Make sure strings are null-terminated
        client_to_server->src_ip[MAX_IP_ADDR_LEN-1] = '\0';
        client_to_server->dst_ip[MAX_IP_ADDR_LEN-1] = '\0';
        server_to_client->src_ip[MAX_IP_ADDR_LEN-1] = '\0';
        server_to_client->dst_ip[MAX_IP_ADDR_LEN-1] = '\0';

        // Log connection info
        log_message("Established direct TCP connection: %s -> %s:%d", client_ip, server_ip, target_port);

        // Start TCP forwarding threads
        THREAD_HANDLE thread_id2;
        CREATE_THREAD(thread_id, forward_tcp_thread, client_to_server);
        CREATE_THREAD(thread_id2, forward_tcp_thread, server_to_client);

        // Wait for both threads to finish
        if (thread_id != NULL) JOIN_THREAD(thread_id);
        if (thread_id2 != NULL) JOIN_THREAD(thread_id2);

        if (config.verbose) {
            printf("TCP connection to %s:%d closed\n", target_host, target_port);
        }
    }

cleanup:
    // Send disconnect notification
    send_disconnect_notification(connection_id, "Connection closed");

    // Log connection closure
    if (target_host[0] != '\0') {
        log_message("Closing connection to %s:%d", target_host, target_port);
    } else {
        log_message("Closing SOCKS5 connection (target unknown)");
    }

    // Clear any OpenSSL errors before cleanup
    ERR_clear_error();

    // Enhanced SSL cleanup with additional validation and error handling
    if (server_ssl) {
        // Check if SSL object is valid before shutdown
        if (SSL_get_fd(server_ssl) != -1) {
            // Attempt graceful shutdown, but don't block if it fails
            int shutdown_result = SSL_shutdown(server_ssl);
            if (shutdown_result == 0) {
                // First shutdown call completed, call again for bidirectional shutdown
                SSL_shutdown(server_ssl);
            } else if (shutdown_result < 0) {
                // Shutdown failed, but continue with cleanup
                int ssl_error = SSL_get_error(server_ssl, shutdown_result);
                if (config.verbose && ssl_error != SSL_ERROR_SYSCALL) {
                    fprintf(stderr, "Warning: SSL_shutdown failed for server SSL: %d\n", ssl_error);
                }
            }
        }

        SSL_free(server_ssl);
        server_ssl = NULL;
    }

    if (client_ssl) {
        // Check if SSL object is valid before shutdown
        if (SSL_get_fd(client_ssl) != -1) {
            // Attempt graceful shutdown, but don't block if it fails
            int shutdown_result = SSL_shutdown(client_ssl);
            if (shutdown_result == 0) {
                // First shutdown call completed, call again for bidirectional shutdown
                SSL_shutdown(client_ssl);
            } else if (shutdown_result < 0) {
                // Shutdown failed, but continue with cleanup
                int ssl_error = SSL_get_error(client_ssl, shutdown_result);
                if (config.verbose && ssl_error != SSL_ERROR_SYSCALL) {
                    fprintf(stderr, "Warning: SSL_shutdown failed for client SSL: %d\n", ssl_error);
                }
            }
        }

        SSL_free(client_ssl);
        client_ssl = NULL;
    }

    // Free SSL contexts with validation
    if (server_ctx) {
        SSL_CTX_free(server_ctx);
        server_ctx = NULL;
    }

    if (client_ctx) {
        SSL_CTX_free(client_ctx);
        client_ctx = NULL;
    }

    // Free X509 and key with validation
    if (cert) {
        X509_free(cert);
        cert = NULL;
    }

    if (key) {
        EVP_PKEY_free(key);
        key = NULL;
    }

    // Close sockets safely
    if (server_sock != INVALID_SOCKET) {
        close_socket(server_sock);
        server_sock = INVALID_SOCKET;
    }

    if (client_sock != INVALID_SOCKET) {
        close_socket(client_sock);
        client_sock = INVALID_SOCKET;
    }

    // Free client info struct - only free once and null the pointer
    if (client) {
        free(client);
        client = NULL;
    }

    THREAD_RETURN;
}
