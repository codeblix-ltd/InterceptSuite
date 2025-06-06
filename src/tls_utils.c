/*
 * TLS MITM Proxy - Data Processing Utilities Implementation
 */

#define _CRT_SECURE_NO_WARNINGS // Suppress strncpy warnings

#include <openssl/ssl.h> // Ensure OpenSSL function prototypes are available
#include <openssl/err.h> // For OpenSSL error handling functions

#include "../include/tls_utils.h"
#include "../include/cert_utils.h"
#include "../include/socks5.h"
#include "../include/utils.h"
#include "../include/tls_proxy_dll.h"
#include <ctype.h>  /* For isprint() */
#include <stdbool.h> // For bool type if not already included
#include <errno.h> // For errno

/* External callback functions from main.c */
extern void send_log_entry(const char* src_ip, const char* dst_ip, int dst_port, const char* message_type, const char* data, int connection_id, int packet_id);
extern void send_status_update(const char* message);
extern void send_connection_notification(const char* client_ip, int client_port, const char* target_host, int target_port, int connection_id);
extern void send_disconnect_notification(int connection_id, const char* reason);

/* External interception data arrays from main.c */
extern intercept_data_t* g_active_intercepts[100];
extern int g_intercept_count;

/* Global connection ID counter */
static int g_connection_id_counter = 0;

/* Each packet will have unique id*/
static int g_packet_id_counter = 0;

/*
 * Pretty print intercepted data in table format
 */
void pretty_print_data(const char *direction, const unsigned char *data, int len,
                     const char *src_ip, const char *dst_ip, int dst_port, int connection_id, int packet_id) {

    char message[BUFFER_SIZE] = {0};    // In non-verbose mode, filter protocol handshake messages more intelligently
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
    }    // Format the message content
    // Show full data content without redundant type prefixes
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
        }

        if (is_text) {
            // For text data, use most of the buffer but leave room for truncation warning
            // BUFFER_SIZE is 16384, but message array is sized to BUFFER_SIZE
            // Leave ~100 bytes for the truncation warning and null terminator
            int max_safe_len = sizeof(message) - 100;
            int copy_len = (len > max_safe_len) ? max_safe_len : len;

            snprintf(message, sizeof(message), "%.*s%s",
                    copy_len, data, (copy_len < len) ? "...(truncated)" : "");
        } else {
            // For binary data, show a more comprehensive hex representation
            message[0] = '\0'; // Start with empty string
            char *msg_ptr = message;
            size_t remaining = sizeof(message) - 1;            // Calculate how many bytes we can safely display
            // Each byte takes ~3 chars (2 hex digits + space)
            // Leave ~30 bytes for the truncation warning
            int max_bytes = (int)((remaining - 30) / 3);
            int hex_len = (len > max_bytes) ? max_bytes : len;

            // Format with line breaks every 16 bytes for better readability
            for (int i = 0; i < hex_len && remaining > 3; i++) {
                int bytes_written;

                // Add a line break every 16 bytes
                if (i > 0 && i % 16 == 0) {
                    bytes_written = snprintf(msg_ptr, remaining, "\n");
                    msg_ptr += bytes_written;
                    remaining -= bytes_written;
                }

                bytes_written = snprintf(msg_ptr, remaining, "%02x ", data[i]);
                msg_ptr += bytes_written;
                remaining -= bytes_written;
            }

            if (hex_len < len && remaining > 15) {
                snprintf(msg_ptr, remaining, "\n...(truncated)");
            }
        }
    } else {
        strncpy(message, "", sizeof(message) - 1);
    }

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
    send_log_entry(src_ip, dst_ip, dst_port, message_type, message, connection_id, packet_id);

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
    int packet_id = ++g_packet_id_counter;

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
        tv.tv_usec = 0;
        ret = select((int)(fd + 1), &readfds, NULL, NULL, &tv);
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
        }        // Print the intercepted data
        pretty_print_data(direction, buffer, len, src_ip, dst_ip, dst_port, connection_id, packet_id);

        // Check if we should intercept this data
        if (should_intercept_data(direction, connection_id)) {
            // Create intercept data structure
            intercept_data_t intercept_data = {0};
            intercept_data.connection_id = connection_id;
            strncpy(intercept_data.direction, direction, sizeof(intercept_data.direction) - 1);
            strncpy(intercept_data.src_ip, src_ip, sizeof(intercept_data.src_ip) - 1);
            strncpy(intercept_data.dst_ip, dst_ip, sizeof(intercept_data.dst_ip) - 1);
            intercept_data.dst_port = dst_port;
            intercept_data.data_length = len;
            intercept_data.is_waiting_for_response = 1;
            intercept_data.action = INTERCEPT_ACTION_FORWARD;
            intercept_data.modified_data = NULL;
            intercept_data.modified_length = 0;

            // Create response event
            intercept_data.response_event = CREATE_EVENT();
            #ifdef INTERCEPT_WINDOWS
            if (!intercept_data.response_event) {
#else
            // POSIX: Assume event creation succeeded
            if (0) {
#endif
                send_status_update("Error: Failed to create intercept response event");
                break;
            }

            // Copy data to intercept structure
            intercept_data.data = malloc(len);
            if (!intercept_data.data) {
                CLOSE_EVENT(intercept_data.response_event);
                send_status_update("Error: Failed to allocate memory for intercept data");
                break;
            }
            memcpy(intercept_data.data, buffer, len);

            // Store in global array for response handling
            LOCK_MUTEX(g_intercept_config.intercept_cs);
            if (g_intercept_count < 100) {
                g_active_intercepts[g_intercept_count] = &intercept_data;
                g_intercept_count++;
            }
            UNLOCK_MUTEX(g_intercept_config.intercept_cs);

            // Send data to GUI for interception
            send_intercept_data(connection_id, direction, src_ip, dst_ip, dst_port, buffer, len, packet_id);

            // Wait for user response
            if (!wait_for_intercept_response(&intercept_data)) {
                // Cleanup on error
                free(intercept_data.data);
                if (intercept_data.modified_data) free(intercept_data.modified_data);
                CLOSE_EVENT(intercept_data.response_event);
                break;
            }

            // Remove from active intercepts array
            LOCK_MUTEX(g_intercept_config.intercept_cs);
            for (int i = 0; i < g_intercept_count; i++) {
                if (g_active_intercepts[i] == &intercept_data) {
                    // Shift remaining elements
                    for (int j = i; j < g_intercept_count - 1; j++) {
                        g_active_intercepts[j] = g_active_intercepts[j + 1];
                    }
                    g_intercept_count--;
                    break;
                }
            }
            UNLOCK_MUTEX(g_intercept_config.intercept_cs);

            // Handle user response
            if (intercept_data.action == INTERCEPT_ACTION_DROP) {
                // Drop the data - don't forward it
                free(intercept_data.data);
                if (intercept_data.modified_data) free(intercept_data.modified_data);
                CLOSE_EVENT(intercept_data.response_event);
                continue; // Skip forwarding and go to next iteration
            } else if (intercept_data.action == INTERCEPT_ACTION_MODIFY && intercept_data.modified_data) {
                // Use modified data instead of original
                memcpy(buffer, intercept_data.modified_data, intercept_data.modified_length);
                len = intercept_data.modified_length;
            }

            // Cleanup intercept data
            free(intercept_data.data);
            if (intercept_data.modified_data) free(intercept_data.modified_data);
            CLOSE_EVENT(intercept_data.response_event);
        }

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
    int packet_id = ++g_packet_id_counter;

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
            } else {                // Error
                if (config.verbose) {
                    char status_msg[256];
#ifdef INTERCEPT_WINDOWS
                    snprintf(status_msg, sizeof(status_msg), "TCP recv error (%s): %d", direction, GET_SOCKET_ERROR());
#else
                    snprintf(status_msg, sizeof(status_msg), "TCP recv error (%s): %s", direction, strerror(errno));
#endif
                    send_status_update(status_msg);
                }
            }
            break;
        }        // Print the intercepted data
        pretty_print_data(direction, buffer, len, src_ip, dst_ip, dst_port,connection_id, packet_id);

        // Check if we should intercept this data
        if (should_intercept_data(direction, connection_id)) {
            // Create intercept data structure
            intercept_data_t intercept_data = {0};
            intercept_data.connection_id = connection_id;
            strncpy(intercept_data.direction, direction, sizeof(intercept_data.direction) - 1);
            strncpy(intercept_data.src_ip, src_ip, sizeof(intercept_data.src_ip) - 1);
            strncpy(intercept_data.dst_ip, dst_ip, sizeof(intercept_data.dst_ip) - 1);
            intercept_data.dst_port = dst_port;
            intercept_data.data_length = len;
            intercept_data.is_waiting_for_response = 1;
            intercept_data.action = INTERCEPT_ACTION_FORWARD;
            intercept_data.modified_data = NULL;
            intercept_data.modified_length = 0;

            // Create response event
            intercept_data.response_event = CREATE_EVENT();
            #ifdef INTERCEPT_WINDOWS
            if (!intercept_data.response_event) {
#else
            // POSIX: Assume event creation succeeded
            if (0) {
#endif
                send_status_update("Error: Failed to create intercept response event");
                break;
            }

            // Copy data to intercept structure
            intercept_data.data = malloc(len);
            if (!intercept_data.data) {
                CLOSE_EVENT(intercept_data.response_event);
                send_status_update("Error: Failed to allocate memory for intercept data");
                break;
            }
            memcpy(intercept_data.data, buffer, len);

            // Store in global array for response handling
            LOCK_MUTEX(g_intercept_config.intercept_cs);
            if (g_intercept_count < 100) {
                g_active_intercepts[g_intercept_count] = &intercept_data;
                g_intercept_count++;
            }
            UNLOCK_MUTEX(g_intercept_config.intercept_cs);

            // Send data to GUI for interception
            send_intercept_data(connection_id, direction, src_ip, dst_ip, dst_port, buffer, len, packet_id);

            // Wait for user response
            if (!wait_for_intercept_response(&intercept_data)) {
                // Cleanup on error
                free(intercept_data.data);
                if (intercept_data.modified_data) free(intercept_data.modified_data);
                CLOSE_EVENT(intercept_data.response_event);
                break;
            }

            // Remove from active intercepts array
            LOCK_MUTEX(g_intercept_config.intercept_cs);
            for (int i = 0; i < g_intercept_count; i++) {
                if (g_active_intercepts[i] == &intercept_data) {
                    // Shift remaining elements
                    for (int j = i; j < g_intercept_count - 1; j++) {
                        g_active_intercepts[j] = g_active_intercepts[j + 1];
                    }
                    g_intercept_count--;
                    break;
                }
            }
            UNLOCK_MUTEX(g_intercept_config.intercept_cs);

            // Handle user response
            if (intercept_data.action == INTERCEPT_ACTION_DROP) {
                // Drop the data - don't forward it
                free(intercept_data.data);
                if (intercept_data.modified_data) free(intercept_data.modified_data);
                CLOSE_EVENT(intercept_data.response_event);
                continue; // Skip forwarding and go to next iteration
            } else if (intercept_data.action == INTERCEPT_ACTION_MODIFY && intercept_data.modified_data) {
                // Use modified data instead of original
                memcpy(buffer, intercept_data.modified_data, intercept_data.modified_length);
                len = intercept_data.modified_length;
            }

            // Cleanup intercept data
            free(intercept_data.data);
            if (intercept_data.modified_data) free(intercept_data.modified_data);
            CLOSE_EVENT(intercept_data.response_event);
        }

        // Forward to the destination
        int sent = 0;
        while (sent < len) {
            int written = send(dst, (char*)buffer + sent, len - sent, 0);            if (written <= 0) {
                if (config.verbose) {
                    char status_msg[256];
#ifdef INTERCEPT_WINDOWS
                    snprintf(status_msg, sizeof(status_msg), "TCP send error (%s): %d", direction, GET_SOCKET_ERROR());
#else
                    snprintf(status_msg, sizeof(status_msg), "TCP send error (%s): %s", direction, strerror(errno));
#endif
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
/*
 * Detect protocol based on first bytes of data
 * Uses universal detection approach that works with any protocol
 *
 * Returns:
 *   PROTOCOL_TLS - If connection starts with TLS handshake
 *   PROTOCOL_PLAIN_TCP - For all other protocols (including HTTP, PostgreSQL, SMTP, etc)
 *
 * Note: This function no longer identifies HTTP separately.
 *       HTTP is treated as PROTOCOL_PLAIN_TCP and can upgrade to TLS later.
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
        if (config.verbose) {
            fprintf(stderr, "TLS protocol detected immediately\n");
        }
        return PROTOCOL_TLS;
    }

    // For all other protocols (including HTTP, PostgreSQL, SMTP, etc.)
    // Return PROTOCOL_PLAIN_TCP and handle potential TLS upgrades later
    if (config.verbose) {
        fprintf(stderr, "Non-TLS protocol detected, treating as plain TCP\n");
    }
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
    int packet_id = ++g_packet_id_counter;


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
        pretty_print_data("??", buffer, len, src_ip, dst_ip, dst_port,connection_id, packet_id);

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
            }        } else {
            // For any non-TLS protocol, forward as plain TCP
            // This includes HTTP, PostgreSQL, SMTP, etc.
            // TLS upgrade detection is handled separately in protocol_detector.c
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


// Helper to check if a string is an IP address (basic version)
static bool is_ip_address(const char *str) {
    if (!str) return false;
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    return inet_pton(AF_INET, str, &(sa.sin_addr)) != 0 || inet_pton(AF_INET6, str, &(sa6.sin6_addr)) != 0;
}

typedef struct {
    const char *original_target_host; // From SOCKS
    SSL_CTX *generated_ctx_for_sni;
    X509 *generated_cert_for_sni;    // Owned by generated_ctx_for_sni
    EVP_PKEY *generated_key_for_sni; // Owned by generated_ctx_for_sni
} client_sni_callback_args;

static int sni_cert_setup_callback(SSL *s, int *ad, void *arg) {
    client_sni_callback_args *cb_args = (client_sni_callback_args *)arg;
    const char *sni_hostname = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    const char *hostname_to_use = NULL;

    if (sni_hostname && strlen(sni_hostname) > 0) {
        hostname_to_use = sni_hostname;
        if (config.verbose) {
            log_message("SNI: Received hostname: %s", sni_hostname);
        }
    } else {
        if (config.verbose) {
            log_message("SNI: No SNI hostname. Falling back to SOCKS target: %s", cb_args->original_target_host ? cb_args->original_target_host : "N/A");
        }
        if (cb_args && cb_args->original_target_host && !is_ip_address(cb_args->original_target_host)) {
            hostname_to_use = cb_args->original_target_host;
        } else {
            log_message("SNI: No usable hostname (SNI absent or SOCKS target is IP/unavailable).");
            *ad = SSL_AD_UNRECOGNIZED_NAME;
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    }

    if (!hostname_to_use) {
        log_message("SNI: Critical - No hostname available to generate certificate.");
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    // Clean up any previous attempt for this session (should not happen if callback is once per handshake)
    if (cb_args->generated_ctx_for_sni) { SSL_CTX_free(cb_args->generated_ctx_for_sni); cb_args->generated_ctx_for_sni = NULL; }
    // Cert and key are owned by context, no separate free here if they were part of a previous context.

    X509 *new_cert = NULL;
    EVP_PKEY *new_key = NULL;

    log_message("SNI: Generating certificate for: %s", hostname_to_use);
    if (!generate_cert_for_host(hostname_to_use, &new_cert, &new_key)) {
        fprintf(stderr, "SNI: Failed to generate certificate for %s\\\\n", hostname_to_use);
        log_message("SNI: Failed to generate certificate for %s", hostname_to_use);
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    SSL_CTX *original_ctx = SSL_get_SSL_CTX(s); // This is the server_ctx passed to SSL_new
    SSL_CTX *new_ctx_for_sni = SSL_CTX_new(SSL_CTX_get_ssl_method(original_ctx)); // Use the same method
    if (!new_ctx_for_sni) {
        fprintf(stderr, "SNI: Failed to create new SSL_CTX for %s\\n", hostname_to_use);
        log_message("SNI: Failed to create new SSL_CTX for %s", hostname_to_use);
        X509_free(new_cert); EVP_PKEY_free(new_key);
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    // Configure new_ctx_for_sni similar to the one from create_server_ssl_context()
    // This should ideally be a function or copied settings.
    // Copy options from the original context
    long options = SSL_CTX_get_options(original_ctx);
    SSL_CTX_set_options(new_ctx_for_sni, options);    // Copy cipher list - Use a standard secure cipher list instead of copying
    if (SSL_CTX_set_cipher_list(new_ctx_for_sni, "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA") != 1) {
        fprintf(stderr, "SNI: Warning: Failed to set cipher list on new_ctx_for_sni\\n");
    }

    // Copy session cache mode
    long cache_mode = SSL_CTX_get_session_cache_mode(original_ctx);
    SSL_CTX_set_session_cache_mode(new_ctx_for_sni, cache_mode);


    if (SSL_CTX_use_certificate(new_ctx_for_sni, new_cert) != 1 ||
        SSL_CTX_use_PrivateKey(new_ctx_for_sni, new_key) != 1 ||
        !SSL_CTX_check_private_key(new_ctx_for_sni)) {
        fprintf(stderr, "SNI: Failed to use generated cert/key for %s in new_ctx_for_sni\\n", hostname_to_use);
        log_message("SNI: Failed to use generated cert/key for %s", hostname_to_use);
        print_openssl_error();
        SSL_CTX_free(new_ctx_for_sni); // new_cert and new_key are freed when new_ctx_for_sni is freed if they were successfully added
        // If not successfully added, they need explicit free. X509_free(new_cert); EVP_PKEY_free(new_key);
        *ad = SSL_AD_CERTIFICATE_UNOBTAINABLE;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    SSL_set_SSL_CTX(s, new_ctx_for_sni);

    cb_args->generated_ctx_for_sni = new_ctx_for_sni;
    cb_args->generated_cert_for_sni = new_cert; // For tracking, owned by context
    cb_args->generated_key_for_sni = new_key;   // For tracking, owned by context

    return SSL_TLSEXT_ERR_OK;
}


/*
 * Handle a client connection
 */
THREAD_RETURN_TYPE handle_client(void *arg) {
    if (!arg) {
        fprintf(stderr, "Error: NULL argument passed to handle_client\\n");
        THREAD_RETURN;
    }    client_info *client = (client_info*)arg;
    socket_t client_sock = client->client_sock;
    socket_t server_sock = SOCKET_ERROR_VAL; // Using platform-independent macro
    SSL_CTX *server_ctx = NULL; // This will be the "template" context
    SSL_CTX *client_ctx = NULL;
    SSL *server_ssl = NULL;
    SSL *client_ssl = NULL;
    client_sni_callback_args sni_cb_args = {0}; // Initialize our callback args

    THREAD_HANDLE thread_id = INVALID_THREAD_ID;
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
    inet_ntop(AF_INET, &(client->client_addr.sin_addr), client_ip, MAX_IP_ADDR_LEN);    // Set socket options for better compatibility
#ifdef INTERCEPT_WINDOWS
    DWORD timeout = 120000;  // 120 seconds timeout in milliseconds for Windows
#else
    struct timeval timeout;
    timeout.tv_sec = 120;    // 120 seconds for POSIX
    timeout.tv_usec = 0;
#endif
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    // TCP keepalive to detect dead connections
#ifdef INTERCEPT_WINDOWS
    DWORD keepAlive = 1;
#else
    int keepAlive = 1;
#endif
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
    server_sock = socket(AF_INET, SOCK_STREAM, 0);    if (server_sock == SOCKET_ERROR_VAL) {
#ifdef INTERCEPT_WINDOWS
        fprintf(stderr, "Failed to create socket for server connection: %d\n", GET_SOCKET_ERROR());
#else
        fprintf(stderr, "Failed to create socket for server connection: %s\n", strerror(errno));
#endif
        goto cleanup;
    }// Set server socket options
#ifdef INTERCEPT_WINDOWS
    DWORD server_timeout = 60000;  // 60 seconds timeout in milliseconds for Windows
#else
    struct timeval server_timeout;
    server_timeout.tv_sec = 60;    // 60 seconds for POSIX
    server_timeout.tv_usec = 0;
#endif
    if (setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&server_timeout, sizeof(server_timeout)) != 0 ||
        setsockopt(server_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&server_timeout, sizeof(server_timeout)) != 0) {
        if (config.verbose) {
#ifdef INTERCEPT_WINDOWS
            fprintf(stderr, "Warning: Failed to set server socket timeout: %d\n", GET_SOCKET_ERROR());
#else
            fprintf(stderr, "Warning: Failed to set server socket timeout: %s\n", strerror(errno));
#endif
        }
    }

    // Resolve hostname
    struct hostent *host = gethostbyname(target_host);
    if (!host) {
        fprintf(stderr, "Failed to resolve hostname %s: %d\n", target_host, GET_SOCKET_ERROR());
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
    if (ret == SOCKET_OPTS_ERROR) {
#ifdef INTERCEPT_WINDOWS
        int error = GET_SOCKET_ERROR();
#else
        int error = errno;
#endif
        fprintf(stderr, "Failed to connect to server %s:%d: %d\n",
                target_host, target_port, error);
        log_message("Connection to %s:%d failed with error %d", target_host, target_port, error);
        goto cleanup;
    }

    // Set TCP_NODELAY for better performance
    int nodelay = 1;
#ifdef INTERCEPT_WINDOWS
    setsockopt(server_sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
#else
    // On POSIX systems, TCP_NODELAY is included from netinet/tcp.h
    setsockopt(server_sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
#endif// Detect protocol type (TLS, HTTP, or plain TCP)
    protocol_type = detect_protocol(client_sock);

    if (protocol_type == PROTOCOL_TLS) {
        // TLS handling path
        if (config.verbose) {
            printf("Detected TLS protocol, proceeding with TLS interception\\n");
        }
        send_status_update("Proceeding with TLS interception");

        // Generate certificate for the target host  -- THIS BLOCK IS REMOVED/MODIFIED
        // if (!generate_cert_for_host(target_host, &cert, &key)) {
        //     fprintf(stderr, "Failed to generate certificate for %s\\n", target_host);
        //     goto cleanup;
        // }

        // Create server context (for client -> proxy)
        server_ctx = create_server_ssl_context(); // This is our base/template context
        if (!server_ctx) {
            fprintf(stderr, "Failed to create server SSL context\\n");
            goto cleanup;
        }

        // Setup SNI callback
        sni_cb_args.original_target_host = target_host; // Pass the SOCKS target as a fallback
        SSL_CTX_set_tlsext_servername_callback(server_ctx, sni_cert_setup_callback);
        SSL_CTX_set_tlsext_servername_arg(server_ctx, &sni_cb_args);


        // Use the generated certificate and key -- THIS BLOCK IS REMOVED/MODIFIED
        // if (SSL_CTX_use_certificate(server_ctx, cert) != 1 ||
        //     SSL_CTX_use_PrivateKey(server_ctx, key) != 1 ||
        //     SSL_CTX_check_private_key(server_ctx) != 1) {
        //     fprintf(stderr, "Failed to set up SSL certificate\\n");
        //     print_openssl_error();
        //     goto cleanup;
        // }

        // Create server SSL object and attach to client socket
        if (config.verbose) {
            printf("Performing TLS handshake with client (SNI callback will set certificate)...\\n");
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

        ret = SSL_accept(server_ssl);        if (ret != 1) {
            int ssl_error = SSL_get_error(server_ssl, ret);
            unsigned long error_reason = ERR_peek_error();
            fprintf(stderr, "Failed to perform TLS handshake with client: %d (reason: 0x%lx)\\n",
                    ssl_error, error_reason); // Use %lx for unsigned long
            print_openssl_error();

            // Log more friendly message for common certificate errors
            if (ERR_GET_REASON(error_reason) == SSL_R_TLSV1_ALERT_BAD_CERTIFICATE ||
                ERR_GET_REASON(error_reason) == SSL_R_CERTIFICATE_VERIFY_FAILED) { // Removed duplicate conditions
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
            // if (cert) { // cert and key are no longer managed here for server_ssl
            //     X509_free(cert);
            //     cert = NULL;
            // }
            // if (key) {
            //     EVP_PKEY_free(key);
            //     key = NULL;
            // }
            // sni_cb_args.generated_cert_for_sni and sni_cb_args.generated_key_for_sni are owned by sni_cb_args.generated_ctx_for_sni
            // sni_cb_args.generated_ctx_for_sni will be freed in the main cleanup block if it was set.

            // Continue with non-TLS handling
        } else { // Handshake with client succeeded
             if (config.verbose) {
                const char* negotiated_cipher = SSL_get_cipher_name(server_ssl);
                const char* negotiated_version = SSL_get_version(server_ssl);
                log_message("TLS handshake with client successful. Cipher: %s, Version: %s",
                    negotiated_cipher ? negotiated_cipher : "N/A",
                    negotiated_version ? negotiated_version : "N/A");
            }
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
    }        client_to_server->src = server_ssl;
        client_to_server->dst = client_ssl;
        strncpy(client_to_server->direction, "Client->Server", sizeof(client_to_server->direction)-1);
    client_to_server->direction[sizeof(client_to_server->direction)-1] = '\0';
    strncpy(client_to_server->src_ip, client_ip, MAX_IP_ADDR_LEN-1);
    strncpy(client_to_server->dst_ip, server_ip, MAX_IP_ADDR_LEN-1);
    client_to_server->dst_port = target_port;
    client_to_server->connection_id = connection_id;

    // Log connection info
    log_message("Established connection: %s -> %s:%d", client_ip, server_ip, target_port);    // Create a second thread for server->client direction
    printf("Validate the connection");
    forward_info *server_to_client = (forward_info*)malloc(sizeof(forward_info));
    if (!server_to_client) {
        fprintf(stderr, "Memory allocation failed\n");
        free(client_to_server); // Don't leak memory
        goto cleanup;
    }
    server_to_client->src = client_ssl;
    server_to_client->dst = server_ssl;
    strncpy(server_to_client->direction, "Server->Client", sizeof(server_to_client->direction)-1);
    server_to_client->direction[sizeof(server_to_client->direction)-1] = '\0';
    strncpy(server_to_client->src_ip, server_ip, MAX_IP_ADDR_LEN-1);
    strncpy(server_to_client->dst_ip, client_ip, MAX_IP_ADDR_LEN-1);
    server_to_client->dst_port = ntohs(client->client_addr.sin_port);
    server_to_client->connection_id = connection_id;
    printf("Hello world connection print check");
    // Make sure strings are null-terminated
    client_to_server->src_ip[MAX_IP_ADDR_LEN-1] = '\0';
    client_to_server->dst_ip[MAX_IP_ADDR_LEN-1] = '\0';
    server_to_client->src_ip[MAX_IP_ADDR_LEN-1] = '\0';
    server_to_client->dst_ip[MAX_IP_ADDR_LEN-1] = '\0';    // Start both forwarding threads
    printf("Create Threads Now");
    THREAD_HANDLE thread_id2 = INVALID_THREAD_ID;
    CREATE_THREAD(thread_id, forward_data_thread, client_to_server);
    CREATE_THREAD(thread_id2, forward_data_thread, server_to_client);
    printf("Wait for Threads");
    // Wait for both threads to finish
    if (thread_id != INVALID_THREAD_ID) JOIN_THREAD(thread_id);
    if (thread_id2 != INVALID_THREAD_ID) JOIN_THREAD(thread_id2);

    printf("Threads completed");

    if (config.verbose) {
        printf("Connection to %s:%d closed\n", target_host, target_port);    }
    } else if (protocol_type == PROTOCOL_PLAIN_TCP) {
        // Non-TLS handling path (any protocol that doesn't start with TLS)
        // This includes HTTP, PostgreSQL, SMTP, and any protocol that might upgrade to TLS later
        if (config.verbose) {
            printf("Detected plain TCP protocol (may upgrade to TLS later)\n");
        }
        send_status_update("Forwarding plain TCP traffic with protocol upgrade detection");

        if (config.verbose) {
            printf("Setting up direct TCP forwarding between client and %s:%d\n", target_host, target_port);
        }

        // Create TCP forwarding info structs
        forward_tcp_info *client_to_server = (forward_tcp_info*)malloc(sizeof(forward_tcp_info));
        if (!client_to_server) {
            fprintf(stderr, "Memory allocation failed\n");
            goto cleanup;
        }        client_to_server->src = client_sock;
        client_to_server->dst = server_sock;
        strncpy(client_to_server->direction, "Client->Server", sizeof(client_to_server->direction)-1);
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
        }        server_to_client->src = server_sock;
        server_to_client->dst = client_sock;
        strncpy(server_to_client->direction, "Server->Client", sizeof(server_to_client->direction)-1);
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
        log_message("Established direct TCP connection: %s -> %s:%d", client_ip, server_ip, target_port);        // Start TCP forwarding threads
        THREAD_HANDLE thread_id2 = INVALID_THREAD_ID;
        CREATE_THREAD(thread_id, forward_tcp_thread, client_to_server);
        CREATE_THREAD(thread_id2, forward_tcp_thread, server_to_client);

        // Wait for both threads to finish
        if (thread_id != INVALID_THREAD_ID) JOIN_THREAD(thread_id);
        if (thread_id2 != INVALID_THREAD_ID) JOIN_THREAD(thread_id2);

        if (config.verbose) {
            printf("TCP connection to %s:%d closed\n", target_host, target_port);
        }
    }

cleanup:
    if (config.verbose) {
        printf("Cleaning up connection to %s:%d (ID: %d)\\n", target_host, target_port, connection_id);
    }
    send_disconnect_notification(connection_id, "Connection closed");

    if (server_ssl) {
        SSL_shutdown(server_ssl);
        SSL_free(server_ssl);
    }
    // server_ctx is the base/template context, sni_cb_args.generated_ctx_for_sni is the one actually used by server_ssl if SNI callback succeeded.
    // SSL_set_SSL_CTX replaces the SSL's CTX, but the original server_ctx (template) still needs freeing.
    // The new CTX created in the SNI callback (sni_cb_args.generated_ctx_for_sni) is associated with the SSL object
    // and should be freed if it was created.
    if (sni_cb_args.generated_ctx_for_sni) {
        SSL_CTX_free(sni_cb_args.generated_ctx_for_sni); // This also frees its cert and key
    }
    if (server_ctx) { // Free the base/template server_ctx
        SSL_CTX_free(server_ctx);
    }
    // cert and key are no longer managed at this level for server_ssl
    // if (cert) X509_free(cert);
    // if (key) EVP_PKEY_free(key);

    if (client_ssl) {
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
    }
    if (client_ctx) {
        SSL_CTX_free(client_ctx);
    }

    // Free client info struct - only free once and null the pointer
    if (client) {
        free(client);
        client = NULL;
    }

    THREAD_RETURN;
}

/* Interception support functions */

int should_intercept_data(const char* direction, int connection_id) {
    if (!g_intercept_config.is_interception_enabled) {
        return 0;
    }

    LOCK_MUTEX(g_intercept_config.intercept_cs);

    int should_intercept = 0;
    if (strcmp(direction, "Client->Server") == 0 &&
        (g_intercept_config.enabled_directions & INTERCEPT_CLIENT_TO_SERVER)) {
        should_intercept = 1;
    } else if (strcmp(direction, "Server->Client") == 0 &&
               (g_intercept_config.enabled_directions & INTERCEPT_SERVER_TO_CLIENT)) {
        should_intercept = 1;
    }

    UNLOCK_MUTEX(g_intercept_config.intercept_cs);
    return should_intercept;
}

void send_intercept_data(int connection_id, const char* direction, const char* src_ip, const char* dst_ip, int dst_port, const unsigned char* data, int data_length, int packet_id) {
    if (g_intercept_callback) {
        g_intercept_callback(connection_id, direction, src_ip, dst_ip, dst_port, data, data_length, packet_id);
    }
}

int wait_for_intercept_response(intercept_data_t* intercept_data) {
    if (!intercept_data || !intercept_data->response_event) {
        return 0;
    }    // Wait for user response with a reasonable timeout (60 seconds)
#ifdef INTERCEPT_WINDOWS
    DWORD wait_result = WAIT_EVENT(intercept_data->response_event, 60000);
    if (wait_result == WAIT_TIMEOUT) {
#else
    int wait_result = WAIT_EVENT(intercept_data->response_event, 60000);
    if (wait_result != 0) { // Non-zero in POSIX typically means timeout or error
#endif
        // Timeout - default to forwarding
        intercept_data->action = INTERCEPT_ACTION_FORWARD;
        intercept_data->is_waiting_for_response = 0;
        if (g_status_callback) {
            g_status_callback("Intercept timeout - data forwarded automatically");
        }
    }

#ifdef INTERCEPT_WINDOWS
    return (wait_result == WAIT_OBJECT_0 || wait_result == WAIT_TIMEOUT);
#else
    return (wait_result == 0 || wait_result != 0); // In POSIX, 0 is success
#endif
}
