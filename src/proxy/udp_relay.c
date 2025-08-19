/*
 * TLS MITM Proxy - UDP Relay Implementation
 *
 * Provides SOCKS5 UDP ASSOCIATE support with packet interception.
 */

#include "udp_relay.h"
#include "../utils/utils.h"
#include "../tls/proxy/tls_proxy_dll.h"
#include "../tls/proxy/tls_utils.h"
#include "../proxy/interceptor/interceptor.h"
#include <string.h>

// Global UDP relay server instance
static udp_relay_server_t g_udp_server = {0};

// External callback functions
extern log_callback_t g_log_callback;
extern status_callback_t g_status_callback;
extern intercept_config_t g_intercept_config;
extern intercept_callback_t g_intercept_callback;
extern intercept_data_t* g_active_intercepts[100];
extern int g_intercept_count;

// External packet ID counter
extern int g_packet_id_counter;

int start_udp_relay_server(const char* bind_addr, int port) {
    if (g_udp_server.thread_handle != 0) {
        log_message("UDP relay server is already running");
        return 0;
    }

    // Create UDP socket
    g_udp_server.socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp_server.socket == SOCKET_ERROR_VAL) {
        log_message("Failed to create UDP socket");
        return 0;
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(g_udp_server.socket, SOL_SOCKET, SO_REUSEADDR,
                   (const char*)&opt, sizeof(opt)) == SOCKET_OPTS_ERROR) {
        log_message("Failed to set UDP socket options");
        CLOSE_SOCKET(g_udp_server.socket);
        return 0;
    }

    // Bind to address and port
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, bind_addr, &(server_addr.sin_addr)) != 1) {
        log_message("Invalid UDP bind address");
        CLOSE_SOCKET(g_udp_server.socket);
        return 0;
    }
    server_addr.sin_port = htons(port);

    if (bind(g_udp_server.socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_OPTS_ERROR) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Failed to bind UDP socket to %s:%d", bind_addr, port);
        log_message(error_msg);
        CLOSE_SOCKET(g_udp_server.socket);
        return 0;
    }

    // Initialize server state
    INIT_MUTEX(g_udp_server.cs);
    g_udp_server.should_stop = 0;
    strncpy(g_udp_server.bind_addr, bind_addr, sizeof(g_udp_server.bind_addr) - 1);
    g_udp_server.bind_addr[sizeof(g_udp_server.bind_addr) - 1] = '\0';
    g_udp_server.port = port;

    // Start UDP relay thread
    if (CREATE_THREAD(g_udp_server.thread_handle, udp_relay_thread, &g_udp_server) != 0) {
        log_message("Failed to create UDP relay thread");
        CLOSE_SOCKET(g_udp_server.socket);
        DESTROY_MUTEX(g_udp_server.cs);
        return 0;
    }

    return 1;
}

void stop_udp_relay_server(void) {
    if (g_udp_server.thread_handle == 0) {
        return;
    }

    LOCK_MUTEX(g_udp_server.cs);
    g_udp_server.should_stop = 1;
    UNLOCK_MUTEX(g_udp_server.cs);

    // Close socket to wake up the thread
    if (g_udp_server.socket != SOCKET_ERROR_VAL) {
        CLOSE_SOCKET(g_udp_server.socket);
        g_udp_server.socket = SOCKET_ERROR_VAL;
    }

    // Wait for thread to finish
    if (g_udp_server.thread_handle != 0) {
        JOIN_THREAD(g_udp_server.thread_handle);
        g_udp_server.thread_handle = 0;
    }

    DESTROY_MUTEX(g_udp_server.cs);
    log_message("UDP relay server stopped");
}

THREAD_RETURN_TYPE THREAD_CALL udp_relay_thread(void* param) {
    udp_relay_server_t* server = (udp_relay_server_t*)param;
    char buffer[65536];
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    while (1) {
        LOCK_MUTEX(server->cs);
        int should_stop = server->should_stop;
        UNLOCK_MUTEX(server->cs);

        if (should_stop) {
            break;
        }

        // Receive UDP packet
        int received = recvfrom(server->socket, buffer, sizeof(buffer) - 1, 0,
                               (struct sockaddr*)&client_addr, &client_addr_len);

        if (received == SOCKET_ERROR_VAL) {
            LOCK_MUTEX(server->cs);
            int should_stop_inner = server->should_stop;
            UNLOCK_MUTEX(server->cs);

            if (should_stop_inner) {
                break;
            }

            #ifdef INTERCEPT_WINDOWS
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK && error != WSAEINTR) {
                log_message("UDP receive error");
                break;
            }
            #else
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                log_message("UDP receive error");
                break;
            }
            #endif
            continue;
        }

        if (received > 0) {
            // Handle the UDP packet
            handle_udp_packet(server->socket, &client_addr, buffer, received);
        }
    }

    THREAD_RETURN;
}

int handle_udp_packet(socket_t sock, struct sockaddr_in* client_addr,
                     const char* data, int data_len) {
    char target_host[256];
    int target_port;
    const char* payload;
    int payload_len;

    // Parse SOCKS5 UDP request format
    if (parse_socks5_udp_request(data, data_len, target_host, &target_port, &payload, &payload_len) != 1) {
        log_message("Invalid SOCKS5 UDP packet format");
        return 0;
    }

    // Convert client address to string for logging
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr->sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr->sin_port);

    // Use connection_id = 0 for UDP (all UDP packets share this ID)
    int connection_id = 0;
    int packet_id = ++g_packet_id_counter;

    // Determine message type using shared utility
    const char* message_type = detect_message_type((const unsigned char*)payload, payload_len);

    // Log original outbound packet to proxy history IMMEDIATELY (like TCP)
    if (g_log_callback) {
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

        g_log_callback(timestamp, connection_id, packet_id, "Client->Server",
                      client_ip, target_host, target_port, "UDP",
                      (const unsigned char*)payload, payload_len, message_type);
    }

    // Prepare data for interception (following TCP pattern exactly)
    unsigned char* forward_data = (unsigned char*)payload;
    int forward_len = payload_len;

    // Check if we should intercept this data (using TCP interception logic)
    if (should_intercept_data("Client->Server", connection_id)) {
        // Create intercept data structure (exactly like TCP)
        intercept_data_t intercept_data = {0};
        intercept_data.connection_id = connection_id;
        intercept_data.packet_id = packet_id;
        strncpy(intercept_data.direction, "Client->Server", sizeof(intercept_data.direction) - 1);
        intercept_data.direction[sizeof(intercept_data.direction) - 1] = '\0';
        strncpy(intercept_data.src_ip, client_ip, sizeof(intercept_data.src_ip) - 1);
        intercept_data.src_ip[sizeof(intercept_data.src_ip) - 1] = '\0';
        strncpy(intercept_data.dst_ip, target_host, sizeof(intercept_data.dst_ip) - 1);
        intercept_data.dst_ip[sizeof(intercept_data.dst_ip) - 1] = '\0';
        intercept_data.dst_port = target_port;
        intercept_data.data_length = payload_len;
        intercept_data.is_waiting_for_response = 1;
        intercept_data.action = INTERCEPT_ACTION_FORWARD;
        intercept_data.modified_data = NULL;
        intercept_data.modified_length = 0;

        // Create response event
        intercept_data.response_event = CREATE_EVENT();
        #ifdef INTERCEPT_WINDOWS
        if (!intercept_data.response_event) {
        #else
        if (0) {
        #endif
            log_message("Error: Failed to create UDP intercept response event");
            return 0;
        }

        // Copy data to intercept structure
        intercept_data.data = malloc(payload_len);
        if (!intercept_data.data) {
            CLOSE_EVENT(intercept_data.response_event);
            log_message("Error: Failed to allocate memory for UDP intercept data");
            return 0;
        }
        memcpy(intercept_data.data, payload, payload_len);

        // Store in global array for response handling
        LOCK_MUTEX(g_intercept_config.intercept_cs);
        if (g_intercept_count < 100) {
            g_active_intercepts[g_intercept_count] = &intercept_data;
            g_intercept_count++;
        }
        UNLOCK_MUTEX(g_intercept_config.intercept_cs);

        // Send data to GUI for interception
        send_intercept_data(connection_id, "Client->Server", client_ip, target_host, target_port, "UDP",
                           (unsigned char*)payload, payload_len, packet_id);

        // Wait for user response
        if (!wait_for_intercept_response(&intercept_data)) {
            // Cleanup on error
            free(intercept_data.data);
            if (intercept_data.modified_data) free(intercept_data.modified_data);
            CLOSE_EVENT(intercept_data.response_event);
            return 0;
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
            // Drop the packet - don't forward it
            free(intercept_data.data);
            if (intercept_data.modified_data) free(intercept_data.modified_data);
            CLOSE_EVENT(intercept_data.response_event);
            return 1; // Return success but don't forward
        } else if (intercept_data.action == INTERCEPT_ACTION_MODIFY && intercept_data.modified_data) {
            // Use modified data instead of original
            forward_data = intercept_data.modified_data;
            forward_len = intercept_data.modified_length;
        }

        // Cleanup intercept data (but keep modified_data until after forwarding)
        free(intercept_data.data);
        CLOSE_EVENT(intercept_data.response_event);
        // Don't free modified_data yet - we're using it for forwarding
    }

    // Create socket to forward to target
    socket_t target_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (target_sock == SOCKET_ERROR_VAL) {
        log_message("Failed to create target UDP socket");
        // Clean up modified data if it was allocated
        if (forward_data != (unsigned char*)payload) {
            free(forward_data);
        }
        return 0;
    }

    // Resolve target address
    struct sockaddr_in target_addr = {0};
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);

    if (inet_pton(AF_INET, target_host, &(target_addr.sin_addr)) != 1) {
        // Try to resolve hostname
        struct hostent* host_entry = gethostbyname(target_host);
        if (host_entry == NULL) {
            char error_msg[512];
            snprintf(error_msg, sizeof(error_msg), "Failed to resolve UDP target: %s", target_host);
            log_message(error_msg);
            CLOSE_SOCKET(target_sock);
            // Clean up modified data if it was allocated
            if (forward_data != (unsigned char*)payload) {
                free(forward_data);
            }
            return 0;
        }
        memcpy(&(target_addr.sin_addr), host_entry->h_addr_list[0], host_entry->h_length);
    }

    // Forward packet to target (using potentially modified data)
    int sent = sendto(target_sock, (const char*)forward_data, forward_len, 0,
                     (struct sockaddr*)&target_addr, sizeof(target_addr));

    // Clean up modified data if it was allocated
    if (forward_data != (unsigned char*)payload) {
        free(forward_data);
    }

    if (sent == SOCKET_ERROR_VAL) {
        log_message("Failed to forward UDP packet to target");
        CLOSE_SOCKET(target_sock);
        return 0;
    }

    // Wait for response (with timeout)
    fd_set read_fds;
    struct timeval timeout;
    FD_ZERO(&read_fds);
    FD_SET(target_sock, &read_fds);
    timeout.tv_sec = 5;  // 5 second timeout
    timeout.tv_usec = 0;

    int select_result = select(target_sock + 1, &read_fds, NULL, NULL, &timeout);
    if (select_result > 0 && FD_ISSET(target_sock, &read_fds)) {
        // Receive response from target
        char response_buffer[65536];
        struct sockaddr_in response_addr;
        socklen_t response_addr_len = sizeof(response_addr);

        int received = recvfrom(target_sock, response_buffer, sizeof(response_buffer) - 1, 0,
                               (struct sockaddr*)&response_addr, &response_addr_len);

        if (received > 0) {
            // Get packet ID for response
            int response_packet_id = ++g_packet_id_counter;

            // Determine response message type
            const char* response_message_type = detect_message_type((const unsigned char*)response_buffer, received);

            // Log original response to proxy history IMMEDIATELY (like TCP)
            if (g_log_callback) {
                time_t now = time(NULL);
                struct tm* tm_info = localtime(&now);
                char timestamp[32];
                strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

                g_log_callback(timestamp, connection_id, response_packet_id, "Server->Client",
                              target_host, client_ip, client_port, "UDP",
                              (const unsigned char*)response_buffer, received, response_message_type);
            }

            // Prepare response data for interception (following TCP pattern exactly)
            unsigned char* response_forward_data = (unsigned char*)response_buffer;
            int response_forward_len = received;

            // Check if we should intercept inbound data
            if (should_intercept_data("Server->Client", connection_id)) {
                // Create intercept data structure for response (exactly like TCP)
                intercept_data_t response_intercept_data = {0};
                response_intercept_data.connection_id = connection_id;
                response_intercept_data.packet_id = response_packet_id;
                strncpy(response_intercept_data.direction, "Server->Client", sizeof(response_intercept_data.direction) - 1);
                response_intercept_data.direction[sizeof(response_intercept_data.direction) - 1] = '\0';
                strncpy(response_intercept_data.src_ip, target_host, sizeof(response_intercept_data.src_ip) - 1);
                response_intercept_data.src_ip[sizeof(response_intercept_data.src_ip) - 1] = '\0';
                strncpy(response_intercept_data.dst_ip, client_ip, sizeof(response_intercept_data.dst_ip) - 1);
                response_intercept_data.dst_ip[sizeof(response_intercept_data.dst_ip) - 1] = '\0';
                response_intercept_data.dst_port = client_port;
                response_intercept_data.data_length = received;
                response_intercept_data.is_waiting_for_response = 1;
                response_intercept_data.action = INTERCEPT_ACTION_FORWARD;
                response_intercept_data.modified_data = NULL;
                response_intercept_data.modified_length = 0;

                // Create response event
                response_intercept_data.response_event = CREATE_EVENT();
                #ifdef INTERCEPT_WINDOWS
                if (!response_intercept_data.response_event) {
                #else
                if (0) {
                #endif
                    log_message("Error: Failed to create UDP response intercept event");
                } else {
                    // Copy response data to intercept structure
                    response_intercept_data.data = malloc(received);
                    if (!response_intercept_data.data) {
                        CLOSE_EVENT(response_intercept_data.response_event);
                        log_message("Error: Failed to allocate memory for UDP response intercept data");
                    } else {
                        memcpy(response_intercept_data.data, response_buffer, received);

                        // Store in global array for response handling
                        LOCK_MUTEX(g_intercept_config.intercept_cs);
                        if (g_intercept_count < 100) {
                            g_active_intercepts[g_intercept_count] = &response_intercept_data;
                            g_intercept_count++;
                        }
                        UNLOCK_MUTEX(g_intercept_config.intercept_cs);

                        // Send response data to GUI for interception
                        send_intercept_data(connection_id, "Server->Client", target_host, client_ip, client_port, "UDP",
                                           (unsigned char*)response_buffer, received, response_packet_id);

                        // Wait for user response
                        if (wait_for_intercept_response(&response_intercept_data)) {
                            // Remove from active intercepts array
                            LOCK_MUTEX(g_intercept_config.intercept_cs);
                            for (int i = 0; i < g_intercept_count; i++) {
                                if (g_active_intercepts[i] == &response_intercept_data) {
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
                            if (response_intercept_data.action == INTERCEPT_ACTION_DROP) {
                                // Drop the response - don't send it back
                                free(response_intercept_data.data);
                                if (response_intercept_data.modified_data) free(response_intercept_data.modified_data);
                                CLOSE_EVENT(response_intercept_data.response_event);
                                CLOSE_SOCKET(target_sock);
                                return 1; // Return success but don't send response
                            } else if (response_intercept_data.action == INTERCEPT_ACTION_MODIFY && response_intercept_data.modified_data) {
                                // Use modified response data
                                response_forward_data = response_intercept_data.modified_data;
                                response_forward_len = response_intercept_data.modified_length;
                            }
                        }

                        // Cleanup intercept data (but keep modified_data until after sending)
                        free(response_intercept_data.data);
                        CLOSE_EVENT(response_intercept_data.response_event);
                        // Don't free modified_data yet - we're using it for sending
                    }
                }
            }

            // Create SOCKS5 UDP response and send back to client
            char socks5_response[65536];
            int socks5_response_len = 10; // Header size for IPv4

            // SOCKS5 UDP response header
            socks5_response[0] = 0x00; // RSV
            socks5_response[1] = 0x00; // RSV
            socks5_response[2] = 0x00; // FRAG
            socks5_response[3] = 0x01; // ATYP (IPv4)

            // Target IP (where response came from)
            memcpy(&socks5_response[4], &(response_addr.sin_addr), 4);

            // Target port
            memcpy(&socks5_response[8], &(response_addr.sin_port), 2);

            // Copy response data (potentially modified)
            memcpy(&socks5_response[10], response_forward_data, response_forward_len);
            socks5_response_len = 10 + response_forward_len;

            // Send back to client
            sendto(sock, socks5_response, socks5_response_len, 0,
                  (struct sockaddr*)client_addr, sizeof(*client_addr));

            // Clean up modified response data if it was allocated
            if (response_forward_data != (unsigned char*)response_buffer) {
                free(response_forward_data);
            }
        }
    } else {
        // No response received from target within timeout
        log_message("UDP: No response received from target %s:%d within timeout", target_host, target_port);
    }

    CLOSE_SOCKET(target_sock);
    return 1;
}

int parse_socks5_udp_request(const char* data, int data_len,
                           char* target_host, int* target_port,
                           const char** payload, int* payload_len) {
    if (data_len < 10) { // Minimum size for IPv4
        return 0;
    }

    // Check SOCKS5 UDP header
    if (data[0] != 0x00 || data[1] != 0x00) { // RSV must be 0
        return 0;
    }

    if (data[2] != 0x00) { // FRAG must be 0 (no fragmentation support)
        return 0;
    }

    uint8_t atyp = data[3];
    int address_len = 0;
    int port_offset = 0;

    if (atyp == 0x01) { // IPv4
        if (data_len < 10) return 0;

        // Extract IPv4 address
        struct in_addr addr;
        memcpy(&addr, &data[4], 4);
        inet_ntop(AF_INET, &addr, target_host, INET_ADDRSTRLEN);

        address_len = 4;
        port_offset = 8;
    } else if (atyp == 0x03) { // Domain name
        if (data_len < 7) return 0;

        uint8_t domain_len = data[4];
        if (data_len < 7 + domain_len) return 0;

        // Extract domain name
        memcpy(target_host, &data[5], domain_len);
        target_host[domain_len] = '\0';

        address_len = 1 + domain_len;
        port_offset = 4 + address_len;
    } else {
        // IPv6 or other address types not supported
        return 0;
    }

    // Extract port
    uint16_t port_network;
    memcpy(&port_network, &data[port_offset], 2);
    *target_port = ntohs(port_network);

    // Extract payload
    int header_len = 4 + address_len + 2;
    *payload = &data[header_len];
    *payload_len = data_len - header_len;

    return 1;
}
