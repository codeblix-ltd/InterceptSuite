/*
 * TLS MITM Proxy - SOCKS5 Protocol Implementation
 */

#include "../include/socks5.h"
#include "../include/utils.h"

/* Debug function to print buffer contents in hex */
static void debug_print_buffer(const char *prefix, const unsigned char *buffer, int length) {
    if (config.verbose) {
        printf("%s: ", prefix);
        for (int i = 0; i < length; i++) {
            printf("%02x ", buffer[i]);
        }
        printf("\n");
        fflush(stdout);
    }
}

int handle_socks5_handshake(socket_t client_sock, char *target_host, int *target_port) {
    unsigned char buffer[512];
    int received, i, total_received = 0;
    unsigned char reply[10] = {0};
    int has_no_auth = 0;

    // Log start of SOCKS5 handshake
    log_message("Starting SOCKS5 handshake with client");

    // Set socket timeout to 60 seconds - longer timeout for better compatibility
    DWORD timeout = 60000;
    if (setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) != 0 ||
        setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) != 0) {
        log_message("Warning: Failed to set socket timeout for SOCKS5: %d", WSAGetLastError());
    }

    // Step 1: Authentication Method Negotiation
    memset(buffer, 0, sizeof(buffer));

    // Read bytes in a loop until we get the complete greeting
    while (total_received < 2) {
        received = recv(client_sock, (char*)buffer + total_received, 2 - total_received, 0);
        if (received <= 0) {
            int err = WSAGetLastError();
            if (config.verbose) {
                printf("SOCKS5 error receiving greeting: %d (received %d/%d bytes)\n",
                       err, total_received, 2);
            }
            return 0;
        }
        total_received += received;
    }

    debug_print_buffer("Initial greeting", buffer, 2);

    if (buffer[0] != 5) {  // Must be SOCKS5
        if (config.verbose) {
            printf("Not a SOCKS5 request (version: %d)\n", buffer[0]);
        }
        return 0;
    }

    // Get number of authentication methods
    int nmethods = buffer[1];
    if (nmethods <= 0) {
        if (config.verbose) {
            printf("Invalid number of authentication methods: %d\n", nmethods);
        }
        return 0;
    }

    // Receive authentication methods with proper loop to ensure we get all data
    total_received = 0;
    while (total_received < nmethods) {
        received = recv(client_sock, (char*)buffer + total_received, nmethods - total_received, 0);
        if (received <= 0) {
            if (config.verbose) {
                printf("Failed to receive auth methods: %d\n", WSAGetLastError());
            }
            return 0;
        }
        total_received += received;
    }

    debug_print_buffer("Auth methods", buffer, nmethods);
      // Check if method 0 (no authentication) is supported
    for (i = 0; i < nmethods; i++) {
        if (buffer[i] == SOCKS5_AUTH_NONE) {
            has_no_auth = 1;
            break;
        }
    }

    if (!has_no_auth) {
        if (config.verbose) {
            printf("No auth method not supported by client\n");
        }
        log_message("Client doesn't support no-auth method, rejecting");

        // Send auth method not supported
        reply[0] = SOCKS5_VERSION;
        reply[1] = SOCKS5_AUTH_NO_ACCEPTABLE;  // No acceptable methods
        if (send(client_sock, (char*)reply, 2, 0) != 2) {
            int error = WSAGetLastError();
            if (config.verbose) {
                printf("Failed to send auth rejection: %d\n", error);
            }
            log_message("Failed to send auth rejection: %d", error);
        }
        return 0;
    }

    log_message("Client supports no-auth method, proceeding");

    // We support method 0 (no authentication required)
    memset(reply, 0, sizeof(reply));
    reply[0] = SOCKS5_VERSION;
    reply[1] = SOCKS5_AUTH_NONE;

    int sent = 0;
    while (sent < 2) {
        int result = send(client_sock, (char*)reply + sent, 2 - sent, 0);
        if (result <= 0) {
            if (config.verbose) {
                printf("Failed to send auth method response: %d\n", WSAGetLastError());
            }
            return 0;
        }
        sent += result;
    }

    if (config.verbose) {
        printf("SOCKS5 authentication negotiation successful\n");
    }
      // Step 2: Client Connection Request
    memset(buffer, 0, sizeof(buffer));
    total_received = 0;

    // Read connection request in a loop to ensure we get all 4 bytes
    while (total_received < 4) {
        received = recv(client_sock, (char*)buffer + total_received, 4 - total_received, 0);
        if (received <= 0) {
            if (config.verbose) {
                printf("Failed to receive connection request: %d\n", WSAGetLastError());
            }
            return 0;
        }
        total_received += received;
    }

    debug_print_buffer("Connection request header", buffer, 4);
      // Check SOCKS version and command
    if (buffer[0] != SOCKS5_VERSION) {
        if (config.verbose) {
            printf("Not a SOCKS5 request (version: %d)\n", buffer[0]);
        }
        log_message("Invalid SOCKS version: received %d, expected %d", buffer[0], SOCKS5_VERSION);
        return 0;
    }

    // Only support CONNECT command
    if (buffer[1] != SOCKS5_CMD_CONNECT) {
        if (config.verbose) {
            printf("Unsupported command: %d (only CONNECT=%d supported)\n", buffer[1], SOCKS5_CMD_CONNECT);
        }
        // Send command not supported response
        memset(reply, 0, sizeof(reply));
        reply[0] = SOCKS5_VERSION;
        reply[1] = SOCKS5_REPLY_CMD_NOTSUP;  // Command not supported
        reply[2] = 0;  // Reserved
        reply[3] = SOCKS5_ADDR_IPV4;  // IPv4
        memset(reply + 4, 0, 6);  // Address and port all zeros

        int sent = 0;
        while (sent < 10) {
            int result = send(client_sock, (char*)reply + sent, 10 - sent, 0);
            if (result <= 0) {
                if (config.verbose) {
                    printf("Failed to send command rejection: %d\n", WSAGetLastError());
                }
                break;
            }
            sent += result;
        }
        return 0;
    }

    // Check reserved byte (must be 0)
    if (buffer[2] != 0) {
        if (config.verbose) {
            printf("Reserved byte is not 0 (value: %d)\n", buffer[2]);
        }
        // Some clients might still work, so we'll continue
    }

    // Get address type
    unsigned char atyp = buffer[3];    // Step 3: Handle Address based on address type
    if (atyp == SOCKS5_ADDR_IPV4) {  // IPv4
        total_received = 0;
        while (total_received < 4) {
            received = recv(client_sock, (char*)buffer + total_received, 4 - total_received, 0);
            if (received <= 0) {
                int error = WSAGetLastError();
                if (config.verbose) {
                    printf("Failed to receive IPv4 address: %d\n", error);
                }
                log_message("Failed to receive IPv4 address: %d", error);
                return 0;
            }
            total_received += received;
        }

        debug_print_buffer("IPv4 address", buffer, 4);

        // Format IPv4 address as a string (e.g., "192.168.1.1")
        snprintf(target_host, MAX_HOSTNAME_LEN, "%d.%d.%d.%d", buffer[0], buffer[1], buffer[2], buffer[3]);

        log_message("Client requested connection to IPv4: %s", target_host);
    }
    else if (atyp == SOCKS5_ADDR_DOMAIN) {  // Domain name
        total_received = 0;
        while (total_received < 1) {
            received = recv(client_sock, (char*)buffer + total_received, 1 - total_received, 0);
            if (received <= 0) {
                if (config.verbose) {
                    printf("Failed to receive domain name length: %d\n", WSAGetLastError());
                }
                return 0;
            }
            total_received += received;
        }

        int domain_len = buffer[0];
        if (domain_len <= 0 || domain_len >= MAX_HOSTNAME_LEN - 1) {
            if (config.verbose) {
                printf("Invalid domain name length: %d\n", domain_len);
            }
            return 0;
        }

        // Receive domain name with proper loop to ensure complete data
        total_received = 0;
        while (total_received < domain_len) {
            received = recv(client_sock, (char*)buffer + total_received, domain_len - total_received, 0);
            if (received <= 0) {
                if (config.verbose) {
                    printf("Failed to receive domain name: %d\n", WSAGetLastError());
                }
                return 0;
            }
            total_received += received;
        }

        debug_print_buffer("Domain name", buffer, domain_len);

        // Copy domain name to target_host
        memcpy(target_host, buffer, domain_len);
        target_host[domain_len] = '\0';
    }    else if (atyp == SOCKS5_ADDR_IPV6) {  // IPv6
        if (config.verbose) {
            printf("IPv6 addresses are not supported\n");
        }
        log_message("Client requested unsupported IPv6 connection");

        // Send address type not supported response
        memset(reply, 0, sizeof(reply));
        reply[0] = SOCKS5_VERSION;
        reply[1] = SOCKS5_REPLY_ADDR_NOTSUP;  // Address type not supported
        reply[2] = 0;  // Reserved
        reply[3] = SOCKS5_ADDR_IPV4;  // IPv4
        memset(reply + 4, 0, 6);  // Address and port all zeros

        int sent = 0;
        while (sent < 10) {
            int result = send(client_sock, (char*)reply + sent, 10 - sent, 0);
            if (result <= 0) {
                if (config.verbose) {
                    printf("Failed to send IPv6 rejection: %d\n", WSAGetLastError());
                }
                break;
            }
            sent += result;
        }
        return 0;
    }
    else {  // Unknown address type
        if (config.verbose) {
            printf("Unknown address type: %d\n", atyp);
        }
        // Send address type not supported response
        memset(reply, 0, sizeof(reply));
        reply[0] = 5;
        reply[1] = 8;  // Address type not supported
        reply[2] = 0;
        reply[3] = 1;  // IPv4
        memset(reply + 4, 0, 6);  // Address and port all zeros

        int sent = 0;
        while (sent < 10) {
            int result = send(client_sock, (char*)reply + sent, 10 - sent, 0);
            if (result <= 0) {
                if (config.verbose) {
                    printf("Failed to send address type rejection: %d\n", WSAGetLastError());
                }
                break;
            }
            sent += result;
        }
        return 0;
    }
      // Step 4: Get Port (2 bytes, big-endian)
    total_received = 0;
    while (total_received < 2) {
        received = recv(client_sock, (char*)buffer + total_received, 2 - total_received, 0);
        if (received <= 0) {
            if (config.verbose) {
                printf("Failed to receive port: %d\n", WSAGetLastError());
            }
            return 0;
        }
        total_received += received;
    }

    debug_print_buffer("Port", buffer, 2);

    // Convert port from big-endian (network byte order)
    *target_port = (buffer[0] << 8) | buffer[1];

    if (config.verbose) {
        printf("SOCKS5 connection request for %s:%d\n", target_host, *target_port);
    }
      // Step 5: Send Success Response (BND.ADDR and BND.PORT are ignored by most clients)
    memset(reply, 0, sizeof(reply));
    reply[0] = SOCKS5_VERSION;    // SOCKS5
    reply[1] = SOCKS5_REPLY_SUCCESS;    // Success
    reply[2] = 0;    // Reserved
    reply[3] = SOCKS5_ADDR_IPV4;    // IPv4 address type

    // Get local address information for BND.ADDR
    struct in_addr addr;
    if (inet_pton(AF_INET, config.bind_addr, &addr) != 1) {
        // Fallback to localhost if bind_addr is invalid
        inet_pton(AF_INET, "127.0.0.1", &addr);
    }
    memcpy(&reply[4], &addr.s_addr, 4);

    // Use listening port for BND.PORT
    reply[8] = (config.port >> 8) & 0xFF;
    reply[9] = config.port & 0xFF;
      // Send response ensuring all bytes are sent
    int sent_bytes = 0;
    while (sent_bytes < 10) {
        int result = send(client_sock, (char*)reply + sent_bytes, 10 - sent_bytes, 0);
        if (result <= 0) {
            if (config.verbose) {
                printf("Failed to send success response: %d\n", WSAGetLastError());
            }
            return 0;
        }
        sent_bytes += result;
    }
      // Log successful handshake with more details
    log_message("SOCKS5 handshake completed successfully for %s:%d", target_host, *target_port);

    return 1;
}
