/*
 * TLS MITM Proxy - SOCKS5 Protocol Implementation
 */

#include "../include/socks5.h"

int handle_socks5_handshake(socket_t client_sock, char *target_host, int *target_port) {
    unsigned char buffer[512];
    int received;
    unsigned char reply[10] = {0};

    // Receive the initial greeting
    received = recv(client_sock, (char*)buffer, 2, 0);
    if (received != 2) {
        fprintf(stderr, "Failed to receive SOCKS5 greeting\n");
        return 0;
    }

    if (buffer[0] != 5) { // SOCKS5 version
        fprintf(stderr, "Unsupported SOCKS version: %d\n", buffer[0]);
        return 0;
    }

    int nmethods = buffer[1];
    received = recv(client_sock, (char*)buffer, nmethods, 0);
    if (received != nmethods) {
        fprintf(stderr, "Failed to receive auth methods\n");
        return 0;
    }

    // Send auth method choice (no auth)
    reply[0] = 5; // SOCKS5
    reply[1] = 0; // No auth
    if (send(client_sock, (char*)reply, 2, 0) != 2) {
        fprintf(stderr, "Failed to send auth method choice\n");
        return 0;
    }

    // Receive connection request
    received = recv(client_sock, (char*)buffer, 4, 0);
    if (received != 4) {
        fprintf(stderr, "Failed to receive connection request\n");
        return 0;
    }

    if (buffer[0] != 5) { // SOCKS5 version
        fprintf(stderr, "Unsupported SOCKS version: %d\n", buffer[0]);
        return 0;
    }

    if (buffer[1] != 1) { // Only support CONNECT command
        fprintf(stderr, "Unsupported command: %d\n", buffer[1]);
        return 0;
    }

    int atyp = buffer[3];
    if (atyp == 1) {
        // IPv4 address
        received = recv(client_sock, (char*)buffer, 4, 0);
        if (received != 4) {
            fprintf(stderr, "Failed to receive IPv4 address\n");
            return 0;
        }

        // Convert IPv4 address to string
        sprintf(target_host, "%d.%d.%d.%d", buffer[0], buffer[1], buffer[2], buffer[3]);
    }
    else if (atyp == 3) {
        // Domain name
        received = recv(client_sock, (char*)buffer, 1, 0);
        if (received != 1) {
            fprintf(stderr, "Failed to receive domain name length\n");
            return 0;
        }

        int domain_len = buffer[0];
        received = recv(client_sock, (char*)buffer, domain_len, 0);
        if (received != domain_len) {
            fprintf(stderr, "Failed to receive domain name\n");
            return 0;
        }

        // Copy domain name to target_host
        memcpy(target_host, buffer, domain_len);
        target_host[domain_len] = '\0';
    }
    else if (atyp == 4) {
        // IPv6 address
        // For simplicity, we'll just read the 16 bytes and not try to convert them to a string
        received = recv(client_sock, (char*)buffer, 16, 0);
        if (received != 16) {
            fprintf(stderr, "Failed to receive IPv6 address\n");
            return 0;
        }

        sprintf(target_host, "IPv6"); // Placeholder
        fprintf(stderr, "IPv6 addresses are not fully supported\n");
    }
    else {
        fprintf(stderr, "Unsupported address type: %d\n", atyp);
        return 0;
    }

    // Receive port
    received = recv(client_sock, (char*)buffer, 2, 0);
    if (received != 2) {
        fprintf(stderr, "Failed to receive port\n");
        return 0;
    }

    *target_port = (buffer[0] << 8) | buffer[1];

    // Send success response
    memset(reply, 0, sizeof(reply));
    reply[0] = 5; // SOCKS5
    reply[1] = 0; // Success
    reply[2] = 0; // Reserved
    reply[3] = 1; // IPv4
    // IP address (all zeros for 0.0.0.0)
    // Port (all zeros)

    if (send(client_sock, (char*)reply, 10, 0) != 10) {
        fprintf(stderr, "Failed to send success response\n");
        return 0;
    }

    return 1;
}
