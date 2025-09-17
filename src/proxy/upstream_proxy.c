/*
 * Intercept Suite - Upstream Proxy Support Implementation
 *
 * Implements routing traffic through upstream HTTP CONNECT and SOCKS5 proxies.
 */

#include "upstream_proxy.h"
#include "../utils/utils.h"
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#ifdef INTERCEPT_WINDOWS
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

/* Global upstream proxy configuration */
upstream_proxy_config_t g_upstream_proxy_config = {0};

static int base64_encode(const char* input, int input_len, char* output, int output_size) {
    int encoded_len = EVP_EncodeBlock((unsigned char*)output, (const unsigned char*)input, input_len);

    if (encoded_len < 0 || encoded_len >= output_size) {
        return 0; /* Error or buffer too small */
    }

    output[encoded_len] = '\0';
    return 1; /* Success */
}

/* Initialize upstream proxy configuration with defaults */
void init_upstream_proxy_config(void) {
    memset(&g_upstream_proxy_config, 0, sizeof(g_upstream_proxy_config));
    g_upstream_proxy_config.enabled = 0;
    g_upstream_proxy_config.type = UPSTREAM_PROXY_NONE;
    g_upstream_proxy_config.port = 0;
    g_upstream_proxy_config.use_auth = 0;
}

/* API Functions for configuration */
INTERCEPT_API void set_upstream_proxy_enabled(int enabled) {
    g_upstream_proxy_config.enabled = enabled ? 1 : 0;
    if (config.verbose) {
        log_message("Upstream proxy %s", enabled ? "enabled" : "disabled");
    }
}

INTERCEPT_API void set_upstream_proxy_type(int type) {
    /* Convert int to enum and validate */
    if (type >= UPSTREAM_PROXY_NONE && type <= UPSTREAM_PROXY_SOCKS5) {
        g_upstream_proxy_config.type = (upstream_proxy_type_t)type;
    } else {
        g_upstream_proxy_config.type = UPSTREAM_PROXY_NONE;
        if (config.verbose) {
            log_message("Invalid upstream proxy type %d, defaulting to NONE", type);
        }
        return;
    }

    if (config.verbose) {
        const char* type_str = (type == UPSTREAM_PROXY_HTTP) ? "HTTP CONNECT" :
                              (type == UPSTREAM_PROXY_SOCKS5) ? "SOCKS5" : "NONE";
        log_message("Upstream proxy type set to: %s", type_str);
    }
}

INTERCEPT_API void set_upstream_proxy_host(const char* host) {
    if (host && strlen(host) < UPSTREAM_PROXY_MAX_HOST) {
        safe_strncpy(g_upstream_proxy_config.host, sizeof(g_upstream_proxy_config.host), host);
        if (config.verbose) {
            log_message("Upstream proxy host set to: %s", host);
        }
    }
}

INTERCEPT_API void set_upstream_proxy_port(int port) {
    if (port > 0 && port <= 65535) {
        g_upstream_proxy_config.port = port;
        if (config.verbose) {
            log_message("Upstream proxy port set to: %d", port);
        }
    }
}

INTERCEPT_API void set_upstream_proxy_auth(const char* username, const char* password) {
    if (username && password) {
        safe_strncpy(g_upstream_proxy_config.username, sizeof(g_upstream_proxy_config.username), username);
        safe_strncpy(g_upstream_proxy_config.password, sizeof(g_upstream_proxy_config.password), password);
        g_upstream_proxy_config.use_auth = 1;
        if (config.verbose) {
            log_message("Upstream proxy authentication configured for user: %s", username);
        }
    }
}

INTERCEPT_API void disable_upstream_proxy_auth(void) {
    memset(g_upstream_proxy_config.username, 0, sizeof(g_upstream_proxy_config.username));
    memset(g_upstream_proxy_config.password, 0, sizeof(g_upstream_proxy_config.password));
    g_upstream_proxy_config.use_auth = 0;
    if (config.verbose) {
        log_message("Upstream proxy authentication disabled");
    }
}

INTERCEPT_API upstream_proxy_config_t* get_upstream_proxy_config(void) {
    return &g_upstream_proxy_config;
}

INTERCEPT_API int configure_upstream_proxy(int type, const char* host, int port,
                                          const char* username, const char* password) {
    if (!host || port <= 0 || port > 65535) {
        return 0; /* Invalid parameters */
    }

    set_upstream_proxy_type(type);
    set_upstream_proxy_host(host);
    set_upstream_proxy_port(port);

    if (username && password && strlen(username) > 0 && strlen(password) > 0) {
        set_upstream_proxy_auth(username, password);
    } else {
        disable_upstream_proxy_auth();
    }

    set_upstream_proxy_enabled(1);

    if (config.verbose) {
        const char* type_str = (type == UPSTREAM_PROXY_HTTP) ? "http" :
                              (type == UPSTREAM_PROXY_SOCKS5) ? "socks5" : "none";
        log_message("Upstream proxy configured: %s://%s:%d", type_str, host, port);
    }

    return 1; /* Success */
}

int should_use_upstream_proxy(const char* target_host, int target_port) {
    return g_upstream_proxy_config.enabled;
}

/* Main connection function - routes through appropriate proxy */
// Need to figure out the possible ways for early HTTP Detection
socket_t connect_through_upstream_proxy(const char* target_host, int target_port) {
    if (!should_use_upstream_proxy(target_host, target_port)) {
        return INVALID_SOCKET;
    }

    switch (g_upstream_proxy_config.type) {
        case UPSTREAM_PROXY_HTTP:
            return connect_through_http_proxy(target_host, target_port);

        case UPSTREAM_PROXY_SOCKS5:
            return connect_through_socks5_proxy(target_host, target_port);

        default:
            return INVALID_SOCKET;
    }
}

/* HTTP CONNECT proxy implementation */
socket_t connect_through_http_proxy(const char* target_host, int target_port) {
    socket_t proxy_sock = INVALID_SOCKET;
    struct sockaddr_in proxy_addr;
    char request[1024];
    char response[1024];
    int bytes_sent, bytes_received;

    proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_sock == INVALID_SOCKET) {
        log_message("Failed to create socket for HTTP proxy connection");
        return INVALID_SOCKET;
    }

    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(g_upstream_proxy_config.port);

    struct hostent* proxy_host = gethostbyname(g_upstream_proxy_config.host);
    if (!proxy_host) {
        log_message("Failed to resolve HTTP proxy hostname: %s", g_upstream_proxy_config.host);
        close_socket(proxy_sock);
        return INVALID_SOCKET;
    }
    memcpy(&proxy_addr.sin_addr, proxy_host->h_addr, proxy_host->h_length);

    if (connect(proxy_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) != 0) {
        log_message("Failed to connect to HTTP proxy %s:%d",
                   g_upstream_proxy_config.host, g_upstream_proxy_config.port);
        close_socket(proxy_sock);
        return INVALID_SOCKET;
    }

    if (g_upstream_proxy_config.use_auth) {
        char auth_string[512];
        char encoded_auth[768]; /* Base64 encoding can be up to 4 times larger, need to validatee the size limit*/

        snprintf(auth_string, sizeof(auth_string), "%s:%s",
                g_upstream_proxy_config.username, g_upstream_proxy_config.password);

        if (!base64_encode(auth_string, (int)strlen(auth_string), encoded_auth, sizeof(encoded_auth))) {
            log_message("Failed to encode authentication credentials");
            close_socket(proxy_sock);
            return INVALID_SOCKET;
        }

        snprintf(request, sizeof(request),
                "CONNECT %s:%d HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "Proxy-Authorization: Basic %s\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "\r\n",
                target_host, target_port, target_host, target_port, encoded_auth);
    } else {
        snprintf(request, sizeof(request),
                "CONNECT %s:%d HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "\r\n",
                target_host, target_port, target_host, target_port);
    }

    bytes_sent = send(proxy_sock, request, (int)strlen(request), 0);
    if (bytes_sent <= 0) {
        log_message("Failed to send CONNECT request to HTTP proxy");
        close_socket(proxy_sock);
        return INVALID_SOCKET;
    }

    bytes_received = recv(proxy_sock, response, sizeof(response) - 1, 0);
    if (bytes_received <= 0) {
        log_message("Failed to receive response from HTTP proxy");
        close_socket(proxy_sock);
        return INVALID_SOCKET;
    }

    response[bytes_received] = '\0';

    if (strstr(response, "200") == NULL) {
        log_message("HTTP proxy CONNECT failed: %s", response);
        close_socket(proxy_sock);
        return INVALID_SOCKET;
    }

    if (config.verbose) {
        log_message("Successfully connected through HTTP proxy to %s:%d", target_host, target_port);
    }

    return proxy_sock;
}

socket_t connect_through_socks5_proxy(const char* target_host, int target_port) {
    socket_t proxy_sock = INVALID_SOCKET;
    struct sockaddr_in proxy_addr;
    unsigned char buffer[512];
    int bytes_sent, bytes_received;

    /* Create socket to proxy */
    proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_sock == INVALID_SOCKET) {
        log_message("Failed to create socket for SOCKS5 proxy connection");
        return INVALID_SOCKET;
    }

    /* Connect to proxy server */
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(g_upstream_proxy_config.port);

    struct hostent* proxy_host = gethostbyname(g_upstream_proxy_config.host);
    if (!proxy_host) {
        log_message("Failed to resolve SOCKS5 proxy hostname: %s", g_upstream_proxy_config.host);
        close_socket(proxy_sock);
        return INVALID_SOCKET;
    }
    memcpy(&proxy_addr.sin_addr, proxy_host->h_addr, proxy_host->h_length);

    if (connect(proxy_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) != 0) {
        log_message("Failed to connect to SOCKS5 proxy %s:%d",
                   g_upstream_proxy_config.host, g_upstream_proxy_config.port);
        close_socket(proxy_sock);
        return INVALID_SOCKET;
    }

    /* SOCKS5 handshake - authentication method negotiation */
    buffer[0] = 0x05; /* SOCKS version 5 */
    buffer[1] = g_upstream_proxy_config.use_auth ? 0x02 : 0x01; /* Number of auth methods */
    buffer[2] = 0x00; /* No authentication */
    if (g_upstream_proxy_config.use_auth) {
        buffer[3] = 0x02; /* Username/password authentication */
    }

    bytes_sent = send(proxy_sock, (char*)buffer, g_upstream_proxy_config.use_auth ? 4 : 3, 0);
    if (bytes_sent <= 0) {
        log_message("Failed to send SOCKS5 handshake");
        close_socket(proxy_sock);
        return INVALID_SOCKET;
    }

    bytes_received = recv(proxy_sock, (char*)buffer, 2, 0);
    if (bytes_received != 2 || buffer[0] != 0x05) {
        log_message("Invalid SOCKS5 handshake response");
        close_socket(proxy_sock);
        return INVALID_SOCKET;
    }

    /* Handle authentication if required */
    if (buffer[1] == 0x02 && g_upstream_proxy_config.use_auth) {
        int username_len = (int)strlen(g_upstream_proxy_config.username);
        int password_len = (int)strlen(g_upstream_proxy_config.password);

        buffer[0] = 0x01; /* Auth version */
        buffer[1] = (unsigned char)username_len;
        memcpy(&buffer[2], g_upstream_proxy_config.username, username_len);
        buffer[2 + username_len] = (unsigned char)password_len;
        memcpy(&buffer[3 + username_len], g_upstream_proxy_config.password, password_len);

        bytes_sent = send(proxy_sock, (char*)buffer, 3 + username_len + password_len, 0);
        if (bytes_sent <= 0) {
            log_message("Failed to send SOCKS5 authentication");
            close_socket(proxy_sock);
            return INVALID_SOCKET;
        }

        bytes_received = recv(proxy_sock, (char*)buffer, 2, 0);
        if (bytes_received != 2 || buffer[1] != 0x00) {
            log_message("SOCKS5 authentication failed");
            close_socket(proxy_sock);
            return INVALID_SOCKET;
        }
    } else if (buffer[1] != 0x00) {
        log_message("SOCKS5 proxy rejected authentication method");
        close_socket(proxy_sock);
        return INVALID_SOCKET;
    }

    /* SOCKS5 connect request */
    int hostname_len = (int)strlen(target_host);
    buffer[0] = 0x05; /* SOCKS version */
    buffer[1] = 0x01; /* CONNECT command */
    buffer[2] = 0x00; /* Reserved */
    buffer[3] = 0x03; /* Domain name address type */
    buffer[4] = (unsigned char)hostname_len;
    memcpy(&buffer[5], target_host, hostname_len);
    buffer[5 + hostname_len] = (unsigned char)(target_port >> 8);
    buffer[6 + hostname_len] = (unsigned char)(target_port & 0xFF);

    bytes_sent = send(proxy_sock, (char*)buffer, 7 + hostname_len, 0);
    if (bytes_sent <= 0) {
        log_message("Failed to send SOCKS5 connect request");
        close_socket(proxy_sock);
        return INVALID_SOCKET;
    }

    /* Read connect response */
    bytes_received = recv(proxy_sock, (char*)buffer, 10, 0);
    if (bytes_received < 10 || buffer[0] != 0x05 || buffer[1] != 0x00) {
        log_message("SOCKS5 connect failed with code: %d", buffer[1]);
        close_socket(proxy_sock);
        return INVALID_SOCKET;
    }

    if (config.verbose) {
        log_message("Successfully connected through SOCKS5 proxy to %s:%d", target_host, target_port);
    }

    return proxy_sock;
}

/* UDP support for SOCKS5 proxy  - Need to test via VPN Once implemented*/
int should_use_upstream_proxy_udp(const char* target_host, int target_port) {
    if (!g_upstream_proxy_config.enabled) {
        return 0;
    }

    /* Only SOCKS5 supports UDP   - Won't work if UpStream Socks5 Proxy doesn't support UDP Associate
    Need to figure out Ways to detect and exclude it directly or via User upstream Config
    */
    return (g_upstream_proxy_config.type == UPSTREAM_PROXY_SOCKS5);
}

/* Setup SOCKS5 UDP ASSOCIATE for UDP traffic */
int setup_socks5_udp_associate(socket_t* control_sock, struct sockaddr_in* udp_relay_addr) {
    unsigned char buffer[512];
    int bytes_sent, bytes_received;
    struct sockaddr_in proxy_addr;

    if (!control_sock || !udp_relay_addr) {
        return 0;
    }

    /* Create control connection to SOCKS5 proxy */
    *control_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (*control_sock == INVALID_SOCKET) {
        log_message("Failed to create control socket for SOCKS5 UDP ASSOCIATE");
        return 0;
    }

    /* Connect to proxy server */
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(g_upstream_proxy_config.port);

    struct hostent* proxy_host = gethostbyname(g_upstream_proxy_config.host);
    if (!proxy_host) {
        log_message("Failed to resolve SOCKS5 proxy hostname for UDP: %s", g_upstream_proxy_config.host);
        close_socket(*control_sock);
        return 0;
    }
    memcpy(&proxy_addr.sin_addr, proxy_host->h_addr, proxy_host->h_length);

    if (connect(*control_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) != 0) {
        log_message("Failed to connect to SOCKS5 proxy for UDP: %s:%d",
                   g_upstream_proxy_config.host, g_upstream_proxy_config.port);
        close_socket(*control_sock);
        return 0;
    }

    /* SOCKS5 handshake (same as TCP) */
    buffer[0] = 0x05; /* SOCKS version 5 */
    buffer[1] = g_upstream_proxy_config.use_auth ? 0x02 : 0x01; /* Number of auth methods */
    buffer[2] = 0x00; /* No authentication */
    if (g_upstream_proxy_config.use_auth) {
        buffer[3] = 0x02; /* Username/password authentication */
    }

    bytes_sent = send(*control_sock, (char*)buffer, g_upstream_proxy_config.use_auth ? 4 : 3, 0);
    if (bytes_sent <= 0) {
        log_message("Failed to send SOCKS5 handshake for UDP");
        close_socket(*control_sock);
        return 0;
    }

    bytes_received = recv(*control_sock, (char*)buffer, 2, 0);
    if (bytes_received != 2 || buffer[0] != 0x05) {
        log_message("Invalid SOCKS5 handshake response for UDP");
        close_socket(*control_sock);
        return 0;
    }

    /* Handle authentication if required (same as TCP) */
    if (buffer[1] == 0x02 && g_upstream_proxy_config.use_auth) {
        int username_len = (int)strlen(g_upstream_proxy_config.username);
        int password_len = (int)strlen(g_upstream_proxy_config.password);

        buffer[0] = 0x01; /* Auth version */
        buffer[1] = (unsigned char)username_len;
        memcpy(&buffer[2], g_upstream_proxy_config.username, username_len);
        buffer[2 + username_len] = (unsigned char)password_len;
        memcpy(&buffer[3 + username_len], g_upstream_proxy_config.password, password_len);

        bytes_sent = send(*control_sock, (char*)buffer, 3 + username_len + password_len, 0);
        if (bytes_sent <= 0) {
            log_message("Failed to send SOCKS5 authentication for UDP");
            close_socket(*control_sock);
            return 0;
        }

        bytes_received = recv(*control_sock, (char*)buffer, 2, 0);
        if (bytes_received != 2 || buffer[1] != 0x00) {
            log_message("SOCKS5 authentication failed for UDP");
            close_socket(*control_sock);
            return 0;
        }
    } else if (buffer[1] != 0x00) {
        log_message("SOCKS5 proxy rejected authentication method for UDP");
        close_socket(*control_sock);
        return 0;
    }

    /* Send UDP ASSOCIATE request */
    buffer[0] = 0x05; /* SOCKS version */
    buffer[1] = 0x03; /* UDP ASSOCIATE command */
    buffer[2] = 0x00; /* Reserved */
    buffer[3] = 0x01; /* IPv4 address type */
    memset(&buffer[4], 0, 4); /* 0.0.0.0 - let proxy choose */
    memset(&buffer[8], 0, 2); /* Port 0 - let proxy choose */

    bytes_sent = send(*control_sock, (char*)buffer, 10, 0);
    if (bytes_sent <= 0) {
        log_message("Failed to send SOCKS5 UDP ASSOCIATE request");
        close_socket(*control_sock);
        return 0;
    }

    /* Read UDP ASSOCIATE response */
    bytes_received = recv(*control_sock, (char*)buffer, 10, 0);
    if (bytes_received < 10 || buffer[0] != 0x05 || buffer[1] != 0x00) {
        log_message("SOCKS5 UDP ASSOCIATE failed with code: %d", buffer[1]);
        close_socket(*control_sock);
        return 0;
    }

    /* Extract UDP relay server address and port */
    memset(udp_relay_addr, 0, sizeof(*udp_relay_addr));
    udp_relay_addr->sin_family = AF_INET;
    memcpy(&udp_relay_addr->sin_addr, &buffer[4], 4);
    memcpy(&udp_relay_addr->sin_port, &buffer[8], 2);

    if (config.verbose) {
        char relay_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &udp_relay_addr->sin_addr, relay_ip, INET_ADDRSTRLEN);
        log_message("SOCKS5 UDP ASSOCIATE successful. Relay server: %s:%d",
                   relay_ip, ntohs(udp_relay_addr->sin_port));
    }

    return 1; /* Success */
}

/* Send UDP packet through SOCKS5 proxy */
int send_udp_through_socks5(socket_t udp_sock, const struct sockaddr_in* relay_addr,
                           const char* target_host, int target_port,
                           const unsigned char* data, int data_len) {
    unsigned char buffer[65536]; /* Max UDP packet size */
    int header_len;
    int total_len;
    int hostname_len;

    if (!relay_addr || !target_host || !data || data_len <= 0) {
        return 0;
    }

    hostname_len = (int)strlen(target_host);
    if (hostname_len > 255) {
        log_message("Target hostname too long for SOCKS5 UDP: %s", target_host);
        return 0;
    }

    /* Build SOCKS5 UDP request header */
    buffer[0] = 0x00; /* Reserved */
    buffer[1] = 0x00; /* Reserved */
    buffer[2] = 0x00; /* Fragment number (0 = not fragmented) */
    buffer[3] = 0x03; /* Domain name address type */
    buffer[4] = (unsigned char)hostname_len;
    memcpy(&buffer[5], target_host, hostname_len);
    buffer[5 + hostname_len] = (unsigned char)(target_port >> 8);
    buffer[6 + hostname_len] = (unsigned char)(target_port & 0xFF);

    header_len = 7 + hostname_len;

    /* Append UDP data */
    if (header_len + data_len > sizeof(buffer)) {
        log_message("UDP packet too large for SOCKS5: %d bytes", header_len + data_len);
        return 0;
    }

    memcpy(&buffer[header_len], data, data_len);
    total_len = header_len + data_len;

    /* Send to UDP relay server */
    int bytes_sent = sendto(udp_sock, (char*)buffer, total_len, 0,
                           (struct sockaddr*)relay_addr, sizeof(*relay_addr));

    if (bytes_sent != total_len) {
        log_message("Failed to send UDP packet through SOCKS5 proxy");
        return 0;
    }

    if (config.verbose) {
        log_message("Sent UDP packet through SOCKS5 to %s:%d (%d bytes)",
                   target_host, target_port, data_len);
    }

    return 1; /* Success */
}

/* Get current upstream proxy status for GUI/API */
INTERCEPT_API upstream_proxy_status_t get_upstream_proxy_status(void) {
    upstream_proxy_status_t status = {0};

    status.enabled = g_upstream_proxy_config.enabled;
    status.type = (int)g_upstream_proxy_config.type;
    safe_strncpy(status.host, sizeof(status.host), g_upstream_proxy_config.host);
    status.port = g_upstream_proxy_config.port;
    status.use_auth = g_upstream_proxy_config.use_auth;

    if (g_upstream_proxy_config.use_auth) {
        safe_strncpy(status.username, sizeof(status.username), g_upstream_proxy_config.username);
        /* Note: We don't return the password for security reasons */
    }

    return status;
}

/* Exported UDP functions for GUI/API */
INTERCEPT_API int setup_upstream_proxy_udp(int* control_sock_out, char* relay_ip_out, int* relay_port_out) {
    socket_t control_sock;
    struct sockaddr_in udp_relay_addr;

    if (!control_sock_out || !relay_ip_out || !relay_port_out) {
        return 0;
    }

    if (!setup_socks5_udp_associate(&control_sock, &udp_relay_addr)) {
        return 0;
    }

    *control_sock_out = (int)control_sock;
    inet_ntop(AF_INET, &udp_relay_addr.sin_addr, relay_ip_out, INET_ADDRSTRLEN);
    *relay_port_out = ntohs(udp_relay_addr.sin_port);

    return 1;
}

INTERCEPT_API int send_udp_via_upstream_proxy(int udp_sock, const char* relay_ip, int relay_port,
                                             const char* target_host, int target_port,
                                             const unsigned char* data, int data_len) {
    struct sockaddr_in relay_addr;

    if (!relay_ip || !target_host || !data) {
        return 0;
    }

    memset(&relay_addr, 0, sizeof(relay_addr));
    relay_addr.sin_family = AF_INET;
    relay_addr.sin_port = htons(relay_port);

    if (inet_pton(AF_INET, relay_ip, &relay_addr.sin_addr) != 1) {
        log_message("Invalid relay IP address: %s", relay_ip);
        return 0;
    }

    return send_udp_through_socks5((socket_t)udp_sock, &relay_addr, target_host, target_port, data, data_len);
}