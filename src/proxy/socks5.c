/*
 * TLS MITM Proxy - SOCKS5 Protocol Implementation
 */

#include "socks5.h"

#include "../utils/utils.h"

#ifndef INTERCEPT_WINDOWS
#include <errno.h>

#include <string.h> /* for strerror() */

#endif

/* Debug function to print buffer contents in hex - disabled for production */
static void debug_print_buffer(const char * prefix,
  const unsigned char * buffer, int length) {
  // Debug buffer printing disabled for production
}

int handle_socks5_handshake(socket_t client_sock, char * target_host, int * target_port) {
  unsigned char buffer[512];
  int received, i, total_received = 0;
  unsigned char reply[10] = {
    0
  };
  int has_no_auth = 0;

  // Set socket timeout to 60 seconds - longer timeout for better compatibility
  #ifdef INTERCEPT_WINDOWS
  DWORD timeout = 60000; // 60 seconds in milliseconds for Windows
  #else
  struct timeval timeout;
  timeout.tv_sec = 60; // 60 seconds for POSIX
  timeout.tv_usec = 0;
  #endif
  if (setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char * ) & timeout, sizeof(timeout)) != 0 ||
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char * ) & timeout, sizeof(timeout)) != 0) {
    // Failed to set socket timeout (non-critical)
  }

  // Step 1: Authentication Method Negotiation
  memset(buffer, 0, sizeof(buffer));

  // Read bytes in a loop until we get the complete greeting
  while (total_received < 2) {
    received = recv(client_sock, (char * ) buffer + total_received, 2 - total_received, 0);
    if (received <= 0) {
      return 0;
    }
    total_received += received;
  }

  if (buffer[0] != 5) { // Must be SOCKS5
    return 0;
  }

  // Get number of authentication methods
  int nmethods = buffer[1];
  if (nmethods <= 0) {
    return 0;
  }

  // Receive authentication methods with proper loop to ensure we get all data
  total_received = 0;
  while (total_received < nmethods) {
    received = recv(client_sock, (char * ) buffer + total_received, nmethods - total_received, 0);
    if (received <= 0) {
      return 0;
    }
    total_received += received;
  }

  // Check if method 0 (no authentication) is supported
  for (i = 0; i < nmethods; i++) {
    if (buffer[i] == SOCKS5_AUTH_NONE) {
      has_no_auth = 1;
      break;
    }
  }

  if (!has_no_auth) {
    // Send auth method not supported
    reply[0] = SOCKS5_VERSION;
    reply[1] = SOCKS5_AUTH_NO_ACCEPTABLE; // No acceptable methods
    if (send(client_sock, (char * ) reply, 2, 0) != 2) {
      // Failed to send rejection response
    }
    return 0;
  }

  // We support method 0 (no authentication required)
  memset(reply, 0, sizeof(reply));
  reply[0] = SOCKS5_VERSION;
  reply[1] = SOCKS5_AUTH_NONE;

  int sent = 0;
  while (sent < 2) {
    int result = send(client_sock, (char * ) reply + sent, 2 - sent, 0);
    if (result <= 0) {
      return 0;
    }
    sent += result;
  }

  // Step 2: Client Connection Request
  memset(buffer, 0, sizeof(buffer));
  total_received = 0;

  // Read connection request in a loop to ensure we get all 4 bytes
  while (total_received < 4) {
    received = recv(client_sock, (char * ) buffer + total_received, 4 - total_received, 0);
    if (received <= 0) {
      return 0;
    }
    total_received += received;
  }

  // Check SOCKS version and command
  if (buffer[0] != SOCKS5_VERSION) {
    return 0;
  }

  // Support CONNECT and UDP ASSOCIATE commands
  if (buffer[1] != SOCKS5_CMD_CONNECT && buffer[1] != SOCKS5_CMD_UDP_ASSOCIATE) {
    // Send command not supported response
    memset(reply, 0, sizeof(reply));
    reply[0] = SOCKS5_VERSION;
    reply[1] = SOCKS5_REPLY_CMD_NOTSUP; // Command not supported
    reply[2] = 0; // Reserved
    reply[3] = SOCKS5_ADDR_IPV4; // IPv4
    memset(reply + 4, 0, 6); // Address and port all zeros

    int sent = 0;
    while (sent < 10) {
      int result = send(client_sock, (char * ) reply + sent, 10 - sent, 0);
      if (result <= 0) {
        break;
      }
      sent += result;
    }
    return 0;
  }

  // Handle UDP ASSOCIATE command immediately
  if (buffer[1] == SOCKS5_CMD_UDP_ASSOCIATE) {
    // For UDP ASSOCIATE, we need to consume the remaining request data but don't process it
    // Read the reserved byte (already read), address type, address, and port to consume the full request

    // Get address type
    unsigned char atyp = buffer[3];
    int bytes_to_consume = 0;

    if (atyp == SOCKS5_ADDR_IPV4) {
      bytes_to_consume = 4 + 2; // 4 bytes for IPv4 + 2 bytes for port
    } else if (atyp == SOCKS5_ADDR_DOMAIN) {
      // Need to read domain length first
      char length_buffer[1];
      int received = recv(client_sock, length_buffer, 1, 0);
      if (received <= 0) {
        return 0;
      }
      bytes_to_consume = length_buffer[0] + 2; // domain length + 2 bytes for port
    } else if (atyp == SOCKS5_ADDR_IPV6) {
      bytes_to_consume = 16 + 2; // 16 bytes for IPv6 + 2 bytes for port
    } else {
      return 0;
    }

    // Consume the remaining bytes
    char consume_buffer[256];
    int total_consumed = 0;
    while (total_consumed < bytes_to_consume) {
      int received = recv(client_sock, consume_buffer + total_consumed, bytes_to_consume - total_consumed, 0);
      if (received <= 0) {
        return 0;
      }
      total_consumed += received;
    }

    // Send UDP ASSOCIATE response with UDP port information
    memset(reply, 0, sizeof(reply));
    reply[0] = SOCKS5_VERSION; // SOCKS5
    reply[1] = SOCKS5_REPLY_SUCCESS; // Success
    reply[2] = 0; // Reserved
    reply[3] = SOCKS5_ADDR_IPV4; // IPv4 address type

    // Get local address information for BND.ADDR
    struct in_addr addr;
    if (inet_pton(AF_INET, config.bind_addr, &addr) != 1) {
      // Fallback to localhost if bind_addr is invalid
      inet_pton(AF_INET, "127.0.0.1", &addr);
    }
    memcpy(&reply[4], &addr.s_addr, 4);

    // Use UDP relay port for BND.PORT (main port + 1)
    int udp_port = config.port + 1;
    reply[8] = (udp_port >> 8) & 0xFF;
    reply[9] = udp_port & 0xFF;

    // Send response ensuring all bytes are sent
    int sent_bytes = 0;
    while (sent_bytes < 10) {
      int result = send(client_sock, (char*)reply + sent_bytes, 10 - sent_bytes, 0);
      if (result <= 0) {
        return 0;
      }
      sent_bytes += result;
    }

    return SOCKS5_RESULT_UDP_ASSOCIATE; // Return special code for UDP ASSOCIATE
  }

  // Check reserved byte (must be 0)
  if (buffer[2] != 0) {
    // Some clients might still work, so we'll continue
  }

  // Get address type
  unsigned char atyp = buffer[3]; // Step 3: Handle Address based on address type
  if (atyp == SOCKS5_ADDR_IPV4) { // IPv4
    total_received = 0;
    while (total_received < 4) {
      received = recv(client_sock, (char * ) buffer + total_received, 4 - total_received, 0);
      if (received <= 0) {
        return 0;
      }
      total_received += received;
    }

    // Format IPv4 address as a string (e.g., "192.168.1.1")
    snprintf(target_host, MAX_HOSTNAME_LEN, "%d.%d.%d.%d", buffer[0], buffer[1], buffer[2], buffer[3]);
  } else if (atyp == SOCKS5_ADDR_DOMAIN) { // Domain name
    total_received = 0;
    while (total_received < 1) {
      received = recv(client_sock, (char * ) buffer + total_received, 1 - total_received, 0);
      if (received <= 0) {
        return 0;
      }
      total_received += received;
    }

    int domain_len = buffer[0];
    if (domain_len <= 0 || domain_len >= MAX_HOSTNAME_LEN - 1) {
      return 0;
    }

    // Receive domain name with proper loop to ensure complete data
    total_received = 0;
    while (total_received < domain_len) {
      received = recv(client_sock, (char * ) buffer + total_received, domain_len - total_received, 0);
      if (received <= 0) {
        return 0;
      }
      total_received += received;
    }

    // Copy domain name to target_host
    memcpy(target_host, buffer, domain_len);
    target_host[domain_len] = '\0';
  } else if (atyp == SOCKS5_ADDR_IPV6) { // IPv6
    // Send address type not supported response
    memset(reply, 0, sizeof(reply));
    reply[0] = SOCKS5_VERSION;
    reply[1] = SOCKS5_REPLY_ADDR_NOTSUP; // Address type not supported
    reply[2] = 0; // Reserved
    reply[3] = SOCKS5_ADDR_IPV4; // IPv4
    memset(reply + 4, 0, 6); // Address and port all zeros

    int sent = 0;
    while (sent < 10) {
      int result = send(client_sock, (char * ) reply + sent, 10 - sent, 0);
      if (result <= 0) {
        break;
      }
      sent += result;
    }
    return 0;
  } else { // Unknown address type
    // Send address type not supported response
    memset(reply, 0, sizeof(reply));
    reply[0] = 5;
    reply[1] = 8; // Address type not supported
    reply[2] = 0;
    reply[3] = 1; // IPv4
    memset(reply + 4, 0, 6); // Address and port all zeros

    int sent = 0;
    while (sent < 10) {
      int result = send(client_sock, (char * ) reply + sent, 10 - sent, 0);
      if (result <= 0) {
        break;
      }
      sent += result;
    }
    return 0;
  }
  // Step 4: Get Port (2 bytes, big-endian)
  total_received = 0;
  while (total_received < 2) {
    received = recv(client_sock, (char * ) buffer + total_received, 2 - total_received, 0);
    if (received <= 0) {
      return 0;
    }
    total_received += received;
  }

  // Convert port from big-endian (network byte order)
  * target_port = (buffer[0] << 8) | buffer[1];

  // Step 5: Send Success Response for CONNECT (BND.ADDR and BND.PORT are ignored by most clients)
  memset(reply, 0, sizeof(reply));
  reply[0] = SOCKS5_VERSION; // SOCKS5
  reply[1] = SOCKS5_REPLY_SUCCESS; // Success
  reply[2] = 0; // Reserved
  reply[3] = SOCKS5_ADDR_IPV4; // IPv4 address type

  // Get local address information for BND.ADDR
  struct in_addr addr;
  if (inet_pton(AF_INET, config.bind_addr, & addr) != 1) {
    // Fallback to localhost if bind_addr is invalid
    inet_pton(AF_INET, "127.0.0.1", & addr);
  }
  memcpy( & reply[4], & addr.s_addr, 4);

  // Use listening port for BND.PORT
  reply[8] = (config.port >> 8) & 0xFF;
  reply[9] = config.port & 0xFF;
  // Send response ensuring all bytes are sent
  int sent_bytes = 0;
  while (sent_bytes < 10) {
    int result = send(client_sock, (char * ) reply + sent_bytes, 10 - sent_bytes, 0);
    if (result <= 0) {
      return 0;
    }
    sent_bytes += result;
  }

  return SOCKS5_RESULT_TCP_CONNECT;
}