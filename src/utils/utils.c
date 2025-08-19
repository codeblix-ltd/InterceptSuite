/*
 * InterceptSuite Proxy - Utility Functions  if (strcmp(ip, "  DWORD result;

  result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &bufferSize);0.0") == 0) {
    return 1;
  }

  if (strcmp(ip, "127.0.0.1") == 0) {
    return 1;
  }r - Sourav Kalal /AnoF-Cyber
 *
 * This file provides utility functions for the TLS MITM proxy,
 * including logging, command line parsing, and IP validation.
 */

#include "../tls/proxy/tls_proxy.h"
#include "utils.h"
#include <stdarg.h>
#include <stdio.h>

/* External config variable */
extern proxy_config config;

#ifndef INTERCEPT_WINDOWS
#include <ifaddrs.h>

#include <netdb.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#endif

/* External server instance from main.c */
extern server_thread_t g_server;

/* External callback functions from main.c */
extern void send_status_update(const char * message);

/* Global configuration */
proxy_config config;

/* Initialize default configuration */
void init_config(void) {
  memset( & config, 0, sizeof(proxy_config));
  config.port = DEFAULT_PROXY_PORT;
  strncpy(config.bind_addr, DEFAULT_BIND_ADDR, sizeof(config.bind_addr) - 1);
  config.verbose = 0;
}

/* Validate that the IP address exists on the system */
int validate_ip_address(const char * ip_addr) {
  // Special case - 0.0.0.0 means listen on all interfaces
  if (strcmp(ip_addr, "0.0.0.0") == 0) {
    return 1;
  }

  if (strcmp(ip_addr, "127.0.0.1") == 0) {
    return 1;
  }

  #ifdef INTERCEPT_WINDOWS
  ULONG bufferSize = 0;
  PIP_ADAPTER_ADDRESSES pAddresses = NULL;
  DWORD result;

  result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, & bufferSize);

  if (result == ERROR_BUFFER_OVERFLOW) {
    pAddresses = (PIP_ADAPTER_ADDRESSES) malloc(bufferSize);
    if (pAddresses == NULL) {
      log_message("Failed to allocate memory for adapter addresses\n");
      return 0;
    }

    result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, & bufferSize);

    if (result == NO_ERROR) {
      PIP_ADAPTER_ADDRESSES pCurrent = pAddresses;
      while (pCurrent) {
        PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrent -> FirstUnicastAddress;
        while (pUnicast) {
          SOCKADDR_IN * addr = (SOCKADDR_IN * ) pUnicast -> Address.lpSockaddr;
          char ip_str[MAX_IP_ADDR_LEN];
          inet_ntop(AF_INET, & (addr -> sin_addr), ip_str, sizeof(ip_str));

          if (strcmp(ip_str, ip_addr) == 0) {
            free(pAddresses);
            return 1; // IP address found
          }

          pUnicast = pUnicast -> Next;
        }
        pCurrent = pCurrent -> Next;
      }
    }

    free(pAddresses);
  }
  #else
  // Linux/macOS implementation
  struct ifaddrs * ifaddr, * ifa;
  int family, s;
  char host[MAX_IP_ADDR_LEN];

  if (getifaddrs( & ifaddr) == -1) {
    log_message("Failed to get network interfaces\n");
    return 0;
  }

  // Walk through linked list, maintaining head pointer for cleanup
  for (ifa = ifaddr; ifa != NULL; ifa = ifa -> ifa_next) {
    if (ifa -> ifa_addr == NULL)
      continue;

    family = ifa -> ifa_addr -> sa_family;

    // Check for IPv4 addresses
    if (family == AF_INET) {
      s = getnameinfo(ifa -> ifa_addr, sizeof(struct sockaddr_in),
        host, MAX_IP_ADDR_LEN,
        NULL, 0, NI_NUMERICHOST);
      if (s != 0) {
        log_message("getnameinfo() failed\n");
        continue;
      }

      if (strcmp(host, ip_addr) == 0) {
        freeifaddrs(ifaddr);
        return 1; // IP address found
      }
    }
  }

  freeifaddrs(ifaddr);
  #endif

  // IP not found on any interface
  log_message("Error: IP address %s does not exist on any interface\n", ip_addr);
  return 0;
}

/* Set proxy configuration */
INTERCEPT_API intercept_bool_t set_config(const char *bind_addr, int port, int verbose_mode) {
  if (!bind_addr || port <= 0 || port > 65535) {
    return FALSE;
  }

  /* Validate IP address */
  if (!validate_ip_address(bind_addr)) {
    return FALSE;
  }

  /* Update configuration */
  strncpy(config.bind_addr, bind_addr, sizeof(config.bind_addr) - 1);
  config.port = port;
  config.verbose = verbose_mode;

  return TRUE;
}

/* Get current proxy configuration */
INTERCEPT_API proxy_config_t get_proxy_config(void) {
  proxy_config_t result;

  /* Copy configuration data */
  strcpy(result.bind_addr, config.bind_addr);
  result.port = config.port;
  result.verbose_mode = config.verbose;

  /* Determine if proxy is running */
#ifdef INTERCEPT_WINDOWS
  result.is_running = (g_server.server_sock != INVALID_SOCKET && g_server.thread_handle != NULL);
#else
  result.is_running = (g_server.server_sock > 0 && g_server.thread_handle != 0);
#endif

  return result;
}

/* Get system IP addresses */
INTERCEPT_API int get_system_ips(char *buffer, int buffer_size) {
  if (!buffer || buffer_size <= 0) return 0;

  buffer[0] = '\0';
  int offset = 0;

  // Add localhost and 0.0.0.0 (any interface) for all platforms
  offset += snprintf(buffer + offset, buffer_size - offset, "127.0.0.1;0.0.0.0;");

#ifdef INTERCEPT_WINDOWS
  // Windows-specific implementation using WinAPI
  ULONG adapter_info_size = 0;
  if (GetAdaptersInfo(NULL, &adapter_info_size) == ERROR_BUFFER_OVERFLOW) {
    PIP_ADAPTER_INFO adapter_info = (PIP_ADAPTER_INFO) malloc(adapter_info_size);
    if (adapter_info && GetAdaptersInfo(adapter_info, &adapter_info_size) == NO_ERROR) {
      PIP_ADAPTER_INFO adapter = adapter_info;
      while (adapter && offset < buffer_size - 20) {
        if (adapter->Type == MIB_IF_TYPE_ETHERNET || adapter->Type == IF_TYPE_IEEE80211) {
          PIP_ADDR_STRING addr = &adapter->IpAddressList;
          while (addr && offset < buffer_size - 20) {
            if (strcmp(addr->IpAddress.String, "0.0.0.0") != 0) {
              offset += snprintf(buffer + offset, buffer_size - offset, "%s;", addr->IpAddress.String);
            }
            addr = addr->Next;
          }
        }
        adapter = adapter->Next;
      }
      free(adapter_info);
    }
  }
#else
  // Linux/macOS implementation using getifaddrs
  struct ifaddrs *ifaddr, *ifa;
  char host[MAX_IP_ADDR_LEN];

  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    return offset;
  }

  // Walk through linked list, maintaining head pointer for cleanup
  for (ifa = ifaddr; ifa != NULL && offset < buffer_size - 20; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL)
      continue;

    // Only handle IPv4 addresses
    if (ifa->ifa_addr->sa_family == AF_INET) {
      // Get the IP address
      int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                         host, MAX_IP_ADDR_LEN,
                         NULL, 0, NI_NUMERICHOST);

      if (s != 0) {
        log_message("getnameinfo() failed: %s", gai_strerror(s));
        continue;
      }

      // Skip duplicates (localhost already added)
      if (strcmp(host, "127.0.0.1") == 0 || strcmp(host, "0.0.0.0") == 0)
        continue;

      offset += snprintf(buffer + offset, buffer_size - offset, "%s;", host);
    }
  }

  freeifaddrs(ifaddr);
#endif

  return offset;
}

/**
 * Log message function - simplified version without file logging
 */
void log_message(const char *format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    send_status_update(buffer);

    if (config.verbose) {
        printf("%s\n", buffer);
        fflush(stdout);
    }
}

/* Packet ID management */
extern int g_packet_id_counter;

int get_next_packet_id(void) {
    return ++g_packet_id_counter;
}