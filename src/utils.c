/*
 * InterceptSuite Proxy - Utility Functions
 * Author - Sourav Kalal /AnoF-Cyber
 *
 * This file provides utility functions for the TLS MITM proxy,
 * including logging, command line parsing, and IP validation.
 */

#include "../include/tls_proxy.h"

#ifndef INTERCEPT_WINDOWS#include <ifaddrs.h>

#include <netdb.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#endif

/* External callback functions from main.c */
extern void send_status_update(const char * message);

/* Global configuration */
proxy_config config;

/* Initialize default configuration */
void init_config(void) {
  memset( & config, 0, sizeof(proxy_config));
  config.port = DEFAULT_PROXY_PORT;
  strncpy(config.bind_addr, DEFAULT_BIND_ADDR, sizeof(config.bind_addr) - 1);
  strncpy(config.log_file, DEFAULT_LOGFILE, sizeof(config.log_file) - 1);
  config.log_fp = NULL;
  config.verbose = 0;
}

/* Validate that the IP address exists on the system */
int validate_ip_address(const char * ip_addr) {
  // Special case - 0.0.0.0 means listen on all interfaces
  if (strcmp(ip_addr, "0.0.0.0") == 0) {
    return 1;
  }

  // Special case - 127.0.0.1 is always valid
  if (strcmp(ip_addr, "127.0.0.1") == 0) {
    return 1;
  }

  #ifdef INTERCEPT_WINDOWS
  // Windows-specific implementation
  // For other IPs, check system interfaces
  ULONG bufferSize = 0;
  PIP_ADAPTER_ADDRESSES pAddresses = NULL;
  DWORD result;

  // First call to get the buffer size
  result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, & bufferSize);

  if (result == ERROR_BUFFER_OVERFLOW) {
    pAddresses = (PIP_ADAPTER_ADDRESSES) malloc(bufferSize);
    if (pAddresses == NULL) {
      fprintf(stderr, "Failed to allocate memory for adapter addresses\n");
      return 0;
    }

    // Second call to get the actual data
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
    fprintf(stderr, "Failed to get network interfaces\n");
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
        fprintf(stderr, "getnameinfo() failed\n");
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
  fprintf(stderr, "Error: IP address %s does not exist on any interface\n", ip_addr);
  return 0;
}

/* Open log file for writing */
int open_log_file(void) {
  if (strlen(config.log_file) == 0) {
    return 1; // No log file specified, which is fine
  }

  // Try to open the log file
  config.log_fp = fopen(config.log_file, "a");
  if (!config.log_fp) {
    fprintf(stderr, "Error: Failed to open log file '%s' for writing\n", config.log_file);
    return 0;
  }

  // Write log file header
  time_t now = time(NULL);
  struct tm * tm_info = localtime( & now);
  char timestamp[26];
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

  fprintf(config.log_fp, "=== TLS MITM Proxy Log Started at %s ===\n", timestamp);
  fprintf(config.log_fp, "%-15s | %-15s | %-5s | %s\n", "Source IP", "Dest IP", "Port", "Message");
  fprintf(config.log_fp, "---------------|----------------|-------|---------------------------\n");
  fflush(config.log_fp);

  return 1;
}

/* Log a message to the log file and optionally to stdout */
void log_message(const char * format, ...) {
  va_list args;
  char message[2048];

  // Format the message
  va_start(args, format);
  vsnprintf(message, sizeof(message), format, args);
  va_end(args);

  // Get current time
  time_t now = time(NULL);
  struct tm * tm_info = localtime( & now);
  char timestamp[26];
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

  // Log to file if enabled
  if (config.log_fp) {
    fprintf(config.log_fp, "[%s] %s\n", timestamp, message);
    fflush(config.log_fp);
  } // Print to console in verbose mode or send to callback
  if (config.verbose) {
    printf("[%s] %s\n", timestamp, message);
    fflush(stdout);
  }

  // Always send status updates to callback if available
  char status_msg[2048];
  snprintf(status_msg, sizeof(status_msg), "[%s] %s", timestamp, message);
  send_status_update(status_msg);
}

/* Close the log file */
void close_log_file(void) {
  if (config.log_fp) {
    time_t now = time(NULL);
    struct tm * tm_info = localtime( & now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(config.log_fp, "=== TLS MITM Proxy Log Ended at %s ===\n\n", timestamp);
    fclose(config.log_fp);
    config.log_fp = NULL;
  }
}