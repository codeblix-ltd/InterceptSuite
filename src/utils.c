/*
 * TLS MITM Proxy - Utility Functions
 *
 * This file provides utility functions for the TLS MITM proxy,
 * including logging, command line parsing, and IP validation.
 */

#include "../include/tls_proxy.h"

/* Global configuration */
proxy_config config;

/* Initialize default configuration */
void init_config(void) {
    memset(&config, 0, sizeof(proxy_config));
    config.port = DEFAULT_PROXY_PORT;
    strncpy(config.bind_addr, DEFAULT_BIND_ADDR, sizeof(config.bind_addr) - 1);
    strncpy(config.log_file, DEFAULT_LOGFILE, sizeof(config.log_file) - 1);
    config.log_fp = NULL;
    config.help_requested = 0;
    config.verbose = 0; /* Default to non-verbose mode (show only table) */
}

/* Print usage information */
void print_usage(const char *program_name) {
    printf("TLS MITM Proxy - Intercepts TLS traffic and displays it in plaintext\n");
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("Options:\n");
    printf("  -h, --help                 Display this help message and exit\n");
    printf("  -p, --port PORT            Port to listen on (default: %d)\n", DEFAULT_PROXY_PORT);
    printf("  -b, --bind-addr ADDRESS    IP address to bind to (default: %s)\n", DEFAULT_BIND_ADDR);
    printf("  -l, --log-file FILE        Log file path (default: %s)\n", DEFAULT_LOGFILE);
    printf("  -v, --verbose              Enable verbose output (default: off)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --port 8080 --bind-addr 0.0.0.0 --log-file mitm_log.txt\n", program_name);
    printf("  %s -p 8080 -b 192.168.1.10 -l capture.log -v\n", program_name);
    printf("\n");
    printf("Notes:\n");
    printf("  - The bind address must be a valid IP address on your system\n");
    printf("  - In default mode (non-verbose), only table output is shown: Source IP | Dest IP | Dest Port | Message\n");
    printf("  - In verbose mode, additional connection details and debug information are displayed\n");
}

/* Parse command line arguments */
int parse_arguments(int argc, char *argv[]) {
    // Start with default configuration
    init_config();

    // No arguments provided, use defaults
    if (argc <= 1) {
        return 1;
    }

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            config.help_requested = 1;
            return 1;
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            config.verbose = 1;
        }
        else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i + 1 < argc) {
            int port = atoi(argv[++i]);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Error: Invalid port number. Must be between 1 and 65535.\n");
                return 0;
            }
            config.port = port;
        }
        else if ((strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--bind-addr") == 0) && i + 1 < argc) {
            i++;
            // Basic IP format validation before deeper system validation
            if (strlen(argv[i]) >= MAX_IP_ADDR_LEN) {
                fprintf(stderr, "Error: IP address is too long\n");
                return 0;
            }
            // Validate if this is a valid IP format using inet_pton
            struct sockaddr_in sa;
            if (inet_pton(AF_INET, argv[i], &(sa.sin_addr)) != 1) {
                fprintf(stderr, "Error: Invalid IP address format\n");
                return 0;
            }
            // Copy the IP address to the configuration
            strncpy(config.bind_addr, argv[i], sizeof(config.bind_addr) - 1);

            // Further validation will be done in validate_ip_address
        }
        else if ((strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log-file") == 0) && i + 1 < argc) {
            i++;
            if (strlen(argv[i]) >= MAX_FILEPATH_LEN) {
                fprintf(stderr, "Error: Log file path is too long\n");
                return 0;
            }
            strncpy(config.log_file, argv[i], sizeof(config.log_file) - 1);
        }
        else {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            return 0;
        }
    }

    return 1;
}

/* Validate that the IP address exists on the system */
int validate_ip_address(const char *ip_addr) {
    // Special case - 0.0.0.0 means listen on all interfaces
    if (strcmp(ip_addr, "0.0.0.0") == 0) {
        return 1;
    }

    // Special case - 127.0.0.1 is always valid
    if (strcmp(ip_addr, "127.0.0.1") == 0) {
        return 1;
    }

    // For other IPs, check system interfaces
    ULONG bufferSize = 0;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    DWORD result;

    // First call to get the buffer size
    result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &bufferSize);

    if (result == ERROR_BUFFER_OVERFLOW) {
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
        if (pAddresses == NULL) {
            fprintf(stderr, "Failed to allocate memory for adapter addresses\n");
            return 0;
        }

        // Second call to get the actual data
        result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &bufferSize);

        if (result == NO_ERROR) {
            PIP_ADAPTER_ADDRESSES pCurrent = pAddresses;
            while (pCurrent) {
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrent->FirstUnicastAddress;
                while (pUnicast) {
                    SOCKADDR_IN* addr = (SOCKADDR_IN*)pUnicast->Address.lpSockaddr;
                    char ip_str[MAX_IP_ADDR_LEN];
                    inet_ntop(AF_INET, &(addr->sin_addr), ip_str, sizeof(ip_str));

                    if (strcmp(ip_str, ip_addr) == 0) {
                        free(pAddresses);
                        return 1;  // IP address found
                    }

                    pUnicast = pUnicast->Next;
                }
                pCurrent = pCurrent->Next;
            }
        }

        free(pAddresses);
    }

    // IP not found on any interface
    fprintf(stderr, "Error: IP address %s does not exist on any interface\n", ip_addr);
    return 0;
}

/* Open log file for writing */
int open_log_file(void) {
    if (strlen(config.log_file) == 0) {
        return 1;  // No log file specified, which is fine
    }

    // Try to open the log file
    config.log_fp = fopen(config.log_file, "a");
    if (!config.log_fp) {
        fprintf(stderr, "Error: Failed to open log file '%s' for writing\n", config.log_file);
        return 0;
    }

    // Write log file header
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(config.log_fp, "=== TLS MITM Proxy Log Started at %s ===\n", timestamp);
    fprintf(config.log_fp, "%-15s | %-15s | %-5s | %s\n", "Source IP", "Dest IP", "Port", "Message");
    fprintf(config.log_fp, "---------------|----------------|-------|---------------------------\n");
    fflush(config.log_fp);

    return 1;
}

/* Log a message to the log file and optionally to stdout */
void log_message(const char *format, ...) {
    va_list args;
    char message[2048];

    // Format the message
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    // Get current time
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    // Log to file if enabled
    if (config.log_fp) {
        fprintf(config.log_fp, "[%s] %s\n", timestamp, message);
        fflush(config.log_fp);
    }

    // Print to console in verbose mode
    if (config.verbose) {
        printf("[%s] %s\n", timestamp, message);
        fflush(stdout);
    }
}

/* Close the log file */
void close_log_file(void) {
    if (config.log_fp) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char timestamp[26];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

        fprintf(config.log_fp, "=== TLS MITM Proxy Log Ended at %s ===\n\n", timestamp);
        fclose(config.log_fp);
        config.log_fp = NULL;
    }
}
