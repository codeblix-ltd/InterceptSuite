/*
 * TLS MITM Proxy - Library Interface
 *
 * Provides exports for controlling the TLS MITM proxy functionality.
 */
#include "platform.h"

#include "../include/tls_proxy.h"

#include "../include/cert_utils.h"

#include "../include/socks5.h"

#include "../include/tls_utils.h"

#include "../include/utils.h"

#include "../include/tls_proxy_dll.h"

#ifdef INTERCEPT_WINDOWS
#include <iphlpapi.h>

#include <time.h>

#pragma comment(lib, "iphlpapi.lib")
#endif

/* Global server instance */
server_thread_t g_server = {
  0
};

/* Global CA certificate and key */
X509 * ca_cert = NULL;
EVP_PKEY * ca_key = NULL;

/* Global callback functions */
log_callback_t g_log_callback = NULL;
status_callback_t g_status_callback = NULL;
connection_callback_t g_connection_callback = NULL;
disconnect_callback_t g_disconnect_callback = NULL;

/* Global interception configuration */
intercept_config_t g_intercept_config = {
  0
};

/* Global interception callback */
intercept_callback_t g_intercept_callback = NULL;

/* Active interception data storage */
intercept_data_t * g_active_intercepts[100] = {
  0
}; // Support up to 100 concurrent intercepts
int g_intercept_count = 0;

/* Statistics */
static int g_total_connections = 0;
static int g_total_bytes = 0;

/* Function to initialize the library/DLL */
static int initialize_library(void) {
  /* Initialize default configuration */
  init_config();

  /* Initialize OpenSSL */
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_crypto_strings();

  /* Initialize interception mutex */
  INIT_MUTEX(g_intercept_config.intercept_cs);

  /* Initialize network subsystem */
  #ifdef INTERCEPT_WINDOWS
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), & wsaData) != 0) {
    return 0;
  }
  #else
  /* On Linux/macOS, ignore SIGPIPE signal which can occur on socket operations */
  signal(SIGPIPE, SIG_IGN);
  #endif

  return 1;
}

/* Function to cleanup the library/DLL */
static void cleanup_library(void) {
  /* Stop proxy if running */
  stop_proxy();

  /* Cleanup OpenSSL */
  ERR_free_strings();
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();

  /* Destroy interception mutex */
  DESTROY_MUTEX(g_intercept_config.intercept_cs);

  /* Cleanup network subsystem */
  #ifdef INTERCEPT_WINDOWS
  WSACleanup();
  #endif
}

#ifdef INTERCEPT_WINDOWS
/* Windows DLL entry point */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    return initialize_library();

  case DLL_PROCESS_DETACH:
    cleanup_library();
    break;
  }
  return TRUE;
}
#else
/* Linux/macOS constructor/destructor functions */
__attribute__((constructor))
static void library_init(void) {
  initialize_library();
}

__attribute__((destructor))
static void library_fini(void) {
  cleanup_library();
}
#endif

/* Exported functions */

/* Exported functions */

INTERCEPT_API intercept_bool_t start_proxy(void) {
  send_status_update("Starting proxy initialization...");
  /* Open log file if configured */
  if (strlen(config.log_file) > 0) {
    send_status_update("Opening log file...");
    if (!open_log_file()) {
      send_status_update("WARNING: Failed to open log file");
      /* Continue anyway as this is not critical */
    } else {
      send_status_update("Log file opened successfully");
    }
  }

  /* Initialize Winsock */
  send_status_update("Initializing Winsock...");
  if (!init_winsock()) {
    send_status_update("ERROR: Failed to initialize Winsock");
    return FALSE;
  }
  send_status_update("Winsock initialized successfully");

  /* Initialize OpenSSL */
  send_status_update("Initializing OpenSSL...");
  if (!init_openssl()) {
    send_status_update("ERROR: Failed to initialize OpenSSL");
    cleanup_winsock();
    return FALSE;
  }
  send_status_update("OpenSSL initialized successfully");

  /* Load or generate CA certificate */
  send_status_update("Loading or generating CA certificate...");
  if (!load_or_generate_ca_cert()) {
    send_status_update("ERROR: Failed to load or generate CA certificate");
    cleanup_openssl();
    cleanup_winsock();
    return FALSE;
  }
  send_status_update("Proxy initialization completed successfully");

  /* Start proxy server */
  /* Initialize critical section/mutex */
  INIT_MUTEX(g_server.cs);
  g_server.should_stop = 0;
  g_server.thread_handle = 0; /* Use 0 for both Windows and POSIX */ /* Create server socket */
  socket_t server_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (server_sock == SOCKET_ERROR_VAL) {
    DESTROY_MUTEX(g_server.cs);
    return FALSE;
  }

  /* Allow socket reuse */
  int opt = 1;
  if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char * ) & opt, sizeof(opt)) == SOCKET_OPTS_ERROR) {
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    return FALSE;
  }

  /* Bind socket */
  struct sockaddr_in server_addr = {
    0
  };
  server_addr.sin_family = AF_INET;
  if (inet_pton(AF_INET, config.bind_addr, & (server_addr.sin_addr)) != 1) {
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    return FALSE;
  }
  server_addr.sin_port = htons(config.port);

  if (bind(server_sock, (struct sockaddr * ) & server_addr, sizeof(server_addr)) == SOCKET_OPTS_ERROR) {
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    return FALSE;
  }

  /* Start listening */
  if (listen(server_sock, SOMAXCONN) == SOCKET_OPTS_ERROR) {
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    return FALSE;
  }

  /* Set socket to non-blocking mode */
  #ifdef INTERCEPT_WINDOWS
  unsigned long nonBlocking = 1;
  if (ioctlsocket(server_sock, FIONBIO, & nonBlocking) != 0) {
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    return FALSE;
  }
  #else
  // POSIX: Use fcntl to set non-blocking mode
  int flags = fcntl(server_sock, F_GETFL, 0);
  if (flags == -1) {
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    return FALSE;
  }
  if (fcntl(server_sock, F_SETFL, flags | O_NONBLOCK) == -1) {
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    return FALSE;
  }
  #endif

  /* Store server socket in global state */
  g_server.server_sock = server_sock;

  /* Start server thread */
  #ifdef INTERCEPT_WINDOWS
  g_server.thread_handle = (thread_t) _beginthreadex(NULL, 0, run_server_thread, NULL, 0, NULL);
  if (g_server.thread_handle == 0) { // _beginthreadex returns 0 on failure, not NULL
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    return FALSE;
  }
  #else
  int ret = pthread_create( & g_server.thread_handle, NULL, run_server_thread, NULL);
  if (ret != 0) {
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    return FALSE;
  }
  #endif

  return TRUE;
}

INTERCEPT_API void stop_proxy(void) {
  /* Signal thread to stop */
  LOCK_MUTEX(g_server.cs);
  g_server.should_stop = 1;
  UNLOCK_MUTEX(g_server.cs);

  /* Close socket to break accept() */
  if (g_server.server_sock != SOCKET_ERROR_VAL) {
    #ifdef INTERCEPT_WINDOWS
    shutdown(g_server.server_sock, SD_BOTH);
    #else
    shutdown(g_server.server_sock, SHUT_RDWR);
    #endif
    close_socket(g_server.server_sock);
    g_server.server_sock = SOCKET_ERROR_VAL;
  }

  /* Wait for thread to finish */
  if (g_server.thread_handle) {
    #ifdef INTERCEPT_WINDOWS
    WaitForSingleObject(g_server.thread_handle, 5000);
    CloseHandle(g_server.thread_handle);
    #else
    pthread_join(g_server.thread_handle, NULL);
    #endif
    g_server.thread_handle = 0;
  }

  /* Delete critical section/mutex */
  DESTROY_MUTEX(g_server.cs);

  /* Close log file */
  close_log_file();
}

INTERCEPT_API intercept_bool_t set_config(const char * bind_addr, int port,
  const char * log_file, int verbose_mode) {
  if (!bind_addr || port <= 0 || port > 65535 || !log_file) {
    return FALSE;
  }

  /* Validate IP address */
  if (!validate_ip_address(bind_addr)) {
    return FALSE;
  } /* Close existing log file if open */
  close_log_file();

  /* Update configuration */
  strncpy(config.bind_addr, bind_addr, sizeof(config.bind_addr) - 1);
  config.port = port;
  strncpy(config.log_file, log_file, sizeof(config.log_file) - 1);
  config.verbose = verbose_mode;

  /* Open new log file */
  if (!open_log_file()) {
    send_status_update("WARNING: Failed to open log file");
    /* Continue anyway as this is not critical */
  } else {
    send_status_update("Log file opened successfully");
  }

  return TRUE;
}

/* Network subsystem initialization and cleanup */
int init_winsock(void) {
  #ifdef INTERCEPT_WINDOWS
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), & wsaData) != 0) {
    return 0;
  }
  #else
  /* On Unix/Linux/macOS, sockets don't need special initialization */
  /* We already handle SIGPIPE in initialize_library() */
  #endif
  return 1;
}

void cleanup_winsock(void) {
  #ifdef INTERCEPT_WINDOWS
  WSACleanup();
  #else
  /* No special cleanup needed for Unix/Linux/macOS sockets */
  #endif
}

/* Server thread function */
THREAD_RETURN_TYPE THREAD_CALL run_server_thread(void * arg) {
  socket_t server_sock = g_server.server_sock;
  client_info * client;
  thread_t thread_id;

  while (!g_server.should_stop) {
    fd_set readfds;
    struct timeval tv;
    FD_ZERO( & readfds);
    FD_SET(server_sock, & readfds);

    #ifdef INTERCEPT_WINDOWS
    int nfds = 0;
    #else
    int nfds = server_sock + 1;
    #endif
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    int ret = select(nfds, & readfds, NULL, NULL, & tv);
    if (ret == SOCKET_ERROR_VAL) {
      // On Windows, use GET_SOCKET_ERROR(), on POSIX use errno
      #ifdef INTERCEPT_WINDOWS
      int err = GET_SOCKET_ERROR();
      if (err != WSAEINTR) {
        fprintf(stderr, "Select failed: %d\n", err);
      }
      #else
      if (errno != EINTR) {
        perror("Select failed");
      }
      #endif
      continue;
    }

    if (ret == 0) {
      continue; // timeout, check should_stop flag again
    }

    client = (client_info * ) malloc(sizeof(client_info));
    if (!client) {
      continue;
    }

    socklen_t client_len = sizeof(client -> client_addr);
    client -> client_sock = accept(server_sock, (struct sockaddr * ) & client -> client_addr, & client_len);
    if (client -> client_sock == SOCKET_ERROR_VAL) {
      free(client);
      #ifdef INTERCEPT_WINDOWS
      int err = GET_SOCKET_ERROR();
      if (err != WSAEWOULDBLOCK) {
        fprintf(stderr, "Failed to accept connection: %d\n", err);
      }
      #else
      if (errno != EWOULDBLOCK && errno != EAGAIN) {
        perror("Failed to accept connection");
      }
      #endif
      continue;
    }

    // Set to blocking mode for normal operation
    #ifdef INTERCEPT_WINDOWS
    unsigned long nonBlocking = 0;
    if (ioctlsocket(client -> client_sock, FIONBIO, & nonBlocking) != 0) {
      CLOSE_SOCKET(client -> client_sock);
      free(client);
      continue;
    }
    #else
    int flags = fcntl(client -> client_sock, F_GETFL, 0);
    if (flags == -1 || fcntl(client -> client_sock, F_SETFL, flags & ~O_NONBLOCK) == -1) {
      CLOSE_SOCKET(client -> client_sock);
      free(client);
      continue;
    }
    #endif

    // Create thread to handle client
    if (CREATE_THREAD(thread_id, handle_client, client) != 0) {
      CLOSE_SOCKET(client -> client_sock);
      free(client);
      continue;
    }

    #ifdef INTERCEPT_WINDOWS
    CloseHandle(thread_id); // close thread handle but thread runs
    #endif
  }

  #ifdef INTERCEPT_WINDOWS
  return 0;
  #else
  return NULL;
  #endif
}

/* Helper function to send status updates */
void send_status_update(const char * message) {
  if (g_status_callback && message) {
    g_status_callback(message);
  }
}

/* Helper function to send log entries */
void send_log_entry(const char * src_ip,
  const char * dst_ip, int dst_port,
    const char * msg_type,
      const char * data, int connection_id, int packet_id) {
  if (g_log_callback && src_ip && dst_ip && msg_type && data) {
    char timestamp[64];
    time_t now = time(NULL);
    struct tm * tm_info = localtime( & now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    g_log_callback(timestamp, connection_id, packet_id, src_ip, dst_ip, dst_port, msg_type, data);
  }
}

/* Helper function to send connection notifications */
void send_connection_notification(const char * client_ip, int client_port,
  const char * target_host, int target_port, int connection_id) {
  g_total_connections++;
  if (g_connection_callback && client_ip && target_host) {
    g_connection_callback(client_ip, client_port, target_host, target_port, connection_id);
  }
}

/* Helper function to send disconnect notifications */
void send_disconnect_notification(int connection_id,
  const char * reason) {
  if (g_disconnect_callback && reason) {
    g_disconnect_callback(connection_id, reason);
  }
}

/* Set callback functions */
INTERCEPT_API void set_log_callback(log_callback_t callback) {
  g_log_callback = callback;
}

INTERCEPT_API void set_status_callback(status_callback_t callback) {
  g_status_callback = callback;
}

INTERCEPT_API void set_connection_callback(connection_callback_t callback) {
  g_connection_callback = callback;
}

INTERCEPT_API void set_disconnect_callback(disconnect_callback_t callback) {
  g_disconnect_callback = callback;
}

/* Interception callback and control functions */

INTERCEPT_API void set_intercept_callback(intercept_callback_t callback) {
  g_intercept_callback = callback;
}

INTERCEPT_API void set_intercept_enabled(int enabled) {
  LOCK_MUTEX(g_intercept_config.intercept_cs);
  g_intercept_config.is_interception_enabled = enabled;
  UNLOCK_MUTEX(g_intercept_config.intercept_cs);

  if (g_status_callback) {
    char status_msg[256];
    snprintf(status_msg, sizeof(status_msg), "Interception %s", enabled ? "enabled" : "disabled");
    g_status_callback(status_msg);
  }
}

INTERCEPT_API void set_intercept_direction(int direction) {
  LOCK_MUTEX(g_intercept_config.intercept_cs);
  g_intercept_config.enabled_directions = (intercept_direction_t) direction;
  UNLOCK_MUTEX(g_intercept_config.intercept_cs);

  if (g_status_callback) {
    char status_msg[256];
    const char * dir_str = "None";
    switch (direction) {
    case INTERCEPT_CLIENT_TO_SERVER:
      dir_str = "Client->Server";
      break;
    case INTERCEPT_SERVER_TO_CLIENT:
      dir_str = "Server->Client";
      break;
    case INTERCEPT_BOTH:
      dir_str = "Both directions";
      break;
    }
    snprintf(status_msg, sizeof(status_msg), "Intercept direction set to: %s", dir_str);
    g_status_callback(status_msg);
  }
}

INTERCEPT_API intercept_status_t get_intercept_config(void) {
  intercept_status_t result = {
    0
  };

  LOCK_MUTEX(g_intercept_config.intercept_cs);
  result.is_enabled = g_intercept_config.is_interception_enabled;
  result.direction = (int) g_intercept_config.enabled_directions;
  UNLOCK_MUTEX(g_intercept_config.intercept_cs);

  return result;
}

INTERCEPT_API void respond_to_intercept(int connection_id, int action,
  const unsigned char * modified_data, int modified_length) {
  LOCK_MUTEX(g_intercept_config.intercept_cs);

  // Find the intercept data for this connection
  for (int i = 0; i < g_intercept_count; i++) {
    if (g_active_intercepts[i] && g_active_intercepts[i] -> connection_id == connection_id &&
      g_active_intercepts[i] -> is_waiting_for_response) {

      intercept_data_t * intercept = g_active_intercepts[i];
      intercept -> action = (intercept_action_t) action;

      // Handle modified data if provided
      if (action == INTERCEPT_ACTION_MODIFY && modified_data && modified_length > 0) {
        // Free existing modified data if any
        if (intercept -> modified_data) {
          free(intercept -> modified_data);
        }

        // Allocate and copy new data
        intercept -> modified_data = malloc(modified_length);
        if (intercept -> modified_data) {
          memcpy(intercept -> modified_data, modified_data, modified_length);
          intercept -> modified_length = modified_length;
        } else {
          // Fall back to forward if allocation fails
          intercept -> action = INTERCEPT_ACTION_FORWARD;
        }
      }

      intercept -> is_waiting_for_response = 0;
      SET_EVENT(intercept -> response_event);
      break;
    }
  }

  UNLOCK_MUTEX(g_intercept_config.intercept_cs);
}

/* Get system IP addresses */
INTERCEPT_API int get_system_ips(char * buffer, int buffer_size) {
  if (!buffer || buffer_size <= 0) return 0;

  buffer[0] = '\0';
  int offset = 0;

  // Add localhost and 0.0.0.0 (any interface) for all platforms
  offset += snprintf(buffer + offset, buffer_size - offset, "127.0.0.1;0.0.0.0;");

  #ifdef INTERCEPT_WINDOWS
  // Windows-specific implementation using WinAPI
  ULONG adapter_info_size = 0;
  if (GetAdaptersInfo(NULL, & adapter_info_size) == ERROR_BUFFER_OVERFLOW) {
    PIP_ADAPTER_INFO adapter_info = (PIP_ADAPTER_INFO) malloc(adapter_info_size);
    if (adapter_info && GetAdaptersInfo(adapter_info, & adapter_info_size) == NO_ERROR) {
      PIP_ADAPTER_INFO adapter = adapter_info;
      while (adapter && offset < buffer_size - 20) {
        if (adapter -> Type == MIB_IF_TYPE_ETHERNET || adapter -> Type == IF_TYPE_IEEE80211) {
          PIP_ADDR_STRING addr = & adapter -> IpAddressList;
          while (addr && offset < buffer_size - 20) {
            if (strcmp(addr -> IpAddress.String, "0.0.0.0") != 0) {
              offset += snprintf(buffer + offset, buffer_size - offset, "%s;", addr -> IpAddress.String);
            }
            addr = addr -> Next;
          }
        }
        adapter = adapter -> Next;
      }
      free(adapter_info);
    }
  }
  #else
  // Linux/macOS implementation using getifaddrs
  struct ifaddrs * ifaddr, * ifa;
  char host[MAX_IP_ADDR_LEN];

  if (getifaddrs( & ifaddr) == -1) {
    perror("getifaddrs");
    return offset;
  }

  // Walk through linked list, maintaining head pointer for cleanup
  for (ifa = ifaddr; ifa != NULL && offset < buffer_size - 20; ifa = ifa -> ifa_next) {
    if (ifa -> ifa_addr == NULL)
      continue;

    // Only handle IPv4 addresses
    if (ifa -> ifa_addr -> sa_family == AF_INET) {
      // Get the IP address
      int s = getnameinfo(ifa -> ifa_addr, sizeof(struct sockaddr_in),
        host, MAX_IP_ADDR_LEN,
        NULL, 0, NI_NUMERICHOST);

      if (s != 0) {
        fprintf(stderr, "getnameinfo() failed: %s\n", gai_strerror(s));
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

/* Get current proxy configuration */
INTERCEPT_API proxy_config_t get_proxy_config(void) {
  proxy_config_t result;

  /* Copy configuration data */
  strcpy(result.bind_addr, config.bind_addr);
  result.port = config.port;
  strcpy(result.log_file, config.log_file);
  result.verbose_mode = config.verbose;

  /* Determine if proxy is running */
  #ifdef INTERCEPT_WINDOWS
  result.is_running = (g_server.server_sock != INVALID_SOCKET && g_server.thread_handle != NULL);
  #else
  result.is_running = (g_server.server_sock > 0 && g_server.thread_handle != 0);
  #endif

  return result;
}

/* Get proxy statistics */
/* Process enumeration functionality has been removed as it was only needed for WinDivert */

/* Export certificate function */
INTERCEPT_API intercept_bool_t export_certificate(const char* output_directory, int export_type) {
  if (!output_directory || strlen(output_directory) == 0) {
    if (g_status_callback) {
      g_status_callback("ERROR: Invalid output directory");
    }
    return FALSE;
  }

  // Ensure certificates are loaded/generated
  if (!load_or_generate_ca_cert()) {
    if (g_status_callback) {
      g_status_callback("ERROR: Failed to load or generate CA certificate");
    }
    return FALSE;
  }

  // Ensure output directory exists
  if (!ensure_directory_exists(output_directory)) {
    if (g_status_callback) {
      g_status_callback("ERROR: Failed to create output directory");
    }
    return FALSE;
  }

  const char* source_cert_path = get_ca_cert_path();
  const char* source_key_path = get_ca_key_path();

  if (!source_cert_path || !source_key_path) {
    if (g_status_callback) {
      g_status_callback("ERROR: Failed to get certificate paths");
    }
    return FALSE;
  }

  char output_path[USER_DATA_MAX_PATH];
  int success = 0;

  if (export_type == 1) {
    // Export private key (PEM format - direct copy)
    snprintf(output_path, sizeof(output_path), "%s%sIntercept_Suite_key.key",
             output_directory,
#ifdef INTERCEPT_WINDOWS
             "\\"
#else
             "/"
#endif
    );

    // Read source key file
    long key_size = 0;
    char* key_data = read_file_to_memory(source_key_path, &key_size);
    if (!key_data) {
      if (g_status_callback) {
        g_status_callback("ERROR: Failed to read source key file");
      }
      return FALSE;
    }    // Write to output location
    success = write_memory_to_file(output_path, key_data, (size_t)key_size);
    free(key_data);

    if (success && g_status_callback) {
      char message[512];
      snprintf(message, sizeof(message), "Private key exported to: %s", output_path);
      g_status_callback(message);
    }

  } else if (export_type == 0) {
    // Export certificate (convert PEM to DER)
    snprintf(output_path, sizeof(output_path), "%s%sIntercept_Suite_Cert.der",
             output_directory,
#ifdef INTERCEPT_WINDOWS
             "\\"
#else
             "/"
#endif
    );

    // Read source certificate file
    long cert_size = 0;
    char* cert_data = read_file_to_memory(source_cert_path, &cert_size);
    if (!cert_data) {
      if (g_status_callback) {
        g_status_callback("ERROR: Failed to read source certificate file");
      }
      return FALSE;
    }

    // Load certificate from PEM data
    BIO* cert_bio = BIO_new_mem_buf(cert_data, cert_size);
    X509* cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    BIO_free(cert_bio);
    free(cert_data);

    if (!cert) {
      if (g_status_callback) {
        g_status_callback("ERROR: Failed to parse certificate");
      }
      return FALSE;
    }

    // Convert to DER format
    BIO* der_bio = BIO_new(BIO_s_mem());
    if (!der_bio || i2d_X509_bio(der_bio, cert) != 1) {
      if (g_status_callback) {
        g_status_callback("ERROR: Failed to convert certificate to DER format");
      }
      X509_free(cert);
      if (der_bio) BIO_free(der_bio);
      return FALSE;
    }

    // Get DER data from BIO
    char* der_data;
    long der_size = BIO_get_mem_data(der_bio, &der_data);    // Write DER data to output file
    success = write_memory_to_file(output_path, der_data, (size_t)der_size);

    BIO_free(der_bio);
    X509_free(cert);

    if (success && g_status_callback) {
      char message[512];
      snprintf(message, sizeof(message), "Certificate exported to: %s", output_path);
      g_status_callback(message);
    }

  } else {
    if (g_status_callback) {
      g_status_callback("ERROR: Invalid export type. Use 0 for certificate, 1 for private key");
    }
    return FALSE;
  }

  if (!success && g_status_callback) {
    g_status_callback("ERROR: Failed to write exported file");
  }

  return success ? TRUE : FALSE;
}