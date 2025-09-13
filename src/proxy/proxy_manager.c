/*
 * TLS MITM Proxy - Proxy Manager Implementation
 *
 * Contains proxy server management functionality moved from main.c.
 */

#include "proxy_manager.h"
#include "../tls/cert/cert_utils.h"
#include "socks5.h"
#include "udp_relay.h"
#include "../tls/proxy/tls_utils.h"
#include "../utils/utils.h"
#include "../config/user_data.h"
#include "../utils/packet_id.h"

#ifdef INTERCEPT_WINDOWS
#include <iphlpapi.h>
#include <time.h>
#pragma comment(lib, "iphlpapi.lib")
#endif

/* External global variables from main.c */
extern server_thread_t g_server;
extern X509 * ca_cert;
extern EVP_PKEY * ca_key;
extern log_callback_t g_log_callback;
extern status_callback_t g_status_callback;
extern connection_callback_t g_connection_callback;
extern disconnect_callback_t g_disconnect_callback;
extern intercept_config_t g_intercept_config;
extern intercept_callback_t g_intercept_callback;
extern intercept_data_t * g_active_intercepts[100];
extern int g_intercept_count;

/* Statistics */
static int g_total_connections = 0;

/* Helper function to check if port is available */
int is_port_available(const char* bind_addr, int port) {
  socket_t test_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (test_sock == SOCKET_ERROR_VAL) {
    return 0;
  }

  struct sockaddr_in test_addr = {0};
  test_addr.sin_family = AF_INET;
  if (inet_pton(AF_INET, bind_addr, &(test_addr.sin_addr)) != 1) {
    close_socket(test_sock);
    return 0;
  }
  test_addr.sin_port = htons(port);

  int bind_result = bind(test_sock, (struct sockaddr*)&test_addr, sizeof(test_addr));
  close_socket(test_sock);

  return (bind_result != SOCKET_OPTS_ERROR);
}

/* Initialize proxy components */
INTERCEPT_API void init_proxy_components(void) {
  /* Initialize packet ID mutex in proxy manager */
  INIT_MUTEX(g_packet_id_mutex);

  /* Initialize upstream proxy configuration */
  init_upstream_proxy_config();
}

INTERCEPT_API proxy_start_result_t start_proxy(void) {
  proxy_start_result_t result = {0};

  /* Initialize proxy components including packet ID system */
  init_proxy_components();

  if (!is_port_available(config.bind_addr, config.port)) {
    snprintf(result.message, sizeof(result.message),
             "Port %d is already in use on address %s",
             config.port, config.bind_addr);
    log_message(result.message);
    result.success = 0;
    return result;
  }

  if (!init_winsock()) {
    snprintf(result.message, sizeof(result.message), "Failed to initialize network subsystem");
    log_message(result.message);
    result.success = 0;
    return result;
  }

  if (!init_openssl()) {
    snprintf(result.message, sizeof(result.message), "Failed to initialize TLS subsystem");
    log_message(result.message);
    cleanup_winsock();
    result.success = 0;
    return result;
  }

  if (!load_or_generate_ca_cert()) {
    snprintf(result.message, sizeof(result.message), "Failed to load CA certificate - check certificate permissions");
    log_message(result.message);
    cleanup_openssl();
    cleanup_winsock();
    result.success = 0;
    return result;
  }

  INIT_MUTEX(g_server.cs);
  g_server.should_stop = 0;
  g_server.thread_handle = 0;

  socket_t server_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (server_sock == SOCKET_ERROR_VAL) {
    snprintf(result.message, sizeof(result.message), "Failed to create server socket");
    log_message(result.message);
    DESTROY_MUTEX(g_server.cs);
    result.success = 0;
    return result;
  }

  int opt = 1;
  if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt)) == SOCKET_OPTS_ERROR) {
    snprintf(result.message, sizeof(result.message), "Failed to set socket options");
    log_message(result.message);
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    result.success = 0;
    return result;
  }

  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  if (inet_pton(AF_INET, config.bind_addr, &(server_addr.sin_addr)) != 1) {
    snprintf(result.message, sizeof(result.message), "Invalid bind address: %s", config.bind_addr);
    log_message(result.message);
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    result.success = 0;
    return result;
  }
  server_addr.sin_port = htons(config.port);

  if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_OPTS_ERROR) {
    snprintf(result.message, sizeof(result.message), "Failed to bind to %s:%d - Port may be in use",
             config.bind_addr, config.port);
    log_message(result.message);
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    result.success = 0;
    return result;
  }

  if (listen(server_sock, SOMAXCONN) == SOCKET_OPTS_ERROR) {
    snprintf(result.message, sizeof(result.message), "Failed to start listening on port %d", config.port);
    log_message(result.message);
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    result.success = 0;
    return result;
  }

  #ifdef INTERCEPT_WINDOWS
  unsigned long nonBlocking = 1;
  if (ioctlsocket(server_sock, FIONBIO, &nonBlocking) != 0) {
    snprintf(result.message, sizeof(result.message), "Failed to set socket to non-blocking mode");
    log_message(result.message);
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    result.success = 0;
    return result;
  }
  #else
  int flags = fcntl(server_sock, F_GETFL, 0);
  if (flags == -1 || fcntl(server_sock, F_SETFL, flags | O_NONBLOCK) == -1) {
    snprintf(result.message, sizeof(result.message), "Failed to set socket to non-blocking mode");
    log_message(result.message);
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    result.success = 0;
    return result;
  }
  #endif

  g_server.server_sock = server_sock;

  #ifdef INTERCEPT_WINDOWS
  g_server.thread_handle = (thread_t)_beginthreadex(NULL, 0, run_server_thread, NULL, 0, NULL);
  if (g_server.thread_handle == 0) {
    snprintf(result.message, sizeof(result.message), "Failed to create server thread");
    log_message(result.message);
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    result.success = 0;
    return result;
  }
  #else
  int ret = pthread_create(&g_server.thread_handle, NULL, run_server_thread, NULL);
  if (ret != 0) {
    snprintf(result.message, sizeof(result.message), "Failed to create server thread");
    log_message(result.message);
    close_socket(server_sock);
    DESTROY_MUTEX(g_server.cs);
    result.success = 0;
    return result;
  }
  #endif

  snprintf(result.message, sizeof(result.message), "Proxy server started successfully on %s:%d",
           config.bind_addr, config.port);

  int udp_port = config.port + 1;
  if (!start_udp_relay_server(config.bind_addr, udp_port)) {
    log_message("Warning: Failed to start UDP relay server - UDP ASSOCIATE may not work");
  }

  result.success = 1;
  return result;
}

INTERCEPT_API void stop_proxy(void) {
  /* Cleanup packet ID system */
  cleanup_packet_id_system();

  /* Stop UDP relay server first */
  stop_udp_relay_server();

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
        log_message("Select failed: %d", err);
      }
      #else
      if (errno != EINTR) {
        log_message("Select failed: %s", strerror(errno));
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
        log_message("Failed to accept connection: %d\n", err);
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
    const char * direction, const unsigned char * data, int data_length,
      const char * msg_type, int connection_id, int packet_id) {
  if (g_log_callback && src_ip && dst_ip && msg_type && data) {
    char timestamp[64];
    time_t now = time(NULL);
    struct tm * tm_info = localtime( & now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    g_log_callback(timestamp, connection_id, packet_id, direction, src_ip, dst_ip, dst_port, "TCP", data, data_length, msg_type);
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
