/*
 * TLS MITM Proxy - Library Interface
 *
 * Provides exports for controlling the TLS MITM proxy functionality.
 */
#include "platform/platform.h"

#include "tls/proxy/tls_proxy.h"

#include "tls/cert/cert_utils.h"

#include "proxy/socks5.h"

#include "tls/proxy/tls_utils.h"

#include "utils/utils.h"

#include "tls/proxy/tls_proxy_dll.h"

#include "config/user_data.h"

#include "proxy/proxy_manager.h"

#include "tls/cert/cert_export.h"

#include "proxy/interceptor/interceptor.h"

#include "utils/utils.h"

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

/* Global packet ID counter for unified packet tracking */
int g_packet_id_counter = 0;

/* Function to initialize the library/DLL */
static int initialize_library(void) {
  /* Initialize default configuration */
  init_config();

  /* Initialize OpenSSL */
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_crypto_strings();

  /* Initialize certificate cache */
  init_cert_cache();

  /* Initialize interception mutex */
  INIT_MUTEX(g_intercept_config.intercept_cs);
  
  /* Initialize packet ID mutex */
  INIT_MUTEX(g_packet_id_mutex);

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

  /* Cleanup certificate cache */
  cleanup_cert_cache();

  /* Cleanup OpenSSL */
  ERR_free_strings();
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();

  /* Destroy interception mutex */
  DESTROY_MUTEX(g_intercept_config.intercept_cs);

  /* Cleanup packet ID system */
  cleanup_packet_id_system();

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

/**
 * DLL export wrapper for certificate regeneration
 * Converts C library return value to Windows BOOL type
 *
 * @return TRUE on success, FALSE on failure
 */
INTERCEPT_API intercept_bool_t regenerate_ca_certificate_wrapper(void) {
    return regenerate_ca_certificate() ? TRUE : FALSE;
}

/* Get current proxy configuration */
/* Process enumeration functionality has been removed as it was only needed for WinDivert */
//TBD