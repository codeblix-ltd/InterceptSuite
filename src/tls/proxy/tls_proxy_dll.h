/*
 * Intercept Suite - Library Interface Header
 */

#ifndef INTERCEPT_DLL_H
#define INTERCEPT_DLL_H

/* Platform detection macros */
#if defined(_WIN32) || defined(_WIN64)
    #ifndef INTERCEPT_WINDOWS
    #define INTERCEPT_WINDOWS
    #endif
    /* Windows.h must be included before winsock2.h to avoid conflicts */
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #define INTERCEPT_EXPORT __declspec(dllexport)
    #define INTERCEPT_IMPORT __declspec(dllimport)
    typedef BOOL intercept_bool_t;
#elif defined(__APPLE__)
    #include <stdbool.h>
    #define INTERCEPT_EXPORT __attribute__((visibility("default")))
    #define INTERCEPT_IMPORT
    typedef bool intercept_bool_t;
#elif defined(__linux__) || defined(__unix__)
   // #define INTERCEPT_LINUX
    #include <stdbool.h>
    #define INTERCEPT_EXPORT __attribute__((visibility("default")))
    #define INTERCEPT_IMPORT
    typedef bool intercept_bool_t;
#else
    #error "Unsupported platform"
#endif

/* Define external linkage based on whether we're building or consuming the library */
#ifdef BUILDING_INTERCEPT_LIB
    #define INTERCEPT_API INTERCEPT_EXPORT
#else
    #define INTERCEPT_API INTERCEPT_IMPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Callback function types for real-time logging */
typedef void (*log_callback_t)(const char* timestamp, int connection_id, int packet_id, const char* direction, const char* src_ip, const char* dst_ip, int dst_port, const char* protocol, const unsigned char* data, int data_length, const char* message_type);
typedef void (*status_callback_t)(const char* message);

/* Callback function types for real-time proxy events */
typedef void (*connection_callback_t)(const char* client_ip, int client_port, const char* target_host, int target_port, int connection_id);
typedef void (*disconnect_callback_t)(int connection_id, const char* reason);

/* Callback function types for interception */
typedef void (*intercept_callback_t)(int connection_id, const char* direction, const char* src_ip, const char* dst_ip, int dst_port, const char* protocol, const unsigned char* data, int data_length, int packet_id);

/* Structure to hold intercept configuration details */
typedef struct {
    int is_enabled;           /* Interception enabled (1) or disabled (0) */
    int direction;            /* Direction: None (0), Client->Server (1), Server->Client (2), Both (3) */
} intercept_status_t;

/* Structure to hold proxy start result */
typedef struct {
    int success;              /* Operation success (1) or failure (0) */
    char message[512];        /* Status or error message */
} proxy_start_result_t;

/* Structure to hold proxy configuration details */
typedef struct {
    char bind_addr[64];       /* Binding IP address */
    int port;                 /* Proxy port */
    int verbose_mode;         /* Verbose logging enabled (1) or disabled (0) */
    int is_running;           /* Proxy status: running (1) or stopped (0) */
} proxy_config_t;

/* Start the proxy server (also initializes proxy subsystems) */
INTERCEPT_API proxy_start_result_t start_proxy(void);

/* Stop the proxy server */
INTERCEPT_API void stop_proxy(void);

/* Configure proxy settings */
INTERCEPT_API intercept_bool_t set_config(const char* bind_addr, int port, int verbose_mode);

/* Set callback functions for real-time logging */
INTERCEPT_API void set_log_callback(log_callback_t callback);
INTERCEPT_API void set_status_callback(status_callback_t callback);

/* Set callback functions for real-time proxy events */
INTERCEPT_API void set_connection_callback(connection_callback_t callback);
INTERCEPT_API void set_disconnect_callback(disconnect_callback_t callback);

/* Set callback functions for interception */
INTERCEPT_API void set_intercept_callback(intercept_callback_t callback);

/* Interception control functions */
INTERCEPT_API void set_intercept_enabled(int enabled);
INTERCEPT_API void set_intercept_direction(int direction);
INTERCEPT_API void respond_to_intercept(int packet_id, int action, const unsigned char* modified_data, int modified_length);

/* Get system network interfaces */
INTERCEPT_API int get_system_ips(char* buffer, int buffer_size);

/* Get current intercept configuration */
INTERCEPT_API intercept_status_t get_intercept_config(void);

/* Get current proxy configuration with status */
INTERCEPT_API proxy_config_t get_proxy_config(void);

/* Certificate export function */
/* export_type: 0 = certificate (PEM to DER), 1 = private key (PEM copy) */
INTERCEPT_API intercept_bool_t export_certificate(const char* output_directory, int export_type);

/* Certificate regeneration function */
INTERCEPT_API intercept_bool_t regenerate_ca_certificate_wrapper(void);

#ifdef __cplusplus
}
#endif

#endif/* TLS_PROXY_DLL_H */
