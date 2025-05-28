/*
 * Intercept Suite - DLL Interface Header
 */

#ifndef INTERCEPT_DLL_H
#define INTERCEPT_DLL_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Callback function types for real-time logging */
typedef void (*log_callback_t)(const char* timestamp, const char* src_ip, const char* dst_ip, int dst_port, const char* message_type, const char* data);
typedef void (*status_callback_t)(const char* message);

/* Callback function types for real-time proxy events */
typedef void (*connection_callback_t)(const char* client_ip, int client_port, const char* target_host, int target_port, int connection_id);
typedef void (*stats_callback_t)(int total_connections, int active_connections, int total_bytes_transferred);
typedef void (*disconnect_callback_t)(int connection_id, const char* reason);

/* Callback function types for interception */
typedef void (*intercept_callback_t)(int connection_id, const char* direction, const char* src_ip, const char* dst_ip, int dst_port, const unsigned char* data, int data_length);

/* Start the proxy server (also initializes proxy subsystems) */
__declspec(dllexport) BOOL start_proxy(void);

/* Stop the proxy server */
__declspec(dllexport) void stop_proxy(void);

/* Configure proxy settings */
__declspec(dllexport) BOOL set_config(const char* bind_addr, int port, const char* log_file, int verbose_mode);

/* Set callback functions for real-time logging */
__declspec(dllexport) void set_log_callback(log_callback_t callback);
__declspec(dllexport) void set_status_callback(status_callback_t callback);

/* Set callback functions for real-time proxy events */
__declspec(dllexport) void set_connection_callback(connection_callback_t callback);
__declspec(dllexport) void set_stats_callback(stats_callback_t callback);
__declspec(dllexport) void set_disconnect_callback(disconnect_callback_t callback);

/* Set callback functions for interception */
__declspec(dllexport) void set_intercept_callback(intercept_callback_t callback);

/* Interception control functions */
__declspec(dllexport) void set_intercept_enabled(int enabled);
__declspec(dllexport) void set_intercept_direction(int direction);
__declspec(dllexport) void respond_to_intercept(int connection_id, int action, const unsigned char* modified_data, int modified_length);

/* Get system network interfaces */
__declspec(dllexport) int get_system_ips(char* buffer, int buffer_size);

/* Get current proxy configuration */
__declspec(dllexport) BOOL get_proxy_config(char* bind_addr, int* port, char* log_file, int* verbose_mode);

/* Get proxy statistics */
__declspec(dllexport) BOOL get_proxy_stats(int* connections, int* bytes_transferred);

#ifdef __cplusplus
}
#endif

#endif/* TLS_PROXY_DLL_H */
