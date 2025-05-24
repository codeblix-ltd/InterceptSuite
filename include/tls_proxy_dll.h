/*
 * TLS MITM Proxy - DLL Interface Header
 */

#ifndef TLS_PROXY_DLL_H
#define TLS_PROXY_DLL_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Callback function types for real-time logging */
typedef void (*log_callback_t)(const char* timestamp, const char* src_ip, const char* dst_ip, int dst_port, const char* message_type, const char* data);
typedef void (*status_callback_t)(const char* message);

/* Initialize the proxy subsystems (Winsock, OpenSSL, etc.) */
__declspec(dllexport) BOOL init_proxy(void);

/* Start the proxy server */
__declspec(dllexport) BOOL start_proxy(void);

/* Stop the proxy server */
__declspec(dllexport) void stop_proxy(void);

/* Configure proxy settings */
__declspec(dllexport) BOOL set_config(const char* bind_addr, int port, const char* log_file);

/* Enable WinDivert functionality */
__declspec(dllexport) BOOL enable_windivert(void);

/* Disable WinDivert functionality */
__declspec(dllexport) void disable_windivert(void);

/* Set callback functions for real-time logging */
__declspec(dllexport) void set_log_callback(log_callback_t callback);
__declspec(dllexport) void set_status_callback(status_callback_t callback);

/* Get system network interfaces */
__declspec(dllexport) int get_system_ips(char* buffer, int buffer_size);

/* Get current proxy configuration */
__declspec(dllexport) BOOL get_proxy_config(char* bind_addr, int* port, char* log_file);

/* Get proxy statistics */
__declspec(dllexport) BOOL get_proxy_stats(int* connections, int* bytes_transferred);

/* Process enumeration and WinDivert process filtering */
__declspec(dllexport) int get_running_processes(char* buffer, int buffer_size);
__declspec(dllexport) BOOL set_windivert_process_filter(int* pids, int pid_count);
__declspec(dllexport) void clear_windivert_process_filter(void);

#ifdef __cplusplus
}
#endif

#endif /* TLS_PROXY_DLL_H */
