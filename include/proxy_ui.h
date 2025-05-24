/*
 * TLS MITM Proxy - Modern GUI Header
 *
 * Provides advanced GUI functionality with tabbed interface for:
 * - Proxy Configuration and Monitoring
 * - WinDivert Traffic Management
 * - Connection Statistics
 */

#ifndef PROXY_UI_H
#define PROXY_UI_H

#include "tls_proxy.h"
#include "process_divert.h"
#include <windows.h>

/* Window dimensions */
#define WINDOW_WIDTH 800
#define WINDOW_HEIGHT 600

/* Tab indices */
#define TAB_PROXY_HISTORY    0
#define TAB_PROXY_CONFIG     1
#define TAB_DIVERT_LOGS     2
#define TAB_DIVERT_CONFIG   3

/* Maximum entries */
#define MAX_LOG_ENTRIES     1000
#define MAX_PROXY_HISTORY   1000
#define MAX_FILTERS         50

/* Message types */
#define WM_UPDATE_PROXY_HISTORY (WM_USER + 1)
#define WM_UPDATE_DIVERT_LOGS   (WM_USER + 2)

/* Control IDs */
#define IDC_BIND_ADDR       1001
#define IDC_PORT            1002
#define IDC_LOG_FILE        1003
#define IDC_BROWSE          1004
#define IDC_APPLY           1005
#define IDC_ENABLE_DIVERT   1006
#define IDC_START_PROXY     1007  /* Added control ID for proxy start/stop button */

/* Server state */
#define PROXY_STATE_STOPPED  0
#define PROXY_STATE_STARTING 1
#define PROXY_STATE_RUNNING  2
#define PROXY_STATE_STOPPING 3

/* Data structures */
typedef struct {
    char timestamp[20];
    char src_ip[46];
    char dst_ip[46];
    int dst_port;
    char process_name[MAX_PATH];
    char message[256];
    int diverted;
    int intercepted;
} log_entry_t;

/* Function prototypes */
BOOL init_proxy_ui(HINSTANCE hInstance);
void cleanup_proxy_ui(void);
void add_proxy_history_entry(const char* src_ip, const char* dst_ip, int dst_port, const char* msg);
void add_divert_log_entry(const char* process_name, const char* src_ip, const char* dst_ip, int dst_port);
BOOL is_ui_initialized(void);
void show_main_window(void);
void hide_main_window(void);

#endif /* PROXY_UI_H */