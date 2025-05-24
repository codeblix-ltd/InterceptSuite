/*
 * TLS MITM Proxy - Modern GUI Implementation
 */

#include "../include/proxy_ui.h"
#include "../include/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <commctrl.h>
#include <windowsx.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

/* Global variables */
static HWND hwndMain = NULL;
static HWND hwndTab = NULL;
static HWND hwndProxyHistory = NULL;
static HWND hwndProxyConfig = NULL;
static HWND hwndDivertLogs = NULL;
static HWND hwndDivertConfig = NULL;

/* Circular buffer for logs */
static log_entry_t proxy_history[MAX_PROXY_HISTORY];
static log_entry_t divert_logs[MAX_LOG_ENTRIES];
static int proxy_history_count = 0;
static int divert_logs_count = 0;
static int current_proxy_index = 0;
static int current_divert_index = 0;

/* Critical sections for thread safety */
static CRITICAL_SECTION proxy_history_cs;
static CRITICAL_SECTION divert_logs_cs;

/* Proxy server state */
static int proxy_state = PROXY_STATE_STOPPED;

/* Function prototypes */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
static BOOL create_controls(HWND hwnd);
static BOOL create_tab_controls(void);
static void update_proxy_history(void);
static void update_divert_logs(void);
static void handle_tab_change(void);
static BOOL init_proxy_config_tab(void);
static BOOL init_divert_config_tab(void);
static void handle_proxy_start_stop(HWND hwnd);
static BOOL start_proxy_server_async(HWND hwnd);
static void stop_proxy_server(HWND hwnd);

/* Window class name */
static const wchar_t* WINDOW_CLASS = L"TlsProxyWindowClass";

BOOL init_proxy_ui(HINSTANCE hInstance) {
    /* Initialize COM for UI elements */
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icex);
    
    /* Initialize critical sections */
    InitializeCriticalSection(&proxy_history_cs);
    InitializeCriticalSection(&divert_logs_cs);
    
    /* Process any pending messages */
    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    /* Register window class */
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = WINDOW_CLASS;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
    
    if (!RegisterClassExW(&wc)) {
        return FALSE;
    }
    
    /* Create main window */
    hwndMain = CreateWindowExW(
        0,
        WINDOW_CLASS,
        L"TLS MITM Proxy",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        WINDOW_WIDTH, WINDOW_HEIGHT,
        NULL, NULL,
        hInstance, NULL
    );
    
    if (!hwndMain) {
        DWORD error = GetLastError();
        wchar_t errorMsg[256];
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            errorMsg,
            sizeof(errorMsg)/sizeof(wchar_t),
            NULL
        );
        MessageBoxW(NULL, errorMsg, L"Error Creating Window", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    
    /* Create child controls */
    SetWindowTextW(hwndMain, L"TLS MITM Proxy");
    if (!create_controls(hwndMain)) {
        MessageBoxW(NULL, L"Failed to create controls", L"Error", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    
    /* Show window */
    ShowWindow(hwndMain, SW_SHOW);
    UpdateWindow(hwndMain);
    
    return TRUE;
}

void cleanup_proxy_ui(void) {
    DeleteCriticalSection(&proxy_history_cs);
    DeleteCriticalSection(&divert_logs_cs);
    
    if (hwndMain) {
        DestroyWindow(hwndMain);
        hwndMain = NULL;
    }
}

static BOOL create_controls(HWND hwnd) {
    /* Create tab control */
    hwndTab = CreateWindowExW(
        0,
        WC_TABCONTROLW,
        NULL,
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0, 0, WINDOW_WIDTH, WINDOW_HEIGHT,
        hwnd, NULL,
        GetModuleHandle(NULL),
        NULL
    );
    
    if (!hwndTab) {
        return FALSE;
    }
    
    /* Add tabs */
    TCITEMW tie;
    tie.mask = TCIF_TEXT;
    
    tie.pszText = L"Proxy History";
    if (TabCtrl_InsertItem(hwndTab, TAB_PROXY_HISTORY, &tie) == -1) {
        return FALSE;
    }
    
    tie.pszText = L"Proxy Config";
    if (TabCtrl_InsertItem(hwndTab, TAB_PROXY_CONFIG, &tie) == -1) {
        return FALSE;
    }
    
    tie.pszText = L"Divert Logs";
    if (TabCtrl_InsertItem(hwndTab, TAB_DIVERT_LOGS, &tie) == -1) {
        return FALSE;
    }
    
    tie.pszText = L"Divert Config";
    if (TabCtrl_InsertItem(hwndTab, TAB_DIVERT_CONFIG, &tie) == -1) {
        return FALSE;
    }
    
    /* Create tab page windows */
    if (!create_tab_controls()) {
        return FALSE;
    }
    
    /* Show first tab */
    handle_tab_change();
    return TRUE;
}

static BOOL create_tab_controls(void) {
    RECT rcClient;
    GetClientRect(hwndTab, &rcClient);
    TabCtrl_AdjustRect(hwndTab, FALSE, &rcClient);
    
    /* Create Proxy History tab */
    hwndProxyHistory = CreateWindowExW(
        0,
        WC_LISTVIEWW,
        NULL,
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
        rcClient.left, rcClient.top,
        rcClient.right - rcClient.left,
        rcClient.bottom - rcClient.top,
        hwndTab, NULL,
        GetModuleHandle(NULL),
        NULL
    );
    
    if (!hwndProxyHistory) {
        return FALSE;
    }
    
    /* Add columns */
    LVCOLUMNW lvc = {0};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    
    lvc.pszText = L"Time";
    lvc.cx = 100;
    ListView_InsertColumn(hwndProxyHistory, 0, &lvc);
    
    lvc.pszText = L"Source IP";
    lvc.cx = 120;
    ListView_InsertColumn(hwndProxyHistory, 1, &lvc);
    
    lvc.pszText = L"Destination IP";
    lvc.cx = 120;
    ListView_InsertColumn(hwndProxyHistory, 2, &lvc);
    
    lvc.pszText = L"Port";
    lvc.cx = 60;
    ListView_InsertColumn(hwndProxyHistory, 3, &lvc);
    
    lvc.pszText = L"Message";
    lvc.cx = 300;
    ListView_InsertColumn(hwndProxyHistory, 4, &lvc);
    
    /* Create Proxy Config tab */
    if (!init_proxy_config_tab()) {
        return FALSE;
    }
    
    /* Create Divert Logs tab */
    hwndDivertLogs = CreateWindowExW(
        0,
        WC_LISTVIEWW,
        NULL,
        WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS,
        rcClient.left, rcClient.top,
        rcClient.right - rcClient.left,
        rcClient.bottom - rcClient.top,
        hwndTab, NULL,
        GetModuleHandle(NULL),
        NULL
    );
    
    if (!hwndDivertLogs) {
        return FALSE;
    }
    
    /* Add columns */
    lvc.pszText = L"Time";
    lvc.cx = 100;
    ListView_InsertColumn(hwndDivertLogs, 0, &lvc);
    
    lvc.pszText = L"Process";
    lvc.cx = 150;
    ListView_InsertColumn(hwndDivertLogs, 1, &lvc);
    
    lvc.pszText = L"Source IP";
    lvc.cx = 120;
    ListView_InsertColumn(hwndDivertLogs, 2, &lvc);
    
    lvc.pszText = L"Destination IP";
    lvc.cx = 120;
    ListView_InsertColumn(hwndDivertLogs, 3, &lvc);
    
    lvc.pszText = L"Port";
    lvc.cx = 60;
    ListView_InsertColumn(hwndDivertLogs, 4, &lvc);
    
    /* Create Divert Config tab */
    if (!init_divert_config_tab()) {
        return FALSE;
    }
    
    return TRUE;
}

static BOOL init_proxy_config_tab(void) {
    RECT rcClient;
    GetClientRect(hwndTab, &rcClient);
    TabCtrl_AdjustRect(hwndTab, FALSE, &rcClient);
    
    /* Create container window */
    hwndProxyConfig = CreateWindowExW(
        0,
        L"STATIC",
        NULL,
        WS_CHILD | WS_VISIBLE,
        rcClient.left, rcClient.top,
        rcClient.right - rcClient.left,
        rcClient.bottom - rcClient.top,
        hwndTab, NULL,
        GetModuleHandle(NULL),
        NULL
    );
    
    if (!hwndProxyConfig) {
        return FALSE;
    }
    
    /* Title */
    if (!CreateWindowExW(
        0, L"STATIC", L"Proxy Configuration",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        10, 10, 200, 20,
        hwndProxyConfig, NULL,
        GetModuleHandle(NULL), NULL
    )) {
        return FALSE;
    }
    
    /* Bind Address */
    if (!CreateWindowExW(
        0, L"STATIC", L"Bind Address:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        10, 40, 100, 20,
        hwndProxyConfig, NULL,
        GetModuleHandle(NULL), NULL
    )) {
        return FALSE;
    }
    
    wchar_t bind_addr[46];
    MultiByteToWideChar(CP_UTF8, 0, config.bind_addr, -1, bind_addr, 46);
    if (!CreateWindowExW(
        0, L"EDIT", bind_addr,
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
        120, 40, 150, 20,
        hwndProxyConfig, (HMENU)IDC_BIND_ADDR,
        GetModuleHandle(NULL), NULL
    )) {
        return FALSE;
    }
    
    /* Port */
    if (!CreateWindowExW(
        0, L"STATIC", L"Port:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        10, 70, 100, 20,
        hwndProxyConfig, NULL,
        GetModuleHandle(NULL), NULL
    )) {
        return FALSE;
    }
    
    wchar_t port[16];
    _snwprintf(port, 16, L"%d", config.port);
    if (!CreateWindowExW(
        0, L"EDIT", port,
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_NUMBER,
        120, 70, 60, 20,
        hwndProxyConfig, (HMENU)IDC_PORT,
        GetModuleHandle(NULL), NULL
    )) {
        return FALSE;
    }
    
    /* Log File */
    if (!CreateWindowExW(
        0, L"STATIC", L"Log File:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        10, 100, 100, 20,
        hwndProxyConfig, NULL,
        GetModuleHandle(NULL), NULL
    )) {
        return FALSE;
    }
    
    wchar_t log_file[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, config.log_file, -1, log_file, MAX_PATH);
    if (!CreateWindowExW(
        0, L"EDIT", log_file,
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
        120, 100, 200, 20,
        hwndProxyConfig, (HMENU)IDC_LOG_FILE,
        GetModuleHandle(NULL), NULL
    )) {
        return FALSE;
    }
    
    /* Browse button */
    if (!CreateWindowExW(
        0, L"BUTTON", L"Browse...",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        330, 100, 60, 20,
        hwndProxyConfig, (HMENU)IDC_BROWSE,
        GetModuleHandle(NULL), NULL
    )) {
        return FALSE;
    }
    
    /* Create Start/Stop button */
    HWND hwndStartButton = CreateWindowExW(
        0, L"BUTTON", L"Start Proxy",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, 140, 100, 25,
        hwndProxyConfig, (HMENU)IDC_START_PROXY,
        GetModuleHandle(NULL), NULL
    );
    
    if (!hwndStartButton) {
        return FALSE;
    }
    
    if (!CreateWindowExW(
        0, L"BUTTON", L"Apply Changes",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        120, 140, 100, 25,
        hwndProxyConfig, (HMENU)IDC_APPLY,
        GetModuleHandle(NULL), NULL
    )) {
        return FALSE;
    }
    
    return TRUE;
}

static BOOL init_divert_config_tab(void) {
    RECT rcClient;
    GetClientRect(hwndTab, &rcClient);
    TabCtrl_AdjustRect(hwndTab, FALSE, &rcClient);
    
    /* Create container window */
    hwndDivertConfig = CreateWindowExW(
        0,
        L"STATIC",
        NULL,
        WS_CHILD | WS_VISIBLE,
        rcClient.left, rcClient.top,
        rcClient.right - rcClient.left,
        rcClient.bottom - rcClient.top,
        hwndTab, NULL,
        GetModuleHandle(NULL),
        NULL
    );
    
    if (!hwndDivertConfig) {
        return FALSE;
    }
    
    /* Create WinDivert enable/disable button */
    HWND hwndEnableButton = CreateWindowExW(
        0,
        L"BUTTON",
        config.windivert_enabled ? L"Disable WinDivert" : L"Enable WinDivert",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, 10, 120, 30,
        hwndDivertConfig,
        (HMENU)IDC_ENABLE_DIVERT,
        GetModuleHandle(NULL),
        NULL
    );
    
    if (!hwndEnableButton) {
        return FALSE;
    }
    
    /* Create process list */
    HWND hwndProcessList = CreateWindowExW(
        0,
        WC_LISTVIEWW,
        NULL,
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
        10, 50,
        rcClient.right - rcClient.left - 20,
        rcClient.bottom - rcClient.top - 100,
        hwndDivertConfig,
        NULL,
        GetModuleHandle(NULL),
        NULL
    );
    
    if (!hwndDivertConfig) {
        return FALSE;
    }
    
    /* Add columns */
    LVCOLUMNW lvc = {0};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    
    lvc.pszText = L"Process";
    lvc.cx = 200;
    ListView_InsertColumn(hwndDivertConfig, 0, &lvc);
    
    lvc.pszText = L"Status";
    lvc.cx = 100;
    ListView_InsertColumn(hwndDivertConfig, 1, &lvc);
    
    return TRUE;
}

static void handle_tab_change(void) {
    int iSel = TabCtrl_GetCurSel(hwndTab);
    
    ShowWindow(hwndProxyHistory, iSel == TAB_PROXY_HISTORY ? SW_SHOW : SW_HIDE);
    ShowWindow(hwndProxyConfig, iSel == TAB_PROXY_CONFIG ? SW_SHOW : SW_HIDE);
    ShowWindow(hwndDivertLogs, iSel == TAB_DIVERT_LOGS ? SW_SHOW : SW_HIDE);
    ShowWindow(hwndDivertConfig, iSel == TAB_DIVERT_CONFIG ? SW_SHOW : SW_HIDE);
    
    /* Update tab content */
    switch (iSel) {
        case TAB_PROXY_HISTORY:
            update_proxy_history();
            break;
            
        case TAB_DIVERT_LOGS:
            update_divert_logs();
            break;
    }
}

void add_proxy_history_entry(const char* src_ip, const char* dst_ip, int dst_port, const char* msg) {
    EnterCriticalSection(&proxy_history_cs);
    
    /* Get current time */
    time_t now;
    struct tm tm_info;
    time(&now);
    localtime_s(&tm_info, &now);
    
    /* Create new entry */
    log_entry_t* entry = &proxy_history[current_proxy_index];
    strftime(entry->timestamp, sizeof(entry->timestamp), "%H:%M:%S", &tm_info);
    strncpy_s(entry->src_ip, sizeof(entry->src_ip), src_ip, _TRUNCATE);
    strncpy_s(entry->dst_ip, sizeof(entry->dst_ip), dst_ip, _TRUNCATE);
    entry->dst_port = dst_port;
    strncpy_s(entry->message, sizeof(entry->message), msg, _TRUNCATE);
    
    /* Update indices */
    current_proxy_index = (current_proxy_index + 1) % MAX_PROXY_HISTORY;
    if (proxy_history_count < MAX_PROXY_HISTORY) {
        proxy_history_count++;
    }
    
    LeaveCriticalSection(&proxy_history_cs);
    
    /* Update UI if visible */
    if (IsWindowVisible(hwndProxyHistory)) {
        PostMessage(hwndMain, WM_UPDATE_PROXY_HISTORY, 0, 0);
    }
}

void add_divert_log_entry(const char* process_name, const char* src_ip, const char* dst_ip, int dst_port) {
    EnterCriticalSection(&divert_logs_cs);
    
    /* Get current time */
    time_t now;
    struct tm tm_info;
    time(&now);
    localtime_s(&tm_info, &now);
    
    /* Create new entry */
    log_entry_t* entry = &divert_logs[current_divert_index];
    strftime(entry->timestamp, sizeof(entry->timestamp), "%H:%M:%S", &tm_info);
    strncpy_s(entry->process_name, sizeof(entry->process_name), process_name, _TRUNCATE);
    strncpy_s(entry->src_ip, sizeof(entry->src_ip), src_ip, _TRUNCATE);
    strncpy_s(entry->dst_ip, sizeof(entry->dst_ip), dst_ip, _TRUNCATE);
    entry->dst_port = dst_port;
    entry->diverted = 1;
    
    /* Update indices */
    current_divert_index = (current_divert_index + 1) % MAX_LOG_ENTRIES;
    if (divert_logs_count < MAX_LOG_ENTRIES) {
        divert_logs_count++;
    }
    
    LeaveCriticalSection(&divert_logs_cs);
    
    /* Update UI if visible */
    if (IsWindowVisible(hwndDivertLogs)) {
        PostMessage(hwndMain, WM_UPDATE_DIVERT_LOGS, 0, 0);
    }
}

static void update_proxy_history(void) {
    EnterCriticalSection(&proxy_history_cs);
    
    /* Clear existing items */
    ListView_DeleteAllItems(hwndProxyHistory);
    
    /* Add items */
    for (int i = 0; i < proxy_history_count; i++) {
        int index = (current_proxy_index - proxy_history_count + i + MAX_PROXY_HISTORY) % MAX_PROXY_HISTORY;
        log_entry_t* entry = &proxy_history[index];
        
        LVITEMW lvi = {0};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;
        
        wchar_t wbuf[256];
        
        /* Time */
        MultiByteToWideChar(CP_UTF8, 0, entry->timestamp, -1, wbuf, sizeof(wbuf)/sizeof(wchar_t));
        lvi.iSubItem = 0;
        lvi.pszText = wbuf;
        ListView_InsertItem(hwndProxyHistory, &lvi);
        
        /* Source IP */
        MultiByteToWideChar(CP_UTF8, 0, entry->src_ip, -1, wbuf, sizeof(wbuf)/sizeof(wchar_t));
        lvi.iSubItem = 1;
        lvi.pszText = wbuf;
        ListView_SetItem(hwndProxyHistory, &lvi);
        
        /* Destination IP */
        MultiByteToWideChar(CP_UTF8, 0, entry->dst_ip, -1, wbuf, sizeof(wbuf)/sizeof(wchar_t));
        lvi.iSubItem = 2;
        lvi.pszText = wbuf;
        ListView_SetItem(hwndProxyHistory, &lvi);
        
        /* Port */
        char port[16];
        snprintf(port, sizeof(port), "%d", entry->dst_port);
        MultiByteToWideChar(CP_UTF8, 0, port, -1, wbuf, sizeof(wbuf)/sizeof(wchar_t));
        lvi.iSubItem = 3;
        lvi.pszText = wbuf;
        ListView_SetItem(hwndProxyHistory, &lvi);
        
        /* Message */
        MultiByteToWideChar(CP_UTF8, 0, entry->message, -1, wbuf, sizeof(wbuf)/sizeof(wchar_t));
        lvi.iSubItem = 4;
        lvi.pszText = wbuf;
        ListView_SetItem(hwndProxyHistory, &lvi);
    }
    
    LeaveCriticalSection(&proxy_history_cs);
}

static void update_divert_logs(void) {
    EnterCriticalSection(&divert_logs_cs);
    
    /* Clear existing items */
    ListView_DeleteAllItems(hwndDivertLogs);
    
    /* Add items */
    for (int i = 0; i < divert_logs_count; i++) {
        int index = (current_divert_index - divert_logs_count + i + MAX_LOG_ENTRIES) % MAX_LOG_ENTRIES;
        log_entry_t* entry = &divert_logs[index];
        
        LVITEMW lvi = {0};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;
        
        wchar_t wbuf[256];
        
        /* Time */
        MultiByteToWideChar(CP_UTF8, 0, entry->timestamp, -1, wbuf, sizeof(wbuf)/sizeof(wchar_t));
        lvi.iSubItem = 0;
        lvi.pszText = wbuf;
        ListView_InsertItem(hwndDivertLogs, &lvi);
        
        /* Process */
        MultiByteToWideChar(CP_UTF8, 0, entry->process_name, -1, wbuf, sizeof(wbuf)/sizeof(wchar_t));
        lvi.iSubItem = 1;
        lvi.pszText = wbuf;
        ListView_SetItem(hwndDivertLogs, &lvi);
        
        /* Source IP */
        MultiByteToWideChar(CP_UTF8, 0, entry->src_ip, -1, wbuf, sizeof(wbuf)/sizeof(wchar_t));
        lvi.iSubItem = 2;
        lvi.pszText = wbuf;
        ListView_SetItem(hwndDivertLogs, &lvi);
        
        /* Destination IP */
        MultiByteToWideChar(CP_UTF8, 0, entry->dst_ip, -1, wbuf, sizeof(wbuf)/sizeof(wchar_t));
        lvi.iSubItem = 3;
        lvi.pszText = wbuf;
        ListView_SetItem(hwndDivertLogs, &lvi);
        
        /* Port */
        char port[16];
        snprintf(port, sizeof(port), "%d", entry->dst_port);
        MultiByteToWideChar(CP_UTF8, 0, port, -1, wbuf, sizeof(wbuf)/sizeof(wchar_t));
        lvi.iSubItem = 4;
        lvi.pszText = wbuf;
        ListView_SetItem(hwndDivertLogs, &lvi);
    }
    
    LeaveCriticalSection(&divert_logs_cs);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_SIZE:
            /* Resize child windows */
            if (hwndTab) {
                SetWindowPos(hwndTab, NULL, 0, 0, LOWORD(lParam), HIWORD(lParam), SWP_NOZORDER);
                handle_tab_change();
            }
            break;
            
        case WM_NOTIFY:
            if (((LPNMHDR)lParam)->hwndFrom == hwndTab) {
                if (((LPNMHDR)lParam)->code == TCN_SELCHANGE) {
                    handle_tab_change();
                }
            }
            break;
            
        case WM_UPDATE_PROXY_HISTORY:
            update_proxy_history();
            break;
            
        case WM_UPDATE_DIVERT_LOGS:
            update_divert_logs();
            break;
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_START_PROXY:
                    handle_proxy_start_stop(hwnd);
                    break;
                    
                case IDC_ENABLE_DIVERT: {
                    HWND button = GetDlgItem(hwndDivertConfig, IDC_ENABLE_DIVERT);
                    if (!config.windivert_enabled) {
                        // Try to enable WinDivert
                        if (init_process_diversion()) {
                            config.windivert_enabled = 1;
                            SetWindowTextW(button, L"Disable WinDivert");
                        } else {
                            MessageBoxW(hwnd, L"Failed to initialize WinDivert. Make sure you have administrator privileges.", 
                                      L"Error", MB_OK | MB_ICONERROR);
                        }
                    } else {
                        // Disable WinDivert
                        cleanup_process_diversion();
                        config.windivert_enabled = 0;
                        SetWindowTextW(button, L"Enable WinDivert");
                    }
                    break;
                }
                
                case IDC_BROWSE: {
                    wchar_t filename[MAX_PATH] = L"";
                    OPENFILENAMEW ofn = {0};
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hwnd;
                    ofn.lpstrFilter = L"Log Files (*.log)\0*.log\0All Files (*.*)\0*.*\0";
                    ofn.lpstrFile = filename;
                    ofn.nMaxFile = MAX_PATH;
                    ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST;
                    
                    if (GetSaveFileNameW(&ofn)) {
                        SetDlgItemTextW(hwndProxyConfig, IDC_LOG_FILE, filename);
                    }
                    break;
                }
                
                case IDC_APPLY: {
                    wchar_t w_bind_addr[46];
                    wchar_t w_log_file[MAX_PATH];
                    wchar_t w_port[16];
                    char new_bind_addr[46];
                    char new_log_file[MAX_PATH];
                    int new_port;
                    
                    /* Get values from UI */
                    GetDlgItemTextW(hwndProxyConfig, IDC_BIND_ADDR, w_bind_addr, ARRAYSIZE(w_bind_addr));
                    GetDlgItemTextW(hwndProxyConfig, IDC_PORT, w_port, ARRAYSIZE(w_port));
                    GetDlgItemTextW(hwndProxyConfig, IDC_LOG_FILE, w_log_file, ARRAYSIZE(w_log_file));
                    
                    /* Convert to UTF-8 */
                    WideCharToMultiByte(CP_UTF8, 0, w_bind_addr, -1, new_bind_addr, sizeof(new_bind_addr), NULL, NULL);
                    new_port = _wtoi(w_port);
                    WideCharToMultiByte(CP_UTF8, 0, w_log_file, -1, new_log_file, sizeof(new_log_file), NULL, NULL);
                    
                    /* Validate IP address */
                    if (!validate_ip_address(new_bind_addr)) {
                        MessageBoxW(hwnd, L"Invalid IP address", L"Error", MB_OK | MB_ICONERROR);
                        break;
                    }
                    
                    /* Validate port */
                    if (new_port <= 0 || new_port > 65535) {
                        MessageBoxW(hwnd, L"Invalid port number", L"Error", MB_OK | MB_ICONERROR);
                        break;
                    }
                    
                    /* Apply changes */
                    strncpy(config.bind_addr, new_bind_addr, sizeof(config.bind_addr) - 1);
                    config.port = new_port;
                    strncpy(config.log_file, new_log_file, sizeof(config.log_file) - 1);
                    
                    /* Restart proxy server */
                    MessageBoxW(hwnd, L"Changes will take effect after restarting the application", 
                             L"Configuration Updated", MB_OK | MB_ICONINFORMATION);
                    break;                
                }
            }
            break;
            
        case WM_CLOSE:
            /* Stop proxy server if running */
            if (proxy_state == PROXY_STATE_RUNNING || proxy_state == PROXY_STATE_STARTING) {
                /* Signal thread to stop */
                EnterCriticalSection(&g_server.cs);
                g_server.should_stop = 1;
                LeaveCriticalSection(&g_server.cs);
                
                /* Close socket to break accept() */
                if (g_server.server_sock != INVALID_SOCKET) {
                    shutdown(g_server.server_sock, SD_BOTH);
                    close_socket(g_server.server_sock);
                    g_server.server_sock = INVALID_SOCKET;
                }

                /* Wait for thread to finish */
                if (g_server.thread_handle) {
                    if (WaitForSingleObject(g_server.thread_handle, 5000) == WAIT_TIMEOUT) {
                        /* Thread didn't finish in time - terminate it */
                        TerminateThread(g_server.thread_handle, 1);
                    }
                    CloseHandle(g_server.thread_handle);
                    g_server.thread_handle = NULL;
                }
                
                /* Delete critical section */
                DeleteCriticalSection(&g_server.cs);
            }
            
            DestroyWindow(hwnd);
            break;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

BOOL is_ui_initialized(void) {
    return (hwndMain != NULL);
}

void show_main_window(void) {
    if (hwndMain) {
        ShowWindow(hwndMain, SW_SHOW);
        UpdateWindow(hwndMain);
    }
}

void hide_main_window(void) {
    if (hwndMain) {
        ShowWindow(hwndMain, SW_HIDE);
    }
}

static void handle_proxy_start_stop(HWND hwnd) {
    HWND button = GetDlgItem(hwndProxyConfig, IDC_START_PROXY);
    if (!button) {
        MessageBoxW(hwnd, L"Internal error: Start/Stop button not found", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    switch (proxy_state) {
        case PROXY_STATE_STOPPED:
            /* Start the proxy server */
            SetWindowTextW(button, L"Starting...");
            EnableWindow(button, FALSE);
            proxy_state = PROXY_STATE_STARTING;
            
            if (!start_proxy_server_async(hwnd)) {
                /* Reset state if startup fails */
                proxy_state = PROXY_STATE_STOPPED;
                SetWindowTextW(button, L"Start Proxy");
                EnableWindow(button, TRUE);
            }
            break;
            
        case PROXY_STATE_STARTING:
            /* Ignore button clicks while starting */
            break;
            
        case PROXY_STATE_RUNNING:
            /* Stop the proxy server */
            SetWindowTextW(button, L"Stopping...");
            EnableWindow(button, FALSE);
            proxy_state = PROXY_STATE_STOPPING;
            stop_proxy_server(hwnd);
            break;
            
        case PROXY_STATE_STOPPING:
            /* Ignore button clicks while stopping */
            break;
    }
}

static BOOL start_proxy_server_async(HWND hwnd) {
    /* Initialize critical section first */
    InitializeCriticalSection(&g_server.cs);
    g_server.should_stop = 0;
    g_server.thread_handle = NULL;
    
    /* Create server socket */
    socket_t server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        MessageBoxW(hwnd, L"Failed to create server socket", L"Error", MB_OK | MB_ICONERROR);
        DeleteCriticalSection(&g_server.cs);
        return FALSE;
    }
    
    /* Allow socket reuse */
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        MessageBoxW(hwnd, L"Failed to set socket options", L"Error", MB_OK | MB_ICONERROR);
        close_socket(server_sock);
        DeleteCriticalSection(&g_server.cs);
        return FALSE;
    }
    
    /* Bind socket */
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, config.bind_addr, &(server_addr.sin_addr)) != 1) {
        MessageBoxW(hwnd, L"Invalid bind address", L"Error", MB_OK | MB_ICONERROR);
        close_socket(server_sock);
        DeleteCriticalSection(&g_server.cs);
        return FALSE;
    }
    server_addr.sin_port = htons(config.port);
    
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        wchar_t errMsg[256];
        _snwprintf(errMsg, 256, L"Failed to bind to %hs:%d (Error: %d)", 
                  config.bind_addr, config.port, WSAGetLastError());
        MessageBoxW(hwnd, errMsg, L"Error", MB_OK | MB_ICONERROR);
        close_socket(server_sock);
        DeleteCriticalSection(&g_server.cs);
        return FALSE;
    }
    
    /* Start listening */
    if (listen(server_sock, SOMAXCONN) == SOCKET_ERROR) {
        MessageBoxW(hwnd, L"Failed to listen on server socket", L"Error", MB_OK | MB_ICONERROR);
        close_socket(server_sock);
        DeleteCriticalSection(&g_server.cs);
        return FALSE;
    }
    
    /* Set socket to non-blocking mode */
    unsigned long nonBlocking = 1;
    if (ioctlsocket(server_sock, FIONBIO, &nonBlocking) != 0) {
        MessageBoxW(hwnd, L"Failed to set non-blocking mode", L"Error", MB_OK | MB_ICONERROR);
        close_socket(server_sock);
        DeleteCriticalSection(&g_server.cs);
        return FALSE;
    }
    
    /* Store server socket in global state */
    g_server.server_sock = server_sock;
    
    /* Start server thread */
    g_server.thread_handle = (HANDLE)_beginthreadex(NULL, 0, run_server_thread, NULL, 0, NULL);
    if (g_server.thread_handle == NULL) {
        MessageBoxW(hwnd, L"Failed to create server thread", L"Error", MB_OK | MB_ICONERROR);
        close_socket(server_sock);
        DeleteCriticalSection(&g_server.cs);
        return FALSE;
    }
    
    /* Update UI */
    HWND button = GetDlgItem(hwndProxyConfig, IDC_START_PROXY);
    SetWindowTextW(button, L"Stop Proxy");
    EnableWindow(button, TRUE);
    proxy_state = PROXY_STATE_RUNNING;
    
    return TRUE;
}

static void stop_proxy_server(HWND hwnd) {
    HWND button = GetDlgItem(hwndProxyConfig, IDC_START_PROXY);
    if (!button) {
        MessageBoxW(hwnd, L"Internal error: Start/Stop button not found", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    /* Signal thread to stop */
    EnterCriticalSection(&g_server.cs);
    g_server.should_stop = 1;
    LeaveCriticalSection(&g_server.cs);
    
    /* Close socket to break accept() */
    if (g_server.server_sock != INVALID_SOCKET) {
        shutdown(g_server.server_sock, SD_BOTH);
        close_socket(g_server.server_sock);
        g_server.server_sock = INVALID_SOCKET;
    }

    /* Wait for thread to finish */
    if (g_server.thread_handle) {
        if (WaitForSingleObject(g_server.thread_handle, 5000) == WAIT_TIMEOUT) {
            /* Thread didn't finish in time - terminate it */
            TerminateThread(g_server.thread_handle, 1);
            MessageBoxW(hwnd, L"Server thread had to be forcefully terminated", 
                      L"Warning", MB_OK | MB_ICONWARNING);
        }
        CloseHandle(g_server.thread_handle);
        g_server.thread_handle = NULL;
    }
    
    /* Delete critical section */
    DeleteCriticalSection(&g_server.cs);
    
    /* Update UI */
    proxy_state = PROXY_STATE_STOPPED;
    SetWindowTextW(button, L"Start Proxy");
    EnableWindow(button, TRUE);
}