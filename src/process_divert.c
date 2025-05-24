/*
 * TLS MITM Proxy - Process-Based Traffic Diversion Implementation
 *
 * Using WinDivert to selectively intercept TLS traffic from specific processes.
 */

#include "../include/process_divert.h"
#include "../include/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windivert.h>
#include <process.h>
#include <iphlpapi.h>

#define MAX_PROCESSES 64
#define MAX_PACKET_SIZE 65536

/* Static variables */
static char *diverted_processes[MAX_PROCESSES] = {0};
static int process_count = 0;
static HANDLE divert_handle = INVALID_HANDLE_VALUE;
static HANDLE divert_thread = NULL;
static volatile int running = 0;
static DivertCallback divert_callback = NULL;

/* Forward declarations of helper functions */
static UINT __stdcall divert_worker(void *arg);
static char* get_process_name_by_pid(DWORD pid);
static DWORD get_pid_by_connection(UINT32 local_addr, UINT16 local_port,
                               UINT32 remote_addr, UINT16 remote_port);
static int string_to_ip(const char* ip, UINT32 *addr);
static void ip_to_string(UINT32 addr, char *str);

int init_process_diversion(void) {
    // Initialize diverted processes array
    memset(diverted_processes, 0, sizeof(diverted_processes));
    process_count = 0;

    // Construct the WinDivert filter for outbound TLS/SSL connections
    // Other common HTTPS ports: 443, 8443
    const char *filter = "outbound and tcp.DstPort == 443";

    // Open a WinDivert handle for the specified filter
    divert_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (divert_handle == INVALID_HANDLE_VALUE) {
        log_message("Failed to open WinDivert handle: %d", GetLastError());
        return 0;
    }

    // Set running flag and create the worker thread
    running = 1;
    divert_thread = (HANDLE)_beginthreadex(NULL, 0, divert_worker, NULL, 0, NULL);
    if (!divert_thread) {
        log_message("Failed to create WinDivert worker thread: %d", GetLastError());
        WinDivertClose(divert_handle);
        divert_handle = INVALID_HANDLE_VALUE;
        running = 0;
        return 0;
    }

    log_message("Process diversion initialized successfully");
    return 1;
}

void cleanup_process_diversion(void) {
    // Signal the worker thread to stop
    running = 0;

    // Close the WinDivert handle (this will also terminate any pending WinDivertRecv calls)
    if (divert_handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(divert_handle);
        divert_handle = INVALID_HANDLE_VALUE;
    }

    // Wait for the worker thread to terminate
    if (divert_thread) {
        WaitForSingleObject(divert_thread, 5000); // Wait up to 5 seconds
        CloseHandle(divert_thread);
        divert_thread = NULL;
    }

    // Clean up the diverted processes list
    for (int i = 0; i < process_count; i++) {
        if (diverted_processes[i]) {
            free(diverted_processes[i]);
            diverted_processes[i] = NULL;
        }
    }
    process_count = 0;

    log_message("Process diversion cleaned up");
}

int add_process_to_divert(const char* process_name) {
    if (!process_name || !*process_name) {
        log_message("Invalid process name");
        return 0;
    }

    // Check if WinDivert was properly initialized
    if (divert_handle == INVALID_HANDLE_VALUE) {
        log_message("Warning: Adding process '%s' to diversion list, but diversion is not properly initialized", process_name);
        log_message("Traffic will not be intercepted until the application is run with administrator privileges");
    }

    // Check if process is already in the list
    for (int i = 0; i < process_count; i++) {
        if (diverted_processes[i] && _stricmp(diverted_processes[i], process_name) == 0) {
            log_message("Process %s is already being diverted", process_name);
            return 1; // Already in the list
        }
    }

    // Check if we have room for more processes
    if (process_count >= MAX_PROCESSES) {
        log_message("Maximum number of diverted processes reached");
        return 0;
    }

    // Add the process to the list
    diverted_processes[process_count] = _strdup(process_name);
    if (!diverted_processes[process_count]) {
        log_message("Failed to allocate memory for process name");
        return 0;
    }

    process_count++;
    log_message("Added process to diversion list: %s", process_name);
    return 1;
}

int remove_process_from_divert(const char* process_name) {
    if (!process_name || !*process_name) {
        return 0;
    }

    for (int i = 0; i < process_count; i++) {
        if (diverted_processes[i] && _stricmp(diverted_processes[i], process_name) == 0) {
            // Free the memory for the process name
            free(diverted_processes[i]);

            // Shift all subsequent entries down by one
            for (int j = i; j < process_count - 1; j++) {
                diverted_processes[j] = diverted_processes[j + 1];
            }

            // Clear the last entry
            diverted_processes[process_count - 1] = NULL;
            process_count--;

            log_message("Removed process from diversion list: %s", process_name);
            return 1;
        }
    }

    log_message("Process %s not found in diversion list", process_name);
    return 0;
}

int is_process_diverted(const char* process_name) {
    if (!process_name || !*process_name) {
        return 0;
    }

    for (int i = 0; i < process_count; i++) {
        if (diverted_processes[i] && _stricmp(diverted_processes[i], process_name) == 0) {
            return 1;
        }
    }

    return 0;
}

void register_divert_callback(DivertCallback callback) {
    divert_callback = callback;
}

int get_diverted_processes(char*** process_list, int* count) {
    if (!process_list || !count) {
        return 0;
    }

    *count = process_count;
    *process_list = diverted_processes;

    return 1;
}

/* Worker thread function that processes diverted packets */
static UINT __stdcall divert_worker(void *arg) {
    WINDIVERT_ADDRESS addr;
    char packet[MAX_PACKET_SIZE];
    UINT packet_len;
    DWORD pid;
    char *process_name;
    char src_ip[46], dst_ip[46];

    while (running) {
        // Receive a diverted packet
        if (!WinDivertRecv(divert_handle, packet, sizeof(packet), &packet_len, &addr)) {
            if (GetLastError() == ERROR_OPERATION_ABORTED) {
                // Handle was closed, exit thread
                break;
            }
            log_message("WinDivertRecv failed: %d", GetLastError());
            continue;
        }
          // Extract IP addresses and ports from packet
        PWINDIVERT_IPHDR ip_header = NULL;
        PWINDIVERT_IPV6HDR ipv6_header = NULL;
        PWINDIVERT_TCPHDR tcp_header = NULL;
        UINT8 protocol = 0;
        PVOID payload = NULL;
        UINT payload_len = 0;
        UINT32 src_addr = 0, dst_addr = 0;
        UINT16 src_port = 0, dst_port = 0;

        // Parse the packet header to get addressing information
        WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header,
                                  &protocol, NULL, NULL, &tcp_header, NULL,
                                  &payload, &payload_len, NULL, NULL);

        if (addr.IPv6) {
            // Not handling IPv6 currently
            WinDivertSend(divert_handle, packet, packet_len, NULL, &addr);
            continue;
        }

        if (ip_header != NULL && tcp_header != NULL) {
            src_addr = ip_header->SrcAddr;
            dst_addr = ip_header->DstAddr;
            src_port = tcp_header->SrcPort;
            dst_port = tcp_header->DstPort;

            // Convert IP addresses to strings for logging
            ip_to_string(src_addr, src_ip);
            ip_to_string(dst_addr, dst_ip);
              // Get the process ID for this connection
            // Note: src_port and dst_port from TCP header are already in network byte order
            // while our function expects host byte order for ports
            pid = get_pid_by_connection(src_addr, ntohs(src_port), dst_addr, ntohs(dst_port));

        if (pid) {
            // Get the process name
            process_name = get_process_name_by_pid(pid);

            if (process_name) {
                // Check if this process should be diverted
                if (is_process_diverted(process_name)) {
                    // Process is in our diversion list                    if (config.verbose) {
                        log_message("Diverted traffic: %s (%u) from %s:%d to %s:%d",
                            process_name, pid, src_ip, ntohs(src_port),
                            dst_ip, ntohs(dst_port));
                    }

                    // Call the callback if registered
                    if (divert_callback) {
                        divert_callback(process_name, src_ip, dst_ip, ntohs(dst_port));
                    }                    // Modify the packet to redirect to our proxy
                    // Change the destination address to our proxy address and port
                    if (ip_header != NULL && tcp_header != NULL) {
                        // Save the original destination for logging
                        UINT32 orig_dst_addr = ip_header->DstAddr;
                        UINT16 orig_dst_port = tcp_header->DstPort;

                        // Convert our proxy address to binary form
                        struct in_addr proxy_addr;
                        if (inet_pton(AF_INET, config.bind_addr, &proxy_addr) == 1) {
                            // Change the destination to our proxy
                            ip_header->DstAddr = proxy_addr.s_addr;
                            tcp_header->DstPort = htons(config.port);

                            // Recalculate IP and TCP checksums
                            WinDivertHelperCalcChecksums(packet, packet_len, NULL, 0);

                            if (config.verbose) {
                                log_message("Redirecting traffic: %s -> %s:%d to proxy %s:%d",
                                    process_name, dst_ip, ntohs(orig_dst_port),
                                    config.bind_addr, config.port);
                            }
                        } else {
                            log_message("Failed to convert proxy address, not redirecting");
                        }
                    }
                }

                free(process_name);
            }        }

        // Re-inject the packet
        if (!WinDivertSend(divert_handle, packet, packet_len, NULL, &addr)) {
            log_message("WinDivertSend failed: %d", GetLastError());
        }
    }
    return 0;
}




/* Helper function to get the process name from a PID */
static char* get_process_name_by_pid(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) {
        return NULL;
    }

    char* name = (char*)malloc(MAX_PATH);
    if (!name) {
        CloseHandle(process);
        return NULL;
    }

    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameA(process, 0, name, &size)) {
        free(name);
        CloseHandle(process);
        return NULL;
    }

    CloseHandle(process);

    // Extract just the filename from the path
    char* filename = strrchr(name, '\\');
    if (filename) {
        filename++; // Skip the backslash
        // Move the filename to the beginning of the buffer
        memmove(name, filename, strlen(filename) + 1);
    }

    return name;
}

/* Get PID associated with a network connection */
static DWORD get_pid_by_connection(UINT32 local_addr, UINT16 local_port,
                               UINT32 remote_addr, UINT16 remote_port) {
    MIB_TCPTABLE_OWNER_PID *table = NULL;
    DWORD size = 0;
    DWORD result;
    DWORD pid = 0;

    // Get required size for the table
    result = GetExtendedTcpTable(NULL, &size, TRUE, AF_INET,
                               TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return 0;
    }

    // Allocate the table
    table = (MIB_TCPTABLE_OWNER_PID*)malloc(size);
    if (!table) {
        return 0;
    }

    // Get the table data
    result = GetExtendedTcpTable(table, &size, TRUE, AF_INET,
                               TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR) {
        free(table);
        return 0;
    }

    // Convert ports to network byte order for comparison
    local_port = htons(local_port);
    remote_port = htons(remote_port);

    // Search for matching connection
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        if (table->table[i].dwLocalAddr == local_addr &&
            table->table[i].dwLocalPort == local_port &&
            (table->table[i].dwRemoteAddr == remote_addr || remote_addr == 0) &&
            (table->table[i].dwRemotePort == remote_port || remote_port == 0)) {
            pid = table->table[i].dwOwningPid;
            break;
        }
    }

    free(table);
    return pid;
}

/* Convert string IP address to UINT32 */
static int string_to_ip(const char* ip, UINT32 *addr) {
    struct in_addr inaddr;
    if (inet_pton(AF_INET, ip, &inaddr) != 1) {
        return 0;
    }
    *addr = inaddr.s_addr;
    return 1;
}

/* Convert UINT32 IP address to string */
static void ip_to_string(UINT32 addr, char *str) {
    struct in_addr inaddr;
    inaddr.s_addr = addr;
    inet_ntop(AF_INET, &inaddr, str, 46);
}

/* Display a console UI for managing process diversion */
void display_process_diversion_ui(void) {
    int choice;
    char process_name[MAX_PATH];

    while (1) {
        printf("\n===== Process Diversion Menu =====\n");
        printf("1. Add process to divert\n");
        printf("2. Remove process from diversion\n");
        printf("3. List diverted processes\n");
        printf("4. Return to main menu\n");
        printf("Enter choice: ");

        if (scanf("%d", &choice) != 1) {
            // Clear the input buffer if scanf fails
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            printf("Invalid input. Please enter a number.\n");
            continue;
        }

        // Consume the newline character
        getchar();

        switch (choice) {
            case 1:
                printf("Enter process name (e.g., chrome.exe): ");
                if (fgets(process_name, sizeof(process_name), stdin)) {
                    // Remove newline character if present
                    size_t len = strlen(process_name);
                    if (len > 0 && process_name[len-1] == '\n') {
                        process_name[len-1] = '\0';
                    }

                    if (add_process_to_divert(process_name)) {
                        printf("Process '%s' added to diversion list.\n", process_name);
                    } else {
                        printf("Failed to add process '%s'.\n", process_name);
                    }
                }
                break;

            case 2:
                printf("Enter process name to remove: ");
                if (fgets(process_name, sizeof(process_name), stdin)) {
                    // Remove newline character if present
                    size_t len = strlen(process_name);
                    if (len > 0 && process_name[len-1] == '\n') {
                        process_name[len-1] = '\0';
                    }

                    if (remove_process_from_divert(process_name)) {
                        printf("Process '%s' removed from diversion list.\n", process_name);
                    } else {
                        printf("Process '%s' not found in diversion list.\n", process_name);
                    }
                }
                break;

            case 3:
                printf("\n--- Diverted Processes ---\n");
                if (process_count == 0) {
                    printf("No processes are currently being diverted.\n");
                } else {
                    for (int i = 0; i < process_count; i++) {
                        printf("%d. %s\n", i+1, diverted_processes[i]);
                    }
                }
                break;

            case 4:
                return;

            default:
                printf("Invalid choice. Please try again.\n");        }
    }
}

/* Global variables for PID-based filtering */
static int* g_filter_pids = NULL;
static int g_filter_pid_count = 0;
static CRITICAL_SECTION g_filter_cs;
static BOOL g_filter_cs_initialized = FALSE;

/* Initialize PID filtering */
static void init_pid_filtering() {
    if (!g_filter_cs_initialized) {
        InitializeCriticalSection(&g_filter_cs);
        g_filter_cs_initialized = TRUE;
    }
}

/* Apply process filter for specific PIDs */
int apply_process_filter(int* pids, int pid_count) {
    if (!pids || pid_count <= 0) return 0;
    
    init_pid_filtering();
    
    EnterCriticalSection(&g_filter_cs);
    
    // Free existing filter
    if (g_filter_pids) {
        free(g_filter_pids);
        g_filter_pids = NULL;
        g_filter_pid_count = 0;
    }
    
    // Allocate and copy new filter
    g_filter_pids = malloc(pid_count * sizeof(int));
    if (!g_filter_pids) {
        LeaveCriticalSection(&g_filter_cs);
        return 0;
    }
    
    memcpy(g_filter_pids, pids, pid_count * sizeof(int));
    g_filter_pid_count = pid_count;
    
    LeaveCriticalSection(&g_filter_cs);
    
    log_message("Applied process filter to %d PIDs", pid_count);
    return 1;
}

/* Clear process filter */
void clear_process_filter(void) {
    init_pid_filtering();
    
    EnterCriticalSection(&g_filter_cs);
    
    if (g_filter_pids) {
        free(g_filter_pids);
        g_filter_pids = NULL;
        g_filter_pid_count = 0;
    }
    
    LeaveCriticalSection(&g_filter_cs);
    
    log_message("Cleared process filter");
}

/* Check if a PID should be filtered */
static int should_filter_pid(DWORD pid) {
    if (!g_filter_pids || g_filter_pid_count == 0) {
        return 0; // No filtering
    }
    
    EnterCriticalSection(&g_filter_cs);
    
    int should_filter = 0;
    for (int i = 0; i < g_filter_pid_count; i++) {
        if (g_filter_pids[i] == (int)pid) {
            should_filter = 1;
            break;
        }
    }
    
    LeaveCriticalSection(&g_filter_cs);
    
    return should_filter;
}
