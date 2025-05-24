/*
 * TLS MITM Proxy - Process-Based Traffic Diversion
 *
 * Using WinDivert to selectively intercept TLS traffic from specific processes.
 */

#ifndef PROCESS_DIVERT_H
#define PROCESS_DIVERT_H

#include "tls_proxy.h"

/* Function prototypes */
int init_process_diversion(void);
void cleanup_process_diversion(void);
int add_process_to_divert(const char* process_name);
int remove_process_from_divert(const char* process_name);
int is_process_diverted(const char* process_name);
void display_process_diversion_ui(void);
int get_diverted_processes(char*** process_list, int* count);

/* New process filtering functions for PID-based filtering */
int apply_process_filter(int* pids, int pid_count);
void clear_process_filter(void);

/* The divert callback type */
typedef void (*DivertCallback)(const char* process_name, const char* src_ip, 
                              const char* dst_ip, int dst_port);

/* Register a callback to be called when traffic is diverted */
void register_divert_callback(DivertCallback callback);

#endif /* PROCESS_DIVERT_H */
