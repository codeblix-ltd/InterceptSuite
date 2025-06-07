/*
 * Intercept Suite - User Data Directory Management
 *
 * Cross-platform functions for managing user data directories
 * and file paths for certificates, logs, and configurations.
 */

#ifndef USER_DATA_H
#define USER_DATA_H

#include "tls_proxy.h"

/* Maximum path length for platform-specific paths */
#define USER_DATA_MAX_PATH 512

/* Function prototypes */
int init_user_data_directory(void);
const char* get_user_data_directory(void);
const char* get_ca_cert_path(void);
const char* get_ca_key_path(void);
const char* get_log_file_path(const char* log_name);
const char* get_default_log_file_path(void);
const char* get_config_file_path(const char* config_name);
int ensure_directory_exists(const char* path);

#endif /* USER_DATA_H */
