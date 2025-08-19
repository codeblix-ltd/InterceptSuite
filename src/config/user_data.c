/*
 * Intercept Suite - User Data Directory Management
 *
 * Cross-platform implementation for managing user data directories
 * and file paths for certificates, logs, and configurations.
 */

#include "user_data.h"
#include "../utils/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef INTERCEPT_WINDOWS
#include <windows.h>
#include <shlobj.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#define PATH_SEPARATOR "\\"
#elif defined(INTERCEPT_MACOS) || defined(INTERCEPT_LINUX)
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#define PATH_SEPARATOR "/"
#endif

/* Static storage for paths */
static char user_data_dir[USER_DATA_MAX_PATH] = {0};
static char ca_cert_path[USER_DATA_MAX_PATH] = {0};
static char ca_key_path[USER_DATA_MAX_PATH] = {0};
static int initialized = 0;

/**
 * Ensure a directory exists, creating it if necessary
 */
int ensure_directory_exists(const char* path) {
    if (!path || strlen(path) == 0) {
        return 0;
    }

#ifdef INTERCEPT_WINDOWS
    DWORD attrs = GetFileAttributesA(path);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        return 1; // Directory already exists
    }

    if (CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
        return 1;
    }
    return 0;
#else
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        return 1; // Directory already exists
    }

    if (mkdir(path, 0755) == 0 || errno == EEXIST) {
        return 1;
    }
    return 0;
#endif
}

/**
 * Initialize user data directory and create necessary subdirectories
 */
int init_user_data_directory(void) {
    if (initialized) {
        return 1;
    }

    memset(user_data_dir, 0, sizeof(user_data_dir));

#ifdef INTERCEPT_WINDOWS
    // Windows: Use %APPDATA%\InterceptSuite
    char* appdata = getenv("APPDATA");
    if (!appdata) {
        // Fallback to USERPROFILE\AppData\Roaming
        char* userprofile = getenv("USERPROFILE");
        if (!userprofile) {
            log_message("Error: Could not determine user data directory on Windows\n");
            return 0;
        }
        snprintf(user_data_dir, sizeof(user_data_dir), "%s\\AppData\\Roaming\\InterceptSuite", userprofile);
    } else {
        snprintf(user_data_dir, sizeof(user_data_dir), "%s\\InterceptSuite", appdata);
    }

#elif defined(INTERCEPT_MACOS)
    // macOS: Use ~/Library/Application Support/InterceptSuite
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        if (!pw) {
            log_message("Error: Could not determine home directory on macOS\n");
            return 0;
        }
        home = pw->pw_dir;
    }
    snprintf(user_data_dir, sizeof(user_data_dir), "%s/Library/Application Support/InterceptSuite", home);

#elif defined(INTERCEPT_LINUX)
    // Linux: Use XDG_DATA_HOME or ~/.local/share/InterceptSuite
    const char* xdg_data_home = getenv("XDG_DATA_HOME");
    if (xdg_data_home && strlen(xdg_data_home) > 0) {
        snprintf(user_data_dir, sizeof(user_data_dir), "%s/InterceptSuite", xdg_data_home);
    } else {
        const char* home = getenv("HOME");
        if (!home) {
            struct passwd* pw = getpwuid(getuid());
            if (!pw) {
                log_message("Error: Could not determine home directory on Linux\n");
                return 0;
            }
            home = pw->pw_dir;
        }
        snprintf(user_data_dir, sizeof(user_data_dir), "%s/.local/share/InterceptSuite", home);
    }
#else
    log_message("Error: Unsupported platform for user data directory\n");
    return 0;
#endif

    // Create the main directory and subdirectories
    if (!ensure_directory_exists(user_data_dir)) {
        log_message("Error: Could not create user data directory: %s\n", user_data_dir);
        return 0;
    }

    // Create certificates subdirectory
    char cert_dir[USER_DATA_MAX_PATH];
    snprintf(cert_dir, sizeof(cert_dir), "%s%scertificates", user_data_dir, PATH_SEPARATOR);
    if (!ensure_directory_exists(cert_dir)) {
        log_message("Error: Could not create certificates directory: %s\n", cert_dir);
        return 0;
    }

    // Create logs subdirectory
    char log_dir[USER_DATA_MAX_PATH];
    snprintf(log_dir, sizeof(log_dir), "%s%slogs", user_data_dir, PATH_SEPARATOR);
    if (!ensure_directory_exists(log_dir)) {
        log_message("Error: Could not create logs directory: %s\n", log_dir);
        return 0;
    }

    // Create config subdirectory
    char config_dir[USER_DATA_MAX_PATH];
    snprintf(config_dir, sizeof(config_dir), "%s%sconfig", user_data_dir, PATH_SEPARATOR);
    if (!ensure_directory_exists(config_dir)) {
        log_message("Error: Could not create config directory: %s\n", config_dir);
        return 0;
    }

    // Initialize certificate paths
    snprintf(ca_cert_path, sizeof(ca_cert_path), "%s%sIntercept_Suite_Cert.pem", cert_dir, PATH_SEPARATOR);
    snprintf(ca_key_path, sizeof(ca_key_path), "%s%sIntercept_Suite_key.key", cert_dir, PATH_SEPARATOR);

    initialized = 1;
    return 1;
}

/**
 * Get the user data directory path
 */
const char* get_user_data_directory(void) {
    if (!initialized && !init_user_data_directory()) {
        return NULL;
    }
    return user_data_dir;
}

/**
 * Get the CA certificate file path
 */
const char* get_ca_cert_path(void) {
    if (!initialized && !init_user_data_directory()) {
        return NULL;
    }
    return ca_cert_path;
}

/**
 * Get the CA key file path
 */
const char* get_ca_key_path(void) {
    if (!initialized && !init_user_data_directory()) {
        return NULL;
    }
    return ca_key_path;
}

/**
 * Get a config file path in the user data directory
 * TBU
 */
const char* get_config_file_path(const char* config_name) {
    static char config_path[USER_DATA_MAX_PATH];

    if (!config_name || strlen(config_name) == 0) {
        return NULL;
    }

    if (!initialized && !init_user_data_directory()) {
        return NULL;
    }

    snprintf(config_path, sizeof(config_path), "%s%sconfig%s%s", user_data_dir, PATH_SEPARATOR, PATH_SEPARATOR, config_name);
    return config_path;
}
