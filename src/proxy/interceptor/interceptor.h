/*
 * TLS MITM Proxy - Interception Manager Header
 *
 * Contains declarations for traffic interception functionality.
 */

#ifndef INTERCEPTOR_H
#define INTERCEPTOR_H

#include "../../platform/platform.h"
#include "../../tls/proxy/tls_proxy.h"
#include "../../tls/proxy/tls_proxy_dll.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Interception callback and control functions */
INTERCEPT_API void set_intercept_callback(intercept_callback_t callback);
INTERCEPT_API void set_intercept_enabled(int enabled);
INTERCEPT_API void set_intercept_direction(int direction);
INTERCEPT_API intercept_status_t get_intercept_config(void);
INTERCEPT_API void respond_to_intercept(int packet_id, int action,
  const unsigned char * modified_data, int modified_length);

/* External global variables from main.c */
extern intercept_config_t g_intercept_config;
extern intercept_callback_t g_intercept_callback;
extern intercept_data_t * g_active_intercepts[100];
extern int g_intercept_count;
extern status_callback_t g_status_callback;

#ifdef __cplusplus
}
#endif

#endif /* INTERCEPTOR_H */
