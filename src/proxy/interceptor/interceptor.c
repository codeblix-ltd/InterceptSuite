/*
 * TLS MITM Proxy - Interception Manager Implementation
 *
 * Contains traffic interception functionality moved from main.c.
 */

/*
TBD - Needs to add conditional intercept /specific IP, port, etc
*/

#include "interceptor.h"

/* External global variables from main.c */
extern intercept_config_t g_intercept_config;
extern intercept_callback_t g_intercept_callback;
extern intercept_data_t * g_active_intercepts[100];
extern int g_intercept_count;
extern status_callback_t g_status_callback;

/* Interception callback and control functions */

INTERCEPT_API void set_intercept_callback(intercept_callback_t callback) {
  g_intercept_callback = callback;
}

INTERCEPT_API void set_intercept_enabled(int enabled) {
  LOCK_MUTEX(g_intercept_config.intercept_cs);
  g_intercept_config.is_interception_enabled = enabled;
  UNLOCK_MUTEX(g_intercept_config.intercept_cs);

  if (g_status_callback) {
    char status_msg[256];
    snprintf(status_msg, sizeof(status_msg), "Interception %s", enabled ? "enabled" : "disabled");
    g_status_callback(status_msg);
  }
}

INTERCEPT_API void set_intercept_direction(int direction) {
  LOCK_MUTEX(g_intercept_config.intercept_cs);
  g_intercept_config.enabled_directions = (intercept_direction_t) direction;
  UNLOCK_MUTEX(g_intercept_config.intercept_cs);

  if (g_status_callback) {
    char status_msg[256];
    const char * dir_str = "None";
    switch (direction) {
    case INTERCEPT_CLIENT_TO_SERVER:
      dir_str = "Client->Server";
      break;
    case INTERCEPT_SERVER_TO_CLIENT:
      dir_str = "Server->Client";
      break;
    case INTERCEPT_BOTH:
      dir_str = "Both directions";
      break;
    }
    snprintf(status_msg, sizeof(status_msg), "Intercept direction set to: %s", dir_str);
    g_status_callback(status_msg);
  }
}

INTERCEPT_API intercept_status_t get_intercept_config(void) {
  intercept_status_t result = {
    0
  };

  LOCK_MUTEX(g_intercept_config.intercept_cs);
  result.is_enabled = g_intercept_config.is_interception_enabled;
  result.direction = (int) g_intercept_config.enabled_directions;
  UNLOCK_MUTEX(g_intercept_config.intercept_cs);

  return result;
}

INTERCEPT_API void respond_to_intercept(int packet_id, int action,
  const unsigned char * modified_data, int modified_length) {
  LOCK_MUTEX(g_intercept_config.intercept_cs);

  // Find the intercept data for this packet_id
  for (int i = 0; i < g_intercept_count; i++) {
    if (g_active_intercepts[i] && g_active_intercepts[i] -> packet_id == packet_id &&
      g_active_intercepts[i] -> is_waiting_for_response) {

      intercept_data_t * intercept = g_active_intercepts[i];
      intercept -> action = (intercept_action_t) action;

      // Handle modified data if provided
      if (action == INTERCEPT_ACTION_MODIFY && modified_data && modified_length > 0) {
        // Free existing modified data if any
        if (intercept -> modified_data) {
          free(intercept -> modified_data);
        }

        // Allocate and copy new data
        intercept -> modified_data = malloc(modified_length);
        if (intercept -> modified_data) {
          memcpy(intercept -> modified_data, modified_data, modified_length);
          intercept -> modified_length = modified_length;
        } else {
          // Fall back to forward if allocation fails
          intercept -> action = INTERCEPT_ACTION_FORWARD;
        }
      }

      intercept -> is_waiting_for_response = 0;
      SET_EVENT(intercept -> response_event);
      break;
    }
  }

  UNLOCK_MUTEX(g_intercept_config.intercept_cs);
}
