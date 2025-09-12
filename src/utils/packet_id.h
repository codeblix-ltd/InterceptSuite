#ifndef PACKET_ID_H
#define PACKET_ID_H

#include "platform/platform.h"

/* Global packet ID counter - initialized to 0 */
extern int g_packet_id_counter;

/* Mutex for packet ID counter */
extern mutex_t g_packet_id_mutex;

int get_next_packet_id(void);

void cleanup_packet_id_system(void);

#endif