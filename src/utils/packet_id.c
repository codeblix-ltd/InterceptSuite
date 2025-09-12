#include "packet_id.h"

mutex_t g_packet_id_mutex;

int get_next_packet_id(void) {
    int packet_id;

    LOCK_MUTEX(g_packet_id_mutex);
    packet_id = ++g_packet_id_counter;
    UNLOCK_MUTEX(g_packet_id_mutex);

    return packet_id;
}

void cleanup_packet_id_system(void) {
    DESTROY_MUTEX(g_packet_id_mutex);
}
