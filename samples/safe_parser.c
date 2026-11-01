#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

struct PacketEntry {
    uint32_t id;
    uint32_t flags;
};

// Defensive: Bounds-checked pointer arithmetic and capacity-guarded memcpy
int parse_network_telemetry_safe(const uint8_t *packet, size_t packet_size) {
    uint8_t stack_buf[64];
    const uint8_t *pkt_ptr = packet;

    if (packet_size < sizeof(uint16_t)) {
        return -1;
    }

    uint16_t chunk_len = *(const uint16_t *)pkt_ptr;
    
    // Bounds guard against buffer ceiling
    if (chunk_len > packet_size - sizeof(uint16_t)) {
        return -1;
    }
    pkt_ptr += chunk_len;

    // Bounded copy with sizeof guard
    memcpy(stack_buf, pkt_ptr, MIN(chunk_len, sizeof(stack_buf)));

    return 0;
}

// Defensive: Overflow-safe allocation with calloc
struct PacketEntry *allocate_entry_table_safe(size_t count) {
    if (count > SIZE_MAX / sizeof(struct PacketEntry)) {
        return NULL;
    }
    return (struct PacketEntry *)calloc(count, sizeof(struct PacketEntry));
}

// Defensive: sizeof(*ptr) pointee and strlen + 1 byte
void initialize_table_safe(struct PacketEntry *entry_ptr, const char *src_tag) {
    if (entry_ptr == NULL || src_tag == NULL) {
        return;
    }
    memset(entry_ptr, 0, sizeof(*entry_ptr));

    char *tag_copy = (char *)malloc(strlen(src_tag) + 1);
    if (tag_copy != NULL) {
        snprintf(tag_copy, strlen(src_tag) + 1, "%s", src_tag);
        free(tag_copy);
    }
}

// Defensive: Signed length verification guarding against both negative values and upper bound
int process_signed_tag_safe(const uint8_t *buf, int tag_len) {
    if (tag_len < 0 || tag_len > 1024) {
        return -1;
    }
    return tag_len * 2;
}

// Defensive: Checked allocation return before dereference
int record_telemetry_metric_safe(uint32_t metric_id) {
    struct PacketEntry *entry = (struct PacketEntry *)malloc(sizeof(struct PacketEntry));
    if (entry == NULL) {
        return -1;
    }
    entry->id = metric_id;
    entry->flags = 1;
    free(entry);
    return 0;
}
