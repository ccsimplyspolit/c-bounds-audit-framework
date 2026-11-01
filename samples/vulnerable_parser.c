#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct PacketEntry {
    uint32_t id;
    uint32_t flags;
};

// CB-001: Unchecked Pointer Arithmetic & CB-002: Unbounded memcpy into fixed buffer
int parse_network_telemetry(const uint8_t *packet, size_t packet_size) {
    uint8_t stack_buf[64];
    const uint8_t *pkt_ptr = packet;

    // Vulnerable: Advancing pointer by network length without verifying packet_size boundary
    uint16_t chunk_len = *(const uint16_t *)pkt_ptr;
    pkt_ptr += chunk_len;

    // Vulnerable: Copying network payload into fixed stack buffer without capacity guard
    memcpy(stack_buf, pkt_ptr, chunk_len);

    return 0;
}

// CB-003: Integer Overflow in Allocation
struct PacketEntry *allocate_entry_table(size_t count) {
    // Vulnerable: Multiplication wrap-around in malloc
    struct PacketEntry *table = (struct PacketEntry *)malloc(count * sizeof(struct PacketEntry));
    return table;
}

// CB-004: Sizeof Pointer & strlen Off-By-One
void initialize_table(struct PacketEntry *entry_ptr, const char *src_tag) {
    // Vulnerable: sizeof(entry_ptr) is 4 or 8 bytes, not sizeof(struct PacketEntry)
    memset(entry_ptr, 0, sizeof(entry_ptr));

    // Vulnerable: strlen without + 1 byte for null terminator
    char *tag_copy = (char *)malloc(strlen(src_tag));
    if (tag_copy) {
        strcpy(tag_copy, src_tag);
    }
}

// CB-005: Signed Length Upper Bound Check (GHSA-cr23-59mg-h2rc BACnet Stack pattern)
int process_signed_tag(const uint8_t *buf, int tag_len) {
    // Vulnerable: Only checks upper bound; negative tag_len bypasses check!
    if (tag_len > 1024) {
        return -1;
    }
    return tag_len * 2;
}

// CB-006: Unchecked Allocation Return Dereference
void record_telemetry_metric(uint32_t metric_id) {
    struct PacketEntry *entry = (struct PacketEntry *)malloc(sizeof(struct PacketEntry));
    // Vulnerable: Dereference without NULL check
    entry->id = metric_id;
    entry->flags = 1;
}
