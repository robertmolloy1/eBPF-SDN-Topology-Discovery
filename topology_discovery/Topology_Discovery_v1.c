#include <linux/bpf.h>
#include <linux/if_ether.h>
#include "ebpf_switch.h"

#define TIMEOUT 5000000000

struct host_map_value {
    uint32_t port;
    uint64_t last_seen;
};

struct notification_data {
    unsigned char mac_address[6];
    uint32_t port;
};

struct bpf_map_def SEC("maps") hosts = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(struct host_map_value),
    .max_entries = 256,
};

uint64_t prog(struct packet *pkt)
{
    if (pkt->eth.h_proto == 52360) // LLDP Ethertype
    {
        return CONTROLLER;
    }

    uint64_t arrival_nsec = (uint64_t)(pkt->metadata.sec) * 1000000000ULL + (uint64_t)(pkt->metadata.nsec);

    struct host_map_value *host_saved_value;
    int lookup_result = bpf_map_lookup_elem(&hosts, pkt->eth.h_source, &host_saved_value);

    if (lookup_result == -1 || host_saved_value->port != pkt->metadata.in_port || arrival_nsec - host_saved_value->last_seen > TIMEOUT) // Controller needs notified
    {
        struct notification_data host_discovery_info = {.port = pkt->metadata.in_port};
        __builtin_memcpy(host_discovery_info.mac_address, pkt->eth.h_source, 6);
        bpf_notify(0, &host_discovery_info, sizeof(struct notification_data)); // Notify controller of host information
    }

    struct host_map_value host_new_value = {.port = pkt->metadata.in_port, .last_seen = arrival_nsec};
    bpf_map_update_elem(&hosts, pkt->eth.h_source, &host_new_value, 0); // Update map entry
    return NEXT;
}
char _license[] SEC("license") = "GPL";