#include <linux/bpf.h>
#include <linux/if_ether.h>
#include "ebpf_switch.h"

#define TIMEOUT 5000000000

struct host_map_value {
    uint32_t port;
    uint64_t last_seen;
};

struct bpf_map_def SEC("maps") hosts = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(struct host_map_value),
    .max_entries = 256,
};

uint64_t prog(struct packet *pkt)
{
    if (pkt->eth.h_proto == 52360)
    {
        return NEXT;
    }

    struct host_map_value *host_info;
    uint64_t time_now = bpf_ktime_get_ns(pkt->eth.h_proto);
    struct host_map_value new_host_info = {.port = pkt->metadata.in_port, .last_seen = time_now};

    if (bpf_map_lookup_elem(&hosts, pkt->eth.h_source, &host_info) == -1) // No entry for this host
    {
        bpf_notify(pkt->metadata.in_port, &(pkt->eth.h_source), sizeof(pkt->eth.h_source)); // Notify controller of new host
        bpf_map_update_elem(&hosts, pkt->eth.h_source, &new_host_info, 0); // Create map entry
        return NEXT;
    }

    if (host_info->port != pkt->metadata.in_port || time_now - host_info->last_seen > TIMEOUT) // Different port or old timestamp
    {
        bpf_notify(pkt->metadata.in_port, &(pkt->eth.h_source), sizeof(pkt->eth.h_source)); // Notify controller of host
        bpf_map_update_elem(&hosts, pkt->eth.h_source, &new_host_info, 0); // Update map entry
        return NEXT;
    }

    bpf_map_update_elem(&hosts, pkt->eth.h_source, &new_host_info, 0); // Update timestamp in map entry
    return NEXT;
}
char _license[] SEC("license") = "GPL";