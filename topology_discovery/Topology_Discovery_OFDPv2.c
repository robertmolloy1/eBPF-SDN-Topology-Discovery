#include <linux/if_ether.h>
#include "ebpf_switch.h"

#define MAX_PORTS 128
#define MAX_TLVS 4
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
    if (pkt->eth.h_proto == 52360)
    {
        if (pkt->metadata.in_port != -1)
        {
            return CONTROLLER; // Notify controller of incoming LLDP packet
        } 

        void *lldp_pointer = ((void *)&pkt->eth) + sizeof(struct metadatahdr);
        void *packet_end = ((void *)&pkt->eth) + pkt->metadata.length;
        uint8_t *port_id;

        for (int i = 0; i<MAX_TLVS; i++)
        {
            uint16_t type_length = __builtin_bswap16(*(uint16_t *) lldp_pointer);

            if (lldp_pointer + 2 > packet_end || type_length == 0)
            {
                break;
            }

            uint8_t tlv_type = (type_length >> 9) & 0x7F;
            uint16_t tlv_length = type_length & 0x1FF;

            lldp_pointer += 2;

            if (tlv_type == 2)
            {
                port_id = (uint8_t *)(lldp_pointer+1);
            }

            lldp_pointer += tlv_length;
        }

        uint32_t port_count = bpf_get_port_count();

        for (uint8_t i = 0; i<MAX_PORTS; i++)
        {
            if (i >= port_count)
            {
                break;
            }

            __builtin_memcpy(port_id, &i, 1);
            bpf_mirror(i,pkt, pkt->metadata.length + sizeof(struct metadatahdr));       
        }
        return DROP;
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