#include <linux/if_ether.h>
#include "ebpf_switch.h"

#define MAX_PORTS 128
#define MAX_TLVS 4

struct bpf_map_def SEC("maps") cycle = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint8_t),
    .max_entries = 1,
};

uint64_t prog(struct packet *pkt)
{
    if (pkt->eth.h_proto == 52360)
    {
        if (pkt->metadata.in_port != -1)
        {
            bpf_notify(1, pkt, pkt->metadata.length + sizeof(struct metadatahdr)); // Notify controller of incoming LLDP packet
        } 

        void *lldp_pointer = ((void *)&pkt->eth) + sizeof(struct metadatahdr);
        void *packet_end = ((void *)&pkt->eth) + pkt->metadata.length;
        uint64_t *chassis_id;
        uint8_t *port_id,*cycle_id,*last_seen_cycle_id;

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

            if (tlv_type == 1)
            {
                chassis_id = (uint64_t *)(lldp_pointer+1);
            }
            else if (tlv_type == 2)
            {
                port_id = (uint8_t *)(lldp_pointer+1);
            }
            else if (tlv_type == 127)
            {
                cycle_id = (uint8_t *)(lldp_pointer+4);
            }

            lldp_pointer += tlv_length;
        }

        uint32_t key = 0;
        int lookup_result = bpf_map_lookup_elem(&cycle, &key, &last_seen_cycle_id);

        if (lookup_result != -1 && *last_seen_cycle_id == *cycle_id) {return DROP;}

        bpf_map_update_elem(&cycle, &key, cycle_id, 0);

        uint64_t dpid = __builtin_bswap64(bpf_get_dpid());
        uint32_t port_count = bpf_get_port_count();

        __builtin_memcpy(chassis_id, &dpid, 8);

        for (uint8_t i = 0; i<MAX_PORTS; i++)
        {
            if (i >= port_count)
            {
                break;
            }
            if (pkt->metadata.in_port == i) 
            {
                continue;
            }
            __builtin_memcpy(port_id, &i, 1);
            bpf_mirror(i,pkt, pkt->metadata.length + sizeof(struct metadatahdr));       
        }
        return DROP;
    }
    return NEXT;
}
char _license[] SEC("license") = "GPL";
