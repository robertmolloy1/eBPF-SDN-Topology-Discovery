#include <linux/if_ether.h>
#include "ebpf_switch.h"

uint64_t prog(struct packet *pkt)
{
    if (pkt->eth.h_proto == 52360)
    {
        return CONTROLLER;
    }

    return NEXT;
}
char _license[] SEC("license") = "GPL";