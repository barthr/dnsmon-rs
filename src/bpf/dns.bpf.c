#include "vmlinux.h"

#include "cursor.h"
#include "parsers.c"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TC_PASS 0
#define IPV4 0x0800
#define UDP_PROTO 17

SEC("tc")
int dns(struct __sk_buff* skb)
{

    cursor cursor = cursor_init_skb(skb);

    struct ethhdr* ethhdr;
    if (!(ethhdr = parse_ethhdr(&cursor))) {
        return TC_PASS;
    }

    if (bpf_ntohs(ethhdr->h_proto) != IPV4) {
        return TC_PASS;
    }

    struct iphdr* ip;
    if (!(ip = parse_iphdr(&cursor))) {
        return TC_PASS;
    }

    __u8 protocol = ip->protocol;
    if (protocol != UDP_PROTO) {
        return TC_PASS;
    }

    struct udphdr* udp;
    if (!(udp = parse_udphdr(&cursor))) {
        return TC_PASS;
    }

    if (bpf_ntohs(udp->source) == 53) {
        debug_bpf_printk("Received UDP packet with port %d!", bpf_ntohs(udp->source));
    }

    return 0;
}