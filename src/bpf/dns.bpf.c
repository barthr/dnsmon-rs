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
#define TCP_PROTO 6
#define DNS_QUERY 0
#define DNS_RESPONSE 1
#define MAX_HOSTNAME_LEN 128

#define check_packet_boundary(boundary)                         \
    if (cursor->pos + boundary > cursor->end) {                 \
        debug_bpf_printk("error: boundary of packet exceeded"); \
        return -1;                                              \
    }

struct dnshdr {
    __be16 id;
    __u8 qr : 1; // QR (Query/Response) flag
    __u8 opcode : 4;
    __u8 aa : 1;
    __u8 tc : 1;
    __u8 rd : 1;
    __u8 ra : 1;
    __u8 z : 3;
    __u8 rcode : 4;
    __be16 qdcount; // The number of entries in the question section.
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
} __attribute__((packed));

PARSE_FUNC_DECLARATION(dnshdr)

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 9);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_events SEC(".maps");

typedef struct {
    __u32 pid;
    char hostname[256];
} dns_event;

static int _parse_dns_query(cursor* cursor, dns_event* ev)
{
    check_packet_boundary(1);
    __u32 n_chars = *(char*)(cursor->pos++);
    // Weird loop to parse dns like 4test4test0
    // This has been a lot of fighting with the verifier since it requires bounded loops
    for (__u32 i = 0; i < MAX_HOSTNAME_LEN; i++) {
        check_packet_boundary(1);
        if (*(char*)(cursor->pos) == 0) {
            break;
        }

        char ch = *(char*)(cursor->pos++);
        if (n_chars == 0) {
            n_chars = ch;
            ev->hostname[i] = '.';
        } else {
            n_chars--;
            ev->hostname[i] = ch;
        }
    }

    return 0;
}

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

    if (ip->protocol != IPPROTO_UDP) {
        return TC_PASS;
    }

    struct udphdr* udp;
    if (!(udp = parse_udphdr(&cursor))) {
        return TC_PASS;
    }

    // We make the assumption that traffic going to 53 is always DNS
    if (bpf_ntohs(udp->dest) != 53) {
        return TC_PASS;
    }

    struct dnshdr* dns;
    if (!(dns = parse_dnshdr(&cursor))) {
        return TC_PASS;
    }

    if (dns->qr != DNS_QUERY) {
        return TC_PASS;
    }
    if (bpf_htons(dns->qdcount) <= 0) {
        return TC_PASS;
    }

    // bpf_get_current_pid_tgid() >> 32

    dns_event ev = { .pid = 1 };

    if (_parse_dns_query(&cursor, &ev) != 0) {
        return TC_PASS;
    };

    // We only want to send the DNS event if we actually match
    // with a item in the blocklist
    // For now we always send it
    debug_bpf_printk("Received DNS packet with hostname %s!", ev.hostname);
    long result = bpf_ringbuf_output(&dns_events, &ev, sizeof(ev), 0);
    if (result < 0) {
        debug_bpf_printk("error: Sending hostname to user space %s!", ev.hostname);
    }
    return TC_PASS;
}