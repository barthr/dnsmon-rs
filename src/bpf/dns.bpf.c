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

static inline __u32 fnv1a_32(const char data[255], __u32 len)
{
    const __u32 FNV_offset_basis = 0x811C9DC5;
    const __u32 FNV_prime = 0x01000193;
    __u32 hash = FNV_offset_basis;

    for (__u32 i = 0; i < len; ++i) {
        hash ^= (unsigned char)data[i];
        hash *= FNV_prime;
    }

    return hash;
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

struct {
    __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
    __type(value, u32);
    __uint(max_entries, 1000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} bf_blocklist_hostnames SEC(".maps");

typedef struct {
    __u32 pid;
    char hostname[256];
} dns_event;

static __u32 _parse_dnsq_hostname(cursor* cursor, dns_event* ev)
{
    check_packet_boundary(1);
    __u32 n_chars = *(char*)(cursor->pos++);
    // Weird loop to parse dns like 4test4test0
    // This has been a lot of fighting with the verifier since it requires bounded loops
    for (__u32 i = 0; i < MAX_HOSTNAME_LEN; i++) {
        check_packet_boundary(1);
        if (*(char*)(cursor->pos) == 0) {
            return i;
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
    return -1;
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

    __u32 hostname_length = _parse_dnsq_hostname(&cursor, &ev);
    if (hostname_length == -1) {
        return TC_PASS;
    };

    // We only want to send the DNS event if we actually match
    // with a item in the blocklist
    // For now we always send it
    // __u64 err = bpf_map_peek_elem(&blocklist_hostnames, &ev.hostname);
    // if  (err) {
    //     debug_bpf_printk("Element [%s] not found in blocklist", ev.hostname);
    // } else {
    const __u32 hash = fnv1a_32(ev.hostname, hostname_length);
    __u64 hostname_found = bpf_map_peek_elem(&bf_blocklist_hostnames, &hash);
    if (hostname_found == 0) {
        debug_bpf_printk("Found malicious hostname!!");
    }
    //
    debug_bpf_printk("hash of hostname: %llu", hash);
    long result = bpf_ringbuf_output(&dns_events, &ev, sizeof(ev), 0);
    if (result < 0) {
        debug_bpf_printk("error: Sending hostname to user space %s!", ev.hostname);
    }

    debug_bpf_printk("Received DNS packet with hostname %s!", ev.hostname);
    return TC_PASS;
}