#pragma once

#include "vmlinux.h"

#define MAX_HOSTNAME_SIZE 255

// The dnshdr structure defines the format of a DNS packet header.
// It is a packed structure to ensure that the compiler doesn't insert any padding
// between the members, which matches the on-wire format of a DNS packet.
struct dnshdr {
    __u16 id; // An identifier assigned by the program that generates any kind of query.
    __u8 qr : 1; // QR (Query/Response) flag
    __u8 opcode : 4; // Opcode field
    __u8 aa : 1; // AA (Authoritative Answer) flag
    __u8 tc : 1; // TC (Truncation) flag
    __u8 rd : 1; // RD (Recursion Desired) flag
    __u8 ra : 1; // RA (Recursion Available) flag
    __u8 z : 3; // Reserved (Z) field
    __u8 rcode : 4; // RCODE (Response Code) field
    __u16 qdcount; // The number of entries in the question section.
    __u16 ancount; // The number of resource records in the answer section.
    __u16 nscount; // The number of name server resource records in the authority records section.
    __u16 arcount; // The number of resource records in the additional records section.
} __attribute__((packed));

// The dnsquery structure defines the format of a DNS query section.
struct dns_query {
    char hostname[MAX_HOSTNAME_SIZE];
    __u16 qtype; // The type of the DNS query.
    __u16 qclass; // The class of the DNS query.
} __attribute__((packed));

// The dnsrr (DNS Resource Record) structure defines the format of a DNS resource record.
// DNS resource records are primarily used in the answer section of a DNS reply message.
struct dns_rr {
    __u16 type; // The type of the DNS resource record.
    __u16 _class; // The class of the DNS resource record.
    __u16 ttl; // The time to live of the DNS resource record.
    __u16 rdlength; // The length of the rdata field.
    char rdata[]; // The data of the resource record, its format varies based on the type and class of the record.
} __attribute__((packed));