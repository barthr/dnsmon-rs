#pragma once

#include "vmlinux.h"

#include "cursor.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define PARSE_FUNC_DECLARATION(STRUCT)                              \
    static __always_inline struct STRUCT* parse_##STRUCT(cursor* c) \
    {                                                               \
        struct STRUCT* ret = c->pos;                                \
        if (c->pos + sizeof(struct STRUCT) > c->end)                \
            return 0;                                               \
        c->pos += sizeof(struct STRUCT);                            \
        return ret;                                                 \
    }

PARSE_FUNC_DECLARATION(ethhdr)
PARSE_FUNC_DECLARATION(iphdr)
PARSE_FUNC_DECLARATION(ipv6hdr)
PARSE_FUNC_DECLARATION(udphdr)
PARSE_FUNC_DECLARATION(tcphdr)