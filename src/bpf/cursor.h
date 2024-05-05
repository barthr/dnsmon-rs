#pragma once

#include "debug.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct {
    void* pos;
    void* end;
} cursor;

static cursor cursor_init(struct xdp_md* ctx)
{
    return (cursor) {
        .end = (void*)(long)ctx->data_end,
        .pos = (void*)(long)ctx->data
    };
}

static cursor cursor_init_skb(struct __sk_buff* buff)
{
    return (cursor) {
        .end = (void*)(long)buff->data_end,
        .pos = (void*)(long)buff->data,
    };
}