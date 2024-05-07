#pragma once

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef DEBUG
#define debug_bpf_printk(fmt, ...) \
    bpf_printk(fmt, ##__VA_ARGS__);
#else
#define debug_bpf_printk(fmt, ...)
#endif
