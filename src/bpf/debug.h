#pragma once

#include <bpf/bpf_helpers.h>

#ifdef DEBUG
#define debug_bpf_printk(fmt, ...) \
    bpf_printk(fmt, ##__VA_ARGS__);
#else
#define debug_bpf_printk(fmt, ...)
#endif