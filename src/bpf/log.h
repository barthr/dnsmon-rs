#pragma once

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 100000); // what value should be good?
} log_output SEC(".maps");

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARNING = 2,
    LOG_ERROR = 3
} l_level;

#define LOG_BUF_CAPACITY 255

typedef struct {
    char message[LOG_BUF_CAPACITY];
} log_message;

#define log_fmt(fmt, ...)                                                                              \
    {                                                                                                  \
        log_message* log_msg = (log_message*)bpf_ringbuf_reserve(&log_output, sizeof(log_message), 0); \
        if (!log_msg) {                                                                                \
            bpf_printk("Failed to reserve ring buffer for log message\n");                             \
        } else {                                                                                       \
            BPF_SNPRINTF(log_msg->message, LOG_BUF_CAPACITY, fmt, ##__VA_ARGS__);                      \
            bpf_ringbuf_submit(log_msg, 0);                                                            \
        }                                                                                              \
    }