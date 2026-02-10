// SPDX-License-Identifier: GPL-2.0
/*
 * SmartScheduler eBPF I/O Tracing Program
 *
 * Monitors I/O-related events:
 * - Block I/O requests
 * - Syscalls (read/write)
 * - I/O completion latency
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_ENTRIES 10240

/* I/O statistics per process */
struct io_stats {
    u64 read_bytes;         /* Total bytes read */
    u64 write_bytes;        /* Total bytes written */
    u64 read_count;         /* Number of read operations */
    u64 write_count;        /* Number of write operations */
    u64 io_wait_ns;         /* Total I/O wait time */
    u64 pending_io;         /* Currently pending I/O operations */
    u64 last_io_time;       /* Last I/O timestamp */
};

/* Map for I/O statistics */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct io_stats);
} io_stats_map SEC(".maps");

/* Map to track pending I/O for latency calculation */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);  /* Request pointer as key */
    __type(value, u64); /* Start timestamp */
} pending_io_map SEC(".maps");

/* Ring buffer for I/O events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} io_events SEC(".maps");

#define IO_EVENT_READ   1
#define IO_EVENT_WRITE  2
#define IO_EVENT_SYNC   3

/*
 * Tracepoint: syscalls/sys_enter_read
 * Track read syscall entry
 */
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct io_stats *stats;
    struct io_stats new_stats = {};
    
    if (pid == 0)
        return 0;
    
    stats = bpf_map_lookup_elem(&io_stats_map, &pid);
    if (!stats) {
        new_stats.read_count = 1;
        new_stats.last_io_time = bpf_ktime_get_ns();
        bpf_map_update_elem(&io_stats_map, &pid, &new_stats, BPF_ANY);
    } else {
        __sync_fetch_and_add(&stats->read_count, 1);
        __sync_fetch_and_add(&stats->pending_io, 1);
        stats->last_io_time = bpf_ktime_get_ns();
    }
    
    return 0;
}

/*
 * Tracepoint: syscalls/sys_exit_read
 * Track read syscall completion and bytes
 */
SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct io_stats *stats;
    long ret = ctx->ret;
    
    if (pid == 0 || ret < 0)
        return 0;
    
    stats = bpf_map_lookup_elem(&io_stats_map, &pid);
    if (stats) {
        __sync_fetch_and_add(&stats->read_bytes, ret);
        if (stats->pending_io > 0)
            __sync_fetch_and_sub(&stats->pending_io, 1);
    }
    
    return 0;
}

/*
 * Tracepoint: syscalls/sys_enter_write
 * Track write syscall entry
 */
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct io_stats *stats;
    struct io_stats new_stats = {};
    
    if (pid == 0)
        return 0;
    
    stats = bpf_map_lookup_elem(&io_stats_map, &pid);
    if (!stats) {
        new_stats.write_count = 1;
        new_stats.last_io_time = bpf_ktime_get_ns();
        bpf_map_update_elem(&io_stats_map, &pid, &new_stats, BPF_ANY);
    } else {
        __sync_fetch_and_add(&stats->write_count, 1);
        __sync_fetch_and_add(&stats->pending_io, 1);
        stats->last_io_time = bpf_ktime_get_ns();
    }
    
    return 0;
}

/*
 * Tracepoint: syscalls/sys_exit_write
 * Track write syscall completion and bytes
 */
SEC("tracepoint/syscalls/sys_exit_write")
int trace_write_exit(struct trace_event_raw_sys_exit *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct io_stats *stats;
    long ret = ctx->ret;
    
    if (pid == 0 || ret < 0)
        return 0;
    
    stats = bpf_map_lookup_elem(&io_stats_map, &pid);
    if (stats) {
        __sync_fetch_and_add(&stats->write_bytes, ret);
        if (stats->pending_io > 0)
            __sync_fetch_and_sub(&stats->pending_io, 1);
    }
    
    return 0;
}

/*
 * Tracepoint: block/block_rq_issue
 * Track block I/O request submission
 */
SEC("tracepoint/block/block_rq_issue")
int trace_block_rq_issue(struct trace_event_raw_block_rq *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    u64 key = (u64)ctx; /* Use context as unique key */
    
    bpf_map_update_elem(&pending_io_map, &key, &ts, BPP_ANY);
    
    return 0;
}

/*
 * Tracepoint: block/block_rq_complete
 * Track block I/O completion for latency
 */
SEC("tracepoint/block/block_rq_complete")
int trace_block_rq_complete(struct trace_event_raw_block_rq *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = (u64)ctx;
    u64 *start_ts;
    u64 now = bpf_ktime_get_ns();
    struct io_stats *stats;
    
    start_ts = bpf_map_lookup_elem(&pending_io_map, &key);
    if (start_ts) {
        u64 latency = now - *start_ts;
        
        stats = bpf_map_lookup_elem(&io_stats_map, &pid);
        if (stats) {
            __sync_fetch_and_add(&stats->io_wait_ns, latency);
        }
        
        bpf_map_delete_elem(&pending_io_map, &key);
    }
    
    return 0;
}

/*
 * Cleanup on process exit
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_io_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    u32 pid = ctx->pid;
    bpf_map_delete_elem(&io_stats_map, &pid);
    return 0;
}
