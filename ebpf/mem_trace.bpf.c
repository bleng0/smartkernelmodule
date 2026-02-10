// SPDX-License-Identifier: GPL-2.0
/*
 * SmartScheduler eBPF Memory Tracing Program
 *
 * Monitors memory-related events:
 * - Page faults (minor and major)
 * - Memory allocations
 * - RSS changes
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_ENTRIES 10240

/* Memory statistics per process */
struct mem_stats {
    u64 minor_faults;       /* Minor page faults */
    u64 major_faults;       /* Major page faults (disk I/O) */
    u64 alloc_count;        /* Memory allocation count */
    u64 alloc_bytes;        /* Total bytes allocated */
    u64 last_fault_time;    /* Timestamp of last fault */
    u64 fault_rate;         /* Faults per second (calculated) */
};

/* BPF map for memory statistics */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct mem_stats);
} mem_stats_map SEC(".maps");

/* Ring buffer for memory events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} mem_events SEC(".maps");

/* Memory event structure */
struct mem_event {
    u32 pid;
    u32 event_type;
    u64 timestamp;
    u64 address;
    u64 bytes;
    char comm[16];
};

#define MEM_EVENT_MINOR_FAULT  1
#define MEM_EVENT_MAJOR_FAULT  2
#define MEM_EVENT_ALLOC        3
#define MEM_EVENT_FREE         4

/*
 * Tracepoint: exceptions/page_fault_user
 * Track user-space page faults
 */
SEC("tracepoint/exceptions/page_fault_user")
int trace_page_fault(struct trace_event_raw_page_fault_user *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 now = bpf_ktime_get_ns();
    struct mem_stats *stats;
    struct mem_stats new_stats = {};
    
    if (pid == 0)
        return 0;
    
    stats = bpf_map_lookup_elem(&mem_stats_map, &pid);
    if (!stats) {
        new_stats.minor_faults = 1;
        new_stats.last_fault_time = now;
        bpf_map_update_elem(&mem_stats_map, &pid, &new_stats, BPF_ANY);
    } else {
        __sync_fetch_and_add(&stats->minor_faults, 1);
        
        /* Calculate fault rate (simple) */
        if (stats->last_fault_time > 0) {
            u64 delta = now - stats->last_fault_time;
            if (delta > 0) {
                stats->fault_rate = 1000000000ULL / delta; /* faults/sec */
            }
        }
        stats->last_fault_time = now;
    }
    
    return 0;
}

/*
 * Kprobe: handle_mm_fault
 * Track all page fault handling
 */
SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(trace_mm_fault, struct vm_area_struct *vma, 
               unsigned long address, unsigned int flags)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct mem_stats *stats;
    struct mem_stats new_stats = {};
    
    if (pid == 0)
        return 0;
    
    stats = bpf_map_lookup_elem(&mem_stats_map, &pid);
    if (!stats) {
        new_stats.minor_faults = 1;
        bpf_map_update_elem(&mem_stats_map, &pid, &new_stats, BPF_ANY);
    } else {
        /* Check if major fault (FAULT_FLAG_ALLOW_RETRY usually set) */
        if (flags & 0x04) { /* FAULT_FLAG_ALLOW_RETRY */
            __sync_fetch_and_add(&stats->major_faults, 1);
        } else {
            __sync_fetch_and_add(&stats->minor_faults, 1);
        }
    }
    
    return 0;
}

/*
 * Tracepoint: kmem/mm_page_alloc
 * Track page allocations
 */
SEC("tracepoint/kmem/mm_page_alloc")
int trace_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct mem_stats *stats;
    
    if (pid == 0)
        return 0;
    
    stats = bpf_map_lookup_elem(&mem_stats_map, &pid);
    if (stats) {
        __sync_fetch_and_add(&stats->alloc_count, 1);
        /* order is log2 of pages, so bytes = PAGE_SIZE << order */
        __sync_fetch_and_add(&stats->alloc_bytes, 4096ULL << ctx->order);
    }
    
    return 0;
}

/*
 * Cleanup on process exit
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_mem_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    u32 pid = ctx->pid;
    bpf_map_delete_elem(&mem_stats_map, &pid);
    return 0;
}
