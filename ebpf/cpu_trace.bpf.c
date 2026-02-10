// SPDX-License-Identifier: GPL-2.0
/*
 * SmartScheduler eBPF CPU Tracing Program
 *
 * Attaches to scheduler tracepoints to monitor:
 * - Context switches (sched_switch)
 * - Process wakeups (sched_wakeup)
 * - CPU migrations
 *
 * Data is collected in BPF maps and read by user-space.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* Maximum number of processes to track */
#define MAX_ENTRIES 10240

/* CPU usage statistics per process */
struct cpu_stats {
    u64 total_runtime_ns;    /* Total CPU time in nanoseconds */
    u64 switch_count;        /* Number of context switches */
    u64 wakeup_count;        /* Number of wakeups */
    u64 last_switch_time;    /* Last context switch timestamp */
    u64 voluntary_switches;  /* Voluntary context switches */
    u64 involuntary_switches;/* Preempted context switches */
};

/* BPF map to store per-process CPU statistics */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);        /* PID */
    __type(value, struct cpu_stats);
} cpu_stats_map SEC(".maps");

/* Ring buffer for real-time events to user-space */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB */
} events SEC(".maps");

/* Event types */
#define EVENT_SWITCH   1
#define EVENT_WAKEUP   2
#define EVENT_SPIKE    3

/* Event structure sent to user-space */
struct event {
    u32 pid;
    u32 event_type;
    u64 timestamp;
    u64 value;
    char comm[16];
};

/*
 * Tracepoint: sched/sched_switch
 * Called on every context switch
 */
SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    u32 prev_pid = ctx->prev_pid;
    u32 next_pid = ctx->next_pid;
    u64 now = bpf_ktime_get_ns();
    struct cpu_stats *stats;
    struct cpu_stats new_stats = {};

    /* Skip kernel threads (PID 0) */
    if (prev_pid == 0 && next_pid == 0)
        return 0;

    /* Update stats for process being switched OUT */
    if (prev_pid != 0) {
        stats = bpf_map_lookup_elem(&cpu_stats_map, &prev_pid);
        if (stats) {
            /* Calculate runtime since last switch */
            if (stats->last_switch_time > 0) {
                u64 runtime = now - stats->last_switch_time;
                __sync_fetch_and_add(&stats->total_runtime_ns, runtime);
            }
            __sync_fetch_and_add(&stats->switch_count, 1);
            
            /* Check if voluntary (prev_state != TASK_RUNNING) */
            if (ctx->prev_state != 0) {
                __sync_fetch_and_add(&stats->voluntary_switches, 1);
            } else {
                __sync_fetch_and_add(&stats->involuntary_switches, 1);
            }
        }
    }

    /* Update stats for process being switched IN */
    if (next_pid != 0) {
        stats = bpf_map_lookup_elem(&cpu_stats_map, &next_pid);
        if (!stats) {
            /* Create new entry */
            new_stats.last_switch_time = now;
            new_stats.switch_count = 1;
            bpf_map_update_elem(&cpu_stats_map, &next_pid, &new_stats, BPF_ANY);
        } else {
            stats->last_switch_time = now;
        }
    }

    return 0;
}

/*
 * Tracepoint: sched/sched_wakeup
 * Called when a process is woken up
 */
SEC("tracepoint/sched/sched_wakeup")
int trace_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    u32 pid = ctx->pid;
    u64 now = bpf_ktime_get_ns();
    struct cpu_stats *stats;
    struct cpu_stats new_stats = {};

    if (pid == 0)
        return 0;

    stats = bpf_map_lookup_elem(&cpu_stats_map, &pid);
    if (!stats) {
        new_stats.wakeup_count = 1;
        new_stats.last_switch_time = now;
        bpf_map_update_elem(&cpu_stats_map, &pid, &new_stats, BPF_ANY);
    } else {
        __sync_fetch_and_add(&stats->wakeup_count, 1);
    }

    return 0;
}

/*
 * Tracepoint: sched/sched_process_exit
 * Clean up when process exits
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    u32 pid = ctx->pid;
    
    /* Remove from map to prevent memory leak */
    bpf_map_delete_elem(&cpu_stats_map, &pid);
    
    return 0;
}
