/*
 * SmartScheduler Kernel Module
 * 
 * A predictive scheduling enhancement module that:
 * - Maintains per-process behavioral signatures
 * - Computes Exponential Moving Averages (EMA) for CPU, memory, and I/O
 * - Predicts resource spikes using online statistical methods
 * - Exposes predictions via procfs interface
 *
 * Author: SmartScheduler Research Team
 * License: GPL v2
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SmartScheduler Research Team");
MODULE_DESCRIPTION("Predictive Process Scheduling Enhancement Module");
MODULE_VERSION("1.0");

/* ============================================
 * CONFIGURATION PARAMETERS
 * ============================================ */

/* EMA smoothing factor: alpha = 30/100 = 0.3 */
#define ALPHA 30
#define ALPHA_COMPLEMENT (100 - ALPHA)

/* Prediction thresholds (scaled by 100 for integer math) */
#define CPU_SPIKE_THRESHOLD    2000   /* 20% increase rate */
#define MEM_SPIKE_THRESHOLD    1500   /* 15% increase rate */
#define IO_SPIKE_THRESHOLD     1000   /* 10% increase rate */

/* Hash table size: 2^10 = 1024 buckets */
#define PROC_HASH_BITS 10

/* Sampling interval in milliseconds */
#define SAMPLE_INTERVAL_MS 100

/* Maximum tracked processes */
#define MAX_TRACKED_PROCS 4096

/* ============================================
 * DATA STRUCTURES
 * ============================================ */

/* Prediction flags - bitfield for efficiency */
#define FLAG_CPU_SPIKE_PREDICTED  (1 << 0)
#define FLAG_MEM_SPIKE_PREDICTED  (1 << 1)
#define FLAG_IO_SPIKE_PREDICTED   (1 << 2)
#define FLAG_ACTIVE               (1 << 7)

/*
 * Per-process behavioral signature
 * Stored in kernel memory, indexed by PID
 */
struct proc_signature {
    pid_t pid;                    /* Process ID */
    char comm[TASK_COMM_LEN];     /* Process name */
    
    /* Current EMA values (scaled by 100) */
    int cpu_ema;
    int mem_ema;
    int io_ema;
    
    /* Previous samples for rate-of-change */
    int cpu_prev;
    int mem_prev;
    int io_prev;
    
    /* Rate of change values */
    int cpu_roc;
    int mem_roc;
    int io_roc;
    
    /* Prediction flags */
    unsigned int flags;
    
    /* Timestamps */
    unsigned long last_update;    /* jiffies */
    unsigned long created;        /* jiffies */
    
    /* Statistics counters */
    unsigned long cpu_spikes_predicted;
    unsigned long mem_spikes_predicted;
    unsigned long io_spikes_predicted;
    unsigned long total_samples;
    
    /* Hash table linkage */
    struct hlist_node hash_node;
};

/* ============================================
 * GLOBAL STATE
 * ============================================ */

/* Hash table for process signatures */
static DEFINE_HASHTABLE(proc_signatures, PROC_HASH_BITS);

/* Spinlock for hash table access */
static DEFINE_SPINLOCK(sig_lock);

/* Timer for periodic sampling */
static struct timer_list sample_timer;

/* Procfs entries */
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_status;
static struct proc_dir_entry *proc_predictions;
static struct proc_dir_entry *proc_stats;

/* Module statistics */
static atomic_t total_tracked = ATOMIC_INIT(0);
static atomic_t total_predictions = ATOMIC_INIT(0);
static unsigned long module_start_time;

/* ============================================
 * STATISTICAL FUNCTIONS
 * ============================================ */

/*
 * Update Exponential Moving Average
 * Uses integer arithmetic: EMA = alpha * sample + (1-alpha) * old
 * All values scaled by 100 for precision
 */
static inline int update_ema(int old_ema, int sample)
{
    return (ALPHA * sample + ALPHA_COMPLEMENT * old_ema) / 100;
}

/*
 * Calculate rate of change
 * Returns the difference between current_val and previous sample
 */
static inline int calc_rate_of_change(int current_val, int previous)
{
    return current_val - previous;
}

/*
 * Check if value indicates a spike
 * Compares rate-of-change against threshold
 */
static inline bool is_spike_predicted(int roc, int threshold)
{
    return roc > threshold;
}

/* ============================================
 * PROCESS SIGNATURE MANAGEMENT
 * ============================================ */

/*
 * Find or create a signature for a process
 * Must be called with sig_lock held
 */
static struct proc_signature *get_or_create_signature(pid_t pid, const char *comm)
{
    struct proc_signature *sig;
    
    /* Search existing */
    hash_for_each_possible(proc_signatures, sig, hash_node, pid) {
        if (sig->pid == pid) {
            return sig;
        }
    }
    
    /* Check limit */
    if (atomic_read(&total_tracked) >= MAX_TRACKED_PROCS) {
        return NULL;
    }
    
    /* Create new signature */
    sig = kzalloc(sizeof(*sig), GFP_ATOMIC);
    if (!sig) {
        return NULL;
    }
    
    sig->pid = pid;
    if (comm) {
        strncpy(sig->comm, comm, TASK_COMM_LEN - 1);
    }
    sig->created = jiffies;
    sig->last_update = jiffies;
    sig->flags = FLAG_ACTIVE;
    
    hash_add(proc_signatures, &sig->hash_node, pid);
    atomic_inc(&total_tracked);
    
    return sig;
}

/*
 * Remove a process signature
 * Must be called with sig_lock held
 */
static void remove_signature(struct proc_signature *sig)
{
    hash_del(&sig->hash_node);
    atomic_dec(&total_tracked);
    kfree(sig);
}

/*
 * Update signature with new sample data
 * Computes EMA, rate-of-change, and sets prediction flags
 */
static void update_signature(struct proc_signature *sig, 
                            int cpu_sample, int mem_sample, int io_sample)
{
    /* Store previous values */
    sig->cpu_prev = sig->cpu_ema;
    sig->mem_prev = sig->mem_ema;
    sig->io_prev = sig->io_ema;
    
    /* Update EMAs */
    sig->cpu_ema = update_ema(sig->cpu_ema, cpu_sample);
    sig->mem_ema = update_ema(sig->mem_ema, mem_sample);
    sig->io_ema = update_ema(sig->io_ema, io_sample);
    
    /* Calculate rates of change */
    sig->cpu_roc = calc_rate_of_change(sig->cpu_ema, sig->cpu_prev);
    sig->mem_roc = calc_rate_of_change(sig->mem_ema, sig->mem_prev);
    sig->io_roc = calc_rate_of_change(sig->io_ema, sig->io_prev);
    
    /* Clear old prediction flags */
    sig->flags &= ~(FLAG_CPU_SPIKE_PREDICTED | 
                    FLAG_MEM_SPIKE_PREDICTED | 
                    FLAG_IO_SPIKE_PREDICTED);
    
    /* Set new prediction flags based on thresholds */
    if (is_spike_predicted(sig->cpu_roc, CPU_SPIKE_THRESHOLD)) {
        sig->flags |= FLAG_CPU_SPIKE_PREDICTED;
        sig->cpu_spikes_predicted++;
        atomic_inc(&total_predictions);
    }
    
    if (is_spike_predicted(sig->mem_roc, MEM_SPIKE_THRESHOLD)) {
        sig->flags |= FLAG_MEM_SPIKE_PREDICTED;
        sig->mem_spikes_predicted++;
        atomic_inc(&total_predictions);
    }
    
    if (is_spike_predicted(sig->io_roc, IO_SPIKE_THRESHOLD)) {
        sig->flags |= FLAG_IO_SPIKE_PREDICTED;
        sig->io_spikes_predicted++;
        atomic_inc(&total_predictions);
    }
    
    sig->total_samples++;
    sig->last_update = jiffies;
}

/* ============================================
 * SAMPLING FUNCTIONS
 * ============================================ */

/*
 * Get CPU usage sample for a task
 * Returns scaled value (0-10000 for 0-100%)
 */
static int get_cpu_sample(struct task_struct *task)
{
    /* Use utime + stime as proxy for CPU usage */
    u64 total_time = task->utime + task->stime;
    /* Scale to percentage * 100 */
    return (int)((total_time * 100) / (jiffies - task->start_time + 1));
}

/*
 * Get memory usage sample for a task
 * Returns scaled value based on memory maps
 */
static int get_mem_sample(struct task_struct *task)
{
    if (task->mm) {
        /* Use total_vm as proxy for memory usage */
        return (int)(task->mm->total_vm * 100 / 1024);
    }
    return 0;
}

/*
 * Get I/O sample for a task
 * Uses ioac if available
 */
static int get_io_sample(struct task_struct *task)
{
#ifdef CONFIG_TASK_IO_ACCOUNTING
    return (int)((task->ioac.read_bytes + task->ioac.write_bytes) / 1024);
#else
    return 0;
#endif
}

/*
 * Timer callback: sample all running processes
 */
static void sample_timer_callback(struct timer_list *t)
{
    struct task_struct *task;
    unsigned long flags;
    
    spin_lock_irqsave(&sig_lock, flags);
    
    rcu_read_lock();
    for_each_process(task) {
        struct proc_signature *sig;
        int cpu_sample, mem_sample, io_sample;
        
        /* Skip kernel threads and zombies */
        if (task->flags & PF_KTHREAD)
            continue;
        if (task->exit_state)
            continue;
        
        /* Get samples */
        cpu_sample = get_cpu_sample(task);
        mem_sample = get_mem_sample(task);
        io_sample = get_io_sample(task);
        
        /* Get or create signature */
        sig = get_or_create_signature(task->pid, task->comm);
        if (sig) {
            update_signature(sig, cpu_sample, mem_sample, io_sample);
        }
    }
    rcu_read_unlock();
    
    spin_unlock_irqrestore(&sig_lock, flags);
    
    /* Reschedule timer */
    mod_timer(&sample_timer, jiffies + msecs_to_jiffies(SAMPLE_INTERVAL_MS));
}

/* ============================================
 * PROCFS INTERFACE
 * ============================================ */

/*
 * /proc/smartscheduler/status
 * Shows module status and configuration
 */
static int status_show(struct seq_file *m, void *v)
{
    unsigned long uptime_secs = (jiffies - module_start_time) / HZ;
    
    seq_puts(m, "=== SmartScheduler Status ===\n\n");
    seq_printf(m, "Module uptime:        %lu seconds\n", uptime_secs);
    seq_printf(m, "Tracked processes:    %d\n", atomic_read(&total_tracked));
    seq_printf(m, "Total predictions:    %d\n", atomic_read(&total_predictions));
    seq_printf(m, "Sample interval:      %d ms\n", SAMPLE_INTERVAL_MS);
    seq_puts(m, "\n=== Thresholds ===\n");
    seq_printf(m, "CPU spike threshold:  %d\n", CPU_SPIKE_THRESHOLD);
    seq_printf(m, "Memory spike thresh:  %d\n", MEM_SPIKE_THRESHOLD);
    seq_printf(m, "I/O spike threshold:  %d\n", IO_SPIKE_THRESHOLD);
    seq_printf(m, "EMA alpha:            0.%d\n", ALPHA);
    
    return 0;
}

static int status_open(struct inode *inode, struct file *file)
{
    return single_open(file, status_show, NULL);
}

static const struct proc_ops status_ops = {
    .proc_open = status_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/*
 * /proc/smartscheduler/predictions
 * Shows current predictions for all tracked processes
 */
static int predictions_show(struct seq_file *m, void *v)
{
    struct proc_signature *sig;
    unsigned long flags;
    int bkt;
    int count = 0;
    
    seq_puts(m, "=== Current Predictions ===\n\n");
    seq_printf(m, "%-8s %-16s %6s %6s %6s %8s\n", "PID", "COMM", "CPU", "MEM", "I/O", "FLAGS");
    seq_printf(m, "%-8s %-16s %6s %6s %6s %8s\n", "---", "----", "---", "---", "---", "-----");
    
    spin_lock_irqsave(&sig_lock, flags);
    
    hash_for_each(proc_signatures, bkt, sig, hash_node) {
        char cpu_flag = (sig->flags & FLAG_CPU_SPIKE_PREDICTED) ? '*' : '-';
        char mem_flag = (sig->flags & FLAG_MEM_SPIKE_PREDICTED) ? '*' : '-';
        char io_flag = (sig->flags & FLAG_IO_SPIKE_PREDICTED) ? '*' : '-';
        
        seq_printf(m, "%-8d %-16s %6c %6c %6c %#8x\n",
                   sig->pid, sig->comm, cpu_flag, mem_flag, io_flag, sig->flags);
        count++;
        
        /* Limit output */
        if (count >= 100) {
            seq_puts(m, "\n... (truncated, showing first 100)\n");
            break;
        }
    }
    
    spin_unlock_irqrestore(&sig_lock, flags);
    
    if (count == 0) {
        seq_puts(m, "(no processes currently tracked)\n");
    }
    
    seq_printf(m, "\nLegend: * = spike predicted, - = normal\n");
    
    return 0;
}

static int predictions_open(struct inode *inode, struct file *file)
{
    return single_open(file, predictions_show, NULL);
}

static const struct proc_ops predictions_ops = {
    .proc_open = predictions_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/*
 * /proc/smartscheduler/stats
 * Shows detailed statistics for all tracked processes
 */
static int stats_show(struct seq_file *m, void *v)
{
    struct proc_signature *sig;
    unsigned long flags;
    int bkt;
    
    seq_puts(m, "=== Process Statistics ===\n\n");
    seq_printf(m, "%-8s %8s %8s %8s %8s %8s %8s %10s\n", 
               "PID", "CPU_EMA", "MEM_EMA", "IO_EMA", "CPU_ROC", "MEM_ROC", "IO_ROC", "SAMPLES");
    seq_printf(m, "%-8s %8s %8s %8s %8s %8s %8s %10s\n",
               "---", "-------", "-------", "------", "-------", "-------", "------", "-------");
    
    spin_lock_irqsave(&sig_lock, flags);
    
    hash_for_each(proc_signatures, bkt, sig, hash_node) {
        seq_printf(m, "%-8d %8d %8d %8d %+8d %+8d %+8d %10lu\n",
                   sig->pid,
                   sig->cpu_ema, sig->mem_ema, sig->io_ema,
                   sig->cpu_roc, sig->mem_roc, sig->io_roc,
                   sig->total_samples);
    }
    
    spin_unlock_irqrestore(&sig_lock, flags);
    
    return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, stats_show, NULL);
}

static const struct proc_ops stats_ops = {
    .proc_open = stats_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* ============================================
 * MODULE INITIALIZATION & CLEANUP
 * ============================================ */

static int __init smartscheduler_init(void)
{
    printk(KERN_INFO "SmartScheduler: Initializing module...\n");
    
    module_start_time = jiffies;
    
    /* Create procfs directory */
    proc_dir = proc_mkdir("smartscheduler", NULL);
    if (!proc_dir) {
        printk(KERN_ERR "SmartScheduler: Failed to create /proc/smartscheduler\n");
        return -ENOMEM;
    }
    
    /* Create procfs entries */
    proc_status = proc_create("status", 0444, proc_dir, &status_ops);
    proc_predictions = proc_create("predictions", 0444, proc_dir, &predictions_ops);
    proc_stats = proc_create("stats", 0444, proc_dir, &stats_ops);
    
    if (!proc_status || !proc_predictions || !proc_stats) {
        printk(KERN_ERR "SmartScheduler: Failed to create proc entries\n");
        goto cleanup_proc;
    }
    
    /* Initialize and start sampling timer */
    timer_setup(&sample_timer, sample_timer_callback, 0);
    mod_timer(&sample_timer, jiffies + msecs_to_jiffies(SAMPLE_INTERVAL_MS));
    
    printk(KERN_INFO "SmartScheduler: Module loaded successfully\n");
    printk(KERN_INFO "SmartScheduler: Sampling every %d ms\n", SAMPLE_INTERVAL_MS);
    printk(KERN_INFO "SmartScheduler: View status at /proc/smartscheduler/\n");
    
    return 0;

cleanup_proc:
    if (proc_stats) proc_remove(proc_stats);
    if (proc_predictions) proc_remove(proc_predictions);
    if (proc_status) proc_remove(proc_status);
    if (proc_dir) proc_remove(proc_dir);
    return -ENOMEM;
}

static void __exit smartscheduler_exit(void)
{
    struct proc_signature *sig;
    struct hlist_node *tmp;
    unsigned long flags;
    int bkt;
    
    printk(KERN_INFO "SmartScheduler: Unloading module...\n");
    
    /* Stop timer */
    del_timer_sync(&sample_timer);
    
    /* Remove procfs entries */
    proc_remove(proc_stats);
    proc_remove(proc_predictions);
    proc_remove(proc_status);
    proc_remove(proc_dir);
    
    /* Free all signatures */
    spin_lock_irqsave(&sig_lock, flags);
    hash_for_each_safe(proc_signatures, bkt, tmp, sig, hash_node) {
        hash_del(&sig->hash_node);
        kfree(sig);
    }
    spin_unlock_irqrestore(&sig_lock, flags);
    
    printk(KERN_INFO "SmartScheduler: Module unloaded. Total predictions made: %d\n",
           atomic_read(&total_predictions));
}

module_init(smartscheduler_init);
module_exit(smartscheduler_exit);
