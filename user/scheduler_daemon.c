/*
 * SmartScheduler Enhanced Response Daemon V2
 *
 * Features:
 * - Categorized advisories by spike type
 * - Persistent spike detection (5-second threshold)
 * - Different actions per spike category
 * - Process group management
 * - Cooldown periods
 * - Statistics and reporting
 * - Action logging with timestamps
 * - Escalation levels
 *
 * Compile: gcc -o scheduler_daemon scheduler_daemon.c -Wall -O2
 * Run: sudo ./scheduler_daemon
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <errno.h>

#define PROC_PREDICTIONS "/proc/smartscheduler/predictions"
#define PROC_STATS       "/proc/smartscheduler/stats"
#define LOG_FILE         "logs/daemon_actions.log"
#define REPORT_FILE      "logs/daemon_report.txt"
#define CHECK_INTERVAL_MS 500
#define PERSISTENT_CHECK_INTERVAL 5  /* Check every 5 seconds */
#define MAX_LINE 256
#define MAX_TRACKED 1024

/* ANSI colors */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"
#define BG_RED        "\033[41m"

/* Spike types */
#define SPIKE_CPU  0x01
#define SPIKE_MEM  0x02
#define SPIKE_IO   0x04

/* Escalation levels */
typedef enum {
    ESCALATION_NONE = 0,
    ESCALATION_ADVISORY,      /* Just log, no action */
    ESCALATION_SOFT,          /* Minor adjustment */
    ESCALATION_HARD,          /* Major adjustment */
    ESCALATION_CRITICAL       /* Emergency measures */
} EscalationLevel;

/* Action results */
typedef enum {
    ACTION_SUCCESS = 0,
    ACTION_FAILED,
    ACTION_SKIPPED,
    ACTION_COOLDOWN
} ActionResult;

/* Configuration for different spike types */
typedef struct {
    const char *name;
    int nice_boost;           /* Nice value adjustment */
    int ionice_class;         /* I/O class */
    int ionice_level;         /* I/O level */
    int cooldown_secs;        /* Cooldown between actions */
    int persistent_threshold; /* Samples before escalation */
} SpikeConfig;

/* Per-process tracking */
typedef struct {
    int pid;
    char comm[32];
    int original_nice;
    int current_nice;
    int adjusted;
    time_t adjusted_time;
    time_t last_seen;
    int spike_type;
    int spike_samples;        /* Consecutive spike samples */
    EscalationLevel escalation;
    int action_count;         /* Total actions taken */
} TrackedProcess;

/* Global state */
static TrackedProcess tracked[MAX_TRACKED];
static int tracked_count = 0;
static volatile int running = 1;
static FILE *log_file = NULL;
static int verbose = 1;
static int dry_run = 0;
static time_t last_persistent_check = 0;
static time_t daemon_start_time;

/* Statistics */
static struct {
    int cpu_advisories;
    int mem_advisories;
    int io_advisories;
    int cpu_boosts;
    int mem_actions;
    int io_boosts;
    int restorations;
    int escalations;
    int persistent_spikes;
} stats = {0};

/* Spike configurations */
static SpikeConfig spike_configs[] = {
    /* CPU spikes */
    {"CPU", -5, 0, 0, 10, 5},
    /* Memory spikes */
    {"MEM", 0, 0, 0, 15, 8},
    /* I/O spikes */
    {"I/O", 0, 2, 0, 10, 5}
};

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

/* Get current time string */
char* get_time_str(void) {
    static char buf[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    return buf;
}

/* Log action with category */
void log_action(const char *category, const char *action, int pid, 
                const char *comm, const char *details) {
    if (verbose) {
        const char *color = COLOR_CYAN;
        if (strcmp(category, "CPU") == 0) color = COLOR_RED;
        else if (strcmp(category, "MEM") == 0) color = COLOR_YELLOW;
        else if (strcmp(category, "I/O") == 0) color = COLOR_MAGENTA;
        else if (strcmp(category, "RESTORE") == 0) color = COLOR_GREEN;
        else if (strcmp(category, "ESCALATE") == 0) color = BG_RED;
        
        printf("%s[%s]%s %s[%s]%s %s PID %d (%s): %s\n",
               COLOR_CYAN, get_time_str(), COLOR_RESET,
               color, category, COLOR_RESET,
               action, pid, comm, details);
    }
    
    if (log_file) {
        fprintf(log_file, "[%s] [%s] %s PID %d (%s): %s\n",
                get_time_str(), category, action, pid, comm, details);
        fflush(log_file);
    }
}

/* Find tracked process by PID */
TrackedProcess* find_tracked(int pid) {
    for (int i = 0; i < tracked_count; i++) {
        if (tracked[i].pid == pid) {
            return &tracked[i];
        }
    }
    return NULL;
}

/* Add process to tracking */
TrackedProcess* add_tracked(int pid, const char *comm) {
    if (tracked_count >= MAX_TRACKED) {
        return NULL;
    }
    TrackedProcess *p = &tracked[tracked_count++];
    memset(p, 0, sizeof(*p));
    p->pid = pid;
    strncpy(p->comm, comm, sizeof(p->comm) - 1);
    p->last_seen = time(NULL);
    return p;
}

/* Get process nice value */
int get_nice(int pid) {
    errno = 0;
    int nice = getpriority(PRIO_PROCESS, pid);
    if (nice == -1 && errno != 0) return 0;
    return nice;
}

/* Set process nice value */
ActionResult set_nice(int pid, int nice_val, const char *comm, const char *reason) {
    if (dry_run) {
        log_action("DRY-RUN", "Would set nice", pid, comm, reason);
        return ACTION_SUCCESS;
    }
    
    if (setpriority(PRIO_PROCESS, pid, nice_val) == 0) {
        return ACTION_SUCCESS;
    }
    return ACTION_FAILED;
}

/* Set I/O priority */
ActionResult set_io_priority(int pid, int ioprio_class, int ioprio_level, 
                             const char *comm, const char *reason) {
    if (dry_run) {
        log_action("DRY-RUN", "Would set ionice", pid, comm, reason);
        return ACTION_SUCCESS;
    }
    
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ionice -c %d -n %d -p %d 2>/dev/null",
             ioprio_class, ioprio_level, pid);
    if (system(cmd) == 0) {
        return ACTION_SUCCESS;
    }
    return ACTION_FAILED;
}

/* Determine escalation level based on spike history */
EscalationLevel get_escalation_level(TrackedProcess *p) {
    if (p->spike_samples <= 2) return ESCALATION_ADVISORY;
    if (p->spike_samples <= 5) return ESCALATION_SOFT;
    if (p->spike_samples <= 10) return ESCALATION_HARD;
    return ESCALATION_CRITICAL;
}

/* Get escalation string */
const char* escalation_str(EscalationLevel level) {
    switch (level) {
        case ESCALATION_ADVISORY: return "ADVISORY";
        case ESCALATION_SOFT:     return "SOFT";
        case ESCALATION_HARD:     return "HARD";
        case ESCALATION_CRITICAL: return "CRITICAL";
        default:                  return "NONE";
    }
}

/* Handle CPU spike with categorization */
void handle_cpu_spike(int pid, const char *comm, int roc) {
    TrackedProcess *p = find_tracked(pid);
    time_t now = time(NULL);
    
    if (!p) {
        p = add_tracked(pid, comm);
        if (!p) return;
        p->original_nice = get_nice(pid);
    }
    
    p->spike_type |= SPIKE_CPU;
    p->spike_samples++;
    p->last_seen = now;
    
    EscalationLevel level = get_escalation_level(p);
    char details[256];
    
    if (level == ESCALATION_ADVISORY) {
        /* Just log, no action */
        snprintf(details, sizeof(details), 
                 "Monitoring (ROC=%d, samples=%d)", roc, p->spike_samples);
        log_action("CPU", "ADVISORY", pid, comm, details);
        stats.cpu_advisories++;
        return;
    }
    
    /* Check cooldown */
    if (p->adjusted && (now - p->adjusted_time) < spike_configs[0].cooldown_secs) {
        return; /* Still in cooldown */
    }
    
    /* Take action based on escalation */
    int nice_boost = spike_configs[0].nice_boost;
    if (level >= ESCALATION_HARD) {
        nice_boost = -10;  /* More aggressive for persistent spikes */
    }
    if (level >= ESCALATION_CRITICAL) {
        nice_boost = -15;  /* Maximum boost for critical */
    }
    
    snprintf(details, sizeof(details), 
             "Boosting priority: nice %d -> %d (level=%s, ROC=%d)",
             p->current_nice, nice_boost, escalation_str(level), roc);
    
    if (set_nice(pid, nice_boost, comm, details) == ACTION_SUCCESS) {
        p->current_nice = nice_boost;
        p->adjusted = 1;
        p->adjusted_time = now;
        p->escalation = level;
        p->action_count++;
        stats.cpu_boosts++;
        
        if (level >= ESCALATION_HARD) {
            stats.escalations++;
        }
        
        log_action("CPU", "BOOST", pid, comm, details);
    }
}

/* Handle Memory spike with categorization */
void handle_mem_spike(int pid, const char *comm, int roc) {
    TrackedProcess *p = find_tracked(pid);
    time_t now = time(NULL);
    
    if (!p) {
        p = add_tracked(pid, comm);
        if (!p) return;
    }
    
    p->spike_type |= SPIKE_MEM;
    p->spike_samples++;
    p->last_seen = now;
    
    EscalationLevel level = get_escalation_level(p);
    char details[256];
    
    /* Memory advisories with different recommendations */
    if (level == ESCALATION_ADVISORY) {
        snprintf(details, sizeof(details),
                 "Normal spike (ROC=%d) - Monitor memory allocation", roc);
        log_action("MEM", "ADVISORY", pid, comm, details);
        stats.mem_advisories++;
    } else if (level == ESCALATION_SOFT) {
        snprintf(details, sizeof(details),
                 "Elevated spike (ROC=%d, samples=%d) - Consider memory limits", 
                 roc, p->spike_samples);
        log_action("MEM", "WARNING", pid, comm, details);
        stats.mem_advisories++;
    } else if (level >= ESCALATION_HARD) {
        snprintf(details, sizeof(details),
                 "PERSISTENT spike (ROC=%d, samples=%d) - Recommend cgroup limit or kill",
                 roc, p->spike_samples);
        log_action("MEM", "ALERT", pid, comm, details);
        stats.mem_actions++;
        stats.persistent_spikes++;
        
        /* For critical, we could add OOM score adjustment */
        if (level >= ESCALATION_CRITICAL && !dry_run) {
            char cmd[128];
            snprintf(cmd, sizeof(cmd), 
                     "echo 500 > /proc/%d/oom_score_adj 2>/dev/null", pid);
            system(cmd);
            log_action("MEM", "OOM_SCORE", pid, comm, 
                      "Set OOM score to 500 (more likely to be killed)");
        }
    }
}

/* Handle I/O spike with categorization */
void handle_io_spike(int pid, const char *comm, int roc) {
    TrackedProcess *p = find_tracked(pid);
    time_t now = time(NULL);
    
    if (!p) {
        p = add_tracked(pid, comm);
        if (!p) return;
    }
    
    p->spike_type |= SPIKE_IO;
    p->spike_samples++;
    p->last_seen = now;
    
    EscalationLevel level = get_escalation_level(p);
    char details[256];
    
    if (level == ESCALATION_ADVISORY) {
        snprintf(details, sizeof(details),
                 "I/O activity spike (ROC=%d) - Monitoring", roc);
        log_action("I/O", "ADVISORY", pid, comm, details);
        stats.io_advisories++;
        return;
    }
    
    /* Check cooldown */
    if (p->adjusted && (now - p->adjusted_time) < spike_configs[2].cooldown_secs) {
        return;
    }
    
    /* Take action */
    int io_class = spike_configs[2].ionice_class;
    int io_level = spike_configs[2].ionice_level;
    
    if (level >= ESCALATION_HARD) {
        io_class = 1;  /* Real-time class */
        io_level = 4;
    }
    
    snprintf(details, sizeof(details),
             "Setting I/O priority: class=%d level=%d (level=%s)",
             io_class, io_level, escalation_str(level));
    
    if (set_io_priority(pid, io_class, io_level, comm, details) == ACTION_SUCCESS) {
        p->adjusted = 1;
        p->adjusted_time = now;
        p->action_count++;
        stats.io_boosts++;
        log_action("I/O", "BOOST", pid, comm, details);
    }
}

/* Restore original priorities */
void restore_priorities(void) {
    time_t now = time(NULL);
    
    for (int i = 0; i < tracked_count; i++) {
        TrackedProcess *p = &tracked[i];
        
        /* If not seen for 5+ seconds and was adjusted, restore */
        if (p->adjusted && (now - p->last_seen) > 5) {
            char details[128];
            snprintf(details, sizeof(details),
                     "Restoring priority: nice %d -> %d (no spike for %lds)",
                     p->current_nice, p->original_nice, now - p->last_seen);
            
            if (set_nice(p->pid, p->original_nice, p->comm, details) == ACTION_SUCCESS) {
                log_action("RESTORE", "PRIORITY", p->pid, p->comm, details);
                p->adjusted = 0;
                p->current_nice = p->original_nice;
                p->spike_samples = 0;
                p->escalation = ESCALATION_NONE;
                stats.restorations++;
            }
        }
    }
}

/* Check for persistent spikes (every 5 seconds) */
void check_persistent_spikes(void) {
    time_t now = time(NULL);
    
    if (now - last_persistent_check < PERSISTENT_CHECK_INTERVAL) {
        return;
    }
    last_persistent_check = now;
    
    printf("\n%s=== Persistent Spike Check ===%s\n", COLOR_YELLOW, COLOR_RESET);
    
    int persistent = 0;
    for (int i = 0; i < tracked_count; i++) {
        TrackedProcess *p = &tracked[i];
        
        if (p->spike_samples >= 5 && (now - p->last_seen) < 2) {
            persistent++;
            
            printf("  %s⚠ PID %d (%s)%s: %d samples, type=%s%s%s, level=%s\n",
                   COLOR_RED, p->pid, p->comm, COLOR_RESET,
                   p->spike_samples,
                   (p->spike_type & SPIKE_CPU) ? "CPU " : "",
                   (p->spike_type & SPIKE_MEM) ? "MEM " : "",
                   (p->spike_type & SPIKE_IO) ? "I/O " : "",
                   escalation_str(p->escalation));
        }
    }
    
    if (persistent == 0) {
        printf("  %s✓ No persistent spikes detected%s\n", COLOR_GREEN, COLOR_RESET);
    } else {
        printf("  %s⚠ %d persistent spike(s) - escalated actions in effect%s\n",
               COLOR_RED, persistent, COLOR_RESET);
    }
    printf("\n");
}

/* Parse stats file to get ROC values */
void read_roc_values(int *cpu_roc, int *mem_roc, int *io_roc, int pid) {
    FILE *f = fopen(PROC_STATS, "r");
    if (!f) return;
    
    char line[MAX_LINE];
    
    /* Skip headers */
    for (int i = 0; i < 4; i++) {
        if (!fgets(line, sizeof(line), f)) break;
    }
    
    while (fgets(line, sizeof(line), f)) {
        int p, cpu_ema, mem_ema, io_ema, c_roc, m_roc, i_roc;
        if (sscanf(line, "%d %d %d %d %d %d %d",
                   &p, &cpu_ema, &mem_ema, &io_ema, &c_roc, &m_roc, &i_roc) >= 7) {
            if (p == pid) {
                *cpu_roc = c_roc;
                *mem_roc = m_roc;
                *io_roc = i_roc;
                break;
            }
        }
    }
    fclose(f);
}

/* Process predictions file */
void process_predictions(void) {
    FILE *f = fopen(PROC_PREDICTIONS, "r");
    if (!f) {
        if (verbose) {
            fprintf(stderr, "%sError: Cannot open %s%s\n",
                    COLOR_RED, PROC_PREDICTIONS, COLOR_RESET);
        }
        return;
    }
    
    char line[MAX_LINE];
    
    /* Skip header lines */
    for (int i = 0; i < 4; i++) {
        if (!fgets(line, sizeof(line), f)) break;
    }
    
    while (fgets(line, sizeof(line), f)) {
        int pid;
        char comm[32];
        char cpu_flag, mem_flag, io_flag;
        int flags;
        
        if (sscanf(line, "%d %31s %c %c %c %x",
                   &pid, comm, &cpu_flag, &mem_flag, &io_flag, &flags) >= 5) {
            
            /* Get ROC values for this process */
            int cpu_roc = 0, mem_roc = 0, io_roc = 0;
            read_roc_values(&cpu_roc, &mem_roc, &io_roc, pid);
            
            if (cpu_flag == '*') {
                handle_cpu_spike(pid, comm, cpu_roc);
            }
            if (mem_flag == '*') {
                handle_mem_spike(pid, comm, mem_roc);
            }
            if (io_flag == '*') {
                handle_io_spike(pid, comm, io_roc);
            }
        }
    }
    
    fclose(f);
    restore_priorities();
}

/* Print status header */
void print_status(void) {
    printf("\n%s╔══════════════════════════════════════════════════════════════╗%s\n",
           COLOR_GREEN, COLOR_RESET);
    printf("%s║       SmartScheduler Response Daemon v2.0                     ║%s\n",
           COLOR_GREEN, COLOR_RESET);
    printf("%s╠══════════════════════════════════════════════════════════════╣%s\n",
           COLOR_GREEN, COLOR_RESET);
    printf("%s║%s Check interval:     %d ms                                    %s║%s\n",
           COLOR_GREEN, COLOR_RESET, CHECK_INTERVAL_MS, COLOR_GREEN, COLOR_RESET);
    printf("%s║%s Persistent check:   Every %d seconds                         %s║%s\n",
           COLOR_GREEN, COLOR_RESET, PERSISTENT_CHECK_INTERVAL, COLOR_GREEN, COLOR_RESET);
    printf("%s║%s Dry run mode:       %s                                     %s║%s\n",
           COLOR_GREEN, COLOR_RESET, 
           dry_run ? "YES (no changes)" : "NO (actions enabled)",
           COLOR_GREEN, COLOR_RESET);
    printf("%s╚══════════════════════════════════════════════════════════════╝%s\n\n",
           COLOR_GREEN, COLOR_RESET);
    
    printf("Action Categories:\n");
    printf("  %s[CPU]%s   → Priority boost (nice value adjustment)\n",
           COLOR_RED, COLOR_RESET);
    printf("  %s[MEM]%s   → Memory advisories, OOM score adjustment\n",
           COLOR_YELLOW, COLOR_RESET);
    printf("  %s[I/O]%s   → I/O priority boost (ionice)\n",
           COLOR_MAGENTA, COLOR_RESET);
    printf("  %s[RESTORE]%s → Priority restoration after spike ends\n",
           COLOR_GREEN, COLOR_RESET);
    printf("  %s[ESCALATE]%s → Elevated response for persistent spikes\n",
           BG_RED, COLOR_RESET);
    printf("\nEscalation Levels:\n");
    printf("  ADVISORY → Just log (1-2 samples)\n");
    printf("  SOFT     → Minor adjustment (3-5 samples)\n");
    printf("  HARD     → Major adjustment (6-10 samples)\n");
    printf("  CRITICAL → Emergency measures (>10 samples)\n");
    printf("\nPress Ctrl+C to stop\n\n");
}

/* Print summary */
void print_summary(void) {
    time_t now = time(NULL);
    long uptime = now - daemon_start_time;
    
    printf("\n%s╔══════════════════════════════════════════════════════════════╗%s\n",
           COLOR_YELLOW, COLOR_RESET);
    printf("%s║                    Daemon Summary                            ║%s\n",
           COLOR_YELLOW, COLOR_RESET);
    printf("%s╠══════════════════════════════════════════════════════════════╣%s\n",
           COLOR_YELLOW, COLOR_RESET);
    printf("%s║%s Uptime:                    %ld seconds                        %s║%s\n",
           COLOR_YELLOW, COLOR_RESET, uptime, COLOR_YELLOW, COLOR_RESET);
    printf("%s║%s Processes tracked:         %d                                  %s║%s\n",
           COLOR_YELLOW, COLOR_RESET, tracked_count, COLOR_YELLOW, COLOR_RESET);
    printf("%s╠══════════════════════════════════════════════════════════════╣%s\n",
           COLOR_YELLOW, COLOR_RESET);
    printf("%s║%s CPU advisories:            %d                                  %s║%s\n",
           COLOR_YELLOW, COLOR_RESET, stats.cpu_advisories, COLOR_YELLOW, COLOR_RESET);
    printf("%s║%s CPU priority boosts:       %d                                  %s║%s\n",
           COLOR_YELLOW, COLOR_RESET, stats.cpu_boosts, COLOR_YELLOW, COLOR_RESET);
    printf("%s║%s Memory advisories:         %d                                  %s║%s\n",
           COLOR_YELLOW, COLOR_RESET, stats.mem_advisories, COLOR_YELLOW, COLOR_RESET);
    printf("%s║%s Memory actions:            %d                                  %s║%s\n",
           COLOR_YELLOW, COLOR_RESET, stats.mem_actions, COLOR_YELLOW, COLOR_RESET);
    printf("%s║%s I/O advisories:            %d                                  %s║%s\n",
           COLOR_YELLOW, COLOR_RESET, stats.io_advisories, COLOR_YELLOW, COLOR_RESET);
    printf("%s║%s I/O priority boosts:       %d                                  %s║%s\n",
           COLOR_YELLOW, COLOR_RESET, stats.io_boosts, COLOR_YELLOW, COLOR_RESET);
    printf("%s║%s Priority restorations:     %d                                  %s║%s\n",
           COLOR_YELLOW, COLOR_RESET, stats.restorations, COLOR_YELLOW, COLOR_RESET);
    printf("%s║%s Escalations:               %d                                  %s║%s\n",
           COLOR_YELLOW, COLOR_RESET, stats.escalations, COLOR_YELLOW, COLOR_RESET);
    printf("%s║%s Persistent spikes handled: %d                                  %s║%s\n",
           COLOR_YELLOW, COLOR_RESET, stats.persistent_spikes, COLOR_YELLOW, COLOR_RESET);
    printf("%s╚══════════════════════════════════════════════════════════════╝%s\n",
           COLOR_YELLOW, COLOR_RESET);
    
    /* Write report to file */
    FILE *f = fopen(REPORT_FILE, "w");
    if (f) {
        fprintf(f, "SmartScheduler Daemon Report\n");
        fprintf(f, "============================\n");
        fprintf(f, "Generated: %s\n\n", get_time_str());
        fprintf(f, "Uptime: %ld seconds\n", uptime);
        fprintf(f, "Processes tracked: %d\n\n", tracked_count);
        fprintf(f, "Statistics:\n");
        fprintf(f, "  CPU advisories: %d\n", stats.cpu_advisories);
        fprintf(f, "  CPU boosts: %d\n", stats.cpu_boosts);
        fprintf(f, "  Memory advisories: %d\n", stats.mem_advisories);
        fprintf(f, "  Memory actions: %d\n", stats.mem_actions);
        fprintf(f, "  I/O advisories: %d\n", stats.io_advisories);
        fprintf(f, "  I/O boosts: %d\n", stats.io_boosts);
        fprintf(f, "  Restorations: %d\n", stats.restorations);
        fprintf(f, "  Escalations: %d\n", stats.escalations);
        fprintf(f, "  Persistent spikes: %d\n", stats.persistent_spikes);
        fclose(f);
        printf("\nReport saved to: %s\n", REPORT_FILE);
    }
}

void usage(const char *prog) {
    printf("SmartScheduler Response Daemon v2.0\n\n");
    printf("Usage: sudo %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -q        Quiet mode\n");
    printf("  -n        Dry run (no priority changes)\n");
    printf("  -h        Show this help\n");
    printf("\nRequires root for priority adjustments.\n");
}

int main(int argc, char *argv[]) {
    int opt;
    
    while ((opt = getopt(argc, argv, "qnh")) != -1) {
        switch (opt) {
            case 'q': verbose = 0; break;
            case 'n': dry_run = 1; break;
            case 'h':
            default:
                usage(argv[0]);
                return 0;
        }
    }
    
    if (geteuid() != 0 && !dry_run) {
        fprintf(stderr, "%sError: Must run as root%s\n", COLOR_RED, COLOR_RESET);
        fprintf(stderr, "Use: sudo %s  or  %s -n (dry-run)\n", argv[0], argv[0]);
        return 1;
    }
    
    FILE *f = fopen(PROC_PREDICTIONS, "r");
    if (!f) {
        fprintf(stderr, "%sError: SmartScheduler module not loaded%s\n",
                COLOR_RED, COLOR_RESET);
        return 1;
    }
    fclose(f);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    mkdir("logs", 0755);
    log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        fprintf(log_file, "\n=== Daemon started at %s ===\n", get_time_str());
    }
    
    daemon_start_time = time(NULL);
    last_persistent_check = daemon_start_time;
    
    print_status();
    
    while (running) {
        process_predictions();
        check_persistent_spikes();
        usleep(CHECK_INTERVAL_MS * 1000);
    }
    
    print_summary();
    
    if (log_file) {
        fprintf(log_file, "=== Daemon stopped at %s ===\n", get_time_str());
        fclose(log_file);
    }
    
    printf("\nDaemon stopped.\n");
    return 0;
}
