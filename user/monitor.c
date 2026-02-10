/*
 * SmartScheduler Enhanced Monitor V2
 *
 * Features:
 * - Real-time process monitoring with RAM usage
 * - Graphical spike indicators (progress bars)
 * - Persistent spike tracking (5-second history)
 * - Alert levels (LOW/MEDIUM/HIGH/CRITICAL)
 * - Top N processes view
 * - System resource summary
 * - Trend indicators (↑ ↓ →)
 * - Advisory categorization
 * - Color-coded severity
 * - Export to CSV
 *
 * Compile: gcc -o monitor monitor.c -Wall -O2
 * Run: ./monitor [options]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <errno.h>
#include <dirent.h>

#define PROC_STATUS      "/proc/smartscheduler/status"
#define PROC_PREDICTIONS "/proc/smartscheduler/predictions"
#define PROC_STATS       "/proc/smartscheduler/stats"

#define DEFAULT_INTERVAL_MS 1000
#define MAX_LINE_LEN 1024
#define MAX_PROCS 512
#define SPIKE_HISTORY_SIZE 10
#define LOG_DIR "logs"

/* ANSI color codes */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_DIM     "\033[2m"
#define BG_RED        "\033[41m"
#define BG_YELLOW     "\033[43m"
#define BG_GREEN      "\033[42m"

/* Alert levels */
typedef enum {
    ALERT_NONE = 0,
    ALERT_LOW = 1,
    ALERT_MEDIUM = 2,
    ALERT_HIGH = 3,
    ALERT_CRITICAL = 4
} AlertLevel;

/* Process info structure */
typedef struct {
    int pid;
    char comm[32];
    int cpu_ema;
    int mem_ema;
    int io_ema;
    int cpu_roc;
    int mem_roc;
    int io_roc;
    int flags;
    int has_cpu_spike;
    int has_mem_spike;
    int has_io_spike;
    int spike_count;           /* How many consecutive samples with spike */
    time_t first_spike_time;
    AlertLevel alert_level;
    long ram_kb;               /* RAM usage in KB */
    float cpu_percent;         /* CPU percentage */
    char cpu_ind[32];          /* CPU indicator string */
    char mem_ind[32];          /* MEM indicator string */
    char io_ind[32];           /* I/O indicator string */
} ProcessInfo;

/* Spike history for persistent tracking */
typedef struct {
    int pid;
    int spike_samples;
    time_t last_seen;
    int type;   /* 1=CPU, 2=MEM, 4=IO */
} SpikeHistory;

static ProcessInfo processes[MAX_PROCS];
static int process_count = 0;
static SpikeHistory spike_history[MAX_PROCS];
static int spike_history_count = 0;

static volatile int running = 1;
static FILE *log_file = NULL;
static int show_top_n = 20;
static int show_all = 0;
static int compact_mode = 0;
static int export_mode = 0;

/* Statistics */
static int total_cpu_spikes = 0;
static int total_mem_spikes = 0;
static int total_io_spikes = 0;
static int persistent_spike_count = 0;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

void clear_screen(void) {
    printf("\033[2J\033[H");
}

int check_module_loaded(void) {
    struct stat st;
    return stat(PROC_STATUS, &st) == 0;
}

/* Get RAM usage for a specific PID */
long get_pid_ram_kb(int pid) {
    char path[64];
    FILE *f;
    char line[256];
    long ram_kb = 0;
    
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    f = fopen(path, "r");
    if (!f) return 0;
    
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%ld", &ram_kb);
            break;
        }
    }
    fclose(f);
    return ram_kb;
}

/* Get CPU usage percentage for a PID */
float get_pid_cpu_percent(int pid) {
    char path[64];
    FILE *f;
    unsigned long utime, stime, starttime;
    long hertz = sysconf(_SC_CLK_TCK);
    
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    f = fopen(path, "r");
    if (!f) return 0.0;
    
    /* Skip to utime (field 14) and stime (field 15) */
    char buf[1024];
    if (fgets(buf, sizeof(buf), f)) {
        char *p = buf;
        int field = 0;
        while (*p && field < 13) {
            if (*p == ' ') field++;
            p++;
        }
        if (sscanf(p, "%lu %lu", &utime, &stime) == 2) {
            /* Get system uptime */
            FILE *upf = fopen("/proc/uptime", "r");
            double uptime = 0;
            if (upf) {
                if (fscanf(upf, "%lf", &uptime) != 1) uptime = 1;
                fclose(upf);
            }
            
            /* Skip to starttime (field 22) */
            field = 0;
            while (*p && field < 8) {
                if (*p == ' ') field++;
                p++;
            }
            if (sscanf(p, "%lu", &starttime) == 1) {
                double total_time = (utime + stime) / (double)hertz;
                double seconds = uptime - (starttime / (double)hertz);
                if (seconds > 0) {
                    fclose(f);
                    return (float)(100.0 * total_time / seconds);
                }
            }
        }
    }
    fclose(f);
    return 0.0;
}

/* Get system memory info */
void get_system_memory(long *total_mb, long *used_mb, long *free_mb) {
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        *total_mb = info.totalram / 1024 / 1024;
        *free_mb = info.freeram / 1024 / 1024;
        *used_mb = *total_mb - *free_mb;
    }
}

/* Get CPU count */
int get_cpu_count(void) {
    return sysconf(_SC_NPROCESSORS_ONLN);
}

/* Get load average */
void get_load_average(double *load1, double *load5, double *load15) {
    double loads[3];
    if (getloadavg(loads, 3) == 3) {
        *load1 = loads[0];
        *load5 = loads[1];
        *load15 = loads[2];
    }
}

/* Determine alert level based on ROC values */
AlertLevel calc_alert_level(int cpu_roc, int mem_roc, int io_roc) {
    int max_roc = cpu_roc > mem_roc ? cpu_roc : mem_roc;
    max_roc = max_roc > io_roc ? max_roc : io_roc;
    
    if (max_roc > 5000) return ALERT_CRITICAL;
    if (max_roc > 3000) return ALERT_HIGH;
    if (max_roc > 1500) return ALERT_MEDIUM;
    if (max_roc > 500) return ALERT_LOW;
    return ALERT_NONE;
}

/* Get alert level string */
const char* alert_level_str(AlertLevel level) {
    switch (level) {
        case ALERT_CRITICAL: return "CRITICAL";
        case ALERT_HIGH:     return "HIGH";
        case ALERT_MEDIUM:   return "MEDIUM";
        case ALERT_LOW:      return "LOW";
        default:             return "NORMAL";
    }
}

/* Get alert level color */
const char* alert_level_color(AlertLevel level) {
    switch (level) {
        case ALERT_CRITICAL: return BG_RED;
        case ALERT_HIGH:     return COLOR_RED;
        case ALERT_MEDIUM:   return COLOR_YELLOW;
        case ALERT_LOW:      return COLOR_CYAN;
        default:             return COLOR_GREEN;
    }
}

/* Draw a progress bar */
void draw_bar(int value, int max, int width, const char *color) {
    int filled = (value * width) / (max > 0 ? max : 1);
    if (filled > width) filled = width;
    if (filled < 0) filled = 0;
    
    printf("%s[", COLOR_DIM);
    for (int i = 0; i < width; i++) {
        if (i < filled) {
            printf("%s█", color);
        } else {
            printf("%s░", COLOR_DIM);
        }
    }
    printf("%s]%s", COLOR_DIM, COLOR_RESET);
}

/* Get trend indicator */
const char* get_trend(int roc) {
    if (roc > 100) return "↑";
    if (roc < -100) return "↓";
    return "→";
}

/* Get trend color */
const char* get_trend_color(int roc) {
    if (roc > 500) return COLOR_RED;
    if (roc > 100) return COLOR_YELLOW;
    if (roc < -100) return COLOR_GREEN;
    return COLOR_DIM;
}

/* Update spike history for persistent tracking */
void update_spike_history(int pid, int spike_type) {
    time_t now = time(NULL);
    
    for (int i = 0; i < spike_history_count; i++) {
        if (spike_history[i].pid == pid) {
            spike_history[i].spike_samples++;
            spike_history[i].last_seen = now;
            spike_history[i].type |= spike_type;
            return;
        }
    }
    
    /* New entry */
    if (spike_history_count < MAX_PROCS) {
        spike_history[spike_history_count].pid = pid;
        spike_history[spike_history_count].spike_samples = 1;
        spike_history[spike_history_count].last_seen = now;
        spike_history[spike_history_count].type = spike_type;
        spike_history_count++;
    }
}

/* Check if spike is persistent (>5 seconds) */
int is_persistent_spike(int pid) {
    time_t now = time(NULL);
    for (int i = 0; i < spike_history_count; i++) {
        if (spike_history[i].pid == pid) {
            if (now - spike_history[i].last_seen < 6 && 
                spike_history[i].spike_samples >= 5) {
                return spike_history[i].spike_samples;
            }
        }
    }
    return 0;
}

/* Clean old spike history entries */
void clean_spike_history(void) {
    time_t now = time(NULL);
    int write_idx = 0;
    
    for (int i = 0; i < spike_history_count; i++) {
        if (now - spike_history[i].last_seen < 30) {
            if (write_idx != i) {
                spike_history[write_idx] = spike_history[i];
            }
            write_idx++;
        }
    }
    spike_history_count = write_idx;
}

/* Print header with system info */
void print_header(void) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    long total_mb, used_mb, free_mb;
    get_system_memory(&total_mb, &used_mb, &free_mb);
    double load1, load5, load15;
    get_load_average(&load1, &load5, &load15);
    int cpus = get_cpu_count();
    
    printf("%s%s", COLOR_BOLD, COLOR_CYAN);
    printf("╔══════════════════════════════════════════════════════════════════════════╗\n");
    printf("║             SmartScheduler Enhanced Monitor v2.0                         ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════╣\n");
    printf("║  %s", COLOR_WHITE);
    printf("%-19s  ", time_str);
    printf("%sCPUs: %d  ", COLOR_CYAN, cpus);
    printf("Load: %.1f %.1f %.1f  ", load1, load5, load15);
    printf("RAM: %ld/%ldMB", used_mb, total_mb);
    printf("%s%s  ║\n", COLOR_CYAN, COLOR_BOLD);
    printf("╚══════════════════════════════════════════════════════════════════════════╝\n");
    printf("%s\n", COLOR_RESET);
}

/* Print module status */
void print_status(void) {
    FILE *f = fopen(PROC_STATUS, "r");
    if (!f) {
        printf("%sError: Cannot read status%s\n", COLOR_RED, COLOR_RESET);
        return;
    }
    
    char line[MAX_LINE_LEN];
    printf("%s╭─ Module Status ─────────────────────────────────────────────────────────╮%s\n",
           COLOR_YELLOW, COLOR_RESET);
    
    int count = 0;
    while (fgets(line, sizeof(line), f) && count < 8) {
        if (line[0] == '=' || line[0] == '\n') continue;
        
        /* Remove newline */
        line[strcspn(line, "\n")] = 0;
        
        if (strstr(line, "Tracked processes:")) {
            printf("│ %s%-74s%s│\n", COLOR_GREEN, line, COLOR_RESET);
        } else if (strstr(line, "Total predictions:")) {
            printf("│ %s%-74s%s│\n", COLOR_MAGENTA, line, COLOR_RESET);
        } else {
            printf("│ %-74s│\n", line);
        }
        count++;
    }
    fclose(f);
    printf("%s╰──────────────────────────────────────────────────────────────────────────╯%s\n\n",
           COLOR_YELLOW, COLOR_RESET);
}

/* Read and parse process stats */
void read_process_stats(void) {
    FILE *f = fopen(PROC_STATS, "r");
    if (!f) return;
    
    char line[MAX_LINE_LEN];
    process_count = 0;
    
    /* Skip header lines */
    for (int i = 0; i < 4; i++) {
        if (!fgets(line, sizeof(line), f)) break;
    }
    
    while (fgets(line, sizeof(line), f) && process_count < MAX_PROCS) {
        ProcessInfo *p = &processes[process_count];
        
        if (sscanf(line, "%d %d %d %d %d %d %d",
                   &p->pid, &p->cpu_ema, &p->mem_ema, &p->io_ema,
                   &p->cpu_roc, &p->mem_roc, &p->io_roc) >= 7) {
            
            /* Get additional info */
            p->ram_kb = get_pid_ram_kb(p->pid);
            p->cpu_percent = get_pid_cpu_percent(p->pid);
            p->alert_level = calc_alert_level(p->cpu_roc, p->mem_roc, p->io_roc);
            
            process_count++;
        }
    }
    fclose(f);
}

/* Read predictions and update process info */
void read_predictions(void) {
    FILE *f = fopen(PROC_PREDICTIONS, "r");
    if (!f) return;
    
    char line[MAX_LINE_LEN];
    total_cpu_spikes = 0;
    total_mem_spikes = 0;
    total_io_spikes = 0;
    persistent_spike_count = 0;
    
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
            
            /* Find matching process */
            for (int i = 0; i < process_count; i++) {
                if (processes[i].pid == pid) {
                    strncpy(processes[i].comm, comm, 31);
                    processes[i].flags = flags;
                    processes[i].has_cpu_spike = (cpu_flag == '*');
                    processes[i].has_mem_spike = (mem_flag == '*');
                    processes[i].has_io_spike = (io_flag == '*');
                    
                    if (processes[i].has_cpu_spike) {
                        total_cpu_spikes++;
                        update_spike_history(pid, 1);
                    }
                    if (processes[i].has_mem_spike) {
                        total_mem_spikes++;
                        update_spike_history(pid, 2);
                    }
                    if (processes[i].has_io_spike) {
                        total_io_spikes++;
                        update_spike_history(pid, 4);
                    }
                    
                    processes[i].spike_count = is_persistent_spike(pid);
                    if (processes[i].spike_count > 0) {
                        persistent_spike_count++;
                    }
                    break;
                }
            }
        }
    }
    fclose(f);
}

/* Compare function for sorting by alert level */
int compare_by_alert(const void *a, const void *b) {
    const ProcessInfo *pa = (const ProcessInfo *)a;
    const ProcessInfo *pb = (const ProcessInfo *)b;
    
    int has_spike_a = pa->has_cpu_spike || pa->has_mem_spike || pa->has_io_spike;
    int has_spike_b = pb->has_cpu_spike || pb->has_mem_spike || pb->has_io_spike;
    
    if (has_spike_a != has_spike_b) return has_spike_b - has_spike_a;
    return pb->alert_level - pa->alert_level;
}

/* Print enhanced predictions table */
void print_predictions(void) {
    printf("%s╭─ Process Monitor ───────────────────────────────────────────────────────╮%s\n",
           COLOR_YELLOW, COLOR_RESET);
    
    /* Sort by alert level */
    qsort(processes, process_count, sizeof(ProcessInfo), compare_by_alert);
    
    /* Header */
    printf("│ %s%-7s %-12s %6s %8s %-6s %-6s %-6s %7s %8s%s │\n",
           COLOR_BOLD, "PID", "NAME", "RAM", "CPU%", "CPU", "MEM", "I/O", "TREND", "ALERT", COLOR_RESET);
    printf("│ %-7s %-12s %6s %8s %-6s %-6s %-6s %7s %8s │\n",
           "───────", "────────────", "──────", "────────", "──────", "──────", "──────", "───────", "────────");
    
    int shown = 0;
    for (int i = 0; i < process_count && (show_all || shown < show_top_n); i++) {
        ProcessInfo *p = &processes[i];
        
        /* Skip if no activity and not in show_all mode */
        if (!show_all && p->alert_level == ALERT_NONE && 
            !p->has_cpu_spike && !p->has_mem_spike && !p->has_io_spike) {
            continue;
        }
        
        /* Graphical spike indicators */
        char cpu_ind[32], mem_ind[32], io_ind[32];
        if (p->has_cpu_spike) {
            if (p->spike_count > 5) 
                snprintf(cpu_ind, sizeof(cpu_ind), "%s█████%s", COLOR_RED, COLOR_RESET);
            else
                snprintf(cpu_ind, sizeof(cpu_ind), "%s███%s  ", COLOR_YELLOW, COLOR_RESET);
        } else {
            snprintf(cpu_ind, sizeof(cpu_ind), "%s─────%s", COLOR_DIM, COLOR_RESET);
        }
        
        if (p->has_mem_spike) {
            if (p->spike_count > 5)
                snprintf(mem_ind, sizeof(mem_ind), "%s█████%s", COLOR_RED, COLOR_RESET);
            else
                snprintf(mem_ind, sizeof(mem_ind), "%s███%s  ", COLOR_YELLOW, COLOR_RESET);
        } else {
            snprintf(mem_ind, sizeof(mem_ind), "%s─────%s", COLOR_DIM, COLOR_RESET);
        }
        
        if (p->has_io_spike) {
            if (p->spike_count > 5)
                snprintf(io_ind, sizeof(io_ind), "%s█████%s", COLOR_RED, COLOR_RESET);
            else
                snprintf(io_ind, sizeof(io_ind), "%s███%s  ", COLOR_YELLOW, COLOR_RESET);
        } else {
            snprintf(io_ind, sizeof(io_ind), "%s─────%s", COLOR_DIM, COLOR_RESET);
        }
        
        /* Trend indicator */
        int max_roc = p->cpu_roc;
        if (p->mem_roc > max_roc) max_roc = p->mem_roc;
        if (p->io_roc > max_roc) max_roc = p->io_roc;
        
        char ram_str[16];
        if (p->ram_kb > 1024*1024)
            snprintf(ram_str, sizeof(ram_str), "%.1fG", p->ram_kb/1024.0/1024.0);
        else if (p->ram_kb > 1024)
            snprintf(ram_str, sizeof(ram_str), "%.0fM", p->ram_kb/1024.0);
        else
            snprintf(ram_str, sizeof(ram_str), "%ldK", p->ram_kb);
        
        /* Print row */
        printf("│ %-7d %-12.12s %6s %7.1f%% %s %s %s %s%s%s %s%-8s%s │",
               p->pid, p->comm, ram_str, p->cpu_percent,
               cpu_ind, mem_ind, io_ind,
               get_trend_color(max_roc), get_trend(max_roc), COLOR_RESET,
               alert_level_color(p->alert_level), alert_level_str(p->alert_level), COLOR_RESET);
        
        /* Persistent indicator */
        if (p->spike_count > 5) {
            printf(" %s⚠%s", COLOR_RED, COLOR_RESET);
        }
        printf("\n");
        
        shown++;
    }
    
    printf("%s╰──────────────────────────────────────────────────────────────────────────╯%s\n\n",
           COLOR_YELLOW, COLOR_RESET);
}

/* Print advisory section */
void print_advisories(void) {
    printf("%s╭─ Advisory Summary ──────────────────────────────────────────────────────╮%s\n",
           COLOR_CYAN, COLOR_RESET);
    
    /* Count advisories by type */
    int cpu_critical = 0, cpu_high = 0;
    int mem_critical = 0, mem_high = 0;
    int io_critical = 0, io_high = 0;
    
    for (int i = 0; i < process_count; i++) {
        ProcessInfo *p = &processes[i];
        if (p->has_cpu_spike) {
            if (p->alert_level >= ALERT_CRITICAL) cpu_critical++;
            else if (p->alert_level >= ALERT_HIGH) cpu_high++;
        }
        if (p->has_mem_spike) {
            if (p->alert_level >= ALERT_CRITICAL) mem_critical++;
            else if (p->alert_level >= ALERT_HIGH) mem_high++;
        }
        if (p->has_io_spike) {
            if (p->alert_level >= ALERT_CRITICAL) io_critical++;
            else if (p->alert_level >= ALERT_HIGH) io_high++;
        }
    }
    
    printf("│                                                                          │\n");
    
    /* CPU Advisory */
    if (total_cpu_spikes > 0) {
        printf("│ %s🔥 CPU SPIKES: %d detected%s                                              │\n",
               COLOR_RED, total_cpu_spikes, COLOR_RESET);
        printf("│    → %sCritical: %d%s  %sHigh: %d%s                                           │\n",
               COLOR_RED, cpu_critical, COLOR_RESET, COLOR_YELLOW, cpu_high, COLOR_RESET);
        printf("│    → %sAction: Boost process priority (nice -5)%s                         │\n",
               COLOR_GREEN, COLOR_RESET);
    } else {
        printf("│ %s✓ CPU: No spikes detected%s                                             │\n",
               COLOR_GREEN, COLOR_RESET);
    }
    
    printf("│                                                                          │\n");
    
    /* Memory Advisory */
    if (total_mem_spikes > 0) {
        printf("│ %s💾 MEMORY SPIKES: %d detected%s                                           │\n",
               COLOR_YELLOW, total_mem_spikes, COLOR_RESET);
        printf("│    → %sCritical: %d%s  %sHigh: %d%s                                           │\n",
               COLOR_RED, mem_critical, COLOR_RESET, COLOR_YELLOW, mem_high, COLOR_RESET);
        printf("│    → %sAction: Monitor closely, consider cgroup limits%s                  │\n",
               COLOR_CYAN, COLOR_RESET);
    } else {
        printf("│ %s✓ MEMORY: No spikes detected%s                                          │\n",
               COLOR_GREEN, COLOR_RESET);
    }
    
    printf("│                                                                          │\n");
    
    /* I/O Advisory */
    if (total_io_spikes > 0) {
        printf("│ %s📀 I/O SPIKES: %d detected%s                                              │\n",
               COLOR_MAGENTA, total_io_spikes, COLOR_RESET);
        printf("│    → %sCritical: %d%s  %sHigh: %d%s                                           │\n",
               COLOR_RED, io_critical, COLOR_RESET, COLOR_YELLOW, io_high, COLOR_RESET);
        printf("│    → %sAction: Boost I/O priority (ionice -c2 -n0)%s                       │\n",
               COLOR_GREEN, COLOR_RESET);
    } else {
        printf("│ %s✓ I/O: No spikes detected%s                                             │\n",
               COLOR_GREEN, COLOR_RESET);
    }
    
    printf("│                                                                          │\n");
    
    /* Persistent spikes warning */
    if (persistent_spike_count > 0) {
        printf("│ %s⚠ PERSISTENT SPIKES: %d processes spiking for >5 seconds!%s              │\n",
               BG_RED, persistent_spike_count, COLOR_RESET);
        printf("│    → %sThese may indicate runaway processes%s                              │\n",
               COLOR_RED, COLOR_RESET);
    }
    
    printf("│                                                                          │\n");
    printf("%s╰──────────────────────────────────────────────────────────────────────────╯%s\n\n",
           COLOR_CYAN, COLOR_RESET);
}

/* Print statistics summary */
void print_stats_summary(void) {
    printf("%s╭─ Statistics ────────────────────────────────────────────────────────────╮%s\n",
           COLOR_MAGENTA, COLOR_RESET);
    
    long total_ram = 0;
    float total_cpu = 0;
    int active = 0;
    
    for (int i = 0; i < process_count; i++) {
        total_ram += processes[i].ram_kb;
        total_cpu += processes[i].cpu_percent;
        if (processes[i].alert_level > ALERT_NONE) active++;
    }
    
    printf("│ Tracked: %-5d  Active: %-4d  Spikes: CPU=%d MEM=%d IO=%d  Persistent: %d │\n",
           process_count, active, total_cpu_spikes, total_mem_spikes, total_io_spikes,
           persistent_spike_count);
    printf("│ Total Tracked RAM: %.1f MB  Total CPU: %.1f%%                              │\n",
           total_ram / 1024.0, total_cpu);
    printf("%s╰──────────────────────────────────────────────────────────────────────────╯%s\n\n",
           COLOR_MAGENTA, COLOR_RESET);
}

/* Print footer */
void print_footer(int interval_ms) {
    printf("%s────────────────────────────────────────────────────────────────────────────%s\n",
           COLOR_DIM, COLOR_RESET);
    printf("Refresh: %dms | Top %d shown | Press Ctrl+C to exit\n", interval_ms, show_top_n);
    printf("Legend: █████ = Spike (Red=Persistent) | ───── = Normal | ↑↓→ = Trend\n");
}

/* Export to CSV */
void export_csv(void) {
    char filename[128];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    
    snprintf(filename, sizeof(filename), "logs/export_%04d%02d%02d_%02d%02d%02d.csv",
             tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec);
    
    FILE *f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "Cannot create %s\n", filename);
        return;
    }
    
    fprintf(f, "PID,COMM,RAM_KB,CPU%%,CPU_EMA,MEM_EMA,IO_EMA,CPU_ROC,MEM_ROC,IO_ROC,ALERT,CPU_SPIKE,MEM_SPIKE,IO_SPIKE\n");
    
    for (int i = 0; i < process_count; i++) {
        ProcessInfo *p = &processes[i];
        fprintf(f, "%d,%s,%ld,%.2f,%d,%d,%d,%d,%d,%d,%s,%d,%d,%d\n",
                p->pid, p->comm, p->ram_kb, p->cpu_percent,
                p->cpu_ema, p->mem_ema, p->io_ema,
                p->cpu_roc, p->mem_roc, p->io_roc,
                alert_level_str(p->alert_level),
                p->has_cpu_spike, p->has_mem_spike, p->has_io_spike);
    }
    
    fclose(f);
    printf("Exported to %s\n", filename);
}

void usage(const char *prog) {
    printf("SmartScheduler Enhanced Monitor v2.0\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -i <ms>    Refresh interval (default: 1000)\n");
    printf("  -t <n>     Show top N processes (default: 20)\n");
    printf("  -a         Show all processes\n");
    printf("  -c         Compact mode\n");
    printf("  -e         Export to CSV and exit\n");
    printf("  -o         One-shot mode (print once and exit)\n");
    printf("  -h         Show this help\n");
}

int main(int argc, char *argv[]) {
    int interval_ms = DEFAULT_INTERVAL_MS;
    int oneshot = 0;
    int opt;
    
    while ((opt = getopt(argc, argv, "i:t:aceoh")) != -1) {
        switch (opt) {
            case 'i':
                interval_ms = atoi(optarg);
                if (interval_ms < 100) interval_ms = 100;
                if (interval_ms > 10000) interval_ms = 10000;
                break;
            case 't':
                show_top_n = atoi(optarg);
                break;
            case 'a':
                show_all = 1;
                break;
            case 'c':
                compact_mode = 1;
                break;
            case 'e':
                export_mode = 1;
                oneshot = 1;
                break;
            case 'o':
                oneshot = 1;
                break;
            case 'h':
            default:
                usage(argv[0]);
                return 0;
        }
    }
    
    if (!check_module_loaded()) {
        fprintf(stderr, "%sError: SmartScheduler kernel module not loaded!%s\n",
                COLOR_RED, COLOR_RESET);
        fprintf(stderr, "Load with: sudo insmod kernel/smartscheduler.ko\n");
        return 1;
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Create logs directory */
    mkdir("logs", 0755);
    
    while (running) {
        if (!oneshot) {
            clear_screen();
        }
        
        /* Read data */
        read_process_stats();
        read_predictions();
        clean_spike_history();
        
        if (export_mode) {
            export_csv();
            break;
        }
        
        /* Display */
        print_header();
        if (!compact_mode) {
            print_status();
        }
        print_predictions();
        print_advisories();
        if (!compact_mode) {
            print_stats_summary();
        }
        print_footer(interval_ms);
        
        if (oneshot) break;
        
        usleep(interval_ms * 1000);
    }
    
    printf("\n%sMonitor stopped.%s\n", COLOR_YELLOW, COLOR_RESET);
    return 0;
}
