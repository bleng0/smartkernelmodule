/*
 * SmartScheduler Health Check Tool
 *
 * Quick diagnostic of system health and module status
 *
 * Compile: gcc -o health_check health_check.c -Wall -O2
 * Run: ./health_check
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <time.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"

#define PROC_STATUS      "/proc/smartscheduler/status"
#define PROC_PREDICTIONS "/proc/smartscheduler/predictions"
#define PROC_STATS       "/proc/smartscheduler/stats"

typedef struct {
    char name[64];
    int status;  /* 0=FAIL, 1=OK, 2=WARN */
    char details[256];
} CheckResult;

static CheckResult checks[20];
static int check_count = 0;

void add_check(const char *name, int status, const char *details) {
    if (check_count >= 20) return;
    strncpy(checks[check_count].name, name, 63);
    checks[check_count].status = status;
    strncpy(checks[check_count].details, details, 255);
    check_count++;
}

/* Check if kernel module is loaded */
void check_module(void) {
    struct stat st;
    if (stat(PROC_STATUS, &st) == 0) {
        FILE *f = fopen(PROC_STATUS, "r");
        if (f) {
            char line[256];
            int tracked = 0, predictions = 0;
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "Tracked processes:"))
                    sscanf(line, "Tracked processes: %d", &tracked);
                if (strstr(line, "Total predictions:"))
                    sscanf(line, "Total predictions: %d", &predictions);
            }
            fclose(f);
            
            char details[256];
            snprintf(details, sizeof(details), 
                     "Tracking %d processes, %d predictions made", tracked, predictions);
            add_check("Kernel Module", 1, details);
        }
    } else {
        add_check("Kernel Module", 0, "Module not loaded - run: sudo insmod kernel/smartscheduler.ko");
    }
}

/* Check system memory */
void check_memory(void) {
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        long total_mb = info.totalram / 1024 / 1024;
        long free_mb = info.freeram / 1024 / 1024;
        int percent_used = 100 - (free_mb * 100 / total_mb);
        
        char details[256];
        snprintf(details, sizeof(details), 
                 "%ld MB free of %ld MB (%d%% used)", free_mb, total_mb, percent_used);
        
        if (percent_used > 90) {
            add_check("System Memory", 0, details);
        } else if (percent_used > 75) {
            add_check("System Memory", 2, details);
        } else {
            add_check("System Memory", 1, details);
        }
    }
}

/* Check CPU load */
void check_cpu(void) {
    double loads[3];
    int cpus = sysconf(_SC_NPROCESSORS_ONLN);
    
    if (getloadavg(loads, 3) == 3) {
        char details[256];
        snprintf(details, sizeof(details), 
                 "Load: %.2f %.2f %.2f (%d CPUs)", 
                 loads[0], loads[1], loads[2], cpus);
        
        if (loads[0] > cpus * 2) {
            add_check("CPU Load", 0, details);
        } else if (loads[0] > cpus) {
            add_check("CPU Load", 2, details);
        } else {
            add_check("CPU Load", 1, details);
        }
    }
}

/* Spike process info */
typedef struct {
    int pid;
    char comm[32];
    int cpu_spike;
    int mem_spike;
    int io_spike;
} SpikeProc;

static SpikeProc spike_procs[50];
static int spike_proc_count = 0;

/* Check for active spikes */
void check_spikes(void) {
    FILE *f = fopen(PROC_PREDICTIONS, "r");
    if (!f) {
        add_check("Active Spikes", 2, "Cannot read predictions");
        return;
    }
    
    char line[256];
    int cpu_spikes = 0, mem_spikes = 0, io_spikes = 0;
    spike_proc_count = 0;
    
    /* Skip header lines */
    for (int i = 0; i < 4 && fgets(line, sizeof(line), f); i++);
    
    while (fgets(line, sizeof(line), f) && spike_proc_count < 50) {
        int pid;
        char comm[32];
        char cpu_flag, mem_flag, io_flag;
        int flags;
        
        if (sscanf(line, "%d %31s %c %c %c %x",
                   &pid, comm, &cpu_flag, &mem_flag, &io_flag, &flags) >= 5) {
            
            int has_spike = 0;
            SpikeProc *sp = &spike_procs[spike_proc_count];
            sp->pid = pid;
            strncpy(sp->comm, comm, 31);
            sp->cpu_spike = 0;
            sp->mem_spike = 0;
            sp->io_spike = 0;
            
            if (cpu_flag == '*') {
                cpu_spikes++;
                sp->cpu_spike = 1;
                has_spike = 1;
            }
            if (mem_flag == '*') {
                mem_spikes++;
                sp->mem_spike = 1;
                has_spike = 1;
            }
            if (io_flag == '*') {
                io_spikes++;
                sp->io_spike = 1;
                has_spike = 1;
            }
            
            if (has_spike) {
                spike_proc_count++;
            }
        }
    }
    fclose(f);
    
    int total = cpu_spikes + mem_spikes + io_spikes;
    char details[256];
    snprintf(details, sizeof(details), 
             "%d total: %d CPU, %d MEM, %d I/O across %d processes",
             total, cpu_spikes, mem_spikes, io_spikes, spike_proc_count);
    
    if (total > 10) {
        add_check("Active Spikes", 0, details);
    } else if (total > 3) {
        add_check("Active Spikes", 2, details);
    } else {
        add_check("Active Spikes", 1, details);
    }
}

/* Print spiking processes */
void print_spiking_processes(void) {
    if (spike_proc_count == 0) return;
    
    printf("\n%s%s┌─ 📊 SPIKING PROCESSES (%d) ─────────────────────────────────────────┐%s\n",
           COLOR_BOLD, COLOR_YELLOW, spike_proc_count, COLOR_RESET);
    printf("%s│ %-8s %-20s %-6s %-6s %-6s                       │%s\n",
           COLOR_YELLOW, "PID", "PROCESS", "CPU", "MEM", "I/O", COLOR_RESET);
    printf("%s│ %-8s %-20s %-6s %-6s %-6s                       │%s\n",
           COLOR_YELLOW, "────────", "────────────────────", "──────", "──────", "──────", COLOR_RESET);
    
    for (int i = 0; i < spike_proc_count && i < 10; i++) {
        SpikeProc *sp = &spike_procs[i];
        printf("%s│ %-8d %-20.20s %s%-6s%s %s%-6s%s %s%-6s%s                       │%s\n",
               COLOR_YELLOW,
               sp->pid, sp->comm,
               sp->cpu_spike ? COLOR_RED : COLOR_GREEN,
               sp->cpu_spike ? "SPIKE" : "OK",
               COLOR_YELLOW,
               sp->mem_spike ? COLOR_RED : COLOR_GREEN,
               sp->mem_spike ? "SPIKE" : "OK",
               COLOR_YELLOW,
               sp->io_spike ? COLOR_RED : COLOR_GREEN,
               sp->io_spike ? "SPIKE" : "OK",
               COLOR_YELLOW,
               COLOR_RESET);
    }
    
    if (spike_proc_count > 10) {
        printf("%s│ ... and %d more processes                                          │%s\n",
               COLOR_YELLOW, spike_proc_count - 10, COLOR_RESET);
    }
    
    printf("%s└──────────────────────────────────────────────────────────────────────┘%s\n",
           COLOR_YELLOW, COLOR_RESET);
}

/* Check disk space */
void check_disk(void) {
    FILE *f = popen("df -h / | tail -1 | awk '{print $5}'", "r");
    if (f) {
        char buf[32];
        if (fgets(buf, sizeof(buf), f)) {
            int percent = atoi(buf);
            char details[256];
            snprintf(details, sizeof(details), "Root filesystem %d%% used", percent);
            
            if (percent > 95) {
                add_check("Disk Space", 0, details);
            } else if (percent > 80) {
                add_check("Disk Space", 2, details);
            } else {
                add_check("Disk Space", 1, details);
            }
        }
        pclose(f);
    }
}

/* Check logs directory */
void check_logs(void) {
    struct stat st;
    if (stat("logs", &st) == 0 && S_ISDIR(st.st_mode)) {
        add_check("Logs Directory", 1, "logs/ directory exists");
    } else {
        add_check("Logs Directory", 2, "logs/ directory missing - will be created on first run");
    }
}

/* Check user tools */
void check_tools(void) {
    struct stat st;
    int tools_ok = 0;
    
    if (stat("user/monitor", &st) == 0) tools_ok++;
    if (stat("user/stress_test", &st) == 0) tools_ok++;
    if (stat("user/scheduler_daemon", &st) == 0) tools_ok++;
    if (stat("user/data_exporter", &st) == 0) tools_ok++;
    
    char details[256];
    snprintf(details, sizeof(details), "%d/4 tools compiled", tools_ok);
    
    if (tools_ok == 4) {
        add_check("User Tools", 1, details);
    } else if (tools_ok > 0) {
        add_check("User Tools", 2, details);
    } else {
        add_check("User Tools", 0, "Run: make -C user");
    }
}

/* Check kernel module file */
void check_ko_file(void) {
    struct stat st;
    if (stat("kernel/smartscheduler.ko", &st) == 0) {
        char details[256];
        snprintf(details, sizeof(details), "Size: %ld bytes", st.st_size);
        add_check("Kernel Module File", 1, details);
    } else {
        add_check("Kernel Module File", 0, "Run: make -C kernel");
    }
}

/* Print results */
void print_results(void) {
    time_t now = time(NULL);
    
    printf("\n%s%s╔══════════════════════════════════════════════════════════════════╗%s\n",
           COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("%s%s║          SmartScheduler Health Check                             ║%s\n",
           COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("%s%s║          %s                                      ║%s\n",
           COLOR_BOLD, COLOR_CYAN, ctime(&now), COLOR_RESET);
    printf("%s%s╚══════════════════════════════════════════════════════════════════╝%s\n\n",
           COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    
    int ok = 0, warn = 0, fail = 0;
    
    /* First pass: count and display all checks */
    printf("%s┌─ All Checks ─────────────────────────────────────────────────────────┐%s\n",
           COLOR_CYAN, COLOR_RESET);
    
    for (int i = 0; i < check_count; i++) {
        const char *icon, *color;
        
        switch (checks[i].status) {
            case 1:
                icon = "✓"; color = COLOR_GREEN; ok++;
                break;
            case 2:
                icon = "⚠"; color = COLOR_YELLOW; warn++;
                break;
            default:
                icon = "✗"; color = COLOR_RED; fail++;
                break;
        }
        
        printf("│ %s%s%s %-20s %s%-45s%s │\n",
               color, icon, COLOR_RESET,
               checks[i].name,
               COLOR_CYAN, checks[i].details, COLOR_RESET);
    }
    printf("%s└──────────────────────────────────────────────────────────────────────┘%s\n",
           COLOR_CYAN, COLOR_RESET);
    
    /* Display WARNINGS section if any */
    if (warn > 0) {
        printf("\n%s%s┌─ ⚠ WARNINGS (%d) ──────────────────────────────────────────────────┐%s\n",
               COLOR_BOLD, COLOR_YELLOW, warn, COLOR_RESET);
        
        for (int i = 0; i < check_count; i++) {
            if (checks[i].status == 2) {
                printf("%s│ %-18s: %-50s│%s\n",
                       COLOR_YELLOW, checks[i].name, checks[i].details, COLOR_RESET);
            }
        }
        printf("%s└──────────────────────────────────────────────────────────────────────┘%s\n",
               COLOR_YELLOW, COLOR_RESET);
    }
    
    /* Display FAILURES section if any */
    if (fail > 0) {
        printf("\n%s%s┌─ ✗ FAILURES (%d) ──────────────────────────────────────────────────┐%s\n",
               COLOR_BOLD, COLOR_RED, fail, COLOR_RESET);
        
        for (int i = 0; i < check_count; i++) {
            if (checks[i].status == 0) {
                printf("%s│ %-18s: %-50s│%s\n",
                       COLOR_RED, checks[i].name, checks[i].details, COLOR_RESET);
            }
        }
        printf("%s└──────────────────────────────────────────────────────────────────────┘%s\n",
               COLOR_RED, COLOR_RESET);
        
        /* Show how to fix */
        printf("\n%s%s  HOW TO FIX:%s\n", COLOR_BOLD, COLOR_RED, COLOR_RESET);
        for (int i = 0; i < check_count; i++) {
            if (checks[i].status == 0) {
                printf("  %s→%s %s: %s\n", 
                       COLOR_RED, COLOR_RESET,
                       checks[i].name, checks[i].details);
            }
        }
    }
    
    /* Summary */
    printf("\n%s════════════════════════════════════════════════════════════════════════%s\n",
           COLOR_CYAN, COLOR_RESET);
    printf("  Summary: %s%s%d OK%s  %s%s%d WARNINGS%s  %s%s%d FAILED%s\n",
           COLOR_BOLD, COLOR_GREEN, ok, COLOR_RESET,
           COLOR_BOLD, COLOR_YELLOW, warn, COLOR_RESET,
           COLOR_BOLD, COLOR_RED, fail, COLOR_RESET);
    printf("%s════════════════════════════════════════════════════════════════════════%s\n",
           COLOR_CYAN, COLOR_RESET);
    
    if (fail > 0) {
        printf("\n  %s%s⛔ ACTION REQUIRED: Fix %d failed item(s) before running!%s\n", 
               COLOR_BOLD, COLOR_RED, fail, COLOR_RESET);
    } else if (warn > 0) {
        printf("\n  %s%s⚠ System functional but has %d warning(s)%s\n",
               COLOR_BOLD, COLOR_YELLOW, warn, COLOR_RESET);
    } else {
        printf("\n  %s%s✓ All systems operational! Ready to run.%s\n",
               COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    }
    printf("\n");
}

int main(void) {
    check_ko_file();
    check_module();
    check_tools();
    check_logs();
    check_memory();
    check_cpu();
    check_disk();
    check_spikes();
    
    print_results();
    print_spiking_processes();  /* Show which processes are spiking */
    
    return 0;
}
