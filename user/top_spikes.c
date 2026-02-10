/*
 * SmartScheduler Top Spikes Tool
 *
 * Shows top N processes by spike severity
 *
 * Compile: gcc -o top_spikes top_spikes.c -Wall -O2
 * Run: ./top_spikes [-n COUNT] [-c] [-m] [-i]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"

#define PROC_STATS "/proc/smartscheduler/stats"
#define MAX_PROCS 512

typedef struct {
    int pid;
    int cpu_ema;
    int mem_ema;
    int io_ema;
    int cpu_roc;
    int mem_roc;
    int io_roc;
    int score;
} Process;

static Process procs[MAX_PROCS];
static int proc_count = 0;

int compare_by_score(const void *a, const void *b) {
    return ((Process*)b)->score - ((Process*)a)->score;
}

int compare_by_cpu(const void *a, const void *b) {
    return ((Process*)b)->cpu_roc - ((Process*)a)->cpu_roc;
}

int compare_by_mem(const void *a, const void *b) {
    return ((Process*)b)->mem_roc - ((Process*)a)->mem_roc;
}

int compare_by_io(const void *a, const void *b) {
    return ((Process*)b)->io_roc - ((Process*)a)->io_roc;
}

void read_stats(void) {
    FILE *f = fopen(PROC_STATS, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open %s\n", PROC_STATS);
        fprintf(stderr, "Is the module loaded?\n");
        exit(1);
    }
    
    char line[256];
    
    /* Skip headers */
    for (int i = 0; i < 4 && fgets(line, sizeof(line), f); i++);
    
    while (fgets(line, sizeof(line), f) && proc_count < MAX_PROCS) {
        Process *p = &procs[proc_count];
        if (sscanf(line, "%d %d %d %d %d %d %d",
                   &p->pid, &p->cpu_ema, &p->mem_ema, &p->io_ema,
                   &p->cpu_roc, &p->mem_roc, &p->io_roc) >= 7) {
            /* Calculate overall score */
            p->score = abs(p->cpu_roc) + abs(p->mem_roc) + abs(p->io_roc);
            proc_count++;
        }
    }
    fclose(f);
}

void print_results(int top_n, const char *title) {
    printf("\n%s%s=== %s ===%s\n\n", COLOR_BOLD, COLOR_CYAN, title, COLOR_RESET);
    printf("%s%7s %10s %10s %10s %10s %10s %10s %8s%s\n",
           COLOR_BOLD,
           "PID", "CPU_EMA", "MEM_EMA", "IO_EMA", "CPU_ROC", "MEM_ROC", "IO_ROC", "SCORE",
           COLOR_RESET);
    printf("%s%7s %10s %10s %10s %10s %10s %10s %8s%s\n",
           COLOR_CYAN,
           "-------", "----------", "----------", "----------",
           "----------", "----------", "----------", "--------",
           COLOR_RESET);
    
    for (int i = 0; i < top_n && i < proc_count; i++) {
        Process *p = &procs[i];
        
        const char *color = COLOR_GREEN;
        if (p->score > 5000) color = COLOR_RED;
        else if (p->score > 2000) color = COLOR_YELLOW;
        
        printf("%s%7d %10d %10d %10d %+10d %+10d %+10d %8d%s\n",
               color,
               p->pid, p->cpu_ema, p->mem_ema, p->io_ema,
               p->cpu_roc, p->mem_roc, p->io_roc, p->score,
               COLOR_RESET);
    }
    printf("\n");
}

void usage(const char *prog) {
    printf("SmartScheduler Top Spikes Tool\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -n <N>    Show top N processes (default: 10)\n");
    printf("  -c        Sort by CPU rate-of-change\n");
    printf("  -m        Sort by Memory rate-of-change\n");
    printf("  -i        Sort by I/O rate-of-change\n");
    printf("  -s        Sort by total score (default)\n");
    printf("  -h        Show this help\n");
}

int main(int argc, char *argv[]) {
    int top_n = 10;
    int sort_mode = 0;  /* 0=score, 1=cpu, 2=mem, 3=io */
    int opt;
    
    while ((opt = getopt(argc, argv, "n:cmish")) != -1) {
        switch (opt) {
            case 'n':
                top_n = atoi(optarg);
                if (top_n < 1) top_n = 1;
                if (top_n > 100) top_n = 100;
                break;
            case 'c': sort_mode = 1; break;
            case 'm': sort_mode = 2; break;
            case 'i': sort_mode = 3; break;
            case 's': sort_mode = 0; break;
            case 'h':
            default:
                usage(argv[0]);
                return 0;
        }
    }
    
    read_stats();
    
    char title[64];
    switch (sort_mode) {
        case 1:
            qsort(procs, proc_count, sizeof(Process), compare_by_cpu);
            snprintf(title, sizeof(title), "Top %d by CPU ROC", top_n);
            break;
        case 2:
            qsort(procs, proc_count, sizeof(Process), compare_by_mem);
            snprintf(title, sizeof(title), "Top %d by Memory ROC", top_n);
            break;
        case 3:
            qsort(procs, proc_count, sizeof(Process), compare_by_io);
            snprintf(title, sizeof(title), "Top %d by I/O ROC", top_n);
            break;
        default:
            qsort(procs, proc_count, sizeof(Process), compare_by_score);
            snprintf(title, sizeof(title), "Top %d by Total Score", top_n);
            break;
    }
    
    print_results(top_n, title);
    
    return 0;
}
