/*
 * SmartScheduler Data Exporter
 *
 * Exports prediction data to CSV format for analysis and graphing
 * Can be used with gnuplot, Python matplotlib, or Excel
 *
 * Compile: gcc -o data_exporter data_exporter.c -Wall
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>

#define PROC_STATS "/proc/smartscheduler/stats"
#define LOG_DIR "../logs"
#define MAX_LINE 1024

static volatile int running = 1;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

/* Get filename with timestamp */
void get_output_filename(char *buf, size_t len, const char *prefix) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    snprintf(buf, len, "%s/%s_%04d%02d%02d_%02d%02d%02d.csv",
             LOG_DIR, prefix,
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
}

/* Export single snapshot */
int export_snapshot(FILE *out, int sample_num) {
    FILE *f = fopen(PROC_STATS, "r");
    if (!f) return -1;
    
    char line[MAX_LINE];
    int count = 0;
    
    /* Skip header lines */
    fgets(line, sizeof(line), f);
    fgets(line, sizeof(line), f);
    fgets(line, sizeof(line), f);
    
    while (fgets(line, sizeof(line), f)) {
        int pid, cpu, mem, io, cpu_roc, mem_roc, io_roc;
        unsigned long samples;
        
        if (sscanf(line, "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%lu",
                   &pid, &cpu, &mem, &io, &cpu_roc, &mem_roc, &io_roc, &samples) == 8) {
            fprintf(out, "%d,%d,%d,%d,%d,%d,%d,%d,%lu\n",
                    sample_num, pid, cpu, mem, io, cpu_roc, mem_roc, io_roc, samples);
            count++;
        }
    }
    
    fclose(f);
    return count;
}

/* Continuous export mode */
void continuous_export(int interval_ms, int max_samples) {
    char filename[256];
    get_output_filename(filename, sizeof(filename), "smartsched_continuous");
    
    printf("Exporting to: %s\n", filename);
    printf("Interval: %dms, Max samples: %d\n", interval_ms, 
           max_samples > 0 ? max_samples : -1);
    printf("Press Ctrl+C to stop\n\n");
    
    FILE *out = fopen(filename, "w");
    if (!out) {
        fprintf(stderr, "Error: Cannot create output file\n");
        return;
    }
    
    /* Write CSV header */
    fprintf(out, "sample,pid,cpu_ema,mem_ema,io_ema,cpu_roc,mem_roc,io_roc,total_samples\n");
    
    int sample = 0;
    while (running) {
        int count = export_snapshot(out, sample);
        if (count < 0) {
            fprintf(stderr, "Error reading proc file\n");
            break;
        }
        
        printf("\rSample %d: %d processes exported", sample, count);
        fflush(stdout);
        fflush(out);
        
        sample++;
        if (max_samples > 0 && sample >= max_samples) break;
        
        usleep(interval_ms * 1000);
    }
    
    fclose(out);
    printf("\n\nExport complete: %d samples to %s\n", sample, filename);
}

/* Export single snapshot */
void single_export(void) {
    char filename[256];
    get_output_filename(filename, sizeof(filename), "smartsched_snapshot");
    
    FILE *out = fopen(filename, "w");
    if (!out) {
        fprintf(stderr, "Error: Cannot create output file\n");
        return;
    }
    
    fprintf(out, "sample,pid,cpu_ema,mem_ema,io_ema,cpu_roc,mem_roc,io_roc,total_samples\n");
    
    int count = export_snapshot(out, 0);
    fclose(out);
    
    printf("Exported %d processes to %s\n", count, filename);
}

/* Generate gnuplot script */
void generate_gnuplot_script(const char *csv_file) {
    char script_file[256];
    snprintf(script_file, sizeof(script_file), "%s/plot.gp", LOG_DIR);
    
    FILE *f = fopen(script_file, "w");
    if (!f) return;
    
    fprintf(f, "# SmartScheduler Gnuplot Script\n");
    fprintf(f, "# Run with: gnuplot -p plot.gp\n\n");
    
    fprintf(f, "set datafile separator ','\n");
    fprintf(f, "set xlabel 'Sample'\n");
    fprintf(f, "set ylabel 'EMA Value'\n");
    fprintf(f, "set title 'SmartScheduler Process Metrics Over Time'\n");
    fprintf(f, "set grid\n");
    fprintf(f, "set key outside right\n\n");
    
    fprintf(f, "# Plot CPU, Memory, and I/O EMA\n");
    fprintf(f, "plot '%s' using 1:3 with lines title 'CPU EMA', \\\n", csv_file);
    fprintf(f, "     '%s' using 1:4 with lines title 'MEM EMA', \\\n", csv_file);
    fprintf(f, "     '%s' using 1:5 with lines title 'I/O EMA'\n\n", csv_file);
    
    fprintf(f, "# Uncomment for rate-of-change plot:\n");
    fprintf(f, "# plot '%s' using 1:6 with lines title 'CPU RoC', \\\n", csv_file);
    fprintf(f, "#      '%s' using 1:7 with lines title 'MEM RoC', \\\n", csv_file);
    fprintf(f, "#      '%s' using 1:8 with lines title 'I/O RoC'\n", csv_file);
    
    fclose(f);
    printf("Generated gnuplot script: %s\n", script_file);
}

void usage(const char *prog) {
    printf("SmartScheduler Data Exporter\n\n");
    printf("Usage: %s [mode] [options]\n\n", prog);
    printf("Modes:\n");
    printf("  snapshot               - Export single snapshot (default)\n");
    printf("  continuous <ms> [max]  - Continuous export\n");
    printf("  gnuplot <csv_file>     - Generate gnuplot script\n");
    printf("\nExamples:\n");
    printf("  %s                     # Single snapshot\n", prog);
    printf("  %s continuous 500      # Record every 500ms\n", prog);
    printf("  %s continuous 100 60   # 60 samples at 100ms\n", prog);
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    
    /* Ensure log directory exists */
    struct stat st;
    if (stat(LOG_DIR, &st) == -1) {
        mkdir(LOG_DIR, 0755);
    }
    
    if (argc < 2) {
        single_export();
        return 0;
    }
    
    if (strcmp(argv[1], "snapshot") == 0) {
        single_export();
    }
    else if (strcmp(argv[1], "continuous") == 0 && argc >= 3) {
        int interval = atoi(argv[2]);
        int max = argc >= 4 ? atoi(argv[3]) : 0;
        continuous_export(interval, max);
    }
    else if (strcmp(argv[1], "gnuplot") == 0 && argc >= 3) {
        generate_gnuplot_script(argv[2]);
    }
    else {
        usage(argv[0]);
        return 1;
    }
    
    return 0;
}
