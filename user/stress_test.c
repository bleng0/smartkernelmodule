/*
 * SmartScheduler Stress Test Generator
 *
 * Generates controlled workloads to test prediction accuracy:
 * - CPU spikes (computation bursts)
 * - Memory spikes (allocation bursts)
 * - I/O spikes (file operations)
 *
 * Compile: gcc -o stress_test stress_test.c -lpthread -Wall
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

#define KB (1024)
#define MB (1024 * KB)

static volatile int running = 1;
static int verbose = 1;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

/* Get current timestamp in milliseconds */
long get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/*
 * CPU Stress: Perform heavy computation
 */
void cpu_burst(int duration_ms, int intensity) {
    long start = get_time_ms();
    volatile double result = 0;
    
    if (verbose) {
        printf("[CPU] Starting burst: %dms @ intensity %d\n", duration_ms, intensity);
    }
    
    while (get_time_ms() - start < duration_ms && running) {
        /* Heavy computation */
        for (int i = 0; i < intensity * 10000; i++) {
            result += sin(i) * cos(i);
            result = sqrt(result * result + 1.0);
        }
    }
    
    if (verbose) {
        printf("[CPU] Burst complete (result=%f)\n", result);
    }
}

/*
 * Memory Stress: Allocate and touch memory
 */
void memory_burst(size_t size_mb, int duration_ms) {
    size_t size = size_mb * MB;
    char *mem = malloc(size);
    
    if (!mem) {
        fprintf(stderr, "[MEM] Allocation failed: %zu MB\n", size_mb);
        return;
    }
    
    if (verbose) {
        printf("[MEM] Starting burst: %zu MB for %dms\n", size_mb, duration_ms);
    }
    
    long start = get_time_ms();
    
    /* Touch all pages to ensure allocation */
    while (get_time_ms() - start < duration_ms && running) {
        for (size_t i = 0; i < size && running; i += 4096) {
            mem[i] = (char)(i & 0xFF);
        }
    }
    
    free(mem);
    
    if (verbose) {
        printf("[MEM] Burst complete\n");
    }
}

/*
 * I/O Stress: Perform file read/write operations
 */
void io_burst(size_t size_mb, int duration_ms) {
    char filename[] = "/tmp/smartsched_io_test_XXXXXX";
    int fd = mkstemp(filename);
    
    if (fd < 0) {
        fprintf(stderr, "[I/O] Cannot create temp file\n");
        return;
    }
    
    close(fd);
    FILE *f = fopen(filename, "w+");
    if (!f) {
        unlink(filename);
        return;
    }
    
    if (verbose) {
        printf("[I/O] Starting burst: %zu MB for %dms\n", size_mb, duration_ms);
    }
    
    size_t block_size = 64 * KB;
    char *buffer = malloc(block_size);
    if (!buffer) {
        fclose(f);
        unlink(filename);
        return;
    }
    
    memset(buffer, 'X', block_size);
    
    long start = get_time_ms();
    size_t total_written = 0;
    size_t total_read = 0;
    
    while (get_time_ms() - start < duration_ms && running) {
        /* Write burst */
        for (size_t i = 0; i < size_mb * MB / block_size && running; i++) {
            if (fwrite(buffer, 1, block_size, f) != block_size) break;
            total_written += block_size;
        }
        fflush(f);
        
        /* Read burst */
        rewind(f);
        while (fread(buffer, 1, block_size, f) == block_size && running) {
            total_read += block_size;
        }
        
        /* Reset for next iteration */
        rewind(f);
        ftruncate(fileno(f), 0);
    }
    
    free(buffer);
    fclose(f);
    unlink(filename);
    
    if (verbose) {
        printf("[I/O] Burst complete: wrote %zu MB, read %zu MB\n",
               total_written / MB, total_read / MB);
    }
}

/*
 * Pattern: Gradual ramp-up
 * CPU usage increases linearly over time
 */
void pattern_rampup(int total_duration_s, int steps) {
    printf("\n=== Pattern: Gradual Ramp-Up ===\n");
    printf("Duration: %ds in %d steps\n\n", total_duration_s, steps);
    
    int step_duration_ms = (total_duration_s * 1000) / steps;
    
    for (int i = 1; i <= steps && running; i++) {
        int intensity = i * 10;
        printf("Step %d/%d: intensity %d\n", i, steps, intensity);
        cpu_burst(step_duration_ms, intensity);
        
        /* Brief pause between steps */
        usleep(100000);
    }
}

/*
 * Pattern: Spike burst
 * Sudden spike after idle period
 */
void pattern_spike(int idle_s, int spike_duration_ms) {
    printf("\n=== Pattern: Spike Burst ===\n");
    printf("Idle: %ds, Spike: %dms\n\n", idle_s, spike_duration_ms);
    
    printf("Idle period...\n");
    sleep(idle_s);
    
    printf("SPIKE!\n");
    cpu_burst(spike_duration_ms, 100);
    memory_burst(256, spike_duration_ms);
}

/*
 * Pattern: Mixed workload
 * Alternating CPU, memory, and I/O bursts
 */
void pattern_mixed(int iterations, int burst_duration_ms) {
    printf("\n=== Pattern: Mixed Workload ===\n");
    printf("Iterations: %d, Burst duration: %dms\n\n", iterations, burst_duration_ms);
    
    for (int i = 0; i < iterations && running; i++) {
        printf("\n--- Iteration %d ---\n", i + 1);
        
        cpu_burst(burst_duration_ms, 50);
        usleep(200000);
        
        memory_burst(128, burst_duration_ms);
        usleep(200000);
        
        io_burst(64, burst_duration_ms);
        usleep(500000);
    }
}

void usage(const char *prog) {
    printf("SmartScheduler Stress Test Generator\n\n");
    printf("Usage: %s <pattern> [options]\n\n", prog);
    printf("Patterns:\n");
    printf("  cpu <duration_ms> <intensity>  - CPU burst\n");
    printf("  mem <size_mb> <duration_ms>    - Memory burst\n");
    printf("  io <size_mb> <duration_ms>     - I/O burst\n");
    printf("  rampup <duration_s> <steps>    - Gradual CPU ramp-up\n");
    printf("  spike <idle_s> <burst_ms>      - Spike after idle\n");
    printf("  mixed <iterations> <burst_ms>  - Mixed workload\n");
    printf("  auto                           - Run all patterns\n");
    printf("\nOptions:\n");
    printf("  -q    Quiet mode\n");
    printf("\nExamples:\n");
    printf("  %s cpu 2000 80        # 2s CPU burst at intensity 80\n", prog);
    printf("  %s mem 256 1000       # 256MB memory burst for 1s\n", prog);
    printf("  %s spike 5 500        # 5s idle then 500ms spike\n", prog);
    printf("  %s auto               # Run all test patterns\n", prog);
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    
    /* Check for quiet flag */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-q") == 0) {
            verbose = 0;
        }
    }
    
    char *pattern = argv[1];
    
    printf("SmartScheduler Stress Test\n");
    printf("PID: %d\n", getpid());
    printf("Press Ctrl+C to stop\n\n");
    
    if (strcmp(pattern, "cpu") == 0 && argc >= 4) {
        cpu_burst(atoi(argv[2]), atoi(argv[3]));
    }
    else if (strcmp(pattern, "mem") == 0 && argc >= 4) {
        memory_burst(atoi(argv[2]), atoi(argv[3]));
    }
    else if (strcmp(pattern, "io") == 0 && argc >= 4) {
        io_burst(atoi(argv[2]), atoi(argv[3]));
    }
    else if (strcmp(pattern, "rampup") == 0 && argc >= 4) {
        pattern_rampup(atoi(argv[2]), atoi(argv[3]));
    }
    else if (strcmp(pattern, "spike") == 0 && argc >= 4) {
        pattern_spike(atoi(argv[2]), atoi(argv[3]));
    }
    else if (strcmp(pattern, "mixed") == 0 && argc >= 4) {
        pattern_mixed(atoi(argv[2]), atoi(argv[3]));
    }
    else if (strcmp(pattern, "auto") == 0) {
        printf("Running automatic test sequence...\n");
        pattern_rampup(10, 5);
        pattern_spike(3, 1000);
        pattern_mixed(3, 500);
    }
    else {
        usage(argv[0]);
        return 1;
    }
    
    printf("\nStress test complete.\n");
    return 0;
}
