#!/bin/bash
#
# SmartScheduler Test Script
# Runs comprehensive tests and generates results
#
# Usage: sudo ./test.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_DIR/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "========================================"
echo "  SmartScheduler Test Suite"
echo "========================================"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Tests require root privileges"
    echo "Run: sudo ./test.sh"
    exit 1
fi

# Create logs directory
mkdir -p "$LOG_DIR"

# Check if module is loaded
if ! lsmod | grep -q smartscheduler; then
    echo "Loading SmartScheduler module..."
    insmod "$PROJECT_DIR/kernel/smartscheduler.ko"
    sleep 1
fi

echo "Module status:"
cat /proc/smartscheduler/status
echo

# Test function
run_test() {
    local name=$1
    local description=$2
    local command=$3
    local duration=$4
    
    echo "----------------------------------------"
    echo "TEST: $name"
    echo "DESC: $description"
    echo "----------------------------------------"
    
    # Start data exporter in background
    "$PROJECT_DIR/user/data_exporter" continuous 100 $((duration * 10)) &
    EXPORTER_PID=$!
    sleep 1
    
    # Run the test command
    echo "Running: $command"
    eval "$command" &
    TEST_PID=$!
    
    # Wait and monitor
    sleep "$duration"
    
    # Stop processes
    kill $TEST_PID 2>/dev/null || true
    kill $EXPORTER_PID 2>/dev/null || true
    wait 2>/dev/null || true
    
    # Show predictions
    echo
    echo "Predictions during test:"
    cat /proc/smartscheduler/predictions | grep '\*' || echo "(none)"
    echo
}

# Test 1: CPU Stress
echo
echo "========== TEST 1: CPU STRESS =========="
run_test "CPU_STRESS" \
    "Heavy CPU computation to trigger CPU spike prediction" \
    "$PROJECT_DIR/user/stress_test cpu 3000 100" \
    5

# Test 2: Memory Stress  
echo
echo "========== TEST 2: MEMORY STRESS =========="
run_test "MEM_STRESS" \
    "Large memory allocation to trigger memory spike prediction" \
    "$PROJECT_DIR/user/stress_test mem 256 3000" \
    5

# Test 3: I/O Stress
echo
echo "========== TEST 3: I/O STRESS =========="
run_test "IO_STRESS" \
    "Heavy disk I/O to trigger I/O spike prediction" \
    "$PROJECT_DIR/user/stress_test io 128 3000" \
    5

# Test 4: Mixed Workload
echo
echo "========== TEST 4: MIXED WORKLOAD =========="
run_test "MIXED" \
    "Alternating CPU, memory, and I/O bursts" \
    "$PROJECT_DIR/user/stress_test mixed 2 1000" \
    10

# Final summary
echo
echo "========================================"
echo "  Test Summary"
echo "========================================"
echo

cat /proc/smartscheduler/status

echo
echo "Test logs saved to: $LOG_DIR"
ls -la "$LOG_DIR"/*.csv 2>/dev/null | tail -5 || true

echo
echo "To generate graphs, run:"
echo "  cd $LOG_DIR && gnuplot plot.gp"
echo
