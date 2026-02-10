#!/bin/bash
#
# SmartScheduler Build All Script
# Builds kernel module, eBPF programs, and user tools
#
# Usage: ./build.sh [clean]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "========================================"
echo "  SmartScheduler Build System"
echo "========================================"
echo

cd "$PROJECT_DIR"

# Clean mode
if [ "$1" == "clean" ]; then
    echo "Cleaning all build artifacts..."
    make -C kernel clean 2>/dev/null || true
    make -C ebpf clean 2>/dev/null || true
    make -C user clean 2>/dev/null || true
    echo "Clean complete."
    exit 0
fi

# Build kernel module
echo "[1/3] Building kernel module..."
cd kernel
if make; then
    echo "  ✓ Kernel module built: smartscheduler.ko"
    
    # Sign the module if keys exist
    if [ -f "../keys/MOK.priv" ] && [ -f "../keys/MOK.der" ]; then
        echo "  - Signing module..."
        /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 \
            ../keys/MOK.priv \
            ../keys/MOK.der \
            smartscheduler.ko
        echo "    ✓ Module signed"
    fi
else
    echo "  ✗ Kernel module build failed"
    exit 1
fi
cd ..

# Build eBPF programs
echo
echo "[2/3] Building eBPF programs..."
cd ebpf
if make 2>/dev/null; then
    echo "  ✓ eBPF programs built"
else
    echo "  ! eBPF build skipped (may need BTF/headers)"
fi
cd ..

# Build user tools
echo
echo "[3/3] Building user-space tools..."
cd user
if make; then
    echo "  ✓ User tools built: monitor, stress_test, data_exporter"
else
    echo "  ✗ User tools build failed"
    exit 1
fi
cd ..

echo
echo "========================================"
echo "  Build Complete!"
echo "========================================"
echo
echo "Files created:"
ls -la kernel/*.ko 2>/dev/null || true
ls -la ebpf/.output/*.o 2>/dev/null || true
ls -la user/monitor user/stress_test user/data_exporter 2>/dev/null || true
echo
echo "To load module: sudo insmod kernel/smartscheduler.ko"
echo "To monitor:     ./user/monitor"
