#!/bin/bash
#
# SmartScheduler Setup Script
# Installs all required dependencies on Ubuntu 24.04
#
# Usage: sudo ./setup.sh
#

set -e

echo "========================================"
echo "  SmartScheduler Setup Script"
echo "  Ubuntu 24.04 / Kernel 6.x"
echo "========================================"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (sudo ./setup.sh)"
    exit 1
fi

# Get kernel version
KERNEL_VERSION=$(uname -r)
echo "Detected kernel: $KERNEL_VERSION"
echo

# Update package lists
echo "[1/5] Updating package lists..."
apt update

# Install build essentials and kernel headers
echo "[2/5] Installing build tools and kernel headers..."
apt install -y \
    build-essential \
    linux-headers-$(uname -r) \
    pkg-config

# Install eBPF toolchain
echo "[3/5] Installing eBPF toolchain..."
apt install -y \
    clang \
    llvm \
    libbpf-dev \
    bpftool \
    bpftrace

# Install optional but useful tools
echo "[4/5] Installing performance tools..."
apt install -y \
    linux-tools-$(uname -r) \
    trace-cmd \
    stress-ng \
    gnuplot || echo "Some optional tools not available"

# Verify installations
echo "[5/5] Verifying installations..."
echo

echo "Checking components:"
echo -n "  - GCC: "
gcc --version | head -1

echo -n "  - Clang: "
clang --version | head -1

echo -n "  - Kernel headers: "
if [ -d "/lib/modules/$(uname -r)/build" ]; then
    echo "OK ($(uname -r))"
else
    echo "MISSING"
    exit 1
fi

echo -n "  - bpftool: "
bpftool version 2>/dev/null || echo "not found"

echo -n "  - BTF support: "
if [ -f "/sys/kernel/btf/vmlinux" ]; then
    echo "OK"
else
    echo "NOT AVAILABLE (eBPF may not work)"
fi

echo
echo "========================================"
echo "  Setup Complete!"
echo "========================================"
echo
echo "Next steps:"
echo "  1. cd kernel && make"
echo "  2. cd ebpf && make"
echo "  3. cd user && make"
echo "  4. sudo insmod kernel/smartscheduler.ko"
echo "  5. ./user/monitor"
echo
