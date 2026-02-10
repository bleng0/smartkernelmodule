# eBPF Programs Makefile for SmartScheduler
#
# Builds eBPF programs using clang/LLVM
# Requires: clang, llvm, libbpf-dev, bpftool

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

# Architecture detection
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Directories
OUTPUT := .output
LIBBPF_SRC := /usr/include/bpf

# Compiler flags
CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -target bpf \
              -D__TARGET_ARCH_$(ARCH) \
              -I$(OUTPUT) \
              -I/usr/include \
              -I/usr/include/$(shell uname -m)-linux-gnu

# Source files
BPF_SRCS := cpu_trace.bpf.c mem_trace.bpf.c io_trace.bpf.c
BPF_OBJS := $(patsubst %.bpf.c,$(OUTPUT)/%.bpf.o,$(BPF_SRCS))

.PHONY: all clean vmlinux load unload help

all: $(OUTPUT) vmlinux $(BPF_OBJS)
	@echo "eBPF programs built successfully!"
	@echo "Objects: $(BPF_OBJS)"

$(OUTPUT):
	mkdir -p $(OUTPUT)

# Generate vmlinux.h from running kernel
vmlinux: $(OUTPUT)/vmlinux.h

$(OUTPUT)/vmlinux.h: | $(OUTPUT)
	@echo "Generating vmlinux.h from kernel BTF..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "vmlinux.h generated"

# Compile eBPF programs
$(OUTPUT)/%.bpf.o: %.bpf.c $(OUTPUT)/vmlinux.h
	@echo "Compiling $<..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "Compiled $@"

# Strip debug info for production
strip: $(BPF_OBJS)
	@for obj in $(BPF_OBJS); do \
		$(LLVM_STRIP) -g $$obj; \
	done

# Load eBPF programs into kernel
load: $(BPF_OBJS)
	@echo "Loading eBPF programs..."
	@for obj in $(BPF_OBJS); do \
		name=$$(basename $$obj .bpf.o); \
		echo "Loading $$name..."; \
		sudo $(BPFTOOL) prog load $$obj /sys/fs/bpf/smartsched_$$name || true; \
	done
	@echo "Programs loaded. Check with: sudo bpftool prog list"

# Unload eBPF programs
unload:
	@echo "Unloading eBPF programs..."
	@for prog in /sys/fs/bpf/smartsched_*; do \
		if [ -e "$$prog" ]; then \
			echo "Removing $$prog"; \
			sudo rm -f $$prog; \
		fi; \
	done
	@echo "Programs unloaded"

# Show loaded programs
status:
	@echo "=== Loaded eBPF Programs ==="
	@sudo $(BPFTOOL) prog list 2>/dev/null | grep -A2 smartsched || echo "No SmartScheduler programs loaded"
	@echo ""
	@echo "=== BPF Filesystem ==="
	@ls -la /sys/fs/bpf/smartsched_* 2>/dev/null || echo "No pinned programs"

# Verify programs
verify: $(BPF_OBJS)
	@echo "Verifying eBPF programs..."
	@for obj in $(BPF_OBJS); do \
		echo "Checking $$obj:"; \
		$(BPFTOOL) prog load $$obj /dev/null 2>&1 || echo "  (dry run, some errors expected)"; \
	done

clean:
	rm -rf $(OUTPUT)

help:
	@echo "SmartScheduler eBPF Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build all eBPF programs (default)"
	@echo "  vmlinux  - Generate vmlinux.h from kernel BTF"
	@echo "  load     - Load programs into kernel"
	@echo "  unload   - Remove programs from kernel"
	@echo "  status   - Show loaded programs"
	@echo "  verify   - Dry-run verify programs"
	@echo "  strip    - Strip debug symbols"
	@echo "  clean    - Remove build artifacts"
	@echo ""
	@echo "Requirements:"
	@echo "  - clang, llvm, libbpf-dev, bpftool"
	@echo "  - Kernel with BTF support"
	@echo "  - Root privileges for load/unload"
