# SmartScheduler Kernel Module Makefile
#
# Usage:
#   make          - Build the kernel module
#   make clean    - Clean build artifacts
#   make install  - Install module (requires root)
#   make load     - Load module into kernel
#   make unload   - Unload module from kernel
#   make reload   - Unload and reload module

obj-m += smartscheduler.o

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

# Compiler flags for extra warnings
ccflags-y := -Wall -Wextra

.PHONY: all clean install load unload reload help

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

load: all
	@echo "Loading SmartScheduler module..."
	sudo insmod smartscheduler.ko
	@echo "Module loaded. Check dmesg for output."
	@dmesg | tail -5

unload:
	@echo "Unloading SmartScheduler module..."
	-sudo rmmod smartscheduler
	@echo "Module unloaded."
	@dmesg | tail -3

reload: unload load

status:
	@echo "=== Module Status ==="
	@lsmod | grep smartscheduler || echo "Module not loaded"
	@echo ""
	@if [ -f /proc/smartscheduler/status ]; then \
		cat /proc/smartscheduler/status; \
	else \
		echo "Procfs interface not available"; \
	fi

help:
	@echo "SmartScheduler Kernel Module Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build the kernel module (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install module system-wide"
	@echo "  load     - Load module into running kernel"
	@echo "  unload   - Remove module from running kernel"
	@echo "  reload   - Unload and reload module"
	@echo "  status   - Show module status"
	@echo "  help     - Show this help message"
