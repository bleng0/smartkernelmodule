# User-Space Tools Makefile - SmartScheduler v2.0

CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS =

# All tools to build
TARGETS = monitor stress_test data_exporter scheduler_daemon \
          health_check top_spikes

.PHONY: all clean install help python-deps smartmonitor

all: $(TARGETS)
	@echo ""
	@echo "✓ All C tools built successfully!"
	@echo ""
	@echo "Available tools:"
	@echo "  ./monitor          - C real-time monitor (legacy)"
	@echo "  ./scheduler_daemon - Response daemon with categorization"
	@echo "  ./stress_test      - Stress test generator"
	@echo "  ./data_exporter    - CSV data exporter"
	@echo "  ./health_check     - System health diagnostics"
	@echo "  ./top_spikes       - Top processes by spike severity"
	@echo ""
	@echo "Python TUI (recommended):"
	@echo "  python3 smartmonitor.py        - Rich TUI monitor v3.0"
	@echo "  python3 smartmonitor.py --demo  - Demo mode (no kernel module)"
	@echo ""

monitor: monitor.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

stress_test: stress_test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -lpthread -lm

data_exporter: data_exporter.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

scheduler_daemon: scheduler_daemon.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

health_check: health_check.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

top_spikes: top_spikes.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)
	rm -f *.o

python-deps:
	pip install --break-system-packages -r requirements.txt 2>/dev/null || pip install -r requirements.txt

smartmonitor: python-deps
	@echo "Launching SmartMonitor TUI..."
	sudo python3 smartmonitor.py --interval 500

install: all
	install -m 755 monitor /usr/local/bin/smartscheduler-monitor
	install -m 755 stress_test /usr/local/bin/smartscheduler-stress
	install -m 755 data_exporter /usr/local/bin/smartscheduler-export
	install -m 755 scheduler_daemon /usr/local/bin/smartscheduler-daemon
	install -m 755 health_check /usr/local/bin/smartscheduler-health
	install -m 755 top_spikes /usr/local/bin/smartscheduler-top
	install -m 755 smartmonitor.py /usr/local/bin/smartscheduler-tui

help:
	@echo "SmartScheduler User-Space Tools v3.0"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build all C tools"
	@echo "  python-deps      - Install Python dependencies (rich, psutil)"
	@echo "  smartmonitor     - Launch Rich TUI monitor"
	@echo "  monitor          - Build C real-time monitor (legacy)"
	@echo "  scheduler_daemon - Build response daemon"
	@echo "  stress_test      - Build stress test generator"
	@echo "  data_exporter    - Build CSV data exporter"
	@echo "  health_check     - Build system health diagnostics"
	@echo "  top_spikes       - Build top processes tool"
	@echo "  clean            - Remove binaries"
	@echo "  install          - Install to /usr/local/bin"
