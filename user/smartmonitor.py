#!/usr/bin/env python3
"""
SmartScheduler Enhanced Monitor — Python Rich TUI v3.0

A terminal-based tool that monitors CPU usage via the SmartScheduler
kernel module and kills flagged processes with a red-pulse animation.

Features:
  - Rich table UI with htop/btop-inspired column layout
  - Blocklist-driven process detection (power-state independent)
  - Safe-app whitelist preventing false-positive kills
  - CSS-inspired red-pulse animation before process termination
  - System resource summary header
  - Advisory panel with spike categorisation
  - Demo mode for testing without the kernel module

Usage:
  python3 smartmonitor.py              # Live mode (requires kernel module)
  python3 smartmonitor.py --demo       # Demo with synthetic data
  python3 smartmonitor.py --interval 500 --top 30

Requirements:
  pip install rich psutil
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import psutil
except ImportError:
    print("ERROR: psutil is required.  Install with:  pip install psutil")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.style import Style
    from rich.table import Table
    from rich.text import Text
    from rich import box
except ImportError:
    print("ERROR: rich is required.  Install with:  pip install rich")
    sys.exit(1)


# ── Paths ────────────────────────────────────────────────────────────────────
PROC_STATUS      = "/proc/smartscheduler/status"
PROC_PREDICTIONS = "/proc/smartscheduler/predictions"
PROC_STATS       = "/proc/smartscheduler/stats"
SCRIPT_DIR       = Path(__file__).resolve().parent
BLOCKLIST_PATH   = SCRIPT_DIR / "blocklist.json"
LOG_DIR          = SCRIPT_DIR.parent / "logs"


# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class ProcessInfo:
    """Per-process monitoring snapshot."""
    pid: int = 0
    name: str = ""
    cpu_percent: float = 0.0
    ram_mb: float = 0.0
    cpu_ema: int = 0
    mem_ema: int = 0
    io_ema: int = 0
    cpu_roc: int = 0
    mem_roc: int = 0
    io_rate: float = 0.0
    has_cpu_spike: bool = False
    has_mem_spike: bool = False
    has_io_spike: bool = False
    flags: int = 0
    alert_level: str = "NORMAL"
    trend: str = "→"
    is_blocklisted: bool = False
    is_safe: bool = False
    consecutive_spikes: int = 0


@dataclass
class SystemInfo:
    """System-wide resource snapshot."""
    cpu_count: int = 0
    cpu_percent: float = 0.0
    ram_total_gb: float = 0.0
    ram_used_gb: float = 0.0
    ram_percent: float = 0.0
    load_1: float = 0.0
    load_5: float = 0.0
    load_15: float = 0.0
    power_state: str = "Unknown"
    module_loaded: bool = False
    tracked_procs: int = 0
    total_predictions: int = 0


# ── Blocklist Manager ────────────────────────────────────────────────────────

class BlocklistManager:
    """Loads and evaluates processes against a blocklist / safe-app whitelist.

    Detection is strictly name + absolute-threshold based.
    Power state does NOT affect thresholds — this fixes the false-positive
    bug where battery mode caused legitimate apps to be flagged.
    """

    def __init__(self, config_path: str | Path = BLOCKLIST_PATH):
        self.blocklist: list[dict] = []
        self.safe_apps: list[str] = []
        self.global_cpu_threshold: float = 95.0
        self.kill_delay: float = 2.0
        self.kill_signal_timeout: float = 0.5
        self._load(config_path)

    def _load(self, path: str | Path) -> None:
        path = Path(path)
        if not path.exists():
            return
        try:
            with open(path) as f:
                cfg = json.load(f)
            self.blocklist = cfg.get("blocklist", [])
            self.safe_apps = [s.lower() for s in cfg.get("safe_apps", [])]
            self.global_cpu_threshold = cfg.get("global_cpu_kill_threshold", 95.0)
            self.kill_delay = cfg.get("kill_delay_seconds", 2.0)
            self.kill_signal_timeout = cfg.get("kill_signal_timeout", 0.5)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"Warning: could not load blocklist: {exc}")

    def is_monitored(self, process_name: str) -> bool:
        """Return True if the process matches a blocklist entry."""
        if self.is_safe(process_name):
            return False
        
        name_lower = process_name.lower()
        for entry in self.blocklist:
            if entry["name"].lower() in name_lower:
                return True
        return False

    def is_safe(self, process_name: str) -> bool:
        return process_name.lower() in self.safe_apps

    def check(self, process_name: str, cpu_percent: float) -> bool:
        """Return True if the process should be killed."""
        name_lower = process_name.lower()

        # Safe apps are NEVER killed regardless of CPU usage
        if self.is_safe(process_name):
            return False

        # Check explicit blocklist entries
        for entry in self.blocklist:
            if entry["name"].lower() in name_lower:
                threshold = entry.get("cpu_threshold", self.global_cpu_threshold)
                if cpu_percent >= threshold:
                    return True

        # Global fallback — unknown process exceeding global threshold
        if cpu_percent >= self.global_cpu_threshold:
            return True

        return False


# ── Power State Detector ─────────────────────────────────────────────────────

def detect_power_state() -> str:
    """Detect AC / Battery status.  Informational only — does NOT change
    any thresholds or detection logic."""
    try:
        supply_dir = Path("/sys/class/power_supply")
        if not supply_dir.exists():
            return "Unknown"
        for entry in supply_dir.iterdir():
            online_path = entry / "online"
            if online_path.exists():
                val = online_path.read_text().strip()
                return "⚡ AC Power" if val == "1" else "🔋 Battery"
            type_path = entry / "type"
            if type_path.exists():
                ptype = type_path.read_text().strip()
                if ptype == "Battery":
                    cap_path = entry / "capacity"
                    cap = cap_path.read_text().strip() if cap_path.exists() else "?"
                    return f"🔋 Battery ({cap}%)"
    except OSError:
        pass
    return "Unknown"


# ── Proc Reader ──────────────────────────────────────────────────────────────

class ProcReader:
    """Reads data from /proc/smartscheduler/* and /proc/<pid>/status."""

    @staticmethod
    def module_loaded() -> bool:
        return os.path.exists(PROC_STATUS)

    @staticmethod
    def read_status() -> dict:
        result = {"tracked": 0, "predictions": 0}
        try:
            with open(PROC_STATUS) as f:
                for line in f:
                    if "Tracked processes:" in line:
                        result["tracked"] = int(line.split(":")[-1].strip())
                    elif "Total predictions:" in line:
                        result["predictions"] = int(line.split(":")[-1].strip())
        except OSError:
            pass
        return result

    @staticmethod
    def read_predictions() -> dict[int, dict]:
        """Returns {pid: {name, cpu_spike, mem_spike, io_spike, flags}}"""
        preds: dict[int, dict] = {}
        try:
            with open(PROC_PREDICTIONS) as f:
                lines = f.readlines()
        except OSError:
            return {}

        # Skip header lines (first 4)
        for line_num, line in enumerate(lines[4:], start=5):
            try:
                parts = line.split()
                if len(parts) >= 6:
                    pid = int(parts[0])
                    preds[pid] = {
                        "name": " ".join(parts[1:-4]),
                        "cpu_spike": parts[-4] == "*",
                        "mem_spike": parts[-3] == "*",
                        "io_spike": parts[-2] == "*",
                        "flags": int(parts[-1], 16),
                    }
            except ValueError:
                continue
        return preds

    @staticmethod
    def read_stats() -> dict[int, dict]:
        """Returns {pid: {cpu_ema, mem_ema, io_ema, cpu_roc, mem_roc, io_roc}}"""
        stats: dict[int, dict] = {}
        try:
            with open(PROC_STATS) as f:
                lines = f.readlines()
            for line in lines[4:]:
                parts = line.split()
                if len(parts) >= 7:
                    pid = int(parts[0])
                    stats[pid] = {
                        "cpu_ema": int(parts[1]),
                        "mem_ema": int(parts[2]),
                        "io_ema": int(parts[3]),
                        "cpu_roc": int(parts[4]),
                        "mem_roc": int(parts[5]),
                        "io_roc": int(parts[6]),
                    }
        except (OSError, ValueError):
            pass
        return stats


# ── Red Pulse Animation ─────────────────────────────────────────────────────

class RedPulseAnimation:
    """Translates the CSS @keyframes redPulse effect into Rich Styles.

    CSS reference:
      from  { background-color: #bc330d; box-shadow: 0 0 9px #333; }
      50%   { background-color: #e33100; box-shadow: 0 0 18px #e33100; }
      to    { background-color: #bc330d; box-shadow: 0 0 9px #333; }

    We cycle through interpolated background colours over ~2 seconds,
    producing a pulsing red glow on the target table row.
    """

    PULSE_COLOURS = [
        "#bc330d",  # 0.00s  — base
        "#c42e09",  # 0.25s
        "#cc2a06",  # 0.50s
        "#d52603",  # 0.75s
        "#e33100",  # 1.00s  — peak intensity
        "#d52603",  # 1.25s
        "#cc2a06",  # 1.50s
        "#c42e09",  # 1.75s
    ]

    FRAME_DURATION = 0.25  # seconds per frame

    @classmethod
    def get_style(cls, frame_index: int) -> Style:
        colour = cls.PULSE_COLOURS[frame_index % len(cls.PULSE_COLOURS)]
        return Style(bgcolor=colour, color="white", bold=True)

    @classmethod
    def total_frames(cls) -> int:
        return len(cls.PULSE_COLOURS)

    @classmethod
    def total_duration(cls) -> float:
        return cls.total_frames() * cls.FRAME_DURATION


# ── Demo Data Generator ─────────────────────────────────────────────────────

import random

def generate_demo_processes(tick: int) -> list[ProcessInfo]:
    """Produce synthetic process data for UI testing without the kernel module."""
    base = [
        ("firefox", 8.5, 1200, False),
        ("code", 12.3, 890, False),
        ("gnome-shell", 3.1, 450, False),
        ("python3", 5.7, 220, False),
        ("node", 4.2, 310, False),
        ("chrome", 15.8, 1800, False),
        ("Xorg", 2.0, 180, False),
        ("pulseaudio", 0.5, 45, False),
        ("cryptominer", 92.0, 50, True),   # blocklisted
        ("tmux", 0.1, 12, False),
        ("nvim", 1.2, 65, False),
        ("stress-ng", 97.5, 30, True),     # blocklisted
    ]
    procs = []
    for i, (name, cpu, ram, blk) in enumerate(base):
        jitter = random.uniform(-2.0, 2.0)
        cpu_val = max(0.0, cpu + jitter + (5 * (tick % 3) if blk else 0))
        roc = int(cpu_val * 100) if blk else random.randint(-200, 500)

        p = ProcessInfo(
            pid=1000 + i * 111,
            name=name,
            cpu_percent=round(cpu_val, 1),
            ram_mb=round(ram + random.uniform(-50, 50), 1),
            cpu_roc=roc,
            mem_roc=random.randint(-100, 300),
            io_rate=random.randint(-50, 200),
            has_cpu_spike=blk,
            has_mem_spike=random.random() < 0.1,
            has_io_spike=random.random() < 0.05,
            is_blocklisted=blk,
        )
        # Derive alert level from ROC
        max_roc = max(abs(p.cpu_roc), abs(p.mem_roc), abs(int(p.io_rate)))
        if max_roc > 5000:
            p.alert_level = "CRITICAL"
        elif max_roc > 3000:
            p.alert_level = "HIGH"
        elif max_roc > 1500:
            p.alert_level = "MEDIUM"
        elif max_roc > 500:
            p.alert_level = "LOW"
        # Trend
        if p.cpu_roc > 100:
            p.trend = "↑"
        elif p.cpu_roc < -100:
            p.trend = "↓"
        procs.append(p)
    return procs


# ── Main Monitor ─────────────────────────────────────────────────────────────

class SmartMonitor:
    """Orchestrates the read → render → detect → animate → kill → refresh loop."""

    def __init__(self, args: argparse.Namespace):
        self.interval = max(100, args.interval) / 1000.0  # ms → s
        self.top_n = args.top
        self.show_all = args.all
        self.demo = args.demo
        self.console = Console()
        self.blocklist = BlocklistManager()
        self.running = True
        self.tick = 0
        self.kill_log: list[str] = []

        # Spike history tracking
        self._spike_history: dict[int, int] = {}  # pid → consecutive count
        self._process_cache: dict[int, psutil.Process] = {}  # pid → psutil object

        signal.signal(signal.SIGINT, self._signal)
        signal.signal(signal.SIGTERM, self._signal)

    def _signal(self, *_):
        self.running = False

    # ── Data Collection ────────────────────────────────────────────────

    def collect_processes(self) -> list[ProcessInfo]:
        """
        Collects all running processes from system (psutil) and enriches
        them with SmartScheduler data (active set).
        """
        if self.demo:
            return generate_demo_processes(self.tick)

        # 1. Get Kernel Data (Enrichment source)
        if ProcReader.module_loaded():
            preds = ProcReader.read_predictions()
            stats = ProcReader.read_stats()
        else:
            preds = {}
            stats = {}

        processes: list[ProcessInfo] = []
        live_pids = set()

        # 2. Iterate ALL system processes (Source of Truth)
        # using process_iter is efficient and robust against kernel desync
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            pid = proc.pid
            live_pids.add(pid)
            
            # Manage Cache
            if pid not in self._process_cache:
                # New process found
                try:
                    # We utilize the yielded proc object but must ensure we
                    # store a persistent reference for cpu_percent state.
                    # psutil.process_iter yields new objects, so we should 
                    # use them to initialize the cache IF valid.
                    p_obj = psutil.Process(pid) 
                    p_obj.cpu_percent() # Init CPU state
                    self._process_cache[pid] = p_obj
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Use Cached Object for CPU Calculation
            p = self._process_cache[pid]
            try:
                cpu_pct = p.cpu_percent(interval=0)
                mem_info = p.memory_info()
                ram_mb = mem_info.rss / (1024 * 1024)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self._process_cache.pop(pid, None)
                continue

            # 3. Merge with Kernel Data
            pred = preds.get(pid, {})
            st = stats.get(pid, {})
            
            # Determine Alert Level
            name = proc.name()
            is_blocked = self.blocklist.is_monitored(name)
            
            # Spike Flags
            has_cpu_spike = pred.get("cpu_spike", False)
            has_mem_spike = pred.get("mem_spike", False)
            has_io_spike = pred.get("io_spike", False)
            
            # Alert Logic
            alert = "NORMAL"
            if is_blocked and self.blocklist.check(name, cpu_pct):
                alert = "CRITICAL"
            elif has_cpu_spike or has_mem_spike or has_io_spike:
                alert = "WARNING"
            
            # Track Consecutive Spikes
            if alert != "NORMAL":
                self._spike_history[pid] = self._spike_history.get(pid, 0) + 1
            else:
                self._spike_history.pop(pid, None)

            consecutive_spikes = self._spike_history.get(pid, 0)

            process_info = ProcessInfo(
                pid=pid,
                name=name,
                cpu_percent=round(cpu_pct, 1),
                ram_mb=round(ram_mb, 1),
                io_rate=st.get("io_roc", 0.0), # From kernel stats if avail
                trend="↑" if st.get("cpu_roc", 0) > 0 else "↓" if st.get("cpu_roc", 0) < 0 else "→",
                alert_level=alert,
                has_cpu_spike=has_cpu_spike,
                has_mem_spike=has_mem_spike,
                has_io_spike=has_io_spike,
                is_blocklisted=is_blocked,
                consecutive_spikes=consecutive_spikes
            )
            processes.append(process_info)


        return processes

    def collect_system_info(self) -> SystemInfo:
        mem = psutil.virtual_memory()
        load = os.getloadavg()
        status = ProcReader.read_status() if not self.demo else {"tracked": 12, "predictions": 47}
        return SystemInfo(
            cpu_count=psutil.cpu_count() or 1,
            cpu_percent=psutil.cpu_percent(interval=0),
            ram_total_gb=round(mem.total / (1024**3), 1),
            ram_used_gb=round(mem.used / (1024**3), 1),
            ram_percent=mem.percent,
            load_1=round(load[0], 2),
            load_5=round(load[1], 2),
            load_15=round(load[2], 2),
            power_state=detect_power_state(),
            module_loaded=ProcReader.module_loaded() if not self.demo else True,
            tracked_procs=status.get("tracked", 0),
            total_predictions=status.get("predictions", 0),
        )

    # ── Rendering ──────────────────────────────────────────────────────

    def _fmt_ram(self, mb: float) -> str:
        if mb >= 1024:
            return f"{mb/1024:.1f} GB"
        return f"{mb:.0f} MB"

    def _io_bar(self, roc: int, width: int = 5) -> Text:
        """Render a small bar from I/O ROC magnitude."""
        magnitude = min(abs(roc), 5000)
        filled = int((magnitude / 5000) * width)
        bar = "█" * filled + "░" * (width - filled)
        colour = "bright_red" if filled >= 4 else ("yellow" if filled >= 2 else "green")
        return Text(bar, style=colour)

    def _alert_style(self, level: str) -> Style:
        return {
            "CRITICAL": Style(color="white", bgcolor="red", bold=True),
            "HIGH":     Style(color="bright_red", bold=True),
            "MEDIUM":   Style(color="yellow"),
            "LOW":      Style(color="cyan"),
        }.get(level, Style(color="green"))

    def _trend_style(self, trend: str) -> Style:
        if trend == "↑":
            return Style(color="bright_red", bold=True)
        if trend == "↓":
            return Style(color="bright_green")
        return Style(color="bright_black")

    def _status_text(self, p: ProcessInfo) -> Text:
        if p.is_blocklisted:
            return Text("⛔ KILL", style="bold bright_red")
        if p.has_cpu_spike or p.has_mem_spike or p.has_io_spike:
            spike_types = []
            if p.has_cpu_spike:
                spike_types.append("CPU")
            if p.has_mem_spike:
                spike_types.append("MEM")
            if p.has_io_spike:
                spike_types.append("I/O")
            label = "SPIKE " + "+".join(spike_types)
            return Text(label, style="bold yellow")
        if p.is_safe:
            return Text("🛡 SAFE", style="green")
        return Text("OK", style="bright_green")

    def build_header(self, sysinfo: SystemInfo) -> Panel:
        """System resource summary header."""
        ram_bar_width = 20
        ram_filled = int((sysinfo.ram_percent / 100) * ram_bar_width)
        ram_bar = "█" * ram_filled + "░" * (ram_bar_width - ram_filled)
        ram_colour = "red" if sysinfo.ram_percent > 80 else ("yellow" if sysinfo.ram_percent > 60 else "green")

        cpu_bar_width = 20
        cpu_filled = int((sysinfo.cpu_percent / 100) * cpu_bar_width)
        cpu_bar = "█" * cpu_filled + "░" * (cpu_bar_width - cpu_filled)
        cpu_colour = "red" if sysinfo.cpu_percent > 80 else ("yellow" if sysinfo.cpu_percent > 60 else "green")

        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        mode_tag = "[bold magenta] DEMO MODE [/bold magenta]" if self.demo else ""

        header = Text.assemble(
            ("  SmartScheduler Monitor v3.0", "bold cyan"),
            ("  │  ", "dim"),
            (ts, "white"),
            ("  │  ", "dim"),
            (sysinfo.power_state, "yellow"),
            ("  ", ""),
        )

        detail_parts = []
        detail_parts.append(f"  CPUs: {sysinfo.cpu_count}  ")
        detail_parts.append(f"Load: {sysinfo.load_1} {sysinfo.load_5} {sysinfo.load_15}  ")
        detail_parts.append(f"Tracked: {sysinfo.tracked_procs}  ")
        detail_parts.append(f"Predictions: {sysinfo.total_predictions}")
        detail_line = Text("".join(detail_parts), style="dim white")

        cpu_line = Text.assemble(
            ("  CPU  [", "dim"),
            (cpu_bar, cpu_colour),
            (f"] {sysinfo.cpu_percent:5.1f}%", "dim"),
            ("    RAM  [", "dim"),
            (ram_bar, ram_colour),
            (f"] {sysinfo.ram_used_gb:.1f}/{sysinfo.ram_total_gb:.1f} GB ({sysinfo.ram_percent:.0f}%)", "dim"),
        )

        content = Text("\n").join([header, detail_line, cpu_line])
        if mode_tag:
            content.append(f"\n  {mode_tag}")

        mod_status = "[bold green]● MODULE LOADED[/bold green]" if sysinfo.module_loaded else "[bold red]● MODULE NOT LOADED[/bold red]"

        return Panel(
            content,
            title=f"[bold white]System Overview[/bold white]  {mod_status}",
            border_style="cyan",
            padding=(0, 1),
        )

    def build_process_table(
        self,
        processes: list[ProcessInfo],
        pulse_pids: dict[int, int] | None = None,
    ) -> Table:
        """Build the main process table with htop-inspired layout."""
        table = Table(
            box=box.ROUNDED,
            border_style="bright_blue",
            header_style="bold bright_white on dark_blue",
            show_lines=False,
            pad_edge=True,
            expand=True,
            title="[bold]Process Monitor[/bold]",
            title_style="bold bright_cyan",
        )

        table.add_column("PID", justify="right", width=8, style="bright_white")
        table.add_column("Process Name", justify="left", min_width=16, max_width=20, style="bright_white")
        table.add_column("CPU %", justify="right", width=8)
        table.add_column("Memory", justify="right", width=10)
        table.add_column("I/O Rate", justify="center", width=7)
        table.add_column("Trend", justify="center", width=5)
        table.add_column("Alert", justify="center", width=10)
        table.add_column("Status", justify="left", min_width=14)

        # Sort: blocklisted first, then by alert severity, then CPU%
        alert_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NORMAL": 4}
        processes.sort(key=lambda p: (
            0 if p.is_blocklisted else 1,
            alert_order.get(p.alert_level, 5),
            -p.cpu_percent,
        ))

        shown = 0
        for p in processes:

            # Filter Logic:
            # 1. Always show spiking/alerting processes
            # 2. Always show blocklisted processes
            # 3. Always show high CPU (> 1.0%)
            # 4. Fill remaining slots with top CPU processes (even if idle)
            
            is_interesting = (
                p.alert_level != "NORMAL" or
                p.has_cpu_spike or p.has_mem_spike or p.has_io_spike or
                p.is_blocklisted or
                p.cpu_percent > 1.0
            )

            if self.show_all or is_interesting or shown < self.top_n:
                # Pulse animation for blocklisted processes being killed
                row_style: Style | str = ""
                if pulse_pids and p.pid in pulse_pids:
                    frame = pulse_pids[p.pid]
                    row_style = RedPulseAnimation.get_style(frame)

                # CPU colour coding
                if p.cpu_percent >= 80:
                    cpu_style = "bold bright_red"
                elif p.cpu_percent >= 50:
                    cpu_style = "yellow"
                elif p.cpu_percent >= 20:
                    cpu_style = "bright_yellow"
                else:
                    cpu_style = "bright_green"

                table.add_row(
                    str(p.pid),
                    Text(p.name[:20], style="bold" if p.is_blocklisted else ""),
                    Text(f"{p.cpu_percent:6.1f}%", style=cpu_style),
                    self._fmt_ram(p.ram_mb),
                    self._io_bar(p.io_rate),
                    Text(p.trend, style=self._trend_style(p.trend)),
                    Text(p.alert_level, style=self._alert_style(p.alert_level)),
                    self._status_text(p),
                    style=row_style,
                )
                shown += 1
            
            if not self.show_all and shown >= self.top_n:
                break

        if shown == 0:
            table.add_row(
                "—", "No active processes", "—", "—", Text("—"), Text("—"), Text("—"), Text("—"),
            )

        return table

    def build_advisory(self, processes: list[ProcessInfo]) -> Panel:
        """Advisory summary panel."""
        cpu_spikes = sum(1 for p in processes if p.has_cpu_spike)
        mem_spikes = sum(1 for p in processes if p.has_mem_spike)
        io_spikes = sum(1 for p in processes if p.has_io_spike)
        blocklisted = sum(1 for p in processes if p.is_blocklisted)
        persistent = sum(1 for p in processes if p.consecutive_spikes >= 5)

        lines: list[Text] = []

        if cpu_spikes:
            lines.append(Text(f"  🔥 CPU Spikes: {cpu_spikes} detected", style="bright_red"))
        else:
            lines.append(Text("  ✓ CPU: No spikes", style="bright_green"))

        if mem_spikes:
            lines.append(Text(f"  💾 MEM Spikes: {mem_spikes} detected", style="yellow"))
        else:
            lines.append(Text("  ✓ MEM: No spikes", style="bright_green"))

        if io_spikes:
            lines.append(Text(f"  📀 I/O Spikes: {io_spikes} detected", style="magenta"))
        else:
            lines.append(Text("  ✓ I/O: No spikes", style="bright_green"))

        if blocklisted:
            lines.append(Text(f"\n  ⛔ BLOCKLISTED: {blocklisted} process(es) flagged for termination", style="bold bright_red"))

        if persistent:
            lines.append(Text(f"  ⚠  PERSISTENT: {persistent} process(es) spiking >5 samples", style="bold red"))

        if self.kill_log:
            lines.append(Text(""))
            for entry in self.kill_log[-3:]:
                lines.append(Text(f"  {entry}", style="dim"))

        content = Text("\n").join(lines)
        return Panel(
            content,
            title="[bold]Advisory Summary[/bold]",
            border_style="yellow",
            padding=(0, 1),
        )

    def build_footer(self) -> Text:
        return Text.assemble(
            ("  Refresh: ", "dim"),
            (f"{int(self.interval*1000)}ms", "cyan"),
            ("  │  Top ", "dim"),
            (f"{self.top_n}", "cyan"),
            (" shown  │  ", "dim"),
            ("Ctrl+C", "bold yellow"),
            (" to exit  │  ", "dim"),
            ("Legend: ", "dim"),
            ("█", "red"), ("=Spike  ", "dim"),
            ("░", "bright_black"), ("=Normal  ", "dim"),
            ("↑↓→", "cyan"), ("=Trend", "dim"),
        )

    def render_full(
        self,
        processes: list[ProcessInfo],
        sysinfo: SystemInfo,
        pulse_pids: dict[int, int] | None = None,
    ) -> Layout:
        """Compose the complete terminal layout."""
        layout = Layout()
        layout.split_column(
            Layout(self.build_header(sysinfo), name="header", size=7 if self.demo else 6),
            Layout(self.build_process_table(processes, pulse_pids), name="table"),
            Layout(self.build_advisory(processes), name="advisory", size=10),
            Layout(self.build_footer(), name="footer", size=1),
        )
        return layout

    # ── Kill Sequence with Red Pulse ───────────────────────────────────

    def execute_kill_sequence(
        self,
        target: ProcessInfo,
        all_processes: list[ProcessInfo],
        sysinfo: SystemInfo,
        live: Live,
    ) -> bool:
        """Animate the red pulse then kill the process.

        Returns True if the process was successfully killed.
        """
        pid = target.pid
        name = target.name
        total_frames = RedPulseAnimation.total_frames()
        # Two full pulse cycles
        cycles = 2
        total = total_frames * cycles

        for frame_idx in range(total):
            if not self.running:
                return False
            pulse_pids = {pid: frame_idx % total_frames}
            layout = self.render_full(all_processes, sysinfo, pulse_pids)
            live.update(layout)
            time.sleep(RedPulseAnimation.FRAME_DURATION)

        # Kill the process
        killed = False
        if not self.demo:
            try:
                proc = psutil.Process(pid)
                proc.terminate()  # SIGTERM
                try:
                    proc.wait(timeout=self.blocklist.kill_signal_timeout)
                    killed = True
                except psutil.TimeoutExpired:
                    proc.kill()  # SIGKILL
                    killed = True
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                self.kill_log.append(f"[{time.strftime('%H:%M:%S')}] Failed to kill PID {pid} ({name}): {e}")
                return False
        else:
            killed = True  # Simulated kill in demo mode

        ts = time.strftime("%H:%M:%S")
        self.kill_log.append(f"[{ts}] ✓ Killed PID {pid} ({name}) — CPU was {target.cpu_percent}%")

        return killed

    # ── Main Loop ──────────────────────────────────────────────────────

    def run(self) -> None:
        self.console.clear()

        if not self.demo and not ProcReader.module_loaded():
            self.console.print(
                    Panel(
                        "[bold red]SmartScheduler kernel module is not loaded![/bold red]\n\n"
                        "Load it with:  [cyan]sudo insmod kernel/smartscheduler.ko[/cyan]\n"
                        "Or run in demo mode:  [cyan]python3 smartmonitor.py --demo[/cyan]",
                        title="Error",
                        border_style="red",
                )
            )
            return

        with Live(console=self.console, refresh_per_second=4, screen=True) as live:
            while self.running:
                self.tick += 1
                processes = self.collect_processes()
                sysinfo = self.collect_system_info()

                # Check for blocklisted processes to kill
                targets = [p for p in processes if p.is_blocklisted]
                if targets:
                    for target in targets:
                        self.execute_kill_sequence(target, processes, sysinfo, live)
                        # Remove killed process from list
                        processes = [p for p in processes if p.pid != target.pid]

                # Normal render
                layout = self.render_full(processes, sysinfo)
                live.update(layout)

                time.sleep(self.interval)


# ── CLI Entry Point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="smartmonitor",
        description="SmartScheduler Enhanced Monitor — Rich TUI v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 smartmonitor.py              # Live monitoring\n"
            "  python3 smartmonitor.py --demo        # Demo with synthetic data\n"
            "  python3 smartmonitor.py --interval 500 --top 30\n"
            "  python3 smartmonitor.py --all         # Show all processes\n"
        ),
    )
    parser.add_argument(
        "--interval", "-i", type=int, default=1000,
        help="Refresh interval in milliseconds (default: 1000)",
    )
    parser.add_argument(
        "--top", "-t", type=int, default=20,
        help="Show top N processes (default: 20)",
    )
    parser.add_argument(
        "--all", "-a", action="store_true",
        help="Show all tracked processes",
    )
    parser.add_argument(
        "--demo", "-d", action="store_true",
        help="Run in demo mode with synthetic data (no kernel module needed)",
    )
    parser.add_argument(
        "--blocklist", "-b", type=str, default=str(BLOCKLIST_PATH),
        help=f"Path to blocklist JSON config (default: {BLOCKLIST_PATH})",
    )
    args = parser.parse_args()

    monitor = SmartMonitor(args)
    if args.blocklist != str(BLOCKLIST_PATH):
        monitor.blocklist = BlocklistManager(args.blocklist)

    monitor.run()


if __name__ == "__main__":
    main()
