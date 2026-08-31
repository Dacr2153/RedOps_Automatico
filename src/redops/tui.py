"""Interactive terminal UI (TUI) for RedOps Automático.

Provides a guided, full-screen menu interface built entirely with Rich.
No extra dependencies beyond what is already in requirements.

Accessible via:
    redops              (default: no subcommand → launches this menu)
    redops menu
    python -m redops menu
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import io
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import json as _json
from pathlib import Path
from typing import Any

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.padding import Padding
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console()

_VERSION = "v1.0.0"

_BANNER_ART = """\
 ██████╗ ███████╗██████╗  ██████╗ ██████╗ ███████╗
 ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝
 ██████╔╝█████╗  ██║  ██║██║   ██║██████╔╝███████╗
 ██╔══██╗██╔══╝  ██║  ██║██║   ██║██╔═══╝ ╚════██║
 ██║  ██║███████╗██████╔╝╚██████╔╝██║     ███████║
 ╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚══════╝"""

_MENU_OPTIONS: list[tuple[str, str, str]] = [
    ("1", "Run Pentest",       "Launch the automated PTES pipeline against a target"),
    ("2", "Health Check",      "Verify connectivity to MSF RPC, Ollama, target and nmap"),
    ("3", "Configuration",     "View and edit all lab settings interactively"),
    ("4", "Generate Report",   "Rebuild a PDF report from a saved checkpoint"),
    ("5", "Cleanup Sessions",  "Close orphaned Metasploit sessions from a previous run"),
    ("6", "Setup Wizard",      "First-time installation and configuration guide"),
    ("0", "Exit",              ""),
]

# Schema for the configuration editor — one entry per .env key
_CONFIG_FIELDS: list[dict[str, Any]] = [
    # section, key, description, default, secret
    {"s": "Metasploit RPC", "key": "MSF_HOST",                   "desc": "Host where msfrpcd is running",                        "def": "127.0.0.1",        "secret": False},
    {"s": "Metasploit RPC", "key": "MSF_PORT",                   "desc": "RPC port number",                                      "def": "55553",            "secret": False},
    {"s": "Metasploit RPC", "key": "MSF_PASSWORD",               "desc": "Password used when starting msfrpcd (-P flag)",        "def": "msf_rpc_password", "secret": True},
    {"s": "Ollama LLM",     "key": "OLLAMA_HOST",                "desc": "Host where Ollama server is running",                  "def": "127.0.0.1",        "secret": False},
    {"s": "Ollama LLM",     "key": "OLLAMA_PORT",                "desc": "Ollama API port",                                      "def": "11434",            "secret": False},
    {"s": "Ollama LLM",     "key": "OLLAMA_MODEL",               "desc": "LLM model for orchestration decisions",                "def": "mistral",          "secret": False},
    {"s": "Ollama LLM",     "key": "OLLAMA_TIMEOUT",             "desc": "Max seconds to wait per LLM response",                "def": "120",              "secret": False},
    {"s": "Target",         "key": "TARGET_NETWORK",             "desc": "CIDR of the lab network  e.g. 192.168.56.0/24",       "def": "192.168.56.0/24",  "secret": False},
    {"s": "Target",         "key": "LHOST",                      "desc": "Attacker IP for reverse payloads (empty = auto)",     "def": "",                 "secret": False},
    {"s": "Evasion",        "key": "EVASION_PROFILE",            "desc": "stealth | balanced | aggressive",                     "def": "balanced",         "secret": False},
    {"s": "Evasion",        "key": "SCAN_TIMING_MIN",            "desc": "Minimum delay between network operations (seconds)",  "def": "1.0",              "secret": False},
    {"s": "Evasion",        "key": "SCAN_TIMING_MAX",            "desc": "Maximum delay between network operations (seconds)",  "def": "5.0",              "secret": False},
    {"s": "Pipeline",       "key": "GLOBAL_TIMEOUT_MINUTES",     "desc": "Maximum total pipeline runtime in minutes",           "def": "15",               "secret": False},
    {"s": "Pipeline",       "key": "MIN_SERVICES_TO_COMPROMISE", "desc": "Number of compromised services needed for success",   "def": "3",                "secret": False},
    {"s": "Pipeline",       "key": "LOG_LEVEL",                  "desc": "DEBUG | INFO | WARNING | ERROR",                      "def": "INFO",             "secret": False},
    {"s": "Output",         "key": "REPORT_OUTPUT_DIR",          "desc": "Directory where PDF reports are saved",               "def": "./reports",        "secret": False},
]


# ── Main TUI class ────────────────────────────────────────────────────────────


class RedOpsTUI:
    """Interactive menu-driven terminal interface for RedOps."""

    def __init__(self) -> None:
        # Locate .env: prefer CWD (project root when run normally),
        # fall back to the path relative to this package file.
        cwd_env = Path(".env")
        pkg_env = Path(__file__).resolve().parent.parent.parent / ".env"
        self._env_file: Path = cwd_env if cwd_env.exists() else pkg_env

    # ══ Public entry point ═══════════════════════════════════════════════════

    def run(self) -> None:
        """Start the interactive TUI loop — runs until the user exits."""
        while True:
            try:
                console.clear()
                self._print_banner()
                self._print_status_strip()
                self._print_main_menu()

                choice = Prompt.ask(
                    "\n  [bold cyan]Choose an option[/bold cyan] [dim][0-6][/dim]",
                    choices=["0", "1", "2", "3", "4", "5", "6"],
                    show_choices=False,
                )
                console.print()

                if choice == "0":
                    break
                elif choice == "1":
                    self._menu_run()
                elif choice == "2":
                    self._menu_health()
                elif choice == "3":
                    self._menu_config()
                elif choice == "4":
                    self._menu_report()
                elif choice == "5":
                    self._menu_cleanup()
                elif choice == "6":
                    self._menu_setup()

                self._pause()

            except KeyboardInterrupt:
                console.print("\n  [dim]Press [bold]0[/bold] + Enter to exit.[/dim]")
                time.sleep(0.5)

        console.print(
            Panel(
                Align.center(
                    "[dim]Stay ethical. Stay authorized.[/dim]",
                    vertical="middle",
                ),
                border_style="dim",
                padding=(1, 4),
            )
        )

    # ══ Screen layout ════════════════════════════════════════════════════════

    def _print_banner(self) -> None:
        art = Text(_BANNER_ART, style="bold red", justify="center")
        line1 = Text(
            f"  LLM-Orchestrated Automated Pentesting Framework  {_VERSION}  ",
            style="bold white",
            justify="center",
        )
        line2 = Text(
            "  ⚠  FOR AUTHORIZED LAB ENVIRONMENTS ONLY  ⚠  ",
            style="bold yellow",
            justify="center",
        )
        content = Group(Align.center(art), Text(""), Align.center(line1), Align.center(line2))
        console.print(
            Panel(content, border_style="bold red", padding=(0, 2))
        )

    def _print_status_strip(self) -> None:
        """Quick connectivity indicators — TCP probes only, no heavy imports."""
        env = self._load_env()
        msf_host = env.get("MSF_HOST", "127.0.0.1")
        msf_port = int(env.get("MSF_PORT", "55553"))
        oll_host = env.get("OLLAMA_HOST", "127.0.0.1")
        oll_port = int(env.get("OLLAMA_PORT", "11434"))
        target = env.get("TARGET_NETWORK", "192.168.56.0/24")

        msf_up = self._tcp_probe(msf_host, msf_port)
        oll_up = self._tcp_probe(oll_host, oll_port)
        nmap_ok = bool(shutil.which("nmap"))

        def _dot(up: bool, label: str, detail: str) -> Text:
            t = Text()
            t.append("● ", style="bold green" if up else "bold red")
            t.append(label + "  ", style="bold")
            t.append(detail, style="dim")
            return t

        row_table = Table(box=None, show_header=False, padding=(0, 3), expand=True)
        row_table.add_column(justify="left")
        row_table.add_column(justify="left")
        row_table.add_column(justify="left")
        row_table.add_column(justify="left")

        row_table.add_row(
            _dot(msf_up, "MSF RPC", f"{msf_host}:{msf_port}"),
            _dot(oll_up, "Ollama", f"{oll_host}:{oll_port}"),
            Text.assemble(("◆ ", "bold cyan"), ("Target  ", "bold"), (target, "dim")),
            _dot(nmap_ok, "nmap", "found" if nmap_ok else "not found"),
        )

        console.print(Panel(row_table, border_style="dim", padding=(0, 1)))

    def _print_main_menu(self) -> None:
        t = Table(
            box=box.ROUNDED,
            show_header=False,
            padding=(0, 2),
            border_style="cyan",
            expand=False,
        )
        t.add_column(style="bold cyan", width=4, justify="right")
        t.add_column(style="bold white", min_width=22)
        t.add_column(style="dim")

        for key, label, desc in _MENU_OPTIONS:
            if key == "0":
                t.add_row("", "", "")  # spacer
                t.add_row("[dim]0[/dim]", "[dim]Exit[/dim]", "")
            else:
                t.add_row(
                    f"[bold cyan]{key}[/bold cyan]",
                    f"[bold white]{label}[/bold white]",
                    f"[dim]{desc}[/dim]",
                )

        console.print(
            Panel(t, title="[bold cyan]  MAIN MENU  [/bold cyan]", border_style="cyan", padding=(0, 1))
        )

    # ══ Menu handlers ════════════════════════════════════════════════════════

    def _menu_run(self) -> None:
        """Guided pentest wizard → executes pipeline with live progress display."""
        console.print(Rule("[bold green]  RUN PENTEST  [/bold green]", style="green"))
        console.print()

        env = self._load_env()

        console.print(
            Panel(
                "[bold]Configure this pentest session.[/bold]\n"
                "[dim]Press Enter to accept the shown default value.[/dim]",
                border_style="green",
                padding=(0, 2),
            )
        )
        console.print()

        target = Prompt.ask(
            "  [bold]Target[/bold]         [dim]IP or CIDR[/dim]",
            default=env.get("TARGET_NETWORK", "192.168.56.0/24"),
        )
        profile = Prompt.ask(
            "  [bold]Profile[/bold]        [dim]stealth | balanced | aggressive[/dim]",
            choices=["stealth", "balanced", "aggressive"],
            default=env.get("EVASION_PROFILE", "balanced"),
        )
        timeout_min = IntPrompt.ask(
            "  [bold]Timeout[/bold]        [dim]minutes[/dim]",
            default=int(env.get("GLOBAL_TIMEOUT_MINUTES", "15")),
        )
        dry_run = Confirm.ask(
            "  [bold]Dry-run?[/bold]       [dim]simulate without real exploits[/dim]",
            default=False,
        )
        verbose = Confirm.ask(
            "  [bold]Verbose?[/bold]       [dim]enable DEBUG log output[/dim]",
            default=False,
        )

        # Summary panel
        console.print()
        s = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        s.add_column(style="bold dim", width=18)
        s.add_column(style="bold green")
        s.add_row("Target",   target)
        s.add_row("Profile",  profile)
        s.add_row("Timeout",  f"{timeout_min} min")
        s.add_row("Mode",     "[yellow]DRY-RUN — no real exploits[/yellow]" if dry_run else "Live exploitation")
        s.add_row("Logging",  "DEBUG" if verbose else "INFO")
        console.print(
            Panel(s, title="[bold green]  Session Summary  [/bold green]", border_style="green")
        )
        console.print()

        if not Confirm.ask("  [bold]Start pentest now?[/bold]", default=True):
            console.print("[dim]  Cancelled.[/dim]")
            return

        # Root check — SYN scan requires raw sockets
        if not dry_run and os.geteuid() != 0:
            console.print()
            console.print(
                Panel(
                    "[yellow bold]Note:[/yellow bold]  nmap SYN scan ([dim]-sS[/dim]) requires root privileges.\n\n"
                    "[dim]Re-run as:[/dim]  [bold]sudo python -m redops menu[/bold]\n"
                    "[dim]Or use:[/dim]     [bold]sudo redops menu[/bold]",
                    border_style="yellow",
                    padding=(0, 2),
                )
            )
            if not Confirm.ask(
                "  Continue anyway? [dim](nmap will fall back to TCP connect scan)[/dim]",
                default=False,
            ):
                return

        console.print()
        asyncio.run(
            self._run_pipeline_live(target, profile, timeout_min, dry_run, verbose)
        )

    async def _run_pipeline_live(
        self,
        target: str,
        profile: str,
        timeout_minutes: int,
        dry_run: bool,
        verbose: bool,
    ) -> None:
        """Execute the full pipeline with a live Rich progress dashboard."""
        from redops.config.constants import EvasionProfile
        from redops.config.settings import get_settings
        from redops.core.events import (
            EventBus,
            ExploitSuccessEvent,
            PhaseCompletedEvent,
            PhaseStartedEvent,
        )
        from redops.core.pipeline import PentestPipeline
        from redops.evasion.evasion_engine import EvasionEngine
        from redops.orchestrator.llm_engine import LLMOrchestrator

        get_settings.cache_clear()
        settings = get_settings().model_copy(
            update={
                "global_timeout_minutes": timeout_minutes,
                "evasion_profile": profile,
                "log_level": "DEBUG" if verbose else "INFO",
            }
        )

        if verbose:
            from redops import set_log_level
            set_log_level("DEBUG")

        event_bus = EventBus()
        evasion = EvasionEngine(EvasionProfile(profile))
        llm = LLMOrchestrator(settings, event_bus)
        pipeline = PentestPipeline(settings, llm, evasion, event_bus)

        # Shared state updated by event subscribers
        _PHASES = ["RECON", "SCAN", "EXPLOIT", "POST_EXPLOIT", "REPORT"]
        phase_status: dict[str, str] = {p: "waiting" for p in _PHASES}
        stats: dict[str, int] = {"compromised": 0}
        start_ts = time.time()

        async def _on_phase_started(ev: PhaseStartedEvent) -> None:  # type: ignore[override]
            pname = ev.phase.value.upper().replace("-", "_")
            phase_status[pname] = "running"

        async def _on_phase_completed(ev: PhaseCompletedEvent) -> None:  # type: ignore[override]
            pname = ev.phase.value.upper().replace("-", "_")
            phase_status[pname] = "done"

        async def _on_exploit_success(ev: ExploitSuccessEvent) -> None:  # type: ignore[override]
            stats["compromised"] += 1

        await event_bus.subscribe(PhaseStartedEvent, _on_phase_started)
        await event_bus.subscribe(PhaseCompletedEvent, _on_phase_completed)
        await event_bus.subscribe(ExploitSuccessEvent, _on_exploit_success)

        _PHASE_LABELS = {
            "RECON":        "Discover live hosts on the network",
            "SCAN":         "Port scan & vulnerability detection",
            "EXPLOIT":      "LLM-driven exploit selection & execution",
            "POST_EXPLOIT": "Evidence collection & privilege escalation check",
            "REPORT":       "Generate PDF pentest report",
        }

        def _build_panel() -> Panel:
            elapsed = int(time.time() - start_ts)
            mm, ss = divmod(elapsed, 60)

            # Header row
            hdr = Text()
            hdr.append("  Target: ", style="bold")
            hdr.append(target, style="cyan")
            hdr.append("   Profile: ", style="bold")
            hdr.append(profile, style="cyan")
            hdr.append("   Elapsed: ", style="bold")
            hdr.append(f"{mm:02d}:{ss:02d}", style="cyan")
            if dry_run:
                hdr.append("   [DRY-RUN]", style="bold yellow")

            # Phase table
            pt = Table(box=None, show_header=False, padding=(0, 1), expand=True)
            pt.add_column(width=3, justify="center")
            pt.add_column(min_width=16, style="bold")
            pt.add_column(style="dim")

            for pname in _PHASES:
                st = phase_status.get(pname, "waiting")
                if st == "done":
                    icon, style = "[bold green]✓[/bold green]", "green"
                elif st == "running":
                    icon, style = "[bold yellow]⟳[/bold yellow]", "bold yellow"
                else:
                    icon, style = "[dim]○[/dim]", "dim"
                label = pname.replace("_", "-")
                desc = _PHASE_LABELS.get(pname, "")
                pt.add_row(icon, f"[{style}]{label}[/{style}]", f"[dim]{desc}[/dim]")

            # Stats footer
            needed = settings.min_services_to_compromise
            comp = stats["compromised"]
            comp_text = Text()
            comp_text.append("\n  Compromised services: ", style="bold")
            comp_text.append(str(comp), style="bold green" if comp >= needed else "bold yellow")
            comp_text.append(f" / {needed} required")

            return Panel(
                Group(hdr, Text(""), pt, comp_text),
                title="[bold green]  PENTEST IN PROGRESS  [/bold green]",
                border_style="green",
                padding=(0, 1),
            )

        # Run pipeline concurrently with live display.
        # Suppress all logging output while Live owns the terminal so that
        # structlog / stdlib log lines don't bleed into the Rich panel.
        import logging as _logging
        _root_logger = _logging.getLogger()
        _original_handlers = _root_logger.handlers[:]
        _null_handler = _logging.NullHandler()
        _root_logger.handlers = [_null_handler]

        error: Exception | None = None
        result = None

        try:
            with Live(_build_panel(), refresh_per_second=4, console=console) as live:
                pipeline_task = asyncio.create_task(
                    pipeline.run(target, dry_run=dry_run)
                )
                while not pipeline_task.done():
                    await asyncio.sleep(0.25)
                    live.update(_build_panel())
        finally:
            # Restore handlers so subsequent commands (health, cleanup…) log normally
            _root_logger.handlers = _original_handlers

        try:
            result = pipeline_task.result()
        except Exception as exc:
            error = exc

        console.print()

        if error:
            console.print(
                Panel(
                    f"[bold red]Pipeline failed:[/bold red]\n{error}",
                    border_style="red",
                    padding=(0, 2),
                )
            )
        elif result:
            comp_count = len(result.compromised_services)
            needed = settings.min_services_to_compromise
            success = comp_count >= needed
            console.print(
                Panel(
                    Text.assemble(
                        ("OBJECTIVE MET" if success else "PARTIAL — objective not fully met",
                         "bold green" if success else "bold yellow"),
                        "\n\n",
                        ("Compromised services: ", "bold"),
                        (str(comp_count), "bold green" if success else "bold yellow"),
                        (f" / {needed} required\n", ""),
                        ("Report directory:     ", "bold"),
                        (settings.report_output_dir, "dim"),
                    ),
                    title="[bold]Run Complete[/bold]",
                    border_style="green" if success else "yellow",
                    padding=(0, 2),
                )
            )

    # ─────────────────────────────────────────────────────────────────────────

    def _menu_health(self) -> None:
        """Full health check with Rich table output."""
        console.print(Rule("[bold cyan]  HEALTH CHECK  [/bold cyan]", style="cyan"))
        console.print()

        async def _check() -> None:
            import ipaddress

            get_settings_fn = None
            try:
                from redops.config.settings import get_settings
                get_settings.cache_clear()
                settings = get_settings()
                get_settings_fn = get_settings
            except Exception as exc:
                console.print(f"[red]Cannot load settings:[/red] {exc}")
                return

            from redops.core.events import EventBus
            from redops.orchestrator.llm_engine import LLMOrchestrator

            event_bus = EventBus()
            llm = LLMOrchestrator(settings, event_bus)

            t = Table(
                title="[bold cyan]  Service Status  [/bold cyan]",
                box=box.ROUNDED,
                border_style="cyan",
                show_lines=True,
            )
            t.add_column("Service",        style="bold white",  min_width=26)
            t.add_column("Status",                              min_width=18)
            t.add_column("Detail",         style="dim",         min_width=44)

            # Metasploit RPC
            try:
                with socket.create_connection(
                    (settings.msf_host, settings.msf_port), timeout=3.0
                ):
                    pass
                from redops.modules.exploiter import MSFClient
                msf = await MSFClient.get_instance(settings)
                sessions = await msf.list_sessions()
                t.add_row(
                    "Metasploit RPC",
                    "[bold green]● ONLINE[/bold green]",
                    f"{settings.msf_host}:{settings.msf_port}  ·  {len(sessions)} active session(s)",
                )
                MSFClient.reset()
            except Exception as exc:
                t.add_row(
                    "Metasploit RPC",
                    "[bold red]● OFFLINE[/bold red]",
                    f"[red]{exc}[/red]\nStart with: bash scripts/start_lab.sh",
                )

            # Ollama
            try:
                ok = await llm.health_check()
                t.add_row(
                    f"Ollama / {settings.ollama_model}",
                    "[bold green]● ONLINE[/bold green]" if ok else "[bold yellow]● MODEL MISSING[/bold yellow]",
                    settings.ollama_base_url
                    + ("" if ok else f"\n  Pull model: ollama pull {settings.ollama_model}"),
                )
            except Exception as exc:
                t.add_row("Ollama LLM", "[bold red]● OFFLINE[/bold red]", f"[red]{exc}[/red]")

            # Target network ping
            try:
                net = ipaddress.ip_network(settings.target_network, strict=False)
                probe = str(next(net.hosts()))
                res = subprocess.run(
                    ["ping", "-c", "1", "-W", "2", probe],
                    capture_output=True,
                    timeout=5,
                )
                if res.returncode == 0:
                    t.add_row(
                        "Target Network",
                        "[bold green]● REACHABLE[/bold green]",
                        f"{settings.target_network}  →  probed {probe}",
                    )
                else:
                    t.add_row(
                        "Target Network",
                        "[bold red]● UNREACHABLE[/bold red]",
                        f"{settings.target_network}\nStart VM: bash scripts/start_lab.sh",
                    )
            except Exception as exc:
                t.add_row("Target Network", "[bold red]● ERROR[/bold red]", str(exc))

            # LHOST
            lhost = settings.attacker_ip
            t.add_row(
                "Attacker IP (LHOST)",
                "[bold green]● DETECTED[/bold green]" if lhost else "[bold yellow]● NOT SET[/bold yellow]",
                lhost if lhost else "Set LHOST= in .env  (needed for reverse payloads)",
            )

            # nmap
            nmap_path = shutil.which("nmap")
            t.add_row(
                "nmap",
                "[bold green]● FOUND[/bold green]" if nmap_path else "[bold red]● MISSING[/bold red]",
                nmap_path or "sudo pacman -S nmap",
            )

            console.print(t)

        asyncio.run(_check())

    # ─────────────────────────────────────────────────────────────────────────

    def _menu_config(self) -> None:
        """Interactive .env configuration editor."""
        console.print(Rule("[bold yellow]  CONFIGURATION  [/bold yellow]", style="yellow"))
        console.print()
        console.print(
            f"  [dim].env file:[/dim]  [bold]{self._env_file}[/bold]\n"
            "  [dim]Enter a field number to change its value. Press Enter with no number to go back.[/dim]\n"
        )

        env = self._load_env()

        while True:
            # (Re-)print the full table each iteration so changes are visible
            t = Table(box=box.ROUNDED, border_style="yellow", show_lines=True)
            t.add_column("#",     style="bold cyan",  width=4,   justify="right")
            t.add_column("Section", style="dim",       min_width=16)
            t.add_column("Key",   style="bold white", min_width=28)
            t.add_column("Value", style="green",      min_width=24)
            t.add_column("Description", style="dim",  min_width=40)

            last_section = ""
            for i, field in enumerate(_CONFIG_FIELDS, 1):
                val = env.get(field["key"], field["def"])
                display = ("•" * min(len(val), 12)) if (field["secret"] and val) else (val or "[dim]not set[/dim]")
                section_cell = field["s"] if field["s"] != last_section else ""
                last_section = field["s"]
                t.add_row(str(i), section_cell, field["key"], display, field["desc"])

            console.print(t)
            console.print()

            choice = Prompt.ask(
                "  [bold yellow]Field # to edit[/bold yellow] [dim](Enter to go back)[/dim]",
                default="",
            )
            if not choice.strip():
                break

            try:
                idx = int(choice) - 1
                if not (0 <= idx < len(_CONFIG_FIELDS)):
                    raise ValueError
            except ValueError:
                console.print("[red]  Invalid number — enter a number from 1 to 16.[/red]\n")
                continue

            field = _CONFIG_FIELDS[idx]
            current = env.get(field["key"], field["def"])

            console.print(
                f"\n  [bold]{field['key']}[/bold]  —  [dim]{field['desc']}[/dim]"
            )

            if field["secret"]:
                new_val = Prompt.ask(
                    "  New value [dim](input hidden)[/dim]",
                    password=True,
                    default=current,
                )
            else:
                new_val = Prompt.ask("  New value", default=current)

            if new_val != current:
                self._save_env_value(field["key"], new_val)
                env[field["key"]] = new_val
                console.print(f"  [green]✓  {field['key']} saved.[/green]\n")
            else:
                console.print("  [dim]No change.[/dim]\n")

        console.print(
            Panel(
                "[green]Configuration saved.[/green]\n"
                "[dim]Changes take effect on the next command or restart.[/dim]",
                border_style="green",
                padding=(0, 2),
            )
        )

    # ─────────────────────────────────────────────────────────────────────────

    def _menu_report(self) -> None:
        """Regenerate a PDF report from a saved checkpoint."""
        console.print(Rule("[bold blue]  GENERATE REPORT  [/bold blue]", style="blue"))
        console.print()

        ckpt_dir = Path("checkpoints")
        checkpoints = sorted(
            ckpt_dir.glob("session_*.json") if ckpt_dir.exists() else [],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        if not checkpoints:
            console.print(
                Panel(
                    "[yellow]No checkpoints found.[/yellow]\n\n"
                    "[dim]Checkpoints are saved automatically during a pentest run.\n"
                    "Run a pentest first, then come back here to regenerate its report.[/dim]",
                    border_style="yellow",
                    padding=(0, 2),
                )
            )
            return

        t = Table(box=box.ROUNDED, border_style="blue", show_lines=False)
        t.add_column("#",          style="bold cyan", width=4,  justify="right")
        t.add_column("Session ID", style="bold white", min_width=18)
        t.add_column("Saved",      style="dim",        min_width=20)
        t.add_column("Size",       style="dim",        justify="right")

        for i, p in enumerate(checkpoints, 1):
            session_id = p.stem.replace("session_", "")
            dt = time.strftime("%Y-%m-%d  %H:%M:%S", time.localtime(p.stat().st_mtime))
            size_kb = p.stat().st_size // 1024
            t.add_row(str(i), session_id, dt, f"{size_kb} KB")

        console.print(t)
        console.print()

        try:
            num = IntPrompt.ask("  [bold]Select checkpoint #[/bold]", default=1)
            ckpt_file = checkpoints[num - 1]
        except (ValueError, IndexError):
            console.print("[red]  Invalid selection.[/red]")
            return

        session_id = ckpt_file.stem.replace("session_", "")
        console.print(f"\n  Generating report for session [bold]{session_id}[/bold]...\n")

        async def _gen() -> None:
            from datetime import UTC, datetime

            from redops.config.settings import get_settings
            from redops.core.events import EventBus
            from redops.core.models import ReportData, SessionState
            from redops.reporting.report_generator import ReportGenerator

            state = SessionState.model_validate_json(ckpt_file.read_text(encoding="utf-8"))
            settings = get_settings()
            gen = ReportGenerator(EventBus())
            report_data = ReportData(
                session_id=state.session_id,
                targets=state.targets,
                vulnerabilities=state.vulnerabilities,
                compromised_services=state.compromised_services,
                phase_results=state.phase_results,
                decisions=state.decisions,
                total_duration_seconds=(datetime.now(UTC) - state.started_at).total_seconds(),
            )
            path = await gen.generate(report_data, settings.report_output_dir)
            console.print(
                Panel(
                    f"[bold green]✓  Report generated:[/bold green]\n[dim]{path}[/dim]",
                    border_style="green",
                    padding=(0, 2),
                )
            )

        asyncio.run(_gen())

    # ─────────────────────────────────────────────────────────────────────────

    def _menu_cleanup(self) -> None:
        """Close orphaned Metasploit sessions."""
        console.print(Rule("[bold magenta]  CLEANUP SESSIONS  [/bold magenta]", style="magenta"))
        console.print()

        async def _do() -> None:
            from redops.config.settings import get_settings
            from redops.modules.exploiter import MSFClient

            settings = get_settings()
            try:
                msf = await MSFClient.get_instance(settings)
                sessions = await msf.list_sessions()

                if not sessions:
                    console.print(
                        Panel(
                            "[bold green]✓  No active sessions — environment is clean.[/bold green]",
                            border_style="green",
                            padding=(0, 2),
                        )
                    )
                    return

                t = Table(box=box.SIMPLE, show_header=True)
                t.add_column("ID",      style="bold cyan",    width=8)
                t.add_column("Type",    style="dim",          min_width=12)
                t.add_column("Target",  style="yellow",       min_width=18)
                t.add_column("Via",     style="dim",          min_width=30)

                for s in sessions:
                    t.add_row(
                        str(s.get("id", "?")),
                        str(s.get("type", "?")),
                        str(s.get("target_host", "?")),
                        str(s.get("via_exploit", "?")),
                    )

                console.print(t)
                console.print()

                if Confirm.ask(
                    f"  [bold]Close all {len(sessions)} session(s)?[/bold]",
                    default=False,
                ):
                    ids = [str(s["id"]) for s in sessions]
                    results = await msf.close_sessions(ids)
                    closed = sum(1 for ok in results.values() if ok)
                    console.print(
                        f"\n  [bold green]✓  Closed {closed} / {len(ids)} session(s).[/bold green]"
                    )
                else:
                    console.print("  [dim]Cancelled — no sessions closed.[/dim]")

            except Exception as exc:
                console.print(
                    Panel(
                        f"[red]Cannot connect to MSF RPC:[/red] {exc}\n\n"
                        "[dim]Start msfrpcd with:[/dim]  [bold]bash scripts/start_lab.sh[/bold]",
                        border_style="red",
                        padding=(0, 2),
                    )
                )
            finally:
                MSFClient.reset()

        # Suppress ALL log and stderr output while connecting to MSF so only
        # the Rich panel reaches the user.
        #   • logging.disable(CRITICAL) kills every stdlib log record globally
        #     (covers structlog via LoggerFactory, urllib3, retry package, etc.)
        #   • sys.stderr swap catches any direct stderr.write() calls that
        #     bypass the logging framework (pymetasploit3 retry noise).
        import logging as _logging
        _old_stderr = sys.stderr
        sys.stderr = io.StringIO()
        _logging.disable(_logging.CRITICAL)
        try:
            asyncio.run(_do())
        finally:
            _logging.disable(_logging.NOTSET)
            sys.stderr = _old_stderr

    # ─────────────────────────────────────────────────────────────────────────

    def _menu_setup(self) -> None:
        """Step-by-step first-time setup and installation wizard."""
        console.print(Rule("[bold white]  SETUP WIZARD  [/bold white]", style="white"))
        console.print()
        console.print(
            Panel(
                "[bold]First-time installation guide[/bold]\n\n"
                "[dim]This wizard checks every required component and guides you\n"
                "through installation, startup and configuration of the full lab.[/dim]",
                border_style="white",
                padding=(0, 2),
            )
        )
        console.print()

        all_ok = True
        env = self._load_env()

        # ── Step 1 — Python virtualenv ────────────────────────────────────
        console.print(Rule("[dim]Step 1 / 6  —  Python Virtualenv[/dim]", style="dim"))
        venv = Path(".venv")
        if (venv / "bin" / "python").exists():
            console.print("  [green]✓[/green]  Virtualenv found at [dim].venv/[/dim]")
            try:
                ver = importlib.metadata.version("redops")
                console.print(f"  [green]✓[/green]  RedOps [bold]{ver}[/bold] installed")
            except importlib.metadata.PackageNotFoundError:
                console.print("  [red]✗[/red]  RedOps package not installed in this environment")
                console.print("     [dim]Run:[/dim]  [bold]pip install -e '.[dev]'[/bold]")
                all_ok = False
        else:
            console.print("  [red]✗[/red]  Virtualenv not found")
            console.print("     [dim]Run:[/dim]  [bold]python3 -m venv .venv && source .venv/bin/activate && pip install -e '.[dev]'[/bold]")
            all_ok = False

        # ── Step 2 — nmap ─────────────────────────────────────────────────
        console.print()
        console.print(Rule("[dim]Step 2 / 6  —  nmap[/dim]", style="dim"))
        nmap = shutil.which("nmap")
        if nmap:
            console.print(f"  [green]✓[/green]  nmap found at [dim]{nmap}[/dim]")
        else:
            console.print("  [red]✗[/red]  nmap not found")
            console.print("     [dim]Install:[/dim]  [bold]sudo pacman -S nmap[/bold]")
            all_ok = False

        # ── Step 3 — Metasploit ───────────────────────────────────────────
        console.print()
        console.print(Rule("[dim]Step 3 / 6  —  Metasploit Framework[/dim]", style="dim"))
        msfrpcd_bin = shutil.which("msfrpcd")
        if msfrpcd_bin:
            console.print(f"  [green]✓[/green]  msfrpcd found at [dim]{msfrpcd_bin}[/dim]")
        else:
            console.print("  [red]✗[/red]  Metasploit not installed")
            console.print("     [dim]Install (AUR):[/dim]  [bold]yay -S metasploit[/bold]")
            all_ok = False

        msf_host = env.get("MSF_HOST", "127.0.0.1")
        msf_port = int(env.get("MSF_PORT", "55553"))
        msf_pass = env.get("MSF_PASSWORD", "msf_rpc_password")

        if self._tcp_probe(msf_host, msf_port):
            console.print(f"  [green]✓[/green]  msfrpcd running on [dim]{msf_host}:{msf_port}[/dim]")
        else:
            console.print(f"  [yellow]⚠[/yellow]  msfrpcd not running on [dim]{msf_host}:{msf_port}[/dim]")
            if msfrpcd_bin and Confirm.ask("     Start msfrpcd now?", default=True):
                console.print("     [dim]Starting msfrpcd...[/dim]")
                log_file = open("/tmp/msfrpcd-redops.log", "w")
                subprocess.Popen(
                    ["msfrpcd", "-P", msf_pass, "-S", "-a", msf_host, "-p", str(msf_port)],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                )
                with console.status("     [dim]Waiting for msfrpcd to initialize...[/dim]"):
                    for _ in range(12):
                        time.sleep(3)
                        if self._tcp_probe(msf_host, msf_port):
                            console.print("     [green]✓[/green]  msfrpcd started")
                            break
                    else:
                        console.print("     [yellow]⚠[/yellow]  Still initializing — check: [dim]tail /tmp/msfrpcd-redops.log[/dim]")

        # ── Step 4 — VirtualBox ───────────────────────────────────────────
        console.print()
        console.print(Rule("[dim]Step 4 / 6  —  VirtualBox & Lab Network[/dim]", style="dim"))
        vbox = shutil.which("VBoxManage")
        if vbox:
            try:
                ver_out = subprocess.run(
                    ["VBoxManage", "--version"], capture_output=True, text=True, timeout=5
                )
                console.print(f"  [green]✓[/green]  VirtualBox [dim]{ver_out.stdout.strip()}[/dim]")
            except Exception:
                console.print("  [green]✓[/green]  VirtualBox found")
        else:
            console.print("  [red]✗[/red]  VirtualBox not installed")
            console.print("     [dim]Install:[/dim]  [bold]sudo pacman -S virtualbox[/bold]")
            all_ok = False

        if self._host_only_net_present():
            console.print("  [green]✓[/green]  Host-only interface 192.168.56.x present")
        else:
            console.print("  [yellow]⚠[/yellow]  No 192.168.56.x interface — run: [bold]sudo bash scripts/setup_vbox_net.sh[/bold]")

        # ── Step 5 — Ollama ───────────────────────────────────────────────
        console.print()
        console.print(Rule("[dim]Step 5 / 6  —  Ollama LLM Server[/dim]", style="dim"))
        ollama_bin = shutil.which("ollama")
        oll_host = env.get("OLLAMA_HOST", "127.0.0.1")
        oll_port = int(env.get("OLLAMA_PORT", "11434"))
        oll_model = env.get("OLLAMA_MODEL", "mistral")

        if ollama_bin:
            console.print(f"  [green]✓[/green]  Ollama found at [dim]{ollama_bin}[/dim]")
        else:
            console.print("  [red]✗[/red]  Ollama not installed")
            console.print("     [dim]Install:[/dim]  [bold]curl -fsSL https://ollama.com/install.sh | sh[/bold]")
            all_ok = False

        if self._tcp_probe(oll_host, oll_port):
            console.print(f"  [green]✓[/green]  Ollama server running on [dim]{oll_host}:{oll_port}[/dim]")
            # Check model availability
            try:
                with urllib.request.urlopen(
                    f"http://{oll_host}:{oll_port}/api/tags", timeout=5
                ) as resp:
                    data = _json.loads(resp.read())
                    models = [m.get("name", "") for m in data.get("models", [])]
                    if any(oll_model in m for m in models):
                        console.print(f"  [green]✓[/green]  Model [bold]{oll_model}[/bold] available")
                    else:
                        console.print(f"  [yellow]⚠[/yellow]  Model [bold]{oll_model}[/bold] not yet downloaded")
                        if Confirm.ask(f"     Pull [bold]{oll_model}[/bold] now? [dim](may take several minutes)[/dim]", default=True):
                            console.print(f"     [dim]Pulling {oll_model}...[/dim]")
                            subprocess.run(["ollama", "pull", oll_model], check=True)
                            console.print(f"     [green]✓[/green]  Model [bold]{oll_model}[/bold] ready")
            except Exception as exc:
                console.print(f"  [yellow]⚠[/yellow]  Could not verify models: {exc}")
        else:
            console.print(f"  [yellow]⚠[/yellow]  Ollama not running on [dim]{oll_host}:{oll_port}[/dim]")
            if ollama_bin and Confirm.ask("     Start Ollama now?", default=True):
                log_file = open("/tmp/ollama-redops.log", "w")
                subprocess.Popen(
                    ["ollama", "serve"], stdout=log_file, stderr=subprocess.STDOUT
                )
                with console.status("     [dim]Waiting for Ollama...[/dim]"):
                    for _ in range(15):
                        time.sleep(1)
                        if self._tcp_probe(oll_host, oll_port):
                            console.print("     [green]✓[/green]  Ollama started")
                            break
                    else:
                        console.print("     [yellow]⚠[/yellow]  Check: [dim]tail /tmp/ollama-redops.log[/dim]")

        # ── Step 6 — .env configuration ───────────────────────────────────
        console.print()
        console.print(Rule("[dim]Step 6 / 6  —  Environment Configuration[/dim]", style="dim"))
        if self._env_file.exists():
            console.print(f"  [green]✓[/green]  .env found at [dim]{self._env_file}[/dim]")
            if Confirm.ask("     Review and edit configuration now?", default=False):
                self._menu_config()
        else:
            console.print(f"  [yellow]⚠[/yellow]  No .env file found")
            if Confirm.ask(f"     Create default .env at [dim]{self._env_file}[/dim]?", default=True):
                self._create_default_env()
                console.print("     [green]✓[/green]  .env created — you can edit it with option [bold]3[/bold]")
                if Confirm.ask("     Edit it now?", default=True):
                    self._menu_config()

        # ── Summary ───────────────────────────────────────────────────────
        console.print()
        if all_ok:
            console.print(
                Panel(
                    "[bold green]✓  All components are installed and configured.[/bold green]\n\n"
                    "[dim]Return to the main menu and select [bold]1 — Run Pentest[/bold] to start.[/dim]",
                    border_style="green",
                    padding=(0, 2),
                )
            )
        else:
            console.print(
                Panel(
                    "[bold yellow]Some components need attention.[/bold yellow]\n\n"
                    "[dim]Fix the items marked [bold red]✗[/bold red] above,\n"
                    "then run the Setup Wizard again.[/dim]",
                    border_style="yellow",
                    padding=(0, 2),
                )
            )

    # ══ .env helpers ═════════════════════════════════════════════════════════

    def _load_env(self) -> dict[str, str]:
        """Parse .env file into a plain dict (no shell expansion)."""
        result: dict[str, str] = {}
        if not self._env_file.exists():
            return result
        for line in self._env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            result[key.strip()] = val.strip().strip('"').strip("'")
        return result

    def _save_env_value(self, key: str, new_value: str) -> None:
        """Update a single key in .env preserving all comments and structure."""
        lines = self._env_file.read_text(encoding="utf-8").splitlines() if self._env_file.exists() else []
        new_lines: list[str] = []
        updated = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(f"{key}=") or stripped.startswith(f"{key} ="):
                new_lines.append(f"{key}={new_value}")
                updated = True
            else:
                new_lines.append(line)
        if not updated:
            new_lines.append(f"{key}={new_value}")
        self._env_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    def _create_default_env(self) -> None:
        """Write a minimal .env from _CONFIG_FIELDS defaults."""
        current_section = ""
        lines = [
            "# RedOps Automático — Environment Configuration",
            "# Generated by setup wizard — edit values as needed.",
            "",
        ]
        for field in _CONFIG_FIELDS:
            if field["s"] != current_section:
                current_section = field["s"]
                lines.append(f"# -- {current_section}")
            lines.append(f"{field['key']}={field['def']}")
        lines.append("")
        self._env_file.write_text("\n".join(lines), encoding="utf-8")

    # ══ Utilities ════════════════════════════════════════════════════════════

    @staticmethod
    def _tcp_probe(host: str, port: int, timeout: float = 2.0) -> bool:
        """Return True if a TCP connection to host:port succeeds."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    @staticmethod
    def _host_only_net_present() -> bool:
        """Check if any interface has an IP in 192.168.56.0/24."""
        try:
            result = subprocess.run(
                ["ip", "addr", "show"], capture_output=True, text=True, timeout=5
            )
            return "192.168.56." in result.stdout
        except Exception:
            return False

    def _pause(self) -> None:
        """Wait for Enter before returning to the main menu."""
        console.print()
        Prompt.ask("[dim]  Press Enter to return to the main menu[/dim]", default="")


# ── Module-level entry point ──────────────────────────────────────────────────


def run_tui() -> None:
    """Launch the interactive TUI. Called by `redops menu` and `redops` (no args)."""
    RedOpsTUI().run()
