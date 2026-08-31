"""RedOps CLI — entry point for the pentesting framework.

Provides ``run``, ``health`` and ``report`` commands via Click with
a Rich live dashboard during pipeline execution.

.. warning::

    This framework is designed EXCLUSIVELY for ethical lab environments.
    Unauthorised use against systems you do not own is **illegal**.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime

import click
import structlog
from rich.console import Console
from rich.live import Live
from rich.table import Table

from redops.config.constants import EvasionProfile
from redops.config.settings import Settings, get_settings
from redops.core.events import EventBus
from redops.core.pipeline import PentestPipeline
from redops.evasion.evasion_engine import EvasionEngine
from redops.orchestrator.llm_engine import LLMOrchestrator

log = structlog.get_logger(__name__)

BANNER = r"""
██████╗ ███████╗██████╗  ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝
██████╔╝█████╗  ██║  ██║██║   ██║██████╔╝███████╗
██╔══██╗██╔══╝  ██║  ██║██║   ██║██╔═══╝ ╚════██║
██║  ██║███████╗██████╔╝╚██████╔╝██║     ███████║
╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚══════╝
      Automated Pentesting Framework v1.0.0
      ⚠  ETHICAL LAB USE ONLY ⚠
"""

console = Console()


# ── Helpers ─────────────────────────────────────────────────────────


def _build_components(
    settings: Settings,
    profile: str,
) -> tuple[LLMOrchestrator, EvasionEngine, EventBus]:
    """Instantiate the shared infrastructure components."""
    event_bus = EventBus()
    llm = LLMOrchestrator(settings, event_bus)
    evasion_profile = EvasionProfile(profile.lower())
    evasion = EvasionEngine(evasion_profile)
    return llm, evasion, event_bus


def _run_async(coro: object) -> object:
    """Run an async coroutine from synchronous Click context."""
    return asyncio.run(coro)  # type: ignore[arg-type]


# ── CLI group ───────────────────────────────────────────────────────


@click.group(invoke_without_command=True)
@click.version_option(version="1.0.0", prog_name="redops")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """RedOps Automático — LLM-orchestrated pentesting framework.

    Run without a subcommand to launch the interactive menu.
    """
    if ctx.invoked_subcommand is None:
        from redops.tui import run_tui
        run_tui()


# ── run command ─────────────────────────────────────────────────────


@cli.command()
@click.option("--target", "-t", required=True, help="Target IP or CIDR")
@click.option(
    "--profile",
    "-p",
    default="balanced",
    type=click.Choice(["stealth", "balanced", "aggressive"], case_sensitive=False),
    help="Evasion profile",
)
@click.option("--model", "-m", default=None, help="Ollama model (override config)")
@click.option("--output", "-o", default="./reports", help="Report output directory")
@click.option("--timeout", default=15, help="Global timeout in minutes")
@click.option("--verbose", "-v", is_flag=True, help="Enable DEBUG logging")
@click.option("--resume", is_flag=True, help="Resume from last checkpoint")
@click.option("--dry-run", is_flag=True, help="Simulate without real exploits")
def run(
    target: str,
    profile: str,
    model: str | None,
    output: str,
    timeout: int,
    verbose: bool,
    resume: bool,
    dry_run: bool,
) -> None:
    """Execute a full PTES penetration test against the target."""
    settings = get_settings()
    # Apply CLI overrides via model_copy (preserves Pydantic validation)
    overrides: dict[str, object] = {"report_output_dir": output, "global_timeout_minutes": timeout}
    if model:
        overrides["ollama_model"] = model
    if verbose:
        overrides["log_level"] = "DEBUG"
    settings = settings.model_copy(update=overrides)

    if verbose:
        from redops import set_log_level
        set_log_level("DEBUG")

    llm, evasion, event_bus = _build_components(settings, profile)
    pipeline = PentestPipeline(settings, llm, evasion, event_bus)

    from rich.panel import Panel as _P
    from rich.table import Table as _T
    t = _T(box=None, show_header=False, padding=(0, 1))
    t.add_column(style="bold dim")
    t.add_column(style="cyan")
    t.add_row("Target",  target)
    t.add_row("Profile", profile)
    t.add_row("Timeout", f"{timeout}m")
    if dry_run:
        t.add_row("Mode", "[yellow]DRY-RUN — no real exploits[/yellow]")
    console.print(_P(t, title="[bold]RedOps — Run[/bold]", border_style="cyan", padding=(0,2)))

    resume_id: str | None = None
    if resume:
        resume_id = _find_latest_checkpoint()

    try:
        report_data = _run_async(
            pipeline.run(target, resume_session_id=resume_id, dry_run=dry_run)
        )
        n = len(report_data.compromised_services)  # type: ignore[union-attr]
        console.print(
            f"\n[bold green]✓ Pipeline complete[/bold green]  —  "
            f"[bold]{n}[/bold] service(s) compromised  ·  "
            f"[dim]reports saved to {settings.report_output_dir}[/dim]"
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — checkpoint saved[/yellow]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"\n[bold red]✗ Pipeline failed: {exc}[/bold red]")
        log.error("pipeline_failed", error=str(exc), exc_info=True)
        sys.exit(1)


# ── health command ──────────────────────────────────────────────────


@cli.command()
def health() -> None:
    """Check connectivity to MSF RPC, Ollama, target network and nmap."""
    import shutil
    import socket
    import ipaddress
    import subprocess

    settings = get_settings()
    llm, _, _ = _build_components(settings, "balanced")

    async def _check() -> None:
        table = Table(title="RedOps — Health Check", show_lines=True, border_style="bold")
        table.add_column("Service", style="bold white", min_width=22)
        table.add_column("Status", min_width=14)
        table.add_column("Detail", style="dim")

        # ── MSF RPC ──────────────────────────────────────────────────────
        try:
            with socket.create_connection(
                (settings.msf_host, settings.msf_port), timeout=3.0
            ):
                pass
            from redops.modules.exploiter import MSFClient
            msf = await MSFClient.get_instance(settings)
            sessions = await msf.list_sessions()
            table.add_row(
                "Metasploit RPC",
                "[bold green]OK[/bold green]",
                f"{settings.msf_host}:{settings.msf_port}  ·  {len(sessions)} session(s) active",
            )
            MSFClient.reset()
        except Exception as exc:
            table.add_row(
                "Metasploit RPC",
                "[bold red]FAIL[/bold red]",
                f"{exc}",
            )

        # ── Ollama / model ────────────────────────────────────────────────
        try:
            ok = await llm.health_check()
            table.add_row(
                f"Ollama / {settings.ollama_model}",
                "[bold green]OK[/bold green]" if ok else "[bold yellow]MODEL MISSING[/bold yellow]",
                settings.ollama_base_url,
            )
        except Exception as exc:
            table.add_row("Ollama LLM", "[bold red]FAIL[/bold red]", str(exc))

        # ── Target network reachability ───────────────────────────────────
        try:
            net = ipaddress.ip_network(settings.target_network, strict=False)
            probe_ip = str(next(net.hosts()))
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", probe_ip],
                capture_output=True,
                timeout=5,
            )
            reachable = result.returncode == 0
            table.add_row(
                "Target Network",
                "[bold green]REACHABLE[/bold green]" if reachable else "[bold red]UNREACHABLE[/bold red]",
                f"{settings.target_network}  →  probed {probe_ip}",
            )
        except Exception as exc:
            table.add_row("Target Network", "[bold red]ERROR[/bold red]", str(exc))

        # ── Attacker IP / LHOST ───────────────────────────────────────────
        lhost = settings.attacker_ip
        table.add_row(
            "Attacker IP (LHOST)",
            "[bold green]AUTO[/bold green]" if lhost else "[bold yellow]UNDETECTED[/bold yellow]",
            lhost if lhost else "Set LHOST= in .env (needed for reverse payloads)",
        )

        # ── nmap binary ───────────────────────────────────────────────────
        nmap_path = shutil.which("nmap")
        table.add_row(
            "nmap",
            "[bold green]FOUND[/bold green]" if nmap_path else "[bold red]MISSING[/bold red]",
            nmap_path or "Install: sudo pacman -S nmap",
        )

        console.print(table)

    _run_async(_check())


# ── report command ──────────────────────────────────────────────────


@cli.command()
@click.option("--checkpoint", required=True, help="Session ID to regenerate report from")
def report(checkpoint: str) -> None:
    """Regenerate a PDF report from an existing checkpoint."""
    from pathlib import Path

    from redops.core.events import EventBus
    from redops.core.models import ReportData, SessionState
    from redops.reporting.report_generator import ReportGenerator

    ckpt_path = Path("checkpoints") / f"session_{checkpoint}.json"
    if not ckpt_path.exists():
        console.print(f"[red]Checkpoint not found: {ckpt_path}[/red]")
        sys.exit(1)

    state = SessionState.model_validate_json(ckpt_path.read_text(encoding="utf-8"))
    settings = get_settings()
    event_bus = EventBus()
    gen = ReportGenerator(event_bus)

    report_data = ReportData(
        session_id=state.session_id,
        targets=state.targets,
        vulnerabilities=state.vulnerabilities,
        compromised_services=state.compromised_services,
        phase_results=state.phase_results,
        decisions=state.decisions,
        total_duration_seconds=(datetime.now(UTC) - state.started_at).total_seconds(),
    )

    async def _gen() -> None:
        path = await gen.generate(report_data, settings.report_output_dir)
        console.print(f"[green]Report generated: {path}[/green]")

    _run_async(_gen())


# ── cleanup command ─────────────────────────────────────────────────


@cli.command()
@click.option(
    "--session-ids", "-s", multiple=True,
    help="Specific session IDs to close (default: all active sessions)",
)
def cleanup(session_ids: tuple[str, ...]) -> None:
    """Close active MSF sessions left from an interrupted run.

    Use this when a pipeline was interrupted before teardown completed,
    or to confirm that no orphaned sessions remain on the target.
    """
    settings = get_settings()

    async def _do_cleanup() -> None:
        from redops.modules.exploiter import MSFClient
        try:
            msf = await MSFClient.get_instance(settings)
            active = await msf.list_sessions()
            if not active:
                console.print("[bold green]✓ No active MSF sessions — environment is clean.[/bold green]")
                return
            to_close = list(session_ids) if session_ids else [s["id"] for s in active]
            console.print(f"[bold]Closing {len(to_close)} session(s)...[/bold]")
            results = await msf.close_sessions(to_close)
            for sid, ok in results.items():
                status = "[green]closed[/green]" if ok else "[red]failed[/red]"
                console.print(f"  Session {sid}: {status}")
            closed = sum(1 for ok in results.values() if ok)
            console.print(f"\n[bold]Done:[/bold] {closed}/{len(to_close)} session(s) closed.")
        except Exception as exc:
            console.print(f"[red]Cleanup error: {exc}[/red]")
        finally:
            from redops.modules.exploiter import MSFClient as _MSF
            _MSF.reset()

    _run_async(_do_cleanup())


# ── Checkpoint lookup ───────────────────────────────────────────────


def _find_latest_checkpoint() -> str | None:
    """Return the session ID of the most recent checkpoint file, or None."""
    from pathlib import Path

    ckdir = Path("checkpoints")
    if not ckdir.exists():
        return None
    files = sorted(ckdir.glob("session_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return None
    name = files[0].stem  # session_<id>
    return name.replace("session_", "")


# ── menu command ───────────────────────────────────────────────────


@cli.command()
def menu() -> None:
    """Launch the interactive TUI menu (default when no command is given)."""
    from redops.tui import run_tui
    run_tui()


# ── Entry point ─────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
