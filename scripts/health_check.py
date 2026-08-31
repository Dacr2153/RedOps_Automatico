#!/usr/bin/env python3
"""RedOps Automático — Standalone pre-venv health check.

Verifies external service connectivity using only Python stdlib.
No virtualenv or installed packages required.

For the full Rich-formatted health check (requires venv):
    .venv/bin/python -m redops health
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import urllib.request
import urllib.error
import json
from pathlib import Path

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

PASS_COUNT = 0
FAIL_COUNT = 0
WARN_COUNT = 0


def ok(msg: str) -> None:
    global PASS_COUNT
    PASS_COUNT += 1
    print(f"  {GREEN}[PASS]{RESET} {msg}")


def fail(msg: str) -> None:
    global FAIL_COUNT
    FAIL_COUNT += 1
    print(f"  {RED}[FAIL]{RESET} {msg}")


def warn(msg: str) -> None:
    global WARN_COUNT
    WARN_COUNT += 1
    print(f"  {YELLOW}[WARN]{RESET} {msg}")


def info(msg: str) -> None:
    print(f"         {msg}")


def _load_env(env_file: Path) -> dict[str, str]:
    """Parse a .env file into a dict (simple key=value, no shell expansion)."""
    result: dict[str, str] = {}
    if not env_file.exists():
        return result
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def check_tcp(host: str, port: int, label: str, timeout: float = 3.0) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            ok(f"{label} ({host}:{port})")
            return True
    except OSError as exc:
        fail(f"{label} ({host}:{port}) — {exc}")
        return False


def check_ollama_model(host: str, port: int, model: str) -> bool:
    """Return True if Ollama is running and the required model is available."""
    url = f"http://{host}:{port}/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            models = [m.get("name", "") for m in data.get("models", [])]
            if any(model in m for m in models):
                ok(f"Ollama model '{model}' available")
                return True
            warn(f"Ollama running but model '{model}' not found")
            info(f"Pull it: ollama pull {model}")
            return False
    except Exception as exc:
        fail(f"Ollama API check: {exc}")
        return False


def check_ping(host: str) -> bool:
    """Return True if host responds to a single ICMP ping."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            ok(f"Target {host} responds to ping")
            return True
        fail(f"Target {host} unreachable")
        return False
    except Exception as exc:
        fail(f"Ping failed: {exc}")
        return False


def check_command(cmd: str, label: str) -> bool:
    """Return True if a binary is found on PATH."""
    result = subprocess.run(
        ["which", cmd], capture_output=True, timeout=5
    )
    if result.returncode == 0:
        path = result.stdout.decode().strip()
        ok(f"{label}: {path}")
        return True
    fail(f"{label} not found on PATH")
    return False


def main() -> int:
    project_dir = Path(__file__).resolve().parent.parent
    env_file = project_dir / ".env"
    env = _load_env(env_file)

    msf_host = env.get("MSF_HOST", "127.0.0.1")
    msf_port = int(env.get("MSF_PORT", "55553"))
    ollama_host = env.get("OLLAMA_HOST", "127.0.0.1")
    ollama_port = int(env.get("OLLAMA_PORT", "11434"))
    ollama_model = env.get("OLLAMA_MODEL", "mistral")
    target_ip = env.get("TARGET_IP", "192.168.56.101")
    venv_dir = project_dir / ".venv"

    print()
    print(f"{BOLD}RedOps Automatico — Standalone Health Check{RESET}")
    print(f"Project: {project_dir}")
    print()

    print(f"{BOLD}-- Metasploit RPC --{RESET}")
    check_tcp(msf_host, msf_port, "msfrpcd")
    print()

    print(f"{BOLD}-- Ollama LLM --{RESET}")
    if check_tcp(ollama_host, ollama_port, "Ollama server"):
        check_ollama_model(ollama_host, ollama_port, ollama_model)
    print()

    print(f"{BOLD}-- Target VM --{RESET}")
    check_ping(target_ip)
    print()

    print(f"{BOLD}-- Tools --{RESET}")
    check_command("nmap", "nmap")
    check_command("msfrpcd", "msfrpcd")
    check_command("ollama", "ollama")
    check_command("VBoxManage", "VBoxManage")
    print()

    print(f"{BOLD}-- Python Virtualenv --{RESET}")
    venv_python = venv_dir / "bin" / "python"
    if venv_python.exists():
        ok(f"Virtualenv: {venv_dir}")
        result = subprocess.run(
            [str(venv_python), "-c", "import redops; print(redops.__version__ if hasattr(redops, '__version__') else 'ok')"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            ver = result.stdout.strip() or "installed"
            ok(f"RedOps package: {ver}")
        else:
            fail("RedOps package not importable from venv")
            info(f"Run: source {venv_dir}/bin/activate && pip install -e '.[dev]'")
    else:
        fail(f"Virtualenv not found at {venv_dir}")
        info("Run: bash scripts/setup_arch.sh")
    print()

    # Summary
    print(f"{BOLD}-- Summary --{RESET}")
    if FAIL_COUNT == 0:
        print(f"  {GREEN}All checks passed.{RESET}")
        print()
        print("  Full Rich health check:")
        print(f"    {venv_dir}/bin/python -m redops health")
        print()
    else:
        print(f"  {GREEN}{PASS_COUNT} passed{RESET}  "
              f"{YELLOW}{WARN_COUNT} warned{RESET}  "
              f"{RED}{FAIL_COUNT} failed{RESET}")
        print()
    return 1 if FAIL_COUNT > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
