# RedOps Automático

> **LLM-Orchestrated Automated Penetration Testing Framework**

```
██████╗ ███████╗██████╗  ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝
██████╔╝█████╗  ██║  ██║██║   ██║██████╔╝███████╗
██╔══██╗██╔══╝  ██║  ██║██║   ██║██╔═══╝ ╚════██║
██║  ██║███████╗██████╔╝╚██████╔╝██║     ███████║
╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚══════╝
      Automated Pentesting Framework v1.0.0
```

**RedOps Automático** is an end-to-end penetration testing framework that follows the [PTES](http://www.pentest-standard.org/) (Penetration Testing Execution Standard) methodology. It uses a local LLM (Ollama/Mistral) to orchestrate reconnaissance, scanning, exploitation, post-exploitation and reporting against intentionally vulnerable lab targets.

> **WARNING:** This framework is designed **EXCLUSIVELY** for use in authorized, isolated laboratory environments (VirtualBox: Kali Linux / Arch Linux attacker + Metasploitable2 target). Using it against systems without explicit authorization is **illegal**.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Environment Variables](#environment-variables)
- [Usage](#usage)
- [CLI Reference](#cli-reference)
- [TUI Menu](#tui-menu)
- [PTES Methodology Flow](#ptes-methodology-flow)
- [Evasion Profiles](#evasion-profiles)
- [CVSS Scoring](#cvss-scoring)
- [Report Output](#report-output)
- [Testing](#testing)
- [Code Quality](#code-quality)
- [Scripts](#scripts)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **LLM-Orchestrated Exploitation** — Local Mistral model via Ollama selects the optimal exploit module, reasons about alternatives, and adapts to failures
- **Full PTES Pipeline** — Automated Recon → Scan → Exploit → Post-Exploit → Report
- **Adaptive Scan Depths** — Quick (top 1000), Full (65535 TCP + UDP critical), or Stealth (top 100)
- **CVSSv3.1 Calculator** — Native implementation following the FIRST specification (no external libraries)
- **MITRE ATT&CK Mapping** — CVEs mapped to MITRE techniques in reports
- **IDS Evasion Engine** — Three pluggable profiles: Stealth, Balanced, Aggressive (IP fragmentation, timing jitter, decoy injection)
- **Interactive TUI** — Rich terminal menu for guided operation (no CLI memory needed)
- **Professional PDF Reports** — Cover page, executive summary, technical findings, attack paths, timeline, remediations
- **Checkpoint & Recovery** — Session state persisted to JSON; resume interrupted runs
- **Automatic Teardown** — MSF sessions are closed in a `finally` block, even on timeout or crash
- **Dry-Run Mode** — Simulate the full pipeline without executing real exploits

---

## Architecture

The framework is built on four software design patterns:

```
┌──────────────────────────────────────────────────────────────────────┐
│                          CLI / TUI (click + Rich)                    │
│                            main.py / tui.py                          │
├──────────────────────────────────────────────────────────────────────┤
│                       PentestPipeline (Chain of Responsibility)       │
│                         core/pipeline.py                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────┐ │
│  │  RECON   │→ │   SCAN   │→ │ EXPLOIT  │→ │ POST-    │→ │REPORT │ │
│  │ (nmap)   │  │ (nmap)   │  │ (MSF+LLM)│  │ EXPLOIT  │  │(PDF)  │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └───────┘ │
├──────────────────────────────────────────────────────────────────────┤
│  EventBus (Observer)          │  LLMOrchestrator (Ollama/Mistral)    │
│  core/events.py               │  orchestrator/llm_engine.py          │
├───────────────────────────────┼──────────────────────────────────────┤
│  EvasionEngine (Strategy)     │  MSFClient (Singleton)               │
│  evasion/evasion_engine.py    │  modules/exploiter.py                │
├───────────────────────────────┴──────────────────────────────────────┤
│  Pydantic Models (core/models.py)  │  Settings (config/settings.py)  │
│  ReportGenerator (reporting/)       │  CVSSv31Calculator              │
└──────────────────────────────────────────────────────────────────────┘
```

### Design Patterns

| Pattern | Component | Purpose |
|---------|-----------|---------|
| **Chain of Responsibility** | `PentestPipeline` | Orchestrates PTES phases sequentially; each phase processes the result of the previous one |
| **Observer** | `EventBus` | Decoupled publish/subscribe for phase events, exploit success, and report generation |
| **Singleton** | `MSFClient` | Persistent Metasploit RPC connection shared across all exploit operations |
| **Strategy** | `EvasionEngine` | Pluggable IDS evasion profiles (Stealth / Balanced / Aggressive) swappable at runtime |

---

## Tech Stack

| Category | Technology |
|----------|------------|
| Language | Python 3.11+ |
| LLM Engine | Ollama + Mistral (local inference) |
| Exploitation | Metasploit Framework (via `pymetasploit3` RPC) |
| Scanning | Nmap (via `python-nmap`) |
| Evasion | Scapy (IP fragmentation, TCP segmentation, decoy injection) |
| Data Models | Pydantic v2 (`pydantic-settings` for env config) |
| PDF Reports | ReportLab |
| CLI | Click |
| TUI | Rich (live dashboard, interactive menus) |
| Logging | Structlog (JSON in production, colored console in dev) |
| Testing | Pytest + pytest-asyncio + pytest-cov + pytest-mock |
| Code Quality | Ruff, Black, isort, mypy (strict mode) |
| Package | setuptools (PEP 621 `pyproject.toml`) |

---

## Project Structure

```
RedOps_Automatico/
├── src/redops/                    # Main package
│   ├── __init__.py                # Version, logging config
│   ├── __main__.py                # python -m redops entry
│   ├── main.py                    # CLI entry point (Click)
│   ├── tui.py                     # Interactive TUI (Rich)
│   ├── config/
│   │   ├── constants.py           # Enums, MSF catalog, CVSS thresholds, MITRE map
│   │   └── settings.py            # Pydantic BaseSettings (.env loader)
│   ├── core/
│   │   ├── events.py              # Async EventBus + typed event dataclasses
│   │   ├── exceptions.py          # Hierarchical exception classes
│   │   ├── models.py              # Domain models (Port, Target, CVSS, Vulnerability, etc.)
│   │   └── pipeline.py            # PentestPipeline orchestrator
│   ├── evasion/
│   │   └── evasion_engine.py      # Scapy-based IDS evasion (Strategy pattern)
│   ├── modules/
│   │   ├── base.py                # BasePTESModule protocol + Factory
│   │   ├── recon.py               # RECON: host discovery, OS fingerprint, banner grab
│   │   ├── scanner.py             # SCAN: port scanning, vulnerability identification
│   │   ├── exploiter.py           # EXPLOIT: MSFClient singleton + LLM-driven loop
│   │   └── post_exploit.py        # POST-EXPLOIT: evidence gathering, PE recon
│   ├── orchestrator/
│   │   ├── context.py             # Sliding-window session context for LLM
│   │   ├── llm_engine.py          # LLMOrchestrator (Ollama API client)
│   │   └── prompts.py             # Chain-of-thought prompt builders
│   ├── reporting/
│   │   ├── cvss_calculator.py     # CVSSv3.1 base-score calculator (FIRST spec)
│   │   ├── report_generator.py    # PDF report assembly (ReportLab)
│   │   └── styles.py              # ReportLab styles, colors, table config
│   └── utils/
│       ├── network.py             # IP/CIDR validation, log redaction
│       └── time_utils.py          # Duration formatting, UTC helpers
├── tests/                         # Test suite (47 tests)
│   ├── conftest.py                # Shared fixtures
│   ├── unit/
│   │   ├── test_cvss.py           # CVSSv3.1 calculator tests
│   │   ├── test_evasion.py        # Evasion engine strategy tests
│   │   ├── test_llm_engine.py     # LLM orchestrator tests
│   │   ├── test_models.py         # Pydantic model validation tests
│   │   └── test_report.py         # PDF generation tests
│   └── integration/
│       ├── test_msf_client.py     # MSFClient singleton + module execution
│       └── test_pipeline.py       # Full pipeline end-to-end (mocked)
├── scripts/
│   ├── setup_arch.sh              # Full Arch Linux installation wizard
│   ├── setup_lab.sh               # Pre-flight check (all services)
│   ├── setup_vbox_net.sh          # VirtualBox host-only network setup
│   ├── start_lab.sh               # Start/stop/status Metasploitable2 VM
│   └── health_check.py            # Standalone health check (no venv needed)
├── checkpoints/                   # Session state JSON files (auto-created)
├── reports/                       # Generated PDF reports (auto-created)
├── pyproject.toml                 # Package metadata + tool configs
├── requirements.txt               # Pinned runtime dependencies
├── requirements-dev.txt           # Pinned dev dependencies
├── Makefile                       # Build/test/lint/run shortcuts
├── .env.example                   # Environment variable template
├── .gitignore
└── LICENSE                        # MIT
```

---

## Prerequisites

| Requirement | Minimum | Purpose |
|-------------|---------|---------|
| Python | 3.11+ | Runtime |
| nmap | Latest | Network scanning |
| Metasploit Framework | 6.x+ | Exploitation engine |
| msfrpcd | (bundled) | Metasploit RPC daemon |
| Ollama | Latest | Local LLM inference |
| Mistral model | (via Ollama) | Decision-making LLM (~4 GB) |
| VirtualBox | 6.1+ | Lab VM host |
| Metasploitable2 | — | Intentionally vulnerable target |
| Arch Linux | Rolling | Primary supported OS |

---

## Installation

### Option A: Arch Linux (Automated)

```bash
git clone <repository-url>
cd RedOps_Automatico
bash scripts/setup_arch.sh
```

The setup wizard performs 8 steps:
1. System packages via `pacman`
2. Python virtualenv + RedOps package
3. Ollama + Mistral model
4. Metasploit Framework
5. Start msfrpcd
6. VirtualBox host-only network
7. Environment configuration (`.env`)
8. Health check

### Option B: Manual Installation

```bash
# 1. Create virtualenv
python -m venv .venv
source .venv/bin/activate

# 2. Install RedOps
pip install -e ".[dev]"

# 3. Install system tools (Arch Linux)
sudo pacman -S nmap

# 4. Install Metasploit (Arch Linux AUR)
yay -S metasploit

# 5. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull mistral

# 6. Configure environment
cp .env.example .env
$EDITOR .env
```

### Option C: Kali Linux

```bash
sudo apt update && sudo apt install -y nmap python3-pip python3-venv

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

curl -fsSL https://ollama.com/install.sh | sh
ollama pull mistral

cp .env.example .env
```

---

## Configuration

Copy `.env.example` to `.env` and edit:

```bash
cp .env.example .env
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MSF_HOST` | `127.0.0.1` | Host running `msfrpcd` |
| `MSF_PORT` | `55553` | Metasploit RPC port |
| `MSF_PASSWORD` | `msf_rpc_password` | Password for msfrpcd (`-P` flag) |
| `MSF_SSL` | `false` | Use HTTPS for MSF RPC |
| `OLLAMA_HOST` | `127.0.0.1` | Ollama server host |
| `OLLAMA_PORT` | `11434` | Ollama API port |
| `OLLAMA_MODEL` | `mistral` | LLM model for orchestration decisions |
| `OLLAMA_TIMEOUT` | `120` | Max seconds per LLM response |
| `TARGET_NETWORK` | `192.168.56.0/24` | CIDR of the target lab network |
| `LHOST` | *(empty = auto-detect)* | Attacker IP for reverse payloads |
| `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `REPORT_OUTPUT_DIR` | `./reports` | Directory for generated PDF reports |
| `SCAN_TIMING_MIN` | `1.0` | Minimum delay between network operations (seconds) |
| `SCAN_TIMING_MAX` | `5.0` | Maximum delay between network operations (seconds) |
| `EVASION_PROFILE` | `balanced` | `stealth` / `balanced` / `aggressive` |
| `GLOBAL_TIMEOUT_MINUTES` | `15` | Maximum total pipeline runtime |
| `MIN_SERVICES_TO_COMPROMISE` | `3` | Compromised services threshold for success |
| `CHECKPOINT_INTERVAL_SECONDS` | `60` | Interval between checkpoint saves |

**LHOST Auto-Detection:** When `LHOST` is empty, the framework opens a UDP socket toward the target network to let the kernel select the source interface. No actual packet is sent.

---

## Usage

### Start the Interactive TUI

```bash
# From project root (default: launches TUI)
redops

# Or explicitly
redops menu
python -m redops menu
```

### Run a Full Pentest

```bash
# CLI mode — full pentest with default profile
redops run --target 192.168.56.0/24

# With options
redops run -t 192.168.56.0/24 -p aggressive -v --timeout 20

# Dry-run (simulate without real exploits)
redops run -t 192.168.56.0/24 --dry-run

# Resume from last checkpoint
redops run -t 192.168.56.0/24 --resume
```

> **Note:** nmap SYN scan (`-sS`) requires root privileges. Run as `sudo` or accept the fallback to TCP connect scan.

### Health Check

```bash
redops health
python -m redops health
```

Verifies connectivity to:
- Metasploit RPC daemon
- Ollama LLM server + model availability
- Target network reachability
- Attacker IP detection (LHOST)
- nmap binary

### Cleanup Sessions

```bash
# Close all active MSF sessions
redops cleanup

# Close specific sessions
redops cleanup -s 1 -s 2
```

### Regenerate Report

```bash
redops report --checkpoint <session-id>
```

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `redops` | Launch interactive TUI (default) |
| `redops menu` | Launch interactive TUI |
| `redops run` | Execute full PTES pipeline |
| `redops health` | Check service connectivity |
| `redops cleanup` | Close orphaned MSF sessions |
| `redops report` | Regenerate PDF from checkpoint |
| `redops --version` | Show version |
| `redops --help` | Show help |

### `redops run` Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--target` | `-t` | *(required)* | Target IP or CIDR |
| `--profile` | `-p` | `balanced` | Evasion profile: `stealth`, `balanced`, `aggressive` |
| `--model` | `-m` | *(from .env)* | Override Ollama model |
| `--output` | `-o` | `./reports` | Report output directory |
| `--timeout` | | `15` | Global timeout in minutes |
| `--verbose` | `-v` | off | Enable DEBUG logging |
| `--resume` | | off | Resume from last checkpoint |
| `--dry-run` | | off | Simulate without real exploits |

---

## TUI Menu

The interactive terminal interface provides 6 options:

| # | Option | Description |
|---|--------|-------------|
| 1 | **Run Pentest** | Guided pentest with interactive parameter input |
| 2 | **Health Check** | Rich-formatted service status table |
| 3 | **Configuration** | View/edit all `.env` settings interactively |
| 4 | **Generate Report** | Rebuild PDF from any saved checkpoint |
| 5 | **Cleanup Sessions** | List and close orphaned MSF sessions |
| 6 | **Setup Wizard** | First-time installation and configuration guide |

The TUI displays a real-time status strip showing MSF RPC, Ollama, target network, and nmap status.

---

## PTES Methodology Flow

```
RECON                    SCAN                     EXPLOIT                  POST-EXPLOIT           REPORT
┌─────────────┐     ┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌──────────┐
│ Ping sweep  │     │ TCP SYN scan │     │ LLM selects      │     │ System info      │     │ PDF      │
│ (nmap -sn)  │────▶│ (-sS -sV)    │────▶│ best module      │────▶│ (whoami, id,     │────▶│ report   │
│             │     │              │     │ from catalog     │     │  uname, ps, etc) │     │          │
│ OS finger-  │     │ UDP scan     │     │                  │     │                  │     │ Cover    │
│ print (-O)  │     │ (critical    │     │ Executes via     │     │ PE vector        │     │ page,    │
│             │     │  ports)      │     │ MSF RPC          │     │ identification   │     │ exec     │
│ Banner grab │     │              │     │                  │     │ (SUID, cron,     │     │ summary, │
│ (-sV)       │     │ Catalog      │     │ Retries with     │     │  sudo, writable) │     │ findings,│
│             │     │ correlation  │     │ backoff on       │     │                  │     │ attack   │
│ Scapy ARP   │     │ (service →   │     │ failure          │     │ Evidence         │     │ paths,   │
│ fallback    │     │  CVE/CVSS)   │     │                  │     │ collection       │     │ timeline,│
│             │     │              │     │ Circuit breaker   │     │                  │     │ remed.   │
│ Max 3 hosts │     │ Max 2 targs  │     │ after 3 fails    │     │ Real access level│     │          │
│ concurrent  │     │ concurrent   │     │                  │     │ from whoami      │     │          │
└─────────────┘     └──────────────┘     │ Max 5 attempts/  │     └──────────────────┘     └──────────┘
                                         │ target, max 2    │
                                         │ targets parallel │
                                         └──────────────────┘
```

**Checkpoint saves** occur after each phase completion. **Automatic session teardown** closes all MSF sessions opened during the run (even on timeout or crash).

---

## Evasion Profiles

| Profile | Timing Delay | Fragment Size | Decoy Injection | Scan Depth |
|---------|-------------|---------------|-----------------|------------|
| **stealth** | 3–8 s + jitter | 8 bytes | Yes (5 RFC-1918 decoys) | Top 100 ports |
| **balanced** | 1–3 s | 16 bytes | No | Top 1000 ports |
| **aggressive** | 0.1–0.5 s | 32 bytes | No | Full 1–65535 + UDP |

---

## CVSS Scoring

The framework includes a native CVSSv3.1 base-score calculator (`reporting/cvss_calculator.py`) implementing the official FIRST specification formula:

```
ISS  = 1 - [(1 - C) * (1 - I) * (1 - A)]
Impact (Unchanged) = 6.42 * ISS
Impact (Changed)   = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02)^15
Exploitability     = 8.22 * AV * AC * PR * UI
BaseScore          = Roundup(min(combined, 10))
```

**Severity mapping:**

| Range | Severity |
|-------|----------|
| 9.0 – 10.0 | CRITICAL |
| 7.0 – 8.9 | HIGH |
| 4.0 – 6.9 | MEDIUM |
| 0.1 – 3.9 | LOW |
| 0.0 | INFO |

---

## Report Output

PDF reports are saved to `./reports/` and include:

1. **Cover Page** — Branded dark background with session metadata
2. **Executive Summary** — Non-technical overview (LLM-generated)
3. **Methodology** — PTES phase durations and status
4. **Technical Findings** — Per-service CVE, CVSS, severity badge, evidence, MITRE ATT&CK mapping
5. **Attack Path Visualization** — Text-based flowchart: Network → Target → Service → CVE → Module → Session
6. **Attack Timeline** — Chronological decision log with LLM reasoning
7. **Prioritized Remediations** — CVE-specific fix recommendations
8. **Appendix** — Full discovered services table

**MITRE ATT&CK mapping** is included for known CVEs:

| CVE | Technique | Name |
|-----|-----------|------|
| CVE-2011-2523 | T1190 | Exploit Public-Facing Application |
| CVE-2007-2447 | T1210 | Exploitation of Remote Services |
| CVE-2004-2687 | T1210 | Exploitation of Remote Services |
| CVE-2012-1823 | T1190 | Exploit Public-Facing Application |
| CVE-2010-2075 | T1190 | Exploit Public-Facing Application |

---

## Testing

The project contains **55 tests** across unit and integration suites.

### Run Tests

```bash
# All tests with coverage
make test
# or
pytest tests/ -v --cov=src/redops --cov-report=term-missing

# Unit tests only
make test-unit
# or
pytest tests/unit/ -v --cov=src/redops --cov-report=term-missing

# Integration tests only
make test-integration
# or
pytest tests/integration/ -v -m integration
```

### Test Coverage

| Module | Tests | Description |
|--------|-------|-------------|
| `test_cvss.py` | 16 | CVSSv3.1 calculator, vector parsing, severity labels |
| `test_models.py` | 17 | Pydantic model validation, serialization, immutability |
| `test_evasion.py` | 8 | Strategy selection, fragmentation, timing delays |
| `test_llm_engine.py` | 3 | LLM call parsing, JSON extraction, error handling |
| `test_report.py` | 3 | PDF generation, filename format |
| `test_msf_client.py` | 6 | Singleton, module execution, session management |
| `test_pipeline.py` | 2 | End-to-end pipeline, checkpoint roundtrip |

---

## Code Quality

```bash
# Linting (Ruff + mypy strict)
make lint

# Formatting (Black + isort)
make format
```

| Tool | Config | Purpose |
|------|--------|---------|
| **Ruff** | `line-length = 99`, target `py311` | Fast Python linter |
| **Black** | `line-length = 99` | Code formatter |
| **isort** | `profile = "black"` | Import sorter |
| **mypy** | `strict = true`, target `py311` | Static type checker |

---

## Scripts

| Script | Purpose | Requires |
|--------|---------|----------|
| `scripts/setup_arch.sh` | Full Arch Linux installation (8 steps) | Root access |
| `scripts/setup_lab.sh` | Pre-flight check for all services | — |
| `scripts/setup_lab.sh --fix` | Pre-flight check + auto-start services | — |
| `scripts/setup_vbox_net.sh` | VirtualBox host-only network setup | `sudo` |
| `scripts/start_lab.sh` | Start/stop/status Metasploitable2 VM | VirtualBox |
| `scripts/start_lab.sh --stop` | Graceful VM shutdown + stop msfrpcd | — |
| `scripts/start_lab.sh --status` | Show VM state and reachability | — |
| `scripts/start_lab.sh --import /path/to.ova` | Import Metasploitable2 OVA | — |
| `scripts/health_check.py` | Standalone health check (no venv needed) | — |

---

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make install` | Create virtualenv + install RedOps with dev deps |
| `make venv` | Create virtualenv only |
| `make setup-arch` | Install Arch Linux system packages |
| `make test` | Run all tests with coverage |
| `make test-unit` | Run unit tests only |
| `make test-integration` | Run integration tests only |
| `make lint` | Run Ruff + mypy |
| `make format` | Run Black + isort |
| `make run` | Execute pentest against default target |
| `make health` | Run health check |
| `make report` | Regenerate report from checkpoint (`CHECKPOINT=<id>`) |
| `make clean` | Remove caches and build artifacts |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `nmap: command not found` | `sudo pacman -S nmap` |
| `msfrpcd: command not found` | `yay -S metasploit` (Arch) or install from [Metasploit](https://www.metasploit.com/download) |
| `Ollama model not found` | `ollama pull mistral` |
| `Cannot connect to Metasploit RPC` | Start: `msfrpcd -P <password> -S -a 127.0.0.1 -p 55553` |
| `Cannot connect to Ollama` | Start: `ollama serve` |
| `Target unreachable` | Ensure Metasploitable2 VM is running on the host-only network |
| `SYN scan requires root` | Run with `sudo` or accept TCP connect fallback |
| `LHOST not detected` | Set `LHOST=<your-ip>` in `.env` manually |
| `Pipeline timeout exceeded` | Increase `GLOBAL_TIMEOUT_MINUTES` in `.env` |
| `Module execution timed out` | Check target availability; increase `OLLAMA_TIMEOUT` |
| `Orphaned MSF sessions` | Run `redops cleanup` |

---

## Security Considerations

- **Lab Only:** This framework targets intentionally vulnerable VMs in isolated VirtualBox networks. Never use against production systems.
- **Isolated Network:** The default `192.168.56.0/24` is a VirtualBox host-only network — no internet routing.
- **Session Teardown:** MSF sessions are automatically closed in a `finally` block, even on timeout, crash, or `KeyboardInterrupt`.
- **No Secrets in Code:** `.env` is gitignored. `.env.example` contains no real credentials.
- **Log Redaction:** IP addresses are partially redacted (`192.168.56.xxx`) in INFO+ logs via `sanitize_ip_for_log()`.
- **Attacker IP Exclusion:** The scanner automatically excludes the attacker's own IP from scan targets to prevent self-scanning.
- **Read-Only Post-Exploit:** All post-exploitation commands are informational only (`whoami`, `id`, `uname`, `find / -perm -4000`).

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Install dev dependencies: `pip install -e ".[dev]"`
4. Make changes following the existing code conventions
5. Run quality checks: `make lint && make test`
6. Commit with a descriptive message
7. Push and create a Pull Request

### Code Conventions

- Python 3.11+ syntax (use `X | Y` union types, not `Optional[X]`)
- All public methods must have docstrings
- Type annotations required (mypy strict mode)
- Line length: 99 characters
- Import sorting: `isort` with `black` profile
- Async-first: all I/O operations use `asyncio`
- Immutable Pydantic models (`frozen=True`) for domain objects
- No external CVSS libraries — native implementation required

---

## License

MIT License — Copyright (c) 2024 David A. Colorado R.

See [LICENSE](LICENSE) for details.
