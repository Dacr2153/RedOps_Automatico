#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════
# RedOps Automático — Arch Linux Lab Setup Script
# ════════════════════════════════════════════════════════════════════════════
# ETHICAL LAB USE ONLY — configure your own isolated VirtualBox lab network.
# Tested on Arch Linux (rolling) with VirtualBox host-only adapter.
# ════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Terminal colours ─────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()    { echo -e "  ${GREEN}✅  $1${NC}"; }
fail()  { echo -e "  ${RED}❌  $1${NC}"; exit 1; }
warn()  { echo -e "  ${YELLOW}⚠   $1${NC}"; }
info()  { echo -e "  ${CYAN}ℹ   $1${NC}"; }
header(){ echo -e "\n${BOLD}━━━ [${1}/${STEPS}] ${2} ━━━${NC}"; }

STEPS=8
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="${PROJECT_DIR}/.venv"

# Configurable via environment variables
MSF_PASSWORD="${MSF_PASSWORD:-msf_rpc_password}"
MSF_PORT="${MSF_PORT:-55553}"
OLLAMA_MODEL="${OLLAMA_MODEL:-mistral}"
TARGET_NETWORK="${TARGET_NETWORK:-192.168.56.0/24}"
TARGET_IP="${TARGET_IP:-192.168.56.101}"

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${RED}"
cat << 'BANNER'
  ██████╗ ███████╗██████╗  ██████╗ ██████╗ ███████╗
  ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝
  ██████╔╝█████╗  ██║  ██║██║   ██║██████╔╝███████╗
  ██╔══██╗██╔══╝  ██║  ██║██║   ██║██╔═══╝ ╚════██║
  ██║  ██║███████╗██████╔╝╚██████╔╝██║     ███████║
  ╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚══════╝
BANNER
echo -e "${NC}${BOLD}  Arch Linux Lab Setup — Automated Pentesting Framework${NC}"
echo -e "  ${YELLOW}⚠  ETHICAL LAB USE ONLY — Isolated VirtualBox network ⚠${NC}"
echo ""
read -rp "  This script installs packages and configures services. Continue? [y/N] " _confirm
[[ "${_confirm,,}" == "y" ]] || { echo "  Aborted."; exit 0; }

# ════════════════════════════════════════════════════════════════════════════
# STEP 1 — System packages via pacman
# ════════════════════════════════════════════════════════════════════════════
header 1 "System packages (pacman)"

PACKAGES=(nmap python python-pip python-virtualenv net-tools iproute2 git curl wget)
MISSING=()
for pkg in "${PACKAGES[@]}"; do
    pacman -Qi "$pkg" &>/dev/null || MISSING+=("$pkg")
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    info "Installing missing packages: ${MISSING[*]}"
    sudo pacman -Sy --noconfirm "${MISSING[@]}" && ok "Packages installed"
else
    ok "All required system packages already installed"
fi

# Verify Python version
PY_MINOR=$(python --version 2>&1 | grep -oP '(?<=3\.)\d+' | head -1)
[[ "${PY_MINOR:-0}" -ge 11 ]] \
    && ok "Python $(python --version): OK" \
    || fail "Python 3.11+ required. Found: $(python --version 2>&1)"

# Verify nmap
command -v nmap &>/dev/null \
    && ok "nmap: $(nmap --version | head -1)" \
    || fail "nmap not found after install — check pacman output"

# ════════════════════════════════════════════════════════════════════════════
# STEP 2 — Python virtualenv + RedOps package
# ════════════════════════════════════════════════════════════════════════════
header 2 "Python virtualenv + RedOps"

cd "$PROJECT_DIR"

if [[ ! -d "$VENV_DIR" ]]; then
    python -m venv "$VENV_DIR" && ok "Virtualenv created: ${VENV_DIR}"
else
    ok "Virtualenv already exists: ${VENV_DIR}"
fi

# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"
pip install --upgrade pip setuptools wheel --quiet
info "Installing RedOps and dependencies (may take a few minutes)..."
pip install -e ".[dev]" --quiet
ok "RedOps installed: $(python -m redops --version 2>/dev/null || echo 'import OK')"

# ════════════════════════════════════════════════════════════════════════════
# STEP 3 — Ollama + LLM model
# ════════════════════════════════════════════════════════════════════════════
header 3 "Ollama + ${OLLAMA_MODEL} model"

if ! command -v ollama &>/dev/null; then
    warn "Ollama not found."
    read -rp "  Install via official script (curl | sh)? [y/N] " _ans
    if [[ "${_ans,,}" == "y" ]]; then
        curl -fsSL https://ollama.com/install.sh | sh
        ok "Ollama installed: $(ollama --version)"
    else
        warn "Skipping Ollama install. Install manually: curl -fsSL https://ollama.com/install.sh | sh"
    fi
fi

if command -v ollama &>/dev/null; then
    # Start daemon if not running
    if ! curl -s --max-time 2 http://127.0.0.1:11434/api/tags &>/dev/null; then
        info "Starting Ollama daemon..."
        nohup ollama serve &>/tmp/ollama-redops.log &
        for i in $(seq 1 20); do
            curl -s --max-time 1 http://127.0.0.1:11434/api/tags &>/dev/null && break
            sleep 1
            [[ $i -eq 20 ]] && fail "Ollama daemon failed to start — check /tmp/ollama-redops.log"
        done
        ok "Ollama daemon started"
    else
        ok "Ollama daemon already running"
    fi

    # Pull model if needed
    if ollama list 2>/dev/null | grep -q "^${OLLAMA_MODEL}"; then
        ok "Model '${OLLAMA_MODEL}' already available"
    else
        info "Pulling '${OLLAMA_MODEL}' (~4 GB — this will take a while)..."
        ollama pull "$OLLAMA_MODEL" && ok "Model '${OLLAMA_MODEL}' ready"
    fi
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 4 — Metasploit Framework
# ════════════════════════════════════════════════════════════════════════════
header 4 "Metasploit Framework"

if command -v msfrpcd &>/dev/null; then
    ok "Metasploit already installed: $(msfconsole --version 2>/dev/null | head -1)"
else
    warn "Metasploit not found."
    echo ""
    echo -e "  ${BOLD}Option A (recommended):${NC} yay -S metasploit"
    echo -e "  ${BOLD}Option B:${NC}               paru -S metasploit"
    echo -e "  ${BOLD}Option C (nightly):${NC}     https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
    echo ""
    read -rp "  Install via AUR helper (yay/paru) now? [y/N] " _ans
    if [[ "${_ans,,}" == "y" ]]; then
        if command -v yay &>/dev/null; then
            yay -S --noconfirm metasploit && ok "Metasploit installed via yay"
        elif command -v paru &>/dev/null; then
            paru -S --noconfirm metasploit && ok "Metasploit installed via paru"
        else
            warn "No AUR helper found. Install yay first:"
            echo "    git clone https://aur.archlinux.org/yay-bin.git /tmp/yay-bin"
            echo "    cd /tmp/yay-bin && makepkg -si"
        fi
    else
        warn "Skipping — install Metasploit before running RedOps"
    fi
fi

# Initialize MSF database if available
if command -v msfdb &>/dev/null; then
    if msfdb status 2>/dev/null | grep -q "connected"; then
        ok "MSF database already initialized"
    else
        info "Initializing MSF database..."
        sudo msfdb init && ok "MSF database initialized" || warn "msfdb init failed — run manually"
    fi
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 5 — Start msfrpcd
# ════════════════════════════════════════════════════════════════════════════
header 5 "Metasploit RPC daemon (msfrpcd)"

if ! command -v msfrpcd &>/dev/null; then
    warn "msfrpcd not available — install Metasploit first (Step 4)"
else
    if ss -tlnp 2>/dev/null | grep -q ":${MSF_PORT}"; then
        ok "msfrpcd already listening on 127.0.0.1:${MSF_PORT}"
    else
        info "Starting msfrpcd on 127.0.0.1:${MSF_PORT}..."
        info "Password: ${MSF_PASSWORD}"
        msfrpcd -P "$MSF_PASSWORD" -S -a 127.0.0.1 -p "$MSF_PORT" &>/tmp/msfrpcd-redops.log &
        for i in $(seq 1 30); do
            ss -tlnp 2>/dev/null | grep -q ":${MSF_PORT}" && { ok "msfrpcd started"; break; }
            sleep 1
            [[ $i -eq 30 ]] && fail "msfrpcd failed to start — check /tmp/msfrpcd-redops.log"
        done
    fi
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 6 — VirtualBox host-only network
# ════════════════════════════════════════════════════════════════════════════
header 6 "Target network (VirtualBox Host-Only)"

if ip addr show 2>/dev/null | grep -q "192.168.56"; then
    IFACE=$(ip addr show | grep -B2 "192.168.56" | grep "^[0-9]" | awk -F': ' '{print $2}' | head -1)
    ok "Host-Only interface detected: ${IFACE:-vboxnet0} (192.168.56.x)"
else
    warn "No 192.168.56.x interface found."
    echo ""
    echo "  If using VirtualBox, create a host-only network:"
    echo "    VBoxManage hostonlyif create"
    echo "    VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0"
    echo "  Then attach Metasploitable2 VM to this adapter."
fi

# Ping target
if ping -c 1 -W 2 "$TARGET_IP" &>/dev/null; then
    ok "Target ${TARGET_IP} is reachable"
else
    warn "Target ${TARGET_IP} is NOT reachable"
    echo "  Ensure Metasploitable2 VM is running and attached to the Host-Only adapter."
    echo "  Default Metasploitable2 credentials: msfadmin / msfadmin"
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 7 — Configure .env
# ════════════════════════════════════════════════════════════════════════════
header 7 "Environment configuration (.env)"

ENV_FILE="${PROJECT_DIR}/.env"

if [[ -f "$ENV_FILE" ]]; then
    ok ".env already exists — skipping (edit manually: nano ${ENV_FILE})"
else
    cp "${PROJECT_DIR}/.env.example" "$ENV_FILE"
    info ".env created from .env.example"

    # Auto-detect LHOST via UDP socket trick (no packets sent)
    DETECTED_LHOST=$(python - <<'PYEOF' 2>/dev/null || echo ""
import socket, ipaddress
try:
    net = ipaddress.ip_network("192.168.56.0/24", strict=False)
    probe = str(next(net.hosts()))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((probe, 80))
    print(s.getsockname()[0])
    s.close()
except Exception:
    print("")
PYEOF
)

    if [[ -n "$DETECTED_LHOST" ]]; then
        sed -i "s|^LHOST=.*|LHOST=${DETECTED_LHOST}|" "$ENV_FILE"
        ok "LHOST auto-detected and set: ${DETECTED_LHOST}"
    else
        warn "Could not auto-detect LHOST — set it manually in .env"
    fi

    # Set MSF password
    sed -i "s|^MSF_PASSWORD=.*|MSF_PASSWORD=${MSF_PASSWORD}|" "$ENV_FILE"
    info "MSF_PASSWORD set to: ${MSF_PASSWORD}"
    info "Review and adjust: nano ${ENV_FILE}"
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 8 — Health check
# ════════════════════════════════════════════════════════════════════════════
header 8 "RedOps health check"

source "${VENV_DIR}/bin/activate"
python -m redops health || true   # non-fatal — user may need to start services first

# ════════════════════════════════════════════════════════════════════════════
# Done
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}"
echo "  ╔══════════════════════════════════════════════════════════════╗"
echo "  ║                                                              ║"
echo "  ║   Setup complete!                                            ║"
echo "  ║                                                              ║"
echo "  ║   Activate virtualenv:                                       ║"
echo "  ║     source .venv/bin/activate                                ║"
echo "  ║                                                              ║"
echo "  ║   Run health check:                                          ║"
echo "  ║     python -m redops health                                  ║"
echo "  ║                                                              ║"
echo "  ║   Start pentest:                                             ║"
echo "  ║     sudo .venv/bin/python -m redops run \\                   ║"
echo "  ║       --target 192.168.56.0/24 --profile balanced            ║"
echo "  ║                                                              ║"
echo "  ║   Sessions close automatically when the pipeline finishes.   ║"
echo "  ║   If a run is interrupted, use:                              ║"
echo "  ║     python -m redops cleanup                                 ║"
echo "  ║                                                              ║"
echo "  ║   PDF reports are saved in: ./reports/                       ║"
echo "  ║                                                              ║"
echo "  ╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
