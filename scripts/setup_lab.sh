#!/usr/bin/env bash
# =============================================================================
# RedOps Automático — Lab Pre-Flight Check
# =============================================================================
# Verifies that all external services required by RedOps are ready:
#   • VirtualBox host-only network  (192.168.56.0/24)
#   • Metasploit RPC daemon         (msfrpcd)
#   • Ollama LLM server + model
#   • Metasploitable2 VM reachability
#   • Python virtualenv + RedOps installation
#
# USAGE:
#   bash scripts/setup_lab.sh          # check everything
#   bash scripts/setup_lab.sh --fix    # check + attempt to start stopped services
#
# For full initial installation of all dependencies:
#   bash scripts/setup_arch.sh
#
# For runtime lab control (start/stop VM + msfrpcd):
#   bash scripts/start_lab.sh
#
# WARNING: For authorized lab use only.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="${PROJECT_DIR}/.venv"
ENV_FILE="${PROJECT_DIR}/.env"
FIX_MODE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fix) FIX_MODE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--fix]"
            echo "  --fix   Attempt to start stopped services (msfrpcd, Ollama)"
            exit 0 ;;
        *) echo "[ERROR] Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# Load .env if present
if [[ -f "$ENV_FILE" ]]; then
    set -o allexport
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +o allexport
fi

MSF_HOST="${MSF_HOST:-127.0.0.1}"
MSF_PORT="${MSF_PORT:-55553}"
MSF_PASSWORD="${MSF_PASSWORD:-msf_rpc_password}"
OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1}"
OLLAMA_PORT="${OLLAMA_PORT:-11434}"
OLLAMA_MODEL="${OLLAMA_MODEL:-mistral}"
TARGET_IP="${TARGET_IP:-192.168.56.101}"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

PASS=0; FAIL=0; WARN=0

ok()     { echo -e "  ${GREEN}[PASS]${NC} $*"; ((PASS++)); }
fail()   { echo -e "  ${RED}[FAIL]${NC} $*"; ((FAIL++)); }
warn()   { echo -e "  ${YELLOW}[WARN]${NC} $*"; ((WARN++)); }
info()   { echo -e "  ${BLUE}[INFO]${NC} $*"; }
banner() { echo -e "\n${BOLD}-- $* --${NC}"; }

# ── TCP probe helper ──────────────────────────────────────────────────────────
tcp_probe() {
    local host="$1" port="$2"
    nc -z -w2 "$host" "$port" 2>/dev/null
}

echo ""
echo -e "${BOLD}RedOps Automatico — Pre-Flight Check${NC}"
echo -e "Project : ${PROJECT_DIR}"
echo -e "Env file: ${ENV_FILE}"
echo ""

# =============================================================================
# 1. VirtualBox
# =============================================================================
banner "VirtualBox"

if command -v VBoxManage &>/dev/null; then
    VBOX_VER=$(VBoxManage --version 2>/dev/null | grep -oP '[\d.]+' | head -1)
    ok "VirtualBox ${VBOX_VER}"
else
    fail "VirtualBox not installed"
    info "Install: sudo pacman -S virtualbox"
fi

if lsmod | grep -q vboxdrv; then
    ok "vboxdrv kernel module loaded"
else
    fail "vboxdrv not loaded"
    info "Run: sudo bash scripts/setup_vbox_net.sh"
fi

if ip addr show 2>/dev/null | grep -q "192\.168\.56\."; then
    ok "Host-only interface 192.168.56.x present"
else
    warn "No 192.168.56.x interface detected"
    info "Run: sudo bash scripts/setup_vbox_net.sh"
fi

# =============================================================================
# 2. Metasploit RPC daemon
# =============================================================================
banner "Metasploit RPC (msfrpcd)"

if command -v msfrpcd &>/dev/null; then
    ok "msfrpcd binary: $(command -v msfrpcd)"
else
    fail "msfrpcd not found"
    info "Install: yay -S metasploit"
fi

if tcp_probe "$MSF_HOST" "$MSF_PORT"; then
    ok "msfrpcd listening on ${MSF_HOST}:${MSF_PORT}"
else
    fail "msfrpcd NOT listening on ${MSF_HOST}:${MSF_PORT}"
    if [[ "$FIX_MODE" == true ]] && command -v msfrpcd &>/dev/null; then
        info "Starting msfrpcd..."
        msfrpcd -P "$MSF_PASSWORD" -S -a "$MSF_HOST" -p "$MSF_PORT" \
            >/tmp/msfrpcd-redops.log 2>&1 &
        for i in $(seq 1 10); do
            sleep 3
            if tcp_probe "$MSF_HOST" "$MSF_PORT"; then
                ok "msfrpcd started"
                break
            fi
            [[ $i -eq 10 ]] && warn "msfrpcd slow — check: tail /tmp/msfrpcd-redops.log"
        done
    else
        info "Run: bash scripts/start_lab.sh  (or use --fix to auto-start)"
    fi
fi

# =============================================================================
# 3. Ollama LLM
# =============================================================================
banner "Ollama LLM"

if command -v ollama &>/dev/null; then
    ok "Ollama binary: $(command -v ollama)"
else
    fail "Ollama not installed"
    info "Install: curl -fsSL https://ollama.com/install.sh | sh"
fi

if tcp_probe "$OLLAMA_HOST" "$OLLAMA_PORT"; then
    ok "Ollama listening on ${OLLAMA_HOST}:${OLLAMA_PORT}"
    if curl -sf "http://${OLLAMA_HOST}:${OLLAMA_PORT}/api/tags" \
            | grep -q "\"${OLLAMA_MODEL}\"" 2>/dev/null; then
        ok "Model '${OLLAMA_MODEL}' available"
    else
        warn "Model '${OLLAMA_MODEL}' not pulled yet"
        info "Pull: ollama pull ${OLLAMA_MODEL}"
    fi
else
    fail "Ollama NOT running on ${OLLAMA_HOST}:${OLLAMA_PORT}"
    if [[ "$FIX_MODE" == true ]] && command -v ollama &>/dev/null; then
        info "Starting Ollama..."
        nohup ollama serve >/tmp/ollama-redops.log 2>&1 &
        for i in $(seq 1 15); do
            sleep 1
            tcp_probe "$OLLAMA_HOST" "$OLLAMA_PORT" && { ok "Ollama started"; break; }
            [[ $i -eq 15 ]] && warn "Ollama slow — check: tail /tmp/ollama-redops.log"
        done
    else
        info "Start: ollama serve &  (or use --fix to auto-start)"
    fi
fi

# =============================================================================
# 4. Target VM (Metasploitable2)
# =============================================================================
banner "Target VM (Metasploitable2 @ ${TARGET_IP})"

if ping -c1 -W2 "$TARGET_IP" &>/dev/null; then
    ok "Metasploitable2 ${TARGET_IP} reachable"
else
    warn "Metasploitable2 ${TARGET_IP} not reachable"
    info "Start the lab: bash scripts/start_lab.sh"
fi

# =============================================================================
# 5. Python virtualenv + RedOps
# =============================================================================
banner "Python Environment"

if [[ -x "${VENV_DIR}/bin/python" ]]; then
    PY_VER=$("${VENV_DIR}/bin/python" --version 2>&1)
    ok "Virtualenv: ${VENV_DIR} (${PY_VER})"

    if "${VENV_DIR}/bin/python" -c "import redops" 2>/dev/null; then
        VER=$("${VENV_DIR}/bin/python" -m redops --version 2>/dev/null || echo "dev")
        ok "RedOps installed (${VER})"
    else
        fail "RedOps not installed in venv"
        info "Run: source ${VENV_DIR}/bin/activate && pip install -e '.[dev]'"
    fi
else
    fail "Virtualenv not found at ${VENV_DIR}"
    info "Run: bash scripts/setup_arch.sh"
fi

if command -v nmap &>/dev/null; then
    NMAP_VER=$(nmap --version 2>/dev/null | head -1 | grep -oP 'Nmap \S+' || echo "nmap")
    ok "${NMAP_VER}"
else
    fail "nmap not installed"
    info "Install: sudo pacman -S nmap"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${BOLD}━━━  Summary  ━━━${NC}"
[[ $PASS -gt 0 ]] && echo -e "  ${GREEN}PASS: ${PASS}${NC}"
[[ $WARN -gt 0 ]] && echo -e "  ${YELLOW}WARN: ${WARN}${NC}"
[[ $FAIL -gt 0 ]] && echo -e "  ${RED}FAIL: ${FAIL}${NC}"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "${BOLD}All required services are ready.${NC}"
    echo ""
    echo "  Full health check (Rich output):"
    echo "    ${VENV_DIR}/bin/python -m redops health"
    echo ""
    echo "  Run a dry-run:"
    echo "    sudo ${VENV_DIR}/bin/python -m redops run --target 192.168.56.0/24 --dry-run"
    echo ""
    echo "  Full pentest:"
    echo "    sudo ${VENV_DIR}/bin/python -m redops run --target 192.168.56.0/24 --profile balanced"
    echo ""
else
    echo -e "${YELLOW}Fix the FAIL items above, then re-run.${NC}"
    echo -e "For automatic service startup: bash $0 --fix"
    echo ""
    exit 1
fi


