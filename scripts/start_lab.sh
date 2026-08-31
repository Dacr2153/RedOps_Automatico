#!/usr/bin/env bash
# =============================================================================
# RedOps Lab — Start Metasploitable2 in VirtualBox (Arch Linux)
# =============================================================================
# Usage:
#   bash scripts/start_lab.sh [--stop] [--status] [--import /path/to/vm.ova]
#
# What it does:
#   1. Verifies VirtualBox is installed (installs via AUR if not)
#   2. Ensures the host-only network 192.168.56.0/24 exists
#   3. Finds or imports the Metasploitable2 VM
#   4. Starts the VM in headless mode
#   5. Polls until 192.168.56.101 responds to ping (max 120 s)
#   6. Runs `python -m redops health` automatically
# =============================================================================

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
VM_PATTERNS=("Metasploitable2" "Metasploitable 2" "metasploitable2" "metasploitable")
TARGET_IP="192.168.56.101"
HOST_ONLY_NET="192.168.56.0/24"
HOST_ONLY_IP="192.168.56.1"
HOST_ONLY_MASK="255.255.255.0"
BOOT_TIMEOUT=120          # seconds to wait for VM to be reachable
PING_INTERVAL=3

# ── Load .env ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="${PROJECT_DIR}/.env"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    set -o allexport; source "$ENV_FILE"; set +o allexport
fi
# Defaults if not set in .env
MSF_HOST="${MSF_HOST:-127.0.0.1}"
MSF_PORT="${MSF_PORT:-55553}"
MSF_PASSWORD="${MSF_PASSWORD:-msf_rpc_password}"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }
banner()  { echo -e "\n${BOLD}━━━  $*  ━━━${NC}"; }

# ── Argument parsing ──────────────────────────────────────────────────────────
MODE="start"
OVA_PATH=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --stop)   MODE="stop"  ; shift ;;
        --status) MODE="status"; shift ;;
        --import) OVA_PATH="${2:-}"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--stop] [--status] [--import /path/to/metasploitable.ova]"
            exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
vbm() { VBoxManage "$@"; }

find_vm() {
    local vms
    vms=$(vbm list vms 2>/dev/null | awk -F'"' '{print $2}') || true
    for pat in "${VM_PATTERNS[@]}"; do
        while IFS= read -r name; do
            if [[ "${name,,}" == *"${pat,,}"* ]]; then
                echo "$name"
                return 0
            fi
        done <<< "$vms"
    done
    return 1
}

vm_state() {
    vbm showvminfo "$1" --machinereadable 2>/dev/null \
        | grep "^VMState=" | cut -d'"' -f2
}

# ── Step 0: Ensure Metasploit RPC daemon is running ─────────────────────────
banner "Step 0 — Metasploit RPC (msfrpcd)"

msf_rpc_running() {
    # Check if something is listening on MSF_PORT
    ss -tnlp 2>/dev/null | grep -q ":${MSF_PORT}" ||
    nc -z "$MSF_HOST" "$MSF_PORT" 2>/dev/null
}

if msf_rpc_running; then
    ok "msfrpcd already listening on ${MSF_HOST}:${MSF_PORT}"
else
    if ! command -v msfrpcd &>/dev/null; then
        die "msfrpcd not found. Install Metasploit: sudo pacman -S metasploit"
    fi
    info "Starting msfrpcd on ${MSF_HOST}:${MSF_PORT}..."
    msfrpcd -P "$MSF_PASSWORD" -S -a "$MSF_HOST" -p "$MSF_PORT" \
        > /tmp/msfrpcd.log 2>&1 &
    # Wait up to 30s for the port to open
    for i in $(seq 1 10); do
        sleep 3
        if msf_rpc_running; then
            ok "msfrpcd started (PID $!) — ${MSF_HOST}:${MSF_PORT}"
            break
        fi
        printf "  [%ds] waiting for msfrpcd...\r" $((i * 3))
    done
    echo ""
    if ! msf_rpc_running; then
        warn "msfrpcd may still be initializing. Check: tail /tmp/msfrpcd.log"
    fi
fi

# ── Step 1: Ensure VirtualBox is installed + kernel module loaded ─────────────
banner "Step 1 — VirtualBox"

# Detect kernel flavour: hardened / zen / lts / vanilla
KERNEL_RELEASE="$(uname -r)"
KERNEL_PKG="linux"
if [[ "$KERNEL_RELEASE" == *hardened* ]]; then
    KERNEL_PKG="linux-hardened"
elif [[ "$KERNEL_RELEASE" == *zen* ]]; then
    KERNEL_PKG="linux-zen"
elif [[ "$KERNEL_RELEASE" == *lts* ]]; then
    KERNEL_PKG="linux-lts"
fi
HEADERS_PKG="${KERNEL_PKG}-headers"

# Decide which VirtualBox host-module package to use:
#   • linux (stock) → virtualbox-host-modules-arch  (pre-built, fast)
#   • any other     → virtualbox-host-dkms           (built via DKMS, works everywhere)
if [[ "$KERNEL_PKG" == "linux" ]]; then
    VBOX_MODULES_PKG="virtualbox-host-modules-arch"
else
    VBOX_MODULES_PKG="virtualbox-host-dkms"
fi

if ! command -v VBoxManage &>/dev/null; then
    warn "VBoxManage not found. Installing VirtualBox via pacman..."
    sudo pacman -S --noconfirm virtualbox "$VBOX_MODULES_PKG" "$HEADERS_PKG" dkms \
        || die "Installation failed. Run: sudo pacman -S virtualbox ${VBOX_MODULES_PKG} ${HEADERS_PKG} dkms"
    ok "VirtualBox installed"
    sudo usermod -aG vboxusers "$USER" 2>/dev/null || true
else
    VBOX_VER=$(VBoxManage --version 2>/dev/null | grep -oP '[\d.]+' | head -1)
    ok "VirtualBox ${VBOX_VER} found (kernel: ${KERNEL_RELEASE})"
fi

# Ensure vboxdrv module is loaded
if ! lsmod | grep -q vboxdrv; then
    info "Loading vboxdrv kernel module..."

    # For DKMS kernels: make sure the module is built before trying to load it
    if [[ "$VBOX_MODULES_PKG" == "virtualbox-host-dkms" ]]; then
        # Check if kernel headers are installed
        if ! pacman -Q "$HEADERS_PKG" &>/dev/null; then
            info "Installing kernel headers: ${HEADERS_PKG}"
            sudo pacman -S --noconfirm "$HEADERS_PKG" dkms \
                || die "Could not install ${HEADERS_PKG}. Run: sudo pacman -S ${HEADERS_PKG} dkms"
        fi
        # Ensure virtualbox-host-dkms is installed
        if ! pacman -Q virtualbox-host-dkms &>/dev/null; then
            info "Installing virtualbox-host-dkms..."
            sudo pacman -S --noconfirm virtualbox-host-dkms \
                || die "Could not install virtualbox-host-dkms"
        fi
        # Build the module via DKMS if not already built
        # The source dir may be named vboxhost-X.Y.Z or vboxhost-X.Y.Z_OSE
        VBOX_DKMS_VER=$(ls /usr/src/ 2>/dev/null | grep -oP '(?<=vboxhost-)[\d._OSE]+' | head -1)
        if [[ -z "$VBOX_DKMS_VER" ]]; then
            # Fallback: derive from pacman version
            PKG_VER=$(pacman -Q virtualbox-host-dkms 2>/dev/null | awk '{print $2}' | cut -d- -f1)
            VBOX_DKMS_VER="${PKG_VER}_OSE"
        fi
        DKMS_STATUS=$(dkms status "vboxhost/${VBOX_DKMS_VER}" -k "${KERNEL_RELEASE}" 2>/dev/null || true)
        if [[ "$DKMS_STATUS" != *"installed"* ]]; then
            info "Building vboxhost/${VBOX_DKMS_VER} for kernel ${KERNEL_RELEASE} (this may take ~1 min)..."
            sudo dkms install "vboxhost/${VBOX_DKMS_VER}" -k "${KERNEL_RELEASE}" 2>&1 \
                | grep -E "^(Error|Building|Installing|DKMS|WARNING)" || true
        fi
    fi

    sudo modprobe vboxdrv 2>/dev/null \
        && ok "vboxdrv loaded" \
        || {
            error "Could not load vboxdrv. Fix steps:"
            echo ""
            echo "  1. Install kernel headers + dkms:"
            echo "       sudo pacman -S ${HEADERS_PKG} dkms virtualbox-host-dkms"
            echo ""
            echo "  2. Build the module:"
            echo "       VBOX_VER=\$(pacman -Q virtualbox-host-dkms | awk '{print \$2}' | cut -d- -f1)"
            echo "       sudo dkms install vboxhost/\${VBOX_VER} -k ${KERNEL_RELEASE}"
            echo ""
            echo "  3. Load the module:"
            echo "       sudo modprobe vboxdrv"
            echo ""
            echo "  4. Re-run this script."
            die "vboxdrv not loaded — cannot start VMs"
        }
fi

# ── Step 2: Host-only network ─────────────────────────────────────────────────
banner "Step 2 — Host-Only Network (${HOST_ONLY_NET})"

# Find existing host-only interface with 192.168.56.x
HOSTONLYIF=""
while IFS= read -r line; do
    if [[ "$line" =~ ^Name:.*vboxnet ]]; then
        CURRENT_IF=$(echo "$line" | awk '{print $2}')
    fi
    if [[ "$line" =~ IPAddress:.*192\.168\.56\. ]]; then
        HOSTONLYIF="$CURRENT_IF"
        break
    fi
done < <(vbm list hostonlyifs 2>/dev/null)

if [[ -z "$HOSTONLYIF" ]]; then
    info "Creating host-only network 192.168.56.0/24..."
    # Create new host-only interface
    HOSTONLYIF=$(vbm hostonlyif create 2>/dev/null \
        | grep -oP "(?<=interface ')vboxnet\d+" || echo "vboxnet0")
    vbm hostonlyif ipconfig "$HOSTONLYIF" \
        --ip "$HOST_ONLY_IP" --netmask "$HOST_ONLY_MASK" 2>/dev/null
    ok "Created host-only interface: ${HOSTONLYIF} (${HOST_ONLY_IP})"
else
    ok "Host-only interface found: ${HOSTONLYIF} (${HOST_ONLY_IP})"
fi

# ── Step 3: Find or import Metasploitable2 VM ─────────────────────────────────
banner "Step 3 — Metasploitable2 VM"
VM_NAME=""
if VM_NAME=$(find_vm); then
    ok "VM found: '${VM_NAME}'"
elif [[ -n "$OVA_PATH" ]]; then
    if [[ ! -f "$OVA_PATH" ]]; then
        die "OVA file not found: $OVA_PATH"
    fi
    info "Importing VM from: $OVA_PATH"
    vbm import "$OVA_PATH" --vsys 0 --vmname "Metasploitable2" 2>&1 | tail -5
    # Attach to host-only network
    vbm modifyvm "Metasploitable2" --nic1 hostonly --hostonlyadapter1 "$HOSTONLYIF"
    VM_NAME="Metasploitable2"
    ok "VM imported successfully"
else
    error "Metasploitable2 VM not found in VirtualBox."
    echo ""
    echo "  Option A — Download and import the OVA:"
    echo "    https://sourceforge.net/projects/metasploitable/files/Metasploitable2/"
    echo "    Then run:  bash scripts/start_lab.sh --import /path/to/metasploitable.ova"
    echo ""
    echo "  Option B — Re-run with import flag pointing to your OVA file"
    echo ""
    # List available VMs for reference
    info "Available VMs in VirtualBox:"
    vbm list vms 2>/dev/null || echo "  (none)"
    exit 1
fi

# ── Helper sub-commands ───────────────────────────────────────────────────────
if [[ "$MODE" == "status" ]]; then
    banner "VM Status"
    STATE=$(vm_state "$VM_NAME")
    echo "  VM:    $VM_NAME"
    echo "  State: $STATE"
    echo ""
    if [[ "$STATE" == "running" ]]; then
        if ping -c1 -W2 "$TARGET_IP" &>/dev/null; then
            ok "Target $TARGET_IP is reachable"
        else
            warn "VM running but $TARGET_IP not reachable yet"
        fi
    fi
    exit 0
fi

if [[ "$MODE" == "stop" ]]; then
    banner "Stopping VM"
    STATE=$(vm_state "$VM_NAME")
    if [[ "$STATE" == "running" ]]; then
        info "Sending ACPI shutdown to '${VM_NAME}'..."
        vbm controlvm "$VM_NAME" acpipowerbutton 2>/dev/null || true
        # Wait up to 30s for graceful shutdown, then poweroff
        for i in $(seq 1 10); do
            sleep 3
            STATE=$(vm_state "$VM_NAME")
            if [[ "$STATE" != "running" ]]; then
                ok "VM stopped gracefully"
                break
            fi
        done
        if [[ "$(vm_state "$VM_NAME")" == "running" ]]; then
            warn "Graceful shutdown timed out — forcing poweroff"
            vbm controlvm "$VM_NAME" poweroff 2>/dev/null || true
        fi
    else
        info "VM is already stopped (state: ${STATE})"
    fi
    # Stop msfrpcd
    if pkill -f msfrpcd 2>/dev/null; then
        ok "msfrpcd stopped"
    else
        info "msfrpcd was not running"
    fi
    exit 0
fi

# ── Step 4: Start VM ──────────────────────────────────────────────────────────
banner "Step 4 — Starting VM"
STATE=$(vm_state "$VM_NAME")

case "$STATE" in
    running)
        ok "VM '${VM_NAME}' is already running"
        ;;
    saved)
        info "Resuming VM from saved state..."
        vbm startvm "$VM_NAME" --type headless 2>&1 | tail -2
        ok "VM resumed (headless)"
        ;;
    poweroff|aborted|"")
        info "Starting '${VM_NAME}' in headless mode..."
        vbm startvm "$VM_NAME" --type headless 2>&1 | tail -2
        ok "VM started (headless)"
        ;;
    *)
        warn "VM is in state '${STATE}' — attempting to start anyway..."
        vbm startvm "$VM_NAME" --type headless 2>&1 | tail -2
        ;;
esac

# ── Step 5: Wait for target to be reachable ───────────────────────────────────
banner "Step 5 — Waiting for ${TARGET_IP}"
echo "  Polling every ${PING_INTERVAL}s (max ${BOOT_TIMEOUT}s)..."

ELAPSED=0
REACHABLE=false
while [[ $ELAPSED -lt $BOOT_TIMEOUT ]]; do
    if ping -c1 -W2 "$TARGET_IP" &>/dev/null; then
        REACHABLE=true
        break
    fi
    printf "  [%3ds] waiting for %s ...\r" "$ELAPSED" "$TARGET_IP"
    sleep "$PING_INTERVAL"
    ELAPSED=$((ELAPSED + PING_INTERVAL))
done
echo ""

if [[ "$REACHABLE" == "true" ]]; then
    ok "${TARGET_IP} is reachable (${ELAPSED}s)"
else
    warn "Timeout after ${BOOT_TIMEOUT}s — VM may still be booting."
    warn "Try pinging manually: ping ${TARGET_IP}"
    warn "Or check status:      bash scripts/start_lab.sh --status"
fi

# ── Step 6: Run health check ──────────────────────────────────────────────────
banner "Step 6 — RedOps Health Check"

PYTHON="${PROJECT_DIR}/.venv/bin/python"

if [[ -x "$PYTHON" ]]; then
    info "Running: python -m redops health"
    echo ""
    "$PYTHON" -m redops health 2>&1
else
    warn ".venv not found at ${PROJECT_DIR}/.venv"
    warn "Activate your venv and run: python -m redops health"
fi

echo ""
echo -e "${BOLD}Lab is ready.${NC}"
echo ""
echo "  Next steps:"
echo "    # Dry run (no exploitation):"
echo "    sudo ${PYTHON} -m redops run --target ${HOST_ONLY_NET} --dry-run"
echo ""
echo "    # Full pentest:"
echo "    sudo ${PYTHON} -m redops run --target ${HOST_ONLY_NET} --profile balanced"
echo ""
echo "    # Stop lab when done:"
echo "    bash scripts/start_lab.sh --stop"
