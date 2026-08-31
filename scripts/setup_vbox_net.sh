#!/usr/bin/env bash
# =============================================================================
# RedOps Lab — Privileged VirtualBox Network Setup (run once with sudo)
# =============================================================================
# Usage:  sudo bash scripts/setup_vbox_net.sh
# =============================================================================
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
    echo "[ERROR] Run with sudo: sudo bash $0"
    exit 1
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
info() { echo -e "${BLUE}[INFO]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }

echo -e "\n${BOLD}━━━  VirtualBox Kernel Modules  ━━━${NC}"

for mod in vboxdrv vboxnetadp vboxnetflt; do
    if lsmod | grep -q "^${mod}"; then
        ok "${mod} already loaded"
    else
        info "Loading ${mod}..."
        if modprobe "$mod"; then
            ok "${mod} loaded"
        else
            echo -e "${RED}[ERROR]${NC} Failed to load ${mod}"
            exit 1
        fi
    fi
done

echo -e "\n${BOLD}━━━  Host-Only Network 192.168.56.0/24  ━━━${NC}"

# Wait up to 5s for /dev/vboxnetctl to appear after modprobe
for i in 1 2 3 4 5; do
    [[ -c /dev/vboxnetctl ]] && break
    sleep 1
done
if [[ ! -c /dev/vboxnetctl ]]; then
    warn "/dev/vboxnetctl still missing after modprobe — trying to continue anyway"
fi

# Run VBoxManage as the real user (not root) to avoid ownership issues
REAL_USER="${SUDO_USER:-${USER}}"

# Create host-only interface if not present
EXISTING=$(sudo -u "$REAL_USER" VBoxManage list hostonlyifs 2>/dev/null | grep "^Name:" | awk '{print $2}' | head -1)
if [[ -n "$EXISTING" ]]; then
    ok "Host-only interface already exists: ${EXISTING}"
    HOSTONLYIF="$EXISTING"
else
    info "Creating host-only interface..."
    OUTPUT=$(sudo -u "$REAL_USER" VBoxManage hostonlyif create 2>&1)
    HOSTONLYIF=$(echo "$OUTPUT" | grep -oP "(?<=interface ')vboxnet\d+" || echo "vboxnet0")
    ok "Created: ${HOSTONLYIF}"
fi

# Configure IP on the interface
info "Configuring ${HOSTONLYIF} → 192.168.56.1/24..."
sudo -u "$REAL_USER" VBoxManage hostonlyif ipconfig "$HOSTONLYIF" \
    --ip 192.168.56.1 --netmask 255.255.255.0
ok "${HOSTONLYIF} configured: 192.168.56.1 / 255.255.255.0"

echo -e "\n${BOLD}━━━  Attach Network to Metasploitable2  ━━━${NC}"

VM_NAME=""
while IFS= read -r line; do
    name=$(echo "$line" | awk -F'"' '{print $2}')
    if [[ "${name,,}" == *"metasploitable"* ]]; then
        VM_NAME="$name"
        break
    fi
done < <(sudo -u "$REAL_USER" VBoxManage list vms 2>/dev/null)

if [[ -n "$VM_NAME" ]]; then
    sudo -u "$REAL_USER" VBoxManage modifyvm "$VM_NAME" \
        --nic1 hostonly --hostonlyadapter1 "$HOSTONLYIF" 2>/dev/null \
        && ok "VM '${VM_NAME}' NIC1 → ${HOSTONLYIF}" \
        || warn "Could not modify VM network (may already be configured)"
else
    warn "Metasploitable2 VM not found — skipping NIC assignment"
fi

echo -e "\n${BOLD}━━━  Add vboxdrv modules to /etc/modules-load.d  ━━━${NC}"

MODS_FILE="/etc/modules-load.d/vboxdrv.conf"
if [[ ! -f "$MODS_FILE" ]]; then
    printf 'vboxdrv\nvboxnetadp\nvboxnetflt\n' > "$MODS_FILE"
    ok "Created ${MODS_FILE} (modules load on boot)"
else
    ok "${MODS_FILE} already exists"
fi

echo ""
ok "Setup complete. Now run (without sudo):"
echo ""
echo "  cd /home/${REAL_USER}/Projects/Portafolio/RedOps_Automatico"
echo "  bash scripts/start_lab.sh"
echo ""
