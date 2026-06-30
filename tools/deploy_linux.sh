#!/usr/bin/env bash
# ArmorPilot Linux Deployment Script
#
# Usage:
#   sudo bash deploy_linux.sh [path/to/armor-pilot_*.deb] [/path/to/kubeconfig]
#
# Examples:
#   sudo bash deploy_linux.sh                                        # auto-detect deb + kubeconfig
#   sudo bash deploy_linux.sh armor-pilot_0.3.8_amd64.deb           # explicit deb
#   sudo bash deploy_linux.sh armor-pilot_*.deb /etc/rancher/k3s/k3s.yaml
#
# The script:
#   1. Installs the .deb package (installs binary + systemd service)
#   2. Copies kubeconfig for the armor-pilot service user
#   3. Sets the initial admin credentials in /etc/armor-pilot/armor-pilot.env
#   4. Starts the systemd service
set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; C='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${G}[OK]${NC}   $*"; }
warn() { echo -e "${Y}[WARN]${NC} $*"; }
err()  { echo -e "${R}[ERROR]${NC} $*" >&2; exit 1; }
info() { echo -e "${C}==>${NC} $*"; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || err "Run as root:  sudo bash $0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo -e "${C}============================================================${NC}"
echo -e "${C}  ArmorPilot Linux Deployment${NC}"
echo -e "${C}============================================================${NC}"
echo ""

# ── Locate .deb ───────────────────────────────────────────────────────────────
DEB="${1:-}"
if [[ -z "$DEB" ]]; then
    # Search: script dir first, then current dir
    DEB=$(find "$SCRIPT_DIR" "$PWD" -maxdepth 2 \
          -name "armor-pilot_*_amd64.deb" 2>/dev/null \
          | sort -V | tail -1)
fi
[[ -n "$DEB" && -f "$DEB" ]] || err "No .deb found. Provide path:\n  sudo bash $0 /path/to/armor-pilot_*.deb"
ok "Package: $DEB"

# ── Install package ───────────────────────────────────────────────────────────
info "Installing package..."
dpkg -i "$DEB"
ok "Package installed."

ENV_FILE="/etc/armor-pilot/armor-pilot.env"
DATA_DIR="/var/lib/armor-pilot"

# ── Kubeconfig ────────────────────────────────────────────────────────────────
KUBE_SRC="${2:-}"
if [[ -z "$KUBE_SRC" ]]; then
    # Auto-detect common locations (order: K3s → RKE2 → kubeadm → user home)
    for candidate in \
        /etc/rancher/k3s/k3s.yaml \
        /etc/rancher/rke2/rke2.yaml \
        /etc/kubernetes/admin.conf \
        /root/.kube/config \
        "$HOME/.kube/config"; do
        if [[ -f "$candidate" ]]; then
            KUBE_SRC="$candidate"
            ok "Auto-detected kubeconfig: $KUBE_SRC"
            break
        fi
    done
fi

if [[ -z "$KUBE_SRC" ]]; then
    echo ""
    warn "No kubeconfig found in standard locations."
    read -rp "  Path to kubeconfig (leave blank to skip): " KUBE_SRC
fi

KUBE_DEST="$DATA_DIR/.kube/config"
if [[ -n "$KUBE_SRC" && -f "$KUBE_SRC" ]]; then
    mkdir -p "$(dirname "$KUBE_DEST")"
    cp "$KUBE_SRC" "$KUBE_DEST"
    chown armor-pilot:armor-pilot "$KUBE_DEST"
    chmod 600 "$KUBE_DEST"
    ok "Kubeconfig installed: $KUBE_DEST"

    # Warn if server is 127.0.0.1 / localhost — K3s default
    if grep -qE "server:.*127\.0\.0\.1|server:.*localhost" "$KUBE_DEST" 2>/dev/null; then
        LOCAL_IP=$(hostname -I | awk '{print $1}')
        warn "kubeconfig server is 127.0.0.1/localhost."
        warn "If accessing from another host, update the server URL:"
        warn "  sed -i 's|https://127.0.0.1|https://${LOCAL_IP}|g' $KUBE_DEST"
    fi

    # Write KUBECONFIG into env file
    if grep -q "^KUBECONFIG=" "$ENV_FILE" 2>/dev/null; then
        sed -i "s|^KUBECONFIG=.*|KUBECONFIG=$KUBE_DEST|" "$ENV_FILE"
    else
        echo "KUBECONFIG=$KUBE_DEST" >> "$ENV_FILE"
    fi
    chown armor-pilot:armor-pilot "$ENV_FILE"
    ok "KUBECONFIG set in $ENV_FILE"
else
    warn "Kubeconfig skipped — policy features unavailable until KUBECONFIG is set in $ENV_FILE"
fi

# ── First-run credentials ─────────────────────────────────────────────────────
DB_PATH=$(grep -E "^DB_PATH=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "$DATA_DIR/users.db")
ALREADY_HAS_DB=false
[[ -f "$DB_PATH" ]] && ALREADY_HAS_DB=true

CURRENT_ADMIN_USER=$(grep -E "^ADMIN_USER=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "")
CURRENT_ADMIN_PASS=$(grep -E "^ADMIN_PASS=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "")

if [[ "$ALREADY_HAS_DB" == "false" && ( -z "$CURRENT_ADMIN_USER" || ${#CURRENT_ADMIN_PASS} -lt 12 ) ]]; then
    echo ""
    info "First-run setup: create the initial admin account."
    echo "  (Stored in $ENV_FILE — only used before the first startup)"
    echo ""

    while true; do
        read -rp "  Admin username: " ADMIN_USER
        [[ -n "$ADMIN_USER" ]] && break
        echo "  Username cannot be empty."
    done

    while true; do
        read -rsp "  Admin password (min 12 chars): " ADMIN_PASS; echo ""
        [[ ${#ADMIN_PASS} -ge 12 ]] && break
        echo "  Password must be at least 12 characters."
    done

    # Update env file
    for KEY_VAL in "ADMIN_USER=$ADMIN_USER" "ADMIN_PASS=$ADMIN_PASS"; do
        KEY="${KEY_VAL%%=*}"
        if grep -q "^${KEY}=" "$ENV_FILE" 2>/dev/null; then
            sed -i "s|^${KEY}=.*|${KEY_VAL}|" "$ENV_FILE"
        else
            echo "$KEY_VAL" >> "$ENV_FILE"
        fi
    done
    chown armor-pilot:armor-pilot "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    ok "Credentials saved to $ENV_FILE"
    echo ""
fi

# ── Start / restart service ───────────────────────────────────────────────────
info "Starting armor-pilot service..."
systemctl daemon-reload
systemctl enable armor-pilot.service --quiet
systemctl restart armor-pilot.service

# Wait a moment for it to start
sleep 2
if systemctl is-active --quiet armor-pilot.service; then
    ok "Service is running."
else
    warn "Service did not start cleanly. Check logs:"
    warn "  sudo journalctl -u armor-pilot -n 40 --no-pager"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
PORT=$(grep -E "^PORT=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "5000")
LOCAL_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${C}============================================================${NC}"
echo -e "${G}  Deployment complete!${NC}"
echo -e "${C}============================================================${NC}"
echo ""
echo "  Service   : sudo systemctl status armor-pilot"
echo "  Logs      : sudo journalctl -u armor-pilot -f"
echo "  Config    : $ENV_FILE"
echo "  Data      : $DATA_DIR/"
echo "  URL       : http://${LOCAL_IP}:${PORT}"
echo ""
echo "  To edit config:"
echo "    sudo nano $ENV_FILE"
echo "    sudo systemctl restart armor-pilot"
echo ""
echo "  To uninstall:"
echo "    sudo apt remove armor-pilot   (or: sudo dpkg -r armor-pilot)"
echo ""
