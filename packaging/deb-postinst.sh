#!/bin/bash
set -e

# Create system user if it does not exist
if ! id armor-pilot &>/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin armor-pilot
fi

# Persistent data directory
mkdir -p /var/lib/armor-pilot
chown armor-pilot:armor-pilot /var/lib/armor-pilot
chmod 700 /var/lib/armor-pilot

# Reload systemd if available
if command -v systemctl &>/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

echo ""
echo "ArmorPilot installed successfully."
echo ""
echo "  1. Edit  /etc/armor-pilot/armor-pilot.env  — set ADMIN_USER and ADMIN_PASS"
echo "  2. Start: systemctl enable --now armor-pilot"
echo "  3. Open:  http://localhost:5000"
echo ""
