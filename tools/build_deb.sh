#!/usr/bin/env bash
# Build a self-contained ArmorPilot .deb package.
#
# Usage:
#   bash tools/build_deb.sh [VERSION]
#
# Must be run from the varmor-console/ directory on a Linux x86_64 machine
# with Python 3.11+ installed.  PyInstaller and waitress are installed
# automatically from requirements.txt.
#
# Output: dist/armor-pilot_<VERSION>_amd64.deb
set -euo pipefail

VERSION="${1:-0.3.8}"
ARCH="amd64"
PKG="armor-pilot"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

# ---------------------------------------------------------------------------
# Step 1 — Install build dependencies
# ---------------------------------------------------------------------------
echo "[1/4] Installing build dependencies..."
pip install --quiet pyinstaller waitress
pip install --quiet -r requirements.txt

# ---------------------------------------------------------------------------
# Step 2 — Build PyInstaller onefile binary
# ---------------------------------------------------------------------------
echo "[2/4] Building PyInstaller binary (this may take a few minutes)..."
pyinstaller ArmorPilot-linux.spec --clean --noconfirm

BINARY="dist/armor-pilot"
if [ ! -f "$BINARY" ]; then
    echo "ERROR: PyInstaller build failed — $BINARY not found" >&2
    exit 1
fi
echo "      Binary size: $(du -sh "$BINARY" | cut -f1)"

# ---------------------------------------------------------------------------
# Step 3 — Assemble .deb directory layout
# ---------------------------------------------------------------------------
echo "[3/4] Assembling .deb package structure..."

DEB_STAGE="dist/deb-stage/${PKG}_${VERSION}_${ARCH}"
rm -rf "$DEB_STAGE"

# Install tree
install -Dm755 "$BINARY"                                   "$DEB_STAGE/usr/local/bin/armor-pilot"
install -Dm644 packaging/deb/lib/systemd/system/armor-pilot.service \
                                                           "$DEB_STAGE/lib/systemd/system/armor-pilot.service"

# Control files
install -Dm644 packaging/deb/DEBIAN/control                "$DEB_STAGE/DEBIAN/control"
install -Dm755 packaging/deb/DEBIAN/postinst               "$DEB_STAGE/DEBIAN/postinst"
install -Dm755 packaging/deb/DEBIAN/prerm                  "$DEB_STAGE/DEBIAN/prerm"

# Patch version in control file
sed -i "s/^Version:.*/Version: ${VERSION}/" "$DEB_STAGE/DEBIAN/control"

# ---------------------------------------------------------------------------
# Step 4 — Build .deb
# ---------------------------------------------------------------------------
echo "[4/4] Building .deb..."

DEB_OUT="dist/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$DEB_STAGE" "$DEB_OUT"

echo ""
echo "============================================================"
echo "  Build complete: $DEB_OUT"
echo "  Size          : $(du -sh "$DEB_OUT" | cut -f1)"
echo "============================================================"
echo ""
echo "Install on target machine:"
echo "  sudo dpkg -i $DEB_OUT"
echo ""
echo "Then check status:"
echo "  sudo systemctl status armor-pilot"
echo "  sudo journalctl -u armor-pilot -f"
echo ""
echo "Edit credentials before first start (optional):"
echo "  sudo nano /etc/armor-pilot/armor-pilot.env"
echo "  sudo systemctl restart armor-pilot"
