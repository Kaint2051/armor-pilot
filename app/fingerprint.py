# Copyright 2026 ArmorPilot Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Hardware fingerprint collection for license binding.

Binding hash formula (v1):
    components = sorted([
        "machine_id:<value>",   # /etc/machine-id or Windows MachineGuid
        "bios_uuid:<value>",    # BIOS system UUID (Linux only, when available)
        "mac:<primary_mac>",    # primary NIC MAC address
    ])
    sha256("|".join(components)).hexdigest()

Only stable, per-machine identifiers are included.  Hostname is collected for
display purposes only and is NOT part of the binding hash.
"""
from __future__ import annotations

import hashlib
import socket
import subprocess
import sys
from typing import Any


def _run(cmd: list[str], timeout: int = 5) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout)
        return out.decode(errors="replace").strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Machine ID
# ---------------------------------------------------------------------------

def _machine_id_linux() -> str:
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path) as f:
                v = f.read().strip()
            if v:
                return v
        except OSError:
            pass
    return ""


def _machine_id_windows() -> str:
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
        )
        val, _ = winreg.QueryValueEx(key, "MachineGuid")
        return str(val).strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# BIOS / System UUID  (Linux only — sysfs first, dmidecode fallback)
# ---------------------------------------------------------------------------

def _bios_uuid_linux() -> str:
    _null_uuids = {
        "",
        "00000000-0000-0000-0000-000000000000",
        "not present",
        "not specified",
    }
    try:
        with open("/sys/class/dmi/id/product_uuid") as f:
            v = f.read().strip().lower()
        if v and v not in _null_uuids:
            return v
    except OSError:
        pass
    v = _run(["dmidecode", "-s", "system-uuid"]).lower()
    if v and v not in _null_uuids:
        return v
    return ""


# ---------------------------------------------------------------------------
# Primary MAC address
# ---------------------------------------------------------------------------

def _primary_mac() -> str:
    """Return primary NIC MAC via uuid.getnode() as lowercase colon-separated hex.

    uuid.getnode() sets the multicast bit when it cannot determine the real MAC
    and falls back to a random value; we treat that as unavailable.
    """
    try:
        import uuid as _uuid
        mac_int = _uuid.getnode()
        # Byte 0 (MSB) of a real unicast MAC has bit 0 (multicast) cleared.
        if (mac_int >> 40) & 0x01:
            return ""
        return ":".join(f"{(mac_int >> (8 * i)) & 0xFF:02x}" for i in range(5, -1, -1))
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect() -> dict[str, Any]:
    """Collect hardware identifiers from the current machine.

    Returns a dict with:
      platform    - "linux" or "windows"
      machine_id  - OS-level stable UUID (used in binding hash)
      bios_uuid   - BIOS system UUID, Linux only (used in binding hash when present)
      mac_primary - primary NIC MAC address (used in binding hash)
      hostname    - display only, NOT part of the binding hash
    """
    is_win = sys.platform == "win32"
    return {
        "platform": "windows" if is_win else "linux",
        "machine_id": _machine_id_windows() if is_win else _machine_id_linux(),
        "bios_uuid": "" if is_win else _bios_uuid_linux(),
        "mac_primary": _primary_mac(),
        "hostname": _safe_hostname(),
    }


def _safe_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return ""


def compute_hash(fp: dict[str, Any]) -> str:
    """Compute the v1 binding hash from a fingerprint dict.

    Returns a lowercase hex SHA-256 string suitable for use as
    ``bound_fingerprint`` in a license payload.

    Raises ValueError if no hardware identifiers are available.
    """
    components: list[str] = []

    machine_id = (fp.get("machine_id") or "").strip()
    if machine_id:
        components.append(f"machine_id:{machine_id}")

    bios_uuid = (fp.get("bios_uuid") or "").strip().lower()
    if bios_uuid:
        components.append(f"bios_uuid:{bios_uuid}")

    mac_primary = (fp.get("mac_primary") or "").strip().lower()
    if mac_primary:
        components.append(f"mac:{mac_primary}")

    if not components:
        raise ValueError(
            "no hardware identifiers available to compute fingerprint hash"
        )

    canonical = "|".join(sorted(components))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def get_current_fingerprint_hash() -> str:
    """Collect current machine hardware info and return its binding hash."""
    return compute_hash(collect())
