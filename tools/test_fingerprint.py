#!/usr/bin/env python3
"""
ArmorPilot — Hardware Fingerprint Test
Tests all 4 fingerprint groups and reports availability, stability notes.
Run on both Windows and Linux to compare.
"""
import json
import os
import platform
import socket
import subprocess
import sys
import time
from typing import Any


RESULTS = {}


def _run(cmd: list[str], timeout: int = 5) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout)
        return out.decode(errors="replace").strip()
    except Exception:
        return ""


def test(group: str, name: str, fn):
    """Run a single fingerprint test and record result."""
    t0 = time.monotonic()
    try:
        value = fn()
        elapsed = time.monotonic() - t0
        status = "OK" if value else "EMPTY"
        RESULTS.setdefault(group, []).append({
            "name": name,
            "status": status,
            "value": (value[:80] + "…") if value and len(value) > 80 else value,
            "ms": round(elapsed * 1000),
        })
    except Exception as e:
        elapsed = time.monotonic() - t0
        RESULTS.setdefault(group, []).append({
            "name": name,
            "status": "ERROR",
            "value": str(e)[:120],
            "ms": round(elapsed * 1000),
        })


# ===========================================================================
# GROUP 1: OS-level identifiers
# ===========================================================================

def g1_machine_id_linux():
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            v = open(path).read().strip()
            if v:
                return v
        except OSError:
            pass
    return ""


def g1_machine_guid_windows():
    import winreg
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
    val, _ = winreg.QueryValueEx(key, "MachineGuid")
    return str(val).strip()


def g1_sqm_machine_id_windows():
    import winreg
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\SQMClient")
    val, _ = winreg.QueryValueEx(key, "MachineId")
    return str(val).strip()


def g1_hostname():
    return socket.gethostname()


def g1_fqdn():
    return socket.getfqdn()


def run_group1():
    is_win = sys.platform == "win32"
    test("GROUP 1: OS-level ID", "machine-id (Linux /etc/machine-id)", g1_machine_id_linux)
    if is_win:
        test("GROUP 1: OS-level ID", "MachineGuid (Windows Registry)", g1_machine_guid_windows)
        test("GROUP 1: OS-level ID", "SQMClient MachineId (Windows Registry)", g1_sqm_machine_id_windows)
    test("GROUP 1: OS-level ID", "hostname", g1_hostname)
    test("GROUP 1: OS-level ID", "FQDN", g1_fqdn)


# ===========================================================================
# GROUP 2: Hardware identifiers
# ===========================================================================

def g2_bios_uuid_linux():
    # Try dmidecode (needs root)
    v = _run(["dmidecode", "-s", "system-uuid"])
    if v and v.lower() not in ("", "not present", "not specified"):
        return v
    # Try sysfs (may not need root)
    try:
        v = open("/sys/class/dmi/id/product_uuid").read().strip()
        if v:
            return v
    except OSError:
        pass
    return ""


def g2_bios_uuid_windows():
    v = _run(["wmic", "csproduct", "get", "UUID"], timeout=10)
    lines = [l.strip() for l in v.splitlines() if l.strip() and l.strip().upper() != "UUID"]
    return lines[0] if lines else ""


def g2_disk_serial_linux():
    # Try lsblk
    v = _run(["lsblk", "-no", "SERIAL", "/dev/sda"])
    if v:
        return f"/dev/sda: {v}"
    # Try by-id symlinks
    try:
        links = os.listdir("/dev/disk/by-id/")
        ids = [l for l in links if not l.startswith("wwn-") and "part" not in l]
        return ids[0] if ids else ""
    except OSError:
        return ""


def g2_disk_serial_windows():
    v = _run(["wmic", "diskdrive", "get", "SerialNumber"], timeout=10)
    lines = [l.strip() for l in v.splitlines() if l.strip() and l.strip().lower() != "serialnumber"]
    return lines[0] if lines else ""


def g2_mac_uuid_getnode():
    import uuid
    mac_int = uuid.getnode()
    # Check multicast bit (bit 0 of first byte) — if set, it's random
    first_byte = (mac_int >> 40) & 0xFF
    if first_byte & 0x01:
        return f"(likely random — multicast bit set): {mac_int:012x}"
    return ":".join(f"{(mac_int >> (8*i)) & 0xff:02x}" for i in range(5, -1, -1))


def g2_mac_all_interfaces():
    macs = []
    if sys.platform == "win32":
        v = _run(["getmac", "/fo", "csv", "/nh"], timeout=8)
        for line in v.splitlines():
            parts = line.strip().strip('"').split('","')
            if parts and len(parts[0]) == 17:
                mac = parts[0].lower().replace("-", ":")
                macs.append(mac)
    else:
        v = _run(["ip", "link", "show"])
        for line in v.splitlines():
            line = line.strip()
            if line.startswith("link/ether"):
                mac = line.split()[1]
                macs.append(mac)
    return ", ".join(sorted(set(macs))) if macs else ""


def g2_cpu_info():
    if sys.platform == "win32":
        v = _run(["wmic", "cpu", "get", "ProcessorId"], timeout=8)
        lines = [l.strip() for l in v.splitlines() if l.strip() and l.strip().lower() != "processorid"]
        return lines[0] if lines else ""
    else:
        v = _run(["dmidecode", "-t", "processor"])
        for line in v.splitlines():
            if "ID:" in line:
                return line.split("ID:")[-1].strip()
        return ""


def run_group2():
    is_win = sys.platform == "win32"
    if is_win:
        test("GROUP 2: Hardware ID", "BIOS/System UUID (wmic csproduct)", g2_bios_uuid_windows)
        test("GROUP 2: Hardware ID", "Disk serial (wmic diskdrive)", g2_disk_serial_windows)
        test("GROUP 2: Hardware ID", "CPU ProcessorId (wmic)", g2_cpu_info)
    else:
        test("GROUP 2: Hardware ID", "BIOS/System UUID (dmidecode/sysfs)", g2_bios_uuid_linux)
        test("GROUP 2: Hardware ID", "Disk serial (lsblk/by-id)", g2_disk_serial_linux)
        test("GROUP 2: Hardware ID", "CPU ProcessorId (dmidecode)", g2_cpu_info)
    test("GROUP 2: Hardware ID", "MAC via uuid.getnode()", g2_mac_uuid_getnode)
    test("GROUP 2: Hardware ID", "All MACs via OS command", g2_mac_all_interfaces)


# ===========================================================================
# GROUP 3: Cloud / Kubernetes
# ===========================================================================

def g3_k8s_namespace_uid():
    try:
        from kubernetes import client, config as k8s_config
        k8s_config.load_incluster_config()
        v1 = client.CoreV1Api()
        ns = v1.read_namespace("kube-system")
        return str(ns.metadata.uid)
    except Exception:
        pass
    # Fallback: env override
    v = os.environ.get("ARMORPILOT_INSTALLATION_CLUSTER_UID", "")
    if v:
        return f"(env override) {v}"
    return ""


def g3_aws_instance_id():
    import urllib.request
    req = urllib.request.Request(
        "http://169.254.169.254/latest/meta-data/instance-id",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "5"}
    )
    with urllib.request.urlopen(req, timeout=2) as r:
        return r.read().decode().strip()


def g3_gcp_instance_id():
    import urllib.request
    req = urllib.request.Request(
        "http://metadata.google.internal/computeMetadata/v1/instance/id",
        headers={"Metadata-Flavor": "Google"}
    )
    with urllib.request.urlopen(req, timeout=2) as r:
        return r.read().decode().strip()


def g3_azure_instance_id():
    import urllib.request
    req = urllib.request.Request(
        "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01&format=text",
        headers={"Metadata": "true"}
    )
    with urllib.request.urlopen(req, timeout=2) as r:
        return r.read().decode().strip()


def run_group3():
    test("GROUP 3: Cloud / K8s", "K8s kube-system namespace UID", g3_k8s_namespace_uid)
    test("GROUP 3: Cloud / K8s", "AWS EC2 instance ID (metadata)", g3_aws_instance_id)
    test("GROUP 3: Cloud / K8s", "GCP instance ID (metadata)", g3_gcp_instance_id)
    test("GROUP 3: Cloud / K8s", "Azure VM ID (metadata)", g3_azure_instance_id)


# ===========================================================================
# GROUP 4: TPM
# ===========================================================================

def g4_tpm_linux():
    # Check device file
    for dev in ("/dev/tpm0", "/dev/tpmrm0"):
        if os.path.exists(dev):
            return f"TPM device present: {dev}"
    # Check sysfs
    try:
        devices = os.listdir("/sys/class/tpm/")
        if devices:
            return f"TPM sysfs devices: {', '.join(devices)}"
    except OSError:
        pass
    return ""


def g4_tpm_windows():
    v = _run(["wmic", "/namespace:\\\\root\\CIMV2\\Security\\MicrosoftTPM",
              "path", "Win32_Tpm", "get", "IsEnabled_InitialValue"], timeout=10)
    lines = [l.strip() for l in v.splitlines() if l.strip() and "IsEnabled" not in l]
    if lines:
        return f"TPM IsEnabled: {lines[0]}"
    # Try PowerShell
    v2 = _run(["powershell", "-Command",
               "Get-Tpm | Select-Object TpmPresent,TpmReady | ConvertTo-Json"],
              timeout=10)
    return v2[:200] if v2 else ""


def g4_tpm_ek_linux():
    """Try to read TPM Endorsement Key public — needs root + tpm2-tools."""
    v = _run(["tpm2_createek", "--ek-context", "/dev/null",
              "--key-algorithm", "rsa"], timeout=8)
    return "tpm2_createek available" if v else ""


def run_group4():
    is_win = sys.platform == "win32"
    if is_win:
        test("GROUP 4: TPM", "TPM presence + IsEnabled (wmic)", g4_tpm_windows)
    else:
        test("GROUP 4: TPM", "TPM device file (/dev/tpm0)", g4_tpm_linux)
        test("GROUP 4: TPM", "TPM2 EK read (tpm2-tools)", g4_tpm_ek_linux)


# ===========================================================================
# MAIN
# ===========================================================================

def print_results():
    plat = f"{platform.system()} {platform.release()} ({platform.machine()})"
    print(f"\n{'='*70}")
    print(f"  ArmorPilot Fingerprint Test — {plat}")
    print(f"  Python {sys.version.split()[0]}")
    print(f"{'='*70}")

    STATUS_ICON = {"OK": "[OK]   ", "EMPTY": "[EMPTY]", "ERROR": "[ERROR]"}

    for group, items in RESULTS.items():
        print(f"\n--- {group} ---")
        for item in items:
            icon = STATUS_ICON.get(item["status"], "[?]")
            ms_str = f"({item['ms']}ms)"
            val = item["value"] or "(empty)"
            print(f"  {icon} {item['name']:<45} {ms_str:>8}")
            if item["value"]:
                print(f"          -> {val}")

    print(f"\n{'='*70}")
    # Summary
    all_items = [i for items in RESULTS.values() for i in items]
    ok = sum(1 for i in all_items if i["status"] == "OK")
    empty = sum(1 for i in all_items if i["status"] == "EMPTY")
    error = sum(1 for i in all_items if i["status"] == "ERROR")
    print(f"  SUMMARY: {ok} available  {empty} empty  {error} error  (total {len(all_items)})")
    print(f"{'='*70}\n")

    # Save JSON for comparison
    out_file = f"fingerprint_test_{platform.system().lower()}.json"
    with open(out_file, "w") as f:
        json.dump({"platform": plat, "results": RESULTS}, f, indent=2)
    print(f"  Saved to: {out_file}")


if __name__ == "__main__":
    print("Running fingerprint tests… (some may take a few seconds)")
    run_group1()
    run_group2()
    run_group3()
    run_group4()
    print_results()
