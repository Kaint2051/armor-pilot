"""
License issuance tool for ArmorPilot.

Usage:
    py tools/issue_license.py [options]

Options:
    --private-key PATH        Path to Ed25519 private key PEM (default: license-test/test-license-private.pem)
    --from-request PATH       Load activation request JSON; auto-fills installation-id and bound-fingerprint
    --customer NAME           Customer name (default: Test Customer)
    --license-id ID           License ID (default: auto-generated)
    --days DAYS               Validity in days (default: 365)
    --grace-days DAYS         Grace period in days (default: 7)
    --max-nodes N             Max nodes limit, 0 = unlimited (default: 0)
    --max-policies N          Max policies limit, 0 = unlimited (default: 0)
    --edition EDITION         License edition (default: enterprise)
    --installation-id ID      Bind to a specific installation ID (overrides --from-request)
    --bound-fingerprint HASH  Hardware fingerprint hash to bind to (overrides --from-request)
    --no-fingerprint          Issue license without hardware binding even when --from-request has fingerprint
    --output PATH             Write key to file (default: print to stdout)
    --prefix PREFIX           License key prefix (default: ARMORPILOT1)

Examples:
    # Bind to specific installation + hardware from activation request
    py tools/issue_license.py --private-key /path/to/prod-license-private.pem \\
        --from-request activation.json --customer "Acme Corp" --days 365

    # Production license, no hardware binding
    py tools/issue_license.py --private-key /path/to/prod-license-private.pem \\
        --customer "Big Corp" --days 365 --no-fingerprint

    # Test license (30 days, 5 nodes)
    py tools/issue_license.py --customer "Acme Corp" --days 30 --max-nodes 5
"""

import argparse
import base64
import json
import sys
import datetime as dt
from pathlib import Path


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def canonical_payload(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_private_key(path: str):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    pem = Path(path).read_bytes()
    return load_pem_private_key(pem, password=None)


def load_activation_request(path: str) -> dict:
    """Load and parse an activation request JSON file."""
    raw = Path(path).read_text(encoding="utf-8")
    req = json.loads(raw)
    if not isinstance(req, dict):
        raise ValueError("activation request must be a JSON object")
    inner = req.get("payload")
    if not isinstance(inner, dict):
        raise ValueError("activation request missing 'payload' field")
    return req


def issue(
    private_key_path: str,
    customer: str,
    license_id: str,
    days: int,
    grace_days: int,
    max_nodes: int,
    max_policies: int,
    edition: str,
    installation_id: str | None,
    bound_fingerprint: str | None,
    prefix: str,
) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    expires_at = now + dt.timedelta(days=days)

    payload = {
        "license_id": license_id,
        "customer": customer,
        "edition": edition,
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "grace_days": grace_days,
        "features": ["*"],
        "limits": {},
    }

    if max_nodes > 0:
        payload["limits"]["max_nodes"] = max_nodes
    if max_policies > 0:
        payload["limits"]["max_policies"] = max_policies
    if installation_id:
        payload["installation_id"] = installation_id
    if bound_fingerprint:
        payload["bound_fingerprint"] = bound_fingerprint.strip().lower()

    key = load_private_key(private_key_path)
    encoded_payload = b64url_encode(canonical_payload(payload))
    signature = b64url_encode(key.sign(canonical_payload(payload)))

    return f"{prefix}.{encoded_payload}.{signature}"


def auto_license_id() -> str:
    import random, string
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return f"LIC-{suffix}"


def _print_request_summary(req: dict) -> None:
    inner = req.get("payload", {})
    print("\n--- Activation Request Summary ---")
    print(f"  Installation UUID : {inner.get('installation_uuid', '(none)')}")
    print(f"  Installation ID   : {inner.get('installation_id', '(none)')}")
    print(f"  Cluster UID       : {inner.get('cluster_uid', '(none)')}")
    print(f"  Generated at      : {inner.get('generated_at', '(none)')}")

    hw = inner.get("hardware_info") or {}
    fp = inner.get("hardware_fingerprint", "")
    if hw or fp:
        print("\n  Hardware Info:")
        print(f"    Platform        : {hw.get('platform', '?')}")
        print(f"    Hostname        : {hw.get('hostname', '?')}")
        print(f"    Machine ID      : {hw.get('machine_id', '?')}")
        if hw.get("bios_uuid"):
            print(f"    BIOS UUID       : {hw.get('bios_uuid')}")
        print(f"    Primary MAC     : {hw.get('mac_primary', '?')}")
        if fp:
            print(f"    Fingerprint Hash: {fp}")

    cr = inner.get("customer_request") or {}
    if cr:
        print("\n  Customer Request:")
        for k, v in cr.items():
            if v:
                print(f"    {k:<24}: {v}")
    print("----------------------------------")


def main():
    parser = argparse.ArgumentParser(description="Issue ArmorPilot license keys")
    parser.add_argument("--private-key", default="license-test/test-license-private.pem")
    parser.add_argument("--from-request", default=None, metavar="PATH",
                        help="Activation request JSON to auto-fill installation-id and bound-fingerprint")
    parser.add_argument("--customer", default="Test Customer")
    parser.add_argument("--license-id", default=None)
    parser.add_argument("--days", type=int, default=365)
    parser.add_argument("--grace-days", type=int, default=7)
    parser.add_argument("--max-nodes", type=int, default=0)
    parser.add_argument("--max-policies", type=int, default=0)
    parser.add_argument("--edition", default="enterprise")
    parser.add_argument("--installation-id", default=None)
    parser.add_argument("--bound-fingerprint", default=None, metavar="HASH")
    parser.add_argument("--no-fingerprint", action="store_true",
                        help="Do not embed hardware fingerprint even if present in activation request")
    parser.add_argument("--output", default=None)
    parser.add_argument("--prefix", default="ARMORPILOT1")
    args = parser.parse_args()

    if not Path(args.private_key).exists():
        print(f"ERROR: private key not found: {args.private_key}", file=sys.stderr)
        sys.exit(1)

    installation_id = args.installation_id
    bound_fingerprint = None if args.no_fingerprint else args.bound_fingerprint

    # Load activation request and auto-fill fields
    if args.from_request:
        if not Path(args.from_request).exists():
            print(f"ERROR: activation request not found: {args.from_request}", file=sys.stderr)
            sys.exit(1)
        req = load_activation_request(args.from_request)
        _print_request_summary(req)
        inner = req["payload"]

        if not installation_id:
            installation_id = inner.get("installation_id") or None
        if not bound_fingerprint and not args.no_fingerprint:
            bound_fingerprint = inner.get("hardware_fingerprint") or None

        # Auto-fill customer name from request if still default
        if args.customer == "Test Customer":
            cr = inner.get("customer_request") or {}
            org = cr.get("organization_name", "").strip()
            if org:
                args.customer = org

    license_id = args.license_id or auto_license_id()

    key_text = issue(
        private_key_path=args.private_key,
        customer=args.customer,
        license_id=license_id,
        days=args.days,
        grace_days=args.grace_days,
        max_nodes=args.max_nodes,
        max_policies=args.max_policies,
        edition=args.edition,
        installation_id=installation_id,
        bound_fingerprint=bound_fingerprint,
        prefix=args.prefix,
    )

    if args.output:
        Path(args.output).write_text(key_text + "\n", encoding="utf-8")
        print(f"\nLicense written to : {args.output}")
        print(f"License ID         : {license_id}")
    else:
        print(f"\nLicense ID         : {license_id}")
        print(f"Customer           : {args.customer}")
        print(f"Edition            : {args.edition}")
        print(f"Valid days         : {args.days}")
        print(f"Max nodes          : {'unlimited' if args.max_nodes == 0 else args.max_nodes}")
        print(f"Max policies       : {'unlimited' if args.max_policies == 0 else args.max_policies}")
        if installation_id:
            print(f"Bound installation : {installation_id}")
        if bound_fingerprint:
            print(f"Bound fingerprint  : {bound_fingerprint}")
        else:
            print(f"Bound fingerprint  : (none — not hardware-bound)")
        print(f"\nLicense key:\n{key_text}\n")


if __name__ == "__main__":
    main()
