#!/usr/bin/env python3
import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _parse_license_text(raw: str) -> dict:
    value = raw.strip()
    if value.startswith("VARMOR1."):
        parts = value.split(".")
        if len(parts) != 3:
            raise SystemExit("license key format is invalid")
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        return {"algorithm": "Ed25519", "payload": payload, "signature": parts[2]}
    return json.loads(value)


def _verify_activation_request(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("version") != "varmor-activation-request/v1":
        raise SystemExit("activation request version is invalid")
    payload = doc.get("payload")
    signature = doc.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str) or not signature:
        raise SystemExit("activation request payload or signature is invalid")
    required_fields = (
        "installation_id",
        "installation_uuid",
        "installation_public_key",
        "cluster_uid",
        "api_ca_sha256",
    )
    for field in required_fields:
        if not isinstance(payload.get(field), str) or not payload[field].strip():
            raise SystemExit(f"activation request is missing {field}")

    try:
        raw_public = base64.b64decode(payload["installation_public_key"], validate=True)
        request_key = Ed25519PublicKey.from_public_bytes(raw_public)
        request_key.verify(_b64url_decode(signature), _canonical(payload))
    except Exception as exc:
        raise SystemExit(f"activation request signature is invalid: {exc}") from exc

    identity_payload = {
        "version": "varmor-installation/v1",
        "installation_uuid": payload.get("installation_uuid"),
        "installation_public_key": payload.get("installation_public_key"),
        "cluster_uid": payload.get("cluster_uid"),
        "api_ca_sha256": payload.get("api_ca_sha256"),
    }
    expected_id = "vmi_" + hashlib.sha256(_canonical(identity_payload)).hexdigest()
    actual_id = str(payload.get("installation_id") or "")
    if not hmac.compare_digest(expected_id, actual_id):
        raise SystemExit("activation request installation_id is invalid")
    return payload


def _read_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("private key is not Ed25519")
    return key


def _read_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise SystemExit("public key is not Ed25519")
    return key


def cmd_gen_key(args) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    args.private_key.write_bytes(private_pem)
    args.public_key.write_bytes(public_pem)
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    print(f"private_key={args.private_key}")
    print(f"public_key={args.public_key}")
    print(f"VARMOR_LICENSE_PUBLIC_KEY={base64.b64encode(raw_public).decode('ascii')}")


def cmd_sign(args) -> None:
    private_key = _read_private_key(args.private_key)
    features = [f.strip() for f in args.features.split(",") if f.strip()]
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    expires = now + dt.timedelta(days=args.days)
    payload = {
        "license_id": args.license_id,
        "customer": args.customer,
        "edition": args.edition,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "grace_days": args.grace_days,
        "features": features,
        "limits": {
            "max_nodes": args.max_nodes,
            "max_policies": args.max_policies,
        },
    }
    if args.cluster_uid:
        payload["cluster_uid"] = args.cluster_uid
    if args.activation_request:
        request_payload = _verify_activation_request(args.activation_request)
        request_cluster_uid = str(request_payload.get("cluster_uid") or "").strip()
        if args.cluster_uid and args.cluster_uid != request_cluster_uid:
            raise SystemExit("--cluster-uid does not match activation request")
        payload["installation_id"] = request_payload["installation_id"]
        if request_cluster_uid:
            payload["cluster_uid"] = request_cluster_uid
    signature = _b64url(private_key.sign(_canonical(payload)))
    doc = {
        "algorithm": "Ed25519",
        "payload": payload,
        "signature": signature,
    }
    if args.format == "key":
        license_text = f"VARMOR1.{_b64url(_canonical(payload))}.{signature}\n"
    else:
        license_text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    args.output.write_text(license_text, encoding="utf-8")
    print(f"wrote {args.output}")


def cmd_verify(args) -> None:
    public_key = _read_public_key(args.public_key)
    doc = _parse_license_text(args.license.read_text(encoding="utf-8"))
    public_key.verify(_b64url_decode(doc["signature"]), _canonical(doc["payload"]))
    print("license signature ok")


def cmd_verify_request(args) -> None:
    payload = _verify_activation_request(args.request)
    print("activation request signature ok")
    print(f"installation_id={payload['installation_id']}")
    print(f"cluster_uid={payload.get('cluster_uid') or ''}")
    customer_request = payload.get("customer_request")
    if isinstance(customer_request, dict):
        print(f"request_type={customer_request.get('request_type') or ''}")
        print(f"organization_name={customer_request.get('organization_name') or ''}")
        print(f"contact_name={customer_request.get('contact_name') or ''}")
        print(f"contact_email={customer_request.get('contact_email') or ''}")
        print(f"requested_edition={customer_request.get('requested_edition') or ''}")
        print(f"requested_days={customer_request.get('requested_days') or ''}")
        print(f"requested_nodes={customer_request.get('requested_nodes') or ''}")
        print(f"requested_policies={customer_request.get('requested_policies') or ''}")
        print(f"existing_license_id={customer_request.get('existing_license_id') or ''}")
        print(f"quote_reference={customer_request.get('quote_reference') or ''}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Create and verify vArmor Console licenses.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("gen-key", help="generate an Ed25519 signing key pair")
    p.add_argument("--private-key", type=Path, default=Path("license-private.pem"))
    p.add_argument("--public-key", type=Path, default=Path("license-public.pem"))
    p.set_defaults(func=cmd_gen_key)

    p = sub.add_parser("sign", help="sign a customer license")
    p.add_argument("--private-key", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--license-id", required=True)
    p.add_argument("--customer", required=True)
    p.add_argument("--edition", default="enterprise")
    p.add_argument("--days", type=int, default=365)
    p.add_argument("--grace-days", type=int, default=7)
    p.add_argument("--features", default="*")
    p.add_argument("--max-nodes", type=int, default=0)
    p.add_argument("--max-policies", type=int, default=0)
    p.add_argument("--cluster-uid", default="")
    p.add_argument("--activation-request", type=Path)
    p.add_argument("--format", choices=("key", "json"), default="key")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="verify a signed license")
    p.add_argument("--public-key", type=Path, required=True)
    p.add_argument("--license", type=Path, required=True)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("verify-request", help="verify an offline activation request")
    p.add_argument("--request", type=Path, required=True)
    p.set_defaults(func=cmd_verify_request)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
