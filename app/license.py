import base64
import binascii
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any


LICENSE_FILE = os.environ.get("VARMOR_LICENSE_FILE", "/app/data/license.json")

# Public keys are safe to distribute, but they are the license trust anchor.
# For production builds, replace this test key with the vendor Ed25519 public key
# and keep VARMOR_LICENSE_ALLOW_ENV_PUBLIC_KEY disabled.
EMBEDDED_LICENSE_PUBLIC_KEY = "OrsGfpk+/4XCzmE/m/CGhXSRFrKgQz8GQqSBcmA/5IE="
LICENSE_KEY_PREFIX = "VARMOR1"


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _canonical_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64url_decode(value: str) -> bytes:
    raw = value.strip().encode("ascii")
    raw += b"=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode(raw)


def parse_license_text(raw: str) -> dict[str, Any]:
    value = (raw or "").strip()
    if not value:
        raise ValueError("license key is required")
    if len(value) > 65536:
        raise ValueError("license key is too large")

    if value.startswith(f"{LICENSE_KEY_PREFIX}."):
        parts = value.split(".")
        if len(parts) != 3:
            raise ValueError("license key format is invalid")
        _, encoded_payload, signature = parts
        try:
            payload = json.loads(_b64url_decode(encoded_payload).decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, ValueError, binascii.Error) as exc:
            raise ValueError("license key payload is invalid") from exc
        if not isinstance(payload, dict):
            raise ValueError("license key payload must be an object")
        if not signature:
            raise ValueError("license key signature is required")
        return {
            "algorithm": "Ed25519",
            "payload": payload,
            "signature": signature,
        }

    try:
        doc = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("license key or JSON is invalid") from exc
    if not isinstance(doc, dict):
        raise ValueError("license must be a key or JSON object")
    return doc


def _verify_hs256(payload: dict[str, Any], signature: str) -> None:
    if not _bool_env("VARMOR_LICENSE_ALLOW_HS256", False):
        raise ValueError("HS256 licenses are disabled")
    secret = os.environ.get("VARMOR_LICENSE_HMAC_SECRET", "")
    if not secret:
        raise ValueError("VARMOR_LICENSE_HMAC_SECRET is not configured")
    expected = hmac.new(secret.encode("utf-8"), _canonical_payload(payload), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64url_decode(signature)):
        raise ValueError("license signature is invalid")


def _load_ed25519_public_key():
    public_key = EMBEDDED_LICENSE_PUBLIC_KEY.strip()
    if _bool_env("VARMOR_LICENSE_ALLOW_ENV_PUBLIC_KEY", False):
        public_key = os.environ.get("VARMOR_LICENSE_PUBLIC_KEY", "").strip() or public_key
    if not public_key:
        raise ValueError("license public key is not configured")
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as exc:
        raise ValueError("cryptography package is required for Ed25519 licenses") from exc
    if public_key.startswith("-----BEGIN"):
        key = load_pem_public_key(public_key.encode("utf-8"))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("VARMOR_LICENSE_PUBLIC_KEY is not an Ed25519 public key")
        return key
    try:
        raw = base64.b64decode(public_key, validate=True)
    except (binascii.Error, ValueError):
        raw = _b64url_decode(public_key)
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise ValueError(f"VARMOR_LICENSE_PUBLIC_KEY is not a valid Ed25519 public key: {exc}") from exc


def _verify_ed25519(payload: dict[str, Any], signature: str) -> None:
    try:
        key = _load_ed25519_public_key()
        key.verify(_b64url_decode(signature), _canonical_payload(payload))
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("license signature is invalid") from exc


def _safe_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "license_id": payload.get("license_id"),
        "customer": payload.get("customer"),
        "edition": payload.get("edition"),
        "issued_at": payload.get("issued_at"),
        "expires_at": payload.get("expires_at"),
        "grace_days": payload.get("grace_days", 0),
        "features": sorted(payload.get("features") or []),
        "limits": payload.get("limits") or {},
        "cluster_uid": payload.get("cluster_uid"),
        "installation_id": payload.get("installation_id"),
    }


def _int_limit(limits: dict[str, Any], name: str) -> int:
    try:
        return int(limits.get(name) or 0)
    except (TypeError, ValueError):
        return 0


def _base_status() -> dict[str, Any]:
    required = _bool_env("VARMOR_LICENSE_REQUIRED", False)
    fail_open = _bool_env("VARMOR_LICENSE_FAIL_OPEN", not required)
    binding_required = _bool_env("VARMOR_LICENSE_REQUIRE_INSTALLATION_BINDING", False)
    return {
        "path": LICENSE_FILE,
        "required": required,
        "fail_open": fail_open,
        "binding_required": binding_required,
        "present": False,
        "valid": False,
        "status": "missing",
        "reason": "license file is not present",
        "payload": None,
        "effective_features": ["*"] if fail_open else [],
        "days_remaining": None,
        "in_grace": False,
        "compliant": True,
        "warnings": [],
        "violations": [],
        "usage": {},
        "limit_status": {},
    }


def verify_license_document(doc: dict[str, Any]) -> dict[str, Any]:
    payload = doc.get("payload")
    signature = doc.get("signature")
    algorithm = (doc.get("algorithm") or doc.get("alg") or "Ed25519").strip()
    if not isinstance(payload, dict):
        raise ValueError("license payload must be an object")
    if not isinstance(signature, str) or not signature.strip():
        raise ValueError("license signature is required")

    if algorithm == "Ed25519":
        _verify_ed25519(payload, signature)
    elif algorithm == "HS256":
        _verify_hs256(payload, signature)
    else:
        raise ValueError(f"unsupported license algorithm: {algorithm}")

    now = _utc_now()
    expires_at = _parse_time(payload.get("expires_at"))
    if not expires_at:
        raise ValueError("payload.expires_at must be an ISO-8601 timestamp")
    grace_days = int(payload.get("grace_days") or 0)
    grace_until = expires_at + dt.timedelta(days=max(grace_days, 0))
    if now > grace_until:
        raise ValueError("license is expired")

    issued_at = _parse_time(payload.get("issued_at"))
    if issued_at and issued_at > now + dt.timedelta(minutes=5):
        raise ValueError("license issued_at is in the future")

    expected_cluster = (payload.get("cluster_uid") or "").strip()
    runtime_cluster = os.environ.get("VARMOR_CLUSTER_UID", "").strip()
    if expected_cluster and runtime_cluster and expected_cluster != runtime_cluster:
        raise ValueError("license cluster_uid does not match this cluster")

    expected_installation = str(payload.get("installation_id") or "").strip()
    binding_required = _bool_env("VARMOR_LICENSE_REQUIRE_INSTALLATION_BINDING", False)
    if binding_required and not expected_installation:
        raise ValueError("license is not bound to this installation")
    if expected_installation:
        try:
            from .installation import get_installation_identity

            runtime_installation = get_installation_identity()["installation_id"]
        except Exception as exc:
            raise ValueError(f"installation identity is unavailable: {exc}") from exc
        if not hmac.compare_digest(expected_installation, runtime_installation):
            raise ValueError("license installation_id does not match this installation")

    return {
        "payload": payload,
        "days_remaining": max(0, (expires_at - now).days),
        "in_grace": now > expires_at,
        "installation_id": expected_installation or None,
    }


def get_license_status() -> dict[str, Any]:
    status = _base_status()
    path = Path(LICENSE_FILE)
    if not path.exists():
        return status
    status["present"] = True
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        verified = verify_license_document(doc)
        payload = verified["payload"]
        features = sorted(set(payload.get("features") or []))
        status.update({
            "valid": True,
            "status": "valid",
            "reason": "license is valid",
            "payload": _safe_payload(payload),
            "effective_features": features,
            "days_remaining": verified["days_remaining"],
            "in_grace": verified["in_grace"],
            "algorithm": doc.get("algorithm") or doc.get("alg") or "Ed25519",
            "compliant": True,
        })
        if status["in_grace"]:
            status["status"] = "in_grace"
            status["reason"] = "license is in grace period"
            status["warnings"].append("license is in grace period")
        elif status["days_remaining"] is not None and status["days_remaining"] <= 30:
            status["warnings"].append("license expires within 30 days")
        if "*" in features:
            status["effective_features"] = ["*"]
        return status
    except Exception as exc:
        status.update({
            "status": "invalid",
            "reason": str(exc),
            "effective_features": ["*"] if status["fail_open"] else [],
        })
        return status


def attach_runtime_usage(status: dict[str, Any], usage: dict[str, Any] | None) -> dict[str, Any]:
    status = dict(status)
    usage = usage or {}
    status["usage"] = usage
    limit_status: dict[str, Any] = {}
    violations = list(status.get("violations") or [])
    warnings = list(status.get("warnings") or [])
    payload = status.get("payload") or {}
    limits = payload.get("limits") or {}

    for limit_key, usage_key in (("max_nodes", "nodes"), ("max_policies", "policies")):
        limit = _int_limit(limits, limit_key)
        current = int(usage.get(usage_key) or 0)
        ok = limit <= 0 or current <= limit
        limit_status[limit_key] = {
            "limit": limit,
            "current": current,
            "ok": ok,
        }
        if limit > 0 and current > limit:
            violations.append(f"{usage_key} usage {current} exceeds {limit_key}={limit}")
        elif limit > 0 and current >= max(1, int(limit * 0.8)):
            warnings.append(f"{usage_key} usage {current} is near {limit_key}={limit}")

    status["limit_status"] = limit_status
    status["warnings"] = sorted(set(warnings))
    status["violations"] = sorted(set(violations))
    status["compliant"] = not status["violations"]
    if status.get("valid") and not status["compliant"]:
        status["status"] = "limit_exceeded"
        status["reason"] = "license limits exceeded"
    return status


def can_add_policies(status: dict[str, Any], count: int = 1) -> tuple[bool, str | None]:
    if count <= 0:
        return True, None
    if not status.get("valid"):
        # When no valid license: respect fail_open — fail-closed deployments block everything
        if not status.get("fail_open", True):
            return False, "A valid license is required to create policies"
        return True, None
    payload = status.get("payload") or {}
    limits = payload.get("limits") or {}
    limit = _int_limit(limits, "max_policies")
    if limit <= 0:
        return True, None
    current = int((status.get("usage") or {}).get("policies") or 0)
    if current + count > limit:
        return False, f"License policy limit exceeded: current={current}, requested={count}, max_policies={limit}"
    return True, None


def is_feature_enabled(feature: str) -> bool:
    features = set(get_license_status().get("effective_features") or [])
    if "*" in features:
        return True
    if feature in features:
        return True
    prefix = feature.split(":", 1)[0] + ":*"
    return prefix in features


def save_license_text(raw: str) -> dict[str, Any]:
    doc = parse_license_text(raw)
    verify_license_document(doc)
    path = Path(LICENSE_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return get_license_status()
