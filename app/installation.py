# Copyright 2026 vArmor Authors
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

import base64
import datetime as dt
import hashlib
import json
import os
import secrets
import threading
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


INSTALLATION_KEY_FILE = os.environ.get(
    "VARMOR_INSTALLATION_KEY_FILE",
    "/app/data/installation-private.pem",
)
INSTALLATION_METADATA_FILE = os.environ.get(
    "VARMOR_INSTALLATION_METADATA_FILE",
    "/app/data/installation.json",
)
SERVICE_ACCOUNT_CA_FILE = os.environ.get(
    "VARMOR_KUBERNETES_CA_FILE",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
)

_identity_lock = threading.Lock()


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _utc_now_text() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        temp_path.write_bytes(data)
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def _load_or_create_identity_material() -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    key_path = Path(INSTALLATION_KEY_FILE)
    metadata_path = Path(INSTALLATION_METADATA_FILE)

    with _identity_lock:
        if key_path.exists():
            private_key = serialization.load_pem_private_key(
                key_path.read_bytes(),
                password=None,
            )
            if not isinstance(private_key, Ed25519PrivateKey):
                raise ValueError("installation private key is not Ed25519")
        else:
            private_key = Ed25519PrivateKey.generate()
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            _atomic_write(key_path, private_pem, 0o600)

        if metadata_path.exists():
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if not isinstance(metadata, dict):
                raise ValueError("installation metadata must be an object")
        else:
            metadata = {
                "version": "varmor-installation-metadata/v1",
                "installation_uuid": str(uuid.uuid4()),
                "created_at": _utc_now_text(),
            }
            _atomic_write(
                metadata_path,
                (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8"),
                0o600,
            )

    installation_uuid = str(metadata.get("installation_uuid") or "").strip()
    if not installation_uuid:
        raise ValueError("installation metadata is missing installation_uuid")
    return private_key, metadata


def _runtime_cluster_uid() -> str:
    override = os.environ.get("VARMOR_INSTALLATION_CLUSTER_UID", "").strip()
    if override:
        return override

    from .k8s_client import core_v1

    namespace = core_v1().read_namespace("kube-system")
    uid = str(getattr(getattr(namespace, "metadata", None), "uid", "") or "").strip()
    if not uid:
        raise ValueError("kube-system namespace UID is unavailable")
    return uid


def _runtime_ca_sha256() -> str:
    override = os.environ.get("VARMOR_INSTALLATION_CA_SHA256", "").strip().lower()
    if override:
        return override

    ca_path = Path(SERVICE_ACCOUNT_CA_FILE)
    if not ca_path.exists():
        raise ValueError("Kubernetes API CA certificate is unavailable")
    return hashlib.sha256(ca_path.read_bytes()).hexdigest()


def _identity_payload(
    metadata: dict[str, Any],
    public_key_b64: str,
    cluster_uid: str,
    ca_sha256: str,
) -> dict[str, Any]:
    return {
        "version": "varmor-installation/v1",
        "installation_uuid": metadata["installation_uuid"],
        "installation_public_key": public_key_b64,
        "cluster_uid": cluster_uid,
        "api_ca_sha256": ca_sha256,
    }


def get_installation_identity() -> dict[str, Any]:
    private_key, metadata = _load_or_create_identity_material()
    raw_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_key_b64 = base64.b64encode(raw_public).decode("ascii")
    cluster_uid = _runtime_cluster_uid()
    ca_sha256 = _runtime_ca_sha256()
    identity_payload = _identity_payload(
        metadata,
        public_key_b64,
        cluster_uid,
        ca_sha256,
    )
    installation_id = "vmi_" + hashlib.sha256(_canonical(identity_payload)).hexdigest()
    return {
        **identity_payload,
        "installation_id": installation_id,
        "created_at": metadata.get("created_at"),
    }


def create_activation_request() -> dict[str, Any]:
    private_key, _ = _load_or_create_identity_material()
    identity = get_installation_identity()
    payload = {
        **identity,
        "generated_at": _utc_now_text(),
        "nonce": secrets.token_urlsafe(24),
    }
    return {
        "version": "varmor-activation-request/v1",
        "payload": payload,
        "signature": _b64url(private_key.sign(_canonical(payload))),
    }
