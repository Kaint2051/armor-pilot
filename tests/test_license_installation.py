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
import importlib
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class LicenseInstallationTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        self.env_names = [
            "ARMORPILOT_INSTALLATION_KEY_FILE",
            "ARMORPILOT_INSTALLATION_METADATA_FILE",
            "ARMORPILOT_INSTALLATION_CLUSTER_UID",
            "ARMORPILOT_INSTALLATION_CA_SHA256",
            "ARMORPILOT_LICENSE_FILE",
            "ARMORPILOT_LICENSE_REQUIRED",
            "ARMORPILOT_LICENSE_FAIL_OPEN",
            "ARMORPILOT_LICENSE_REQUIRE_INSTALLATION_BINDING",
            "ARMORPILOT_LICENSE_ALLOW_ENV_PUBLIC_KEY",
            "ARMORPILOT_LICENSE_PUBLIC_KEY",
        ]
        self.previous_env = {name: os.environ.get(name) for name in self.env_names}
        self.addCleanup(self._restore_env)

        vendor_private = Ed25519PrivateKey.generate()
        raw_vendor_public = vendor_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.vendor_private = vendor_private
        os.environ.update({
            "ARMORPILOT_INSTALLATION_KEY_FILE": str(root / "installation-private.pem"),
            "ARMORPILOT_INSTALLATION_METADATA_FILE": str(root / "installation.json"),
            "ARMORPILOT_INSTALLATION_CLUSTER_UID": "cluster-a",
            "ARMORPILOT_INSTALLATION_CA_SHA256": "a" * 64,
            "ARMORPILOT_LICENSE_FILE": str(root / "license.json"),
            "ARMORPILOT_LICENSE_REQUIRED": "true",
            "ARMORPILOT_LICENSE_FAIL_OPEN": "false",
            "ARMORPILOT_LICENSE_REQUIRE_INSTALLATION_BINDING": "true",
            "ARMORPILOT_LICENSE_ALLOW_ENV_PUBLIC_KEY": "true",
            "ARMORPILOT_LICENSE_PUBLIC_KEY": base64.b64encode(raw_vendor_public).decode("ascii"),
        })

        import app.installation as installation
        import app.license as license_module

        self.installation = importlib.reload(installation)
        self.license = importlib.reload(license_module)

    def _restore_env(self):
        for name, value in self.previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def _license_document(self, installation_id=None):
        payload = {
            "license_id": "LIC-UNIT-001",
            "customer": "Unit Test",
            "edition": "enterprise",
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:00:00Z",
            "grace_days": 7,
            "features": ["*"],
            "limits": {"max_nodes": 10, "max_policies": 500},
        }
        if installation_id:
            payload["installation_id"] = installation_id
        signature = self.vendor_private.sign(self.license._canonical_payload(payload))
        return {
            "algorithm": "Ed25519",
            "payload": payload,
            "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        }

    def test_identity_is_stable_and_request_is_signed(self):
        first = self.installation.get_installation_identity()
        second = self.installation.get_installation_identity()
        self.assertEqual(first["installation_id"], second["installation_id"])
        self.assertTrue(first["installation_id"].startswith("api_"))
        self.assertEqual(first["version"], "armor-pilot-installation/v1")

        request = self.installation.create_activation_request()
        raw_public = base64.b64decode(request["payload"]["installation_public_key"], validate=True)
        installation_private = serialization.load_pem_private_key(
            Path(os.environ["ARMORPILOT_INSTALLATION_KEY_FILE"]).read_bytes(),
            password=None,
        )
        installation_public = installation_private.public_key()
        self.assertEqual(
            installation_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            raw_public,
        )
        installation_public.verify(
            self._decode_b64url(request["signature"]),
            self.installation._canonical(request["payload"]),
        )

    def test_new_and_legacy_license_key_prefixes_are_accepted(self):
        identity = self.installation.get_installation_identity()
        document = self._license_document(identity["installation_id"])
        payload = document["payload"]
        encoded_payload = base64.urlsafe_b64encode(
            self.license._canonical_payload(payload),
        ).decode("ascii").rstrip("=")

        for prefix in ("ARMORPILOT1", "VARMOR1"):
            key = f"{prefix}.{encoded_payload}.{document['signature']}"
            parsed = self.license.parse_license_text(key)
            self.assertEqual(parsed["payload"], payload)
            self.assertEqual(
                self.license.verify_license_document(parsed)["installation_id"],
                identity["installation_id"],
            )

    @staticmethod
    def _decode_b64url(value):
        return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))

    def test_bound_license_is_rejected_on_another_installation(self):
        identity = self.installation.get_installation_identity()
        document = self._license_document(identity["installation_id"])
        self.assertEqual(
            self.license.verify_license_document(document)["installation_id"],
            identity["installation_id"],
        )

        os.environ["ARMORPILOT_INSTALLATION_CLUSTER_UID"] = "cluster-b"
        with self.assertRaisesRegex(ValueError, "does not match this installation"):
            self.license.verify_license_document(document)

    def test_unbound_license_is_rejected_when_binding_is_required(self):
        with self.assertRaisesRegex(ValueError, "not bound to this installation"):
            self.license.verify_license_document(self._license_document())


if __name__ == "__main__":
    unittest.main()
