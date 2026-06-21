import ast
import base64
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.license import can_add_policies
from tools.prepare_runtime import ENTERPRISE_PACKS, prepare_runtime


ROOT = Path(__file__).resolve().parents[1]


def assignment_value(path: Path, name: str):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found")


class BuildHardeningTest(unittest.TestCase):
    def _public_key(self) -> str:
        public = Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(public).decode("ascii")

    def test_community_runtime_excludes_enterprise_template_payloads(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "app"
            removed = prepare_runtime(
                ROOT / "app",
                output,
                edition="community",
                revision="unit-test",
            )
            templates = assignment_value(output / "policy_templates.py", "TEMPLATES")
            self.assertGreater(removed, 0)
            self.assertFalse({
                template["pack"] for template in templates
            } & ENTERPRISE_PACKS)
            profile = assignment_value(output / "build_profile.py", "BUILD_EDITION")
            self.assertEqual(profile, "community")

    def test_enterprise_runtime_requires_a_real_ed25519_public_key(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "public key"):
                prepare_runtime(
                    ROOT / "app",
                    Path(temp) / "invalid",
                    edition="enterprise",
                    revision="unit-test",
                )

            output = Path(temp) / "valid"
            prepare_runtime(
                ROOT / "app",
                output,
                edition="enterprise",
                revision="unit-test",
                public_key=self._public_key(),
            )
            templates = assignment_value(output / "policy_templates.py", "TEMPLATES")
            self.assertTrue({
                template["pack"] for template in templates
            } & ENTERPRISE_PACKS)
            self.assertFalse(
                assignment_value(output / "build_profile.py", "ALLOW_RUNTIME_PUBLIC_KEY_OVERRIDE")
            )
            self.assertFalse(
                assignment_value(output / "build_profile.py", "BUILTIN_TRIAL_CAPABLE")
            )

    def test_community_build_does_not_require_commercial_license(self):
        allowed, reason = can_add_policies({
            "build_edition": "community",
            "valid": False,
            "fail_open": False,
        })
        self.assertTrue(allowed)
        self.assertIsNone(reason)

    def test_docker_runtime_removes_python_sources_and_runs_non_root(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        compiler = (ROOT / "tools" / "build_extensions.py").read_text(encoding="utf-8")
        self.assertIn("test -z \"$(find /build/runtime/app -type f -name '*.py'", dockerfile)
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertIn("tools/build_extensions.py", dockerfile)
        self.assertIn('"binding": True', compiler)


if __name__ == "__main__":
    unittest.main()
