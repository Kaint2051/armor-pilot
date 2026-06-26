#!/usr/bin/env python3
"""Prepare edition-specific ArmorPilot application sources for compilation."""

from __future__ import annotations

import argparse
import ast
import base64
import pprint
import shutil
import subprocess
from pathlib import Path


ENTERPRISE_PACKS = frozenset({
    "data-protection",
    "platform-infra",
    "incident-response",
})


def _validated_public_key(value: str) -> str:
    value = (value or "").strip()
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError("commercial build public key must be valid base64") from exc
    if len(raw) != 32:
        raise ValueError("commercial build public key must contain exactly 32 Ed25519 bytes")
    return value


def _assignment_value(tree: ast.Module, name: str):
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return node, ast.literal_eval(node.value)
    raise ValueError(f"{name} assignment was not found")


def strip_enterprise_templates(path: Path) -> int:
    """Remove Enterprise template payloads while retaining non-sensitive pack metadata."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    node, templates = _assignment_value(tree, "TEMPLATES")
    filtered = [item for item in templates if item.get("pack") not in ENTERPRISE_PACKS]
    removed = len(templates) - len(filtered)

    lines = source.splitlines(keepends=True)
    replacement = "TEMPLATES = " + pprint.pformat(
        filtered,
        indent=4,
        width=120,
        sort_dicts=False,
    ) + "\n"
    lines[node.lineno - 1:node.end_lineno] = [replacement]
    path.write_text("".join(lines), encoding="utf-8", newline="\n")
    return removed


def write_build_profile(
    path: Path,
    *,
    edition: str,
    revision: str,
    public_key: str,
) -> None:
    if edition == "enterprise":
        public_key = _validated_public_key(public_key)
    else:
        public_key = ""

    content = f'''"""Generated at image build time. Do not edit."""

BUILD_EDITION = {edition!r}
BUILD_REVISION = {revision!r}
LICENSE_PUBLIC_KEY = {public_key!r}
ALLOW_RUNTIME_PUBLIC_KEY_OVERRIDE = False
BUILTIN_TRIAL_CAPABLE = False
'''
    path.write_text(content, encoding="utf-8", newline="\n")


def prepare_runtime(
    source: Path,
    output: Path,
    *,
    edition: str,
    revision: str,
    public_key: str = "",
) -> int:
    if edition not in {"community", "enterprise"}:
        raise ValueError("edition must be community or enterprise")
    if output.exists():
        shutil.rmtree(output)
    shutil.copytree(source, output)

    removed = 0
    if edition == "community":
        removed = strip_enterprise_templates(output / "policy_templates.py")
    write_build_profile(
        output / "build_profile.py",
        edition=edition,
        revision=revision,
        public_key=public_key,
    )
    return removed


def _git_revision() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short=12", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--edition", choices=("community", "enterprise"), required=True)
    parser.add_argument("--revision", default=_git_revision())
    parser.add_argument("--license-public-key", default="")
    args = parser.parse_args()

    removed = prepare_runtime(
        args.source,
        args.output,
        edition=args.edition,
        revision=args.revision,
        public_key=args.license_public_key,
    )
    print(
        f"prepared edition={args.edition} revision={args.revision} "
        f"removed_enterprise_templates={removed}"
    )


if __name__ == "__main__":
    main()
