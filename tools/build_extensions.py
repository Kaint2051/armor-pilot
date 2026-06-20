#!/usr/bin/env python3
"""Compile ArmorPilot Python modules into native extension modules."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from Cython.Build import cythonize
from setuptools import Extension, setup


def module_name(root: Path, path: Path) -> str:
    return ".".join(path.relative_to(root).with_suffix("").parts)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()

    sources = sorted(
        path for path in (root / "app").rglob("*.py")
        if path.name != "__init__.py"
    )
    extensions = [
        Extension(module_name(root, path), [str(path)])
        for path in sources
    ]
    os.chdir(root)
    setup(
        name="armor-pilot-runtime",
        script_args=["build_ext", "--inplace"],
        ext_modules=cythonize(
            extensions,
            nthreads=max(1, os.cpu_count() or 1),
            compiler_directives={
                "language_level": 3,
                "binding": False,
                "embedsignature": False,
                "emit_code_comments": False,
                "docstrings": False,
                "annotation_typing": False,
            },
        ),
    )

    for pattern in ("*.py", "*.c"):
        for path in (root / "app").rglob(pattern):
            path.unlink()


if __name__ == "__main__":
    main()
