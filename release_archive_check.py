#!/usr/bin/env python3
"""Verify that the submitted Git source archive contains exactly the release surface."""
from __future__ import annotations

import sys
from pathlib import Path
from zipfile import ZipFile

REQUIRED = {
    ".gitignore",
    ".sealboxignore",
    ".zero-dep.toml",
    "ARCHITECTURE.md",
    "DEMO.md",
    "LICENSE",
    "Makefile",
    "README.md",
    "SECURITY.md",
    "STDLIB.md",
    "build.sh",
    "build_repro.py",
    "deps-proof.txt",
    "release_check.sh",
    "requirements.txt",
    "sealbox.py",
    "testdata/fake_secrets.txt",
    "tests/test_sealbox.py",
    "tests/test_release_archive.py",
    "PLAYGROUND.md",
    ".devcontainer/devcontainer.json",
}

FORBIDDEN = ("/.git/", "/__pycache__/", "/sealbox.vault", "/demo.txt", "/received_")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} ARCHIVE.zip", file=sys.stderr)
        return 2
    archive = Path(sys.argv[1])
    if not archive.is_file():
        print(f"ERROR: archive does not exist: {archive}", file=sys.stderr)
        return 1
    with ZipFile(archive) as zf:
        names = {name.removesuffix("/") for name in zf.namelist()}
    missing = sorted(REQUIRED - names)
    forbidden = sorted(
        name for name in names if any(marker in f"/{name}" for marker in FORBIDDEN)
    )
    if missing:
        print("ERROR: source archive missing:", *missing, sep="\n  ", file=sys.stderr)
        return 1
    if forbidden:
        print("ERROR: forbidden files in source archive:", *forbidden, sep="\n  ", file=sys.stderr)
        return 1
    print("source archive contents: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
