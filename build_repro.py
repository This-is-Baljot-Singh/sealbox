#!/usr/bin/env python3
"""Build a byte-reproducible sealbox.pyz using only the Python stdlib."""
from __future__ import annotations

import hashlib
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "build" / "sealbox.pyz"
ENTRY = "__main__.py"
SOURCE = ROOT / "sealbox.py"


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    data = SOURCE.read_bytes()
    with zipfile.ZipFile(OUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        info = zipfile.ZipInfo(ENTRY)
        info.date_time = (1980, 1, 1, 0, 0, 0)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.create_system = 3
        info.external_attr = 0o100755 << 16
        archive.writestr(info, data)
    digest = hashlib.sha256(OUT.read_bytes()).hexdigest()
    print(f"built {OUT}")
    print(f"sha256 {digest}")


if __name__ == "__main__":
    main()
