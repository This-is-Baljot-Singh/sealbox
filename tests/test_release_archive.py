from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

import release_archive_check


class TestReleaseArchiveCheck(unittest.TestCase):
    def _make_archive(self, names: list[str]) -> Path:
        tmp = Path(tempfile.mkstemp(suffix=".zip")[1])
        with ZipFile(tmp, "w") as zf:
            for name in names:
                zf.writestr(name, b"x")
        return tmp

    def test_valid_archive_passes(self):
        archive = self._make_archive(sorted(release_archive_check.REQUIRED))
        try:
            old = release_archive_check.sys.argv
            release_archive_check.sys.argv = ["release_archive_check.py", str(archive)]
            self.assertEqual(release_archive_check.main(), 0)
        finally:
            release_archive_check.sys.argv = old
            archive.unlink(missing_ok=True)

    def test_forbidden_demo_file_fails(self):
        names = sorted(release_archive_check.REQUIRED | {"demo.txt"})
        archive = self._make_archive(names)
        try:
            old = release_archive_check.sys.argv
            release_archive_check.sys.argv = ["release_archive_check.py", str(archive)]
            self.assertEqual(release_archive_check.main(), 1)
        finally:
            release_archive_check.sys.argv = old
            archive.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
