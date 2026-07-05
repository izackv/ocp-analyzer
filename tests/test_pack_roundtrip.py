#!/usr/bin/env python3
"""Round-trip tests for pack-bundle.sh / unpack-bundle.sh.

pack -> unpack must reproduce the bundle byte-for-byte, via both the binary
archive and the base64 --text path; a tampered archive must be rejected by
the checksum check.

Python 3.6+ stdlib only:
    python3 -m unittest discover tests
"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
PACK = PROJECT / "pack-bundle.sh"
UNPACK = PROJECT / "unpack-bundle.sh"
FIXTURE = PROJECT / "tests" / "fixtures" / "ocp-review_ocpprod_20260701-120000"


def sh(script, args, cwd):
    return subprocess.run(["bash", str(script)] + [str(a) for a in args],
                          cwd=str(cwd), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, universal_newlines=True)


def dir_bytes(path):
    return {f.name: f.read_bytes() for f in path.iterdir() if f.is_file()}


class PackRoundtripTest(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ocp-pack-test-"))
        self.bundle = self.tmp / FIXTURE.name
        shutil.copytree(str(FIXTURE), str(self.bundle))

    def tearDown(self):
        shutil.rmtree(str(self.tmp), ignore_errors=True)

    def pack(self, *extra):
        res = sh(PACK, [self.bundle.name] + list(extra), cwd=self.tmp)
        self.assertEqual(res.returncode, 0, res.stderr)
        return self.tmp / (self.bundle.name + ".tar.gz")

    def test_binary_roundtrip(self):
        archive = self.pack()
        self.assertTrue(archive.is_file())
        self.assertTrue((self.tmp / (archive.name + ".sha256")).is_file())

        dest = self.tmp / "restore"
        res = sh(UNPACK, [archive, dest], cwd=self.tmp)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("checksum: OK", res.stdout)
        self.assertEqual(dir_bytes(self.bundle),
                         dir_bytes(dest / self.bundle.name))

    def test_text_b64_roundtrip(self):
        """Simulate a text-only transfer path: ONLY the .b64 file makes it
        to the other side (no archive, no checksum file)."""
        archive = self.pack("--text")
        b64 = self.tmp / (archive.name + ".b64")
        self.assertTrue(b64.is_file())

        other_side = self.tmp / "other-side"
        other_side.mkdir()
        shutil.copy(str(b64), str(other_side / b64.name))

        dest = other_side / "restore"
        res = sh(UNPACK, [other_side / b64.name, dest], cwd=other_side)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("skipping verification", res.stdout)  # no .sha256 came along
        self.assertEqual(dir_bytes(self.bundle),
                         dir_bytes(dest / self.bundle.name))

    def test_tampered_archive_is_rejected(self):
        archive = self.pack()
        data = bytearray(archive.read_bytes())
        data[len(data) // 2] ^= 0xFF
        archive.write_bytes(bytes(data))

        res = sh(UNPACK, [archive, self.tmp / "restore"], cwd=self.tmp)
        self.assertNotEqual(res.returncode, 0,
                            "tampered archive must not unpack")
        self.assertIn("MISMATCH", res.stderr)
        self.assertFalse((self.tmp / "restore" / self.bundle.name).exists())

    def test_missing_checksum_warns_but_unpacks(self):
        archive = self.pack()
        (self.tmp / (archive.name + ".sha256")).unlink()

        dest = self.tmp / "restore"
        res = sh(UNPACK, [archive, dest], cwd=self.tmp)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("skipping verification", res.stdout)
        self.assertEqual(dir_bytes(self.bundle),
                         dir_bytes(dest / self.bundle.name))


if __name__ == "__main__":
    unittest.main()
