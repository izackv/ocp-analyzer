#!/usr/bin/env python3
"""Leak tests for sanitize-ocp-bundle.py.

The fixture bundle in tests/fixtures/ is seeded with known fake-sensitive
values (domain, usernames, node names, IPs, UUIDs, emails, LDAP DNs, a
non-ASCII name). The core assertion is simple: after sanitization, NONE of
those strings may appear anywhere in the output.

Python 3.6+ stdlib only, like the tools themselves:
    python3 -m unittest discover tests
"""
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
SANITIZER = PROJECT / "sanitize-ocp-bundle.py"
FIXTURE = PROJECT / "tests" / "fixtures" / "ocp-review_ocpprod_20260701-120000"

# Every fake-sensitive value seeded into the fixture bundle. If ANY of these
# survives sanitization, real customer data would leak the same way.
SENSITIVE = [
    "acme-corp",                               # org name + part of every domain
    "ocpprod",                                 # cluster name
    "jsmith", "ocpprodadmin", "yossic",        # users from 07-users.txt
    "dana",                                    # user seen only as a group member
    "rbaconly",                                # user seen only in an RBAC binding
    "master-0", "worker-1",                    # node hostnames
    "10.128.0.12", "192.168.10.5",             # IPs
    "d2f1a8e4-3c5b-4e6f-9a7b-1c2d3e4f5a6b",    # cluster UUID
    "2a7d9f10-1234-4abc-8def-aaaaaaaaaaaa",    # user UID
    "john.smith",                              # email local part
    "svc-ocp-bind", "Service Accounts",        # LDAP DN components
    "יוסי", "כהן",                             # non-ASCII full name
]


def run_sanitizer(bundle, outdir, extra_args=()):
    cmd = [sys.executable, str(SANITIZER), str(bundle), "-o", str(outdir)]
    cmd += list(extra_args)
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True)


def dir_hashes(path):
    return {f.name: hashlib.sha256(f.read_bytes()).hexdigest()
            for f in path.iterdir() if f.is_file()}


class SanitizerTest(unittest.TestCase):
    """One sanitizer run shared by all tests (the bundle is read-only input)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="ocp-sanitize-test-"))
        cls.bundle = cls.tmp / FIXTURE.name
        shutil.copytree(str(FIXTURE), str(cls.bundle))
        cls.hashes_before = dir_hashes(cls.bundle)

        cls.outdir = cls.tmp / "sanitized"
        cls.mapfile = cls.tmp / "sanitized-map.json"
        cls.result = run_sanitizer(cls.bundle, cls.outdir)
        if cls.result.returncode != 0:
            raise RuntimeError("sanitizer failed:\n" + cls.result.stderr)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(str(cls.tmp), ignore_errors=True)

    def read_out(self, name):
        return (self.outdir / name).read_text(errors="replace")

    def all_output_text(self):
        return "\n".join(f.read_text(errors="replace")
                         for f in sorted(self.outdir.iterdir()) if f.is_file())

    # ---- the test that matters most --------------------------------------
    def test_fixture_actually_contains_the_leak_list(self):
        """Guard against fixture rot: if a seeded value disappears from the
        fixture, the leak test below silently stops testing it."""
        text = "\n".join(f.read_text(errors="replace")
                         for f in sorted(FIXTURE.iterdir()) if f.is_file()).lower()
        missing = [s for s in SENSITIVE if s.lower() not in text]
        self.assertEqual(missing, [],
                         "fixture no longer contains: %s" % missing)

    def test_no_sensitive_string_survives(self):
        text = self.all_output_text().lower()
        leaked = [s for s in SENSITIVE if s.lower() in text]
        self.assertEqual(leaked, [],
                         "sensitive values leaked into sanitized output: %s" % leaked)

    def test_map_file_reverses_the_leak_list(self):
        """Everything scrubbed must be recoverable from the private map."""
        mapping = json.loads(self.mapfile.read_text())
        literals = {k.lower() for k in mapping["literals"]}
        self.assertIn("ocpprod.acme-corp.com", literals)
        self.assertIn("jsmith", literals)
        self.assertIn("rbaconly", literals)      # RBAC-only subject was found
        self.assertIn("dana", literals)          # group-member-only user was found
        self.assertIn("10.128.0.12", mapping["ips"])
        self.assertIn("d2f1a8e4-3c5b-4e6f-9a7b-1c2d3e4f5a6b", mapping["uuids"])
        self.assertEqual(len(mapping["emails"]), 1)

    def test_map_file_is_outside_the_sanitized_dir(self):
        self.assertTrue(self.mapfile.is_file())
        inside = [f.name for f in self.outdir.iterdir() if f.name.endswith(".json")
                  and "map" in f.name]
        self.assertEqual(inside, [], "reverse map must never sit inside the "
                                     "shareable directory")

    # ---- consistency & ordering ------------------------------------------
    def test_same_ip_maps_to_same_fake_everywhere(self):
        mapping = json.loads(self.mapfile.read_text())
        fake = mapping["ips"]["10.128.0.12"]
        self.assertIn(fake, self.read_out("02-nodes-wide.txt"))
        self.assertIn(fake, self.read_out("06-pods-all.txt"))

    def test_username_containing_cluster_name(self):
        """'ocpprodadmin' must become userNNNN — not 'ocpclusteradmin'
        (usernames must be replaced before the cluster-name literal)."""
        text = self.all_output_text()
        self.assertNotIn("ocpclusteradmin", text)
        self.assertRegex(self.read_out("07-users.txt"), r"user\d{4}")

    def test_node_names_mapped_to_roles(self):
        nodes = self.read_out("02-nodes-wide.txt")
        self.assertIn("master01", nodes)
        self.assertIn("worker01", nodes)

    def test_rbac_only_user_is_pseudonymized(self):
        crb = self.read_out("07-clusterrolebindings.txt")
        self.assertRegex(crb, r"user\d{4},user\d{4}")

    def test_domain_replaced_with_example_domain(self):
        access = self.read_out("00-access.txt")
        self.assertIn("api.ocp.example.com", access)

    def test_err_files_are_sanitized_too(self):
        err = self.read_out("04-cephcluster.txt.err")
        self.assertNotIn("acme-corp", err)
        self.assertNotIn("jsmith", err)

    # ---- safety properties -------------------------------------------------
    def test_original_bundle_untouched(self):
        self.assertEqual(self.hashes_before, dir_hashes(self.bundle))

    def test_non_text_files_are_skipped_not_copied(self):
        self.assertFalse((self.outdir / "topology.png").exists())
        self.assertIn("skipped", self.result.stdout)


class SanitizerOptionsTest(unittest.TestCase):
    """Separate runs for CLI-option behavior."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ocp-sanitize-test-"))
        self.bundle = self.tmp / FIXTURE.name
        shutil.copytree(str(FIXTURE), str(self.bundle))

    def tearDown(self):
        shutil.rmtree(str(self.tmp), ignore_errors=True)

    def test_extra_replace_rules(self):
        """-r removes org-specific strings the auto-detection can't know —
        here a human full name, which is documented as needing -r."""
        outdir = self.tmp / "out"
        res = run_sanitizer(self.bundle, outdir,
                            ["-r", "John Smith=SOME-NAME", "-r", "ocp-admins"])
        self.assertEqual(res.returncode, 0, res.stderr)
        text = "\n".join(f.read_text(errors="replace")
                         for f in outdir.iterdir() if f.is_file())
        self.assertNotIn("john smith", text.lower())
        self.assertIn("SOME-NAME", text)
        self.assertNotIn("ocp-admins", text)     # default replacement: REDACTED
        self.assertIn("REDACTED", text)

    def test_refuses_non_empty_output_dir(self):
        outdir = self.tmp / "out"
        outdir.mkdir()
        (outdir / "leftover.txt").write_text("old run")
        res = run_sanitizer(self.bundle, outdir)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("already exists", res.stderr)


if __name__ == "__main__":
    unittest.main()
