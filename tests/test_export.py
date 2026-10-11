"""Explicit filtered export tests use a temporary synthetic Engram source."""
import contextlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import unittest
from unittest.mock import patch
import test_filter
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import filtered_export as e


@unittest.skipUnless(shutil.which("engram"), "requires Engram")
class ExportTests(unittest.TestCase):
    setUp = test_filter.StoreTests.setUp

    def policy(self):
        test_filter.g.write_json(self.state / "allowed-projects.json",
                                {"mode": "pinned", "projects": ["synthetic-project"]})
        test_filter.g.write_json(self.state / "blocked-terms.json", {"terms": ["filter-alpha", "filter-beta", "private-fixture"]})

    def test_inherited_ownership_and_deletions(self):
        self.policy()
        with contextlib.closing(sqlite3.connect(self.source / "engram.db")) as db:
            db.execute("UPDATE observations SET project=NULL WHERE project='synthetic-project'")
            db.commit()
        with e.filtered_file(self.source, self.state) as path:
            doc = json.loads(path.read_bytes())
            self.assertEqual(doc["data"]["observations"][0]["project"], "synthetic-project")
            self.assertNotEqual(path.read_bytes()[:16], b"SQLite format 3\x00")
        self.assertFalse(path.exists())
        with contextlib.closing(sqlite3.connect(self.source / "engram.db")) as db:
            db.execute("UPDATE observations SET deleted_at='2026' WHERE project IS NULL")
            db.commit()
        with e.filtered_file(self.source, self.state) as path:
            self.assertEqual(json.loads(path.read_bytes())["data"]["observations"], [])

    def test_matching_session_and_private_terms_are_removed(self):
        self.policy()
        for table, field, term in (("sessions", "summary", "filter-alpha"),
                                   ("observations", "content", "private-fixture")):
            with self.subTest(table=table), contextlib.closing(sqlite3.connect(self.source / "engram.db")) as db:
                db.execute("UPDATE " + table + " SET " + field + "=? WHERE project='synthetic-project'", (term,))
                db.commit()
                with e.filtered_file(self.source, self.state) as path:
                    self.assertEqual(json.loads(path.read_bytes())["data"]["observations"], [])
                db.execute("UPDATE " + table + " SET " + field + "='' WHERE project='synthetic-project'")
                db.commit()

    def test_missing_or_malformed_policy_fails_closed(self):
        self.policy()
        for value in (None, "invalid", '{"terms":"not a list"}'):
            file = self.state / "blocked-terms.json"
            file.unlink(missing_ok=True)
            if value is not None:
                file.write_text(value)
            with self.assertRaises(ValueError):
                with e.filtered_file(self.source, self.state):
                    self.fail("unavailable policy must not export")
        self.assertFalse(list(self.state.glob("export-*")))

    def test_cleanup_after_consumer_failure_and_source_unchanged(self):
        self.policy()
        before = (self.source / "engram.db").read_bytes()
        with self.assertRaises(RuntimeError):
            with e.filtered_file(self.source, self.state) as path:
                raise RuntimeError("synthetic consumer failed")
        self.assertFalse(path.exists())
        self.assertFalse(list(self.state.glob("export-*")))
        self.assertEqual((self.source / "engram.db").read_bytes(), before)

    def test_cli_requires_explicit_paths_and_writes_only_filtered_json(self):
        self.policy()
        import subprocess
        script = Path(e.__file__)
        denied = subprocess.run([sys.executable, str(script)], capture_output=True)
        self.assertNotEqual(denied.returncode, 0)
        output = self.root / "filtered.json"
        result = subprocess.run([sys.executable, str(script), "--source", str(self.source),
                                 "--policy-state", str(self.state), "--output", str(output)], capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(output.read_bytes())["format"], "engram-filtered-v1")
        self.assertNotIn(b"Synthetic content", result.stdout + result.stderr)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)


from policy_fixture import enable_policy

def setUpModule():
    global cleanup_policy
    cleanup_policy = enable_policy()

def tearDownModule():
    cleanup_policy()
