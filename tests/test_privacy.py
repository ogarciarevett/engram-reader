"""Privacy regressions use synthetic records; the installed audit is opt in."""
import contextlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

import test_filter
from test_filter import g, SCRIPT


class RowPrivacyTests(unittest.TestCase):
    def fixture(self):
        return {"version": "0.2.0", "exported_at": "", "sessions": [
            {"id": "safe", "project": "synthetic-project", "summary": None, "directory": ""}],
            "observations": [{"id": 1, "session_id": "safe", "project": "synthetic-project",
                              "title": "Allowed title", "content": "Allowed content"}],
            "prompts": [{"id": 2, "session_id": "safe", "project": "synthetic-project",
                         "content": "Allowed prompt"}]}

    def test_every_text_field_is_filtered_case_insensitively(self):
        terms = ("filter-alpha", "filter-beta", "restricted-host.example", "restricted-repo")
        values = ("filter-alpha", "filter-alpha-Finance", "filter-alpha.finance", "filter-beta", "filter-beta-web",
                  "HTTPS://RESTRICTED-HOST.EXAMPLE/path", "org/RESTRICTED-REPO")
        for kind in ("sessions", "observations", "prompts"):
            for field in ("title", "content", "topic_key", "directory", "summary", "future_text"):
                for value in values:
                    with self.subTest(kind=kind, field=field, value=value):
                        data = self.fixture()
                        data[kind][0][field] = value
                        out = g.sanitize(data, {"synthetic-project"}, terms)
                        self.assertEqual(len(out[kind]), 0)
                        if kind == "sessions":
                            self.assertEqual(out["observations"], [])
                            self.assertEqual(out["prompts"], [])

    def test_unmatched_rows_remain_and_project_exclusion_is_mandatory(self):
        out = g.sanitize(self.fixture(), {"synthetic-project"}, ("restricted-host.example",))
        self.assertEqual([len(out[k]) for k in ("sessions", "observations", "prompts")], [1, 1, 1])
        data = self.fixture()
        data["sessions"][0]["project"] = "filter-alpha"
        self.assertEqual(g.sanitize(data, {"filter-alpha"})["sessions"], [])



@unittest.skipUnless(shutil.which("engram"), "requires installed Engram v3.3.2")
class StorePrivacyTests(unittest.TestCase):
    setUp = test_filter.StoreTests.setUp

    def test_export_filters_original_session_text_before_redaction(self):
        for field in ("summary", "directory", "local_creation_project"):
            with self.subTest(field=field):
                with contextlib.closing(sqlite3.connect(self.source / "engram.db")) as db:
                    db.execute("UPDATE sessions SET " + field + "='mentions filter-alpha' WHERE project='synthetic-project'")
                    db.commit()
                self.assertEqual(g.refresh(self.state)["observations"], 0)
                with contextlib.closing(sqlite3.connect(self.source / "engram.db")) as db:
                    db.execute("UPDATE sessions SET " + field + "='' WHERE project='synthetic-project'")
                    db.commit()

    def test_export_filters_text_fields_outside_backup_projection(self):
        with contextlib.closing(sqlite3.connect(self.source / "engram.db")) as db:
            db.execute("UPDATE observations SET embedding_model='filter-alpha' WHERE project='synthetic-project'")
            db.commit()
        self.assertEqual(g.refresh(self.state)["observations"], 0)

    def test_verify_rejects_content_contamination_and_hides_payload(self):
        g.refresh(self.state)
        with contextlib.closing(sqlite3.connect(self.state / "filtered/engram.db")) as db:
            db.execute("UPDATE observations SET topic_key='restricted-host.example'")
            db.commit()
        g.write_json(self.state / "blocked-terms.json", {"terms": ["filter-alpha", "filter-beta", "restricted-host.example"]})
        with self.assertRaises(ValueError):
            g.audit(self.state / "filtered/engram.db", {"synthetic-project"}, g.load_terms(self.state))
        result = subprocess.run(["python3", str(SCRIPT), "--state", str(self.state), "verify"],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"restricted-host.example", result.stdout + result.stderr)

    def test_failed_refresh_empties_dirty_snapshot(self):
        g.refresh(self.state)
        with contextlib.closing(sqlite3.connect(self.state / "filtered/engram.db")) as db:
            db.execute("UPDATE observations SET content='filter-alpha-Finance'")
            db.commit()
        with patch.object(g, "export_selected", side_effect=RuntimeError("withheld")):
            with self.assertRaises(RuntimeError):
                g.refresh(self.state)
        counts = g.audit(self.state / "filtered/engram.db", {"synthetic-project", "other"})
        self.assertEqual([counts[k] for k in ("sessions", "observations", "user_prompts")], [0, 0, 0])

    def test_failed_refresh_keeps_clean_snapshot(self):
        g.refresh(self.state)
        before = (self.state / "filtered/engram.db").read_bytes()
        with patch.object(g, "export_selected", side_effect=RuntimeError("withheld")):
            with self.assertRaises(RuntimeError):
                g.refresh(self.state)
        self.assertEqual((self.state / "filtered/engram.db").read_bytes(), before)

    def test_early_failure_clears_dirty_snapshot_and_unknown_policy(self):
        g.refresh(self.state)
        with contextlib.closing(sqlite3.connect(self.state / "filtered/engram.db")) as db:
            db.execute("UPDATE observations SET title='filter-beta'")
            db.commit()
        with patch.object(g, "require_version", side_effect=ValueError("withheld")):
            with self.assertRaises(ValueError):
                g.refresh(self.state)
        self.assertEqual(g.audit(self.state / "filtered/engram.db", {"synthetic-project", "other"})["observations"], 0)
        g.refresh(self.state)
        (self.state / "blocked-terms.json").write_text("invalid JSON")
        with self.assertRaises(ValueError):
            g.refresh(self.state)
        self.assertEqual(g.audit(self.state / "filtered/engram.db", {"synthetic-project", "other"})["observations"], 0)

    def test_unverified_candidate_is_never_published(self):
        g.refresh(self.state)
        before = (self.state / "filtered/engram.db").read_bytes()
        real_export = g.export_selected

        def corrupt(*args):
            data = real_export(*args)
            data["observations"][0]["content"] = "filter-beta-web"
            return data

        with patch.object(g, "export_selected", side_effect=corrupt):
            with self.assertRaises(ValueError):
                g.refresh(self.state)
        self.assertEqual((self.state / "filtered/engram.db").read_bytes(), before)


class UnicodeFilterTests(unittest.TestCase):
    variants = ("filter-alpha", "ｆｉｌｔｅｒ-ａｌｐｈａ", "f\u200bilter-alpha", "filter-\u00adalpha", "fіltеr-аlphа", "filter-a\u0301lpha")

    def test_unicode_keys_and_values_cannot_bypass_owner_filter(self):
        for value in self.variants:
            for row in ({"content": value}, {value: "synthetic value"}):
                with self.subTest(value=value, row=row):
                    self.assertTrue(g.matches(row))

    def test_unicode_projects_are_excluded(self):
        for value in self.variants:
            with self.subTest(value=value):
                self.assertFalse(g.allowed(value))
        self.assertFalse(g.allowed("\u200b"))
        self.assertTrue(g.allowed("Synthetic project"))

    def test_rows_and_session_closure_are_filtered_without_rewriting_text(self):
        for value in self.variants:
            data = RowPrivacyTests().fixture()
            data["observations"][0]["content"] = value
            self.assertEqual(g.sanitize(data, {"synthetic-project"})["observations"], [])
            data = RowPrivacyTests().fixture()
            data["sessions"][0]["summary"] = value
            out = g.sanitize(data, {"synthetic-project"})
            self.assertEqual([out[k] for k in ("sessions", "observations", "prompts")], [[], [], []])
        data = RowPrivacyTests().fixture()
        data["observations"][0]["content"] = "Synthetic Ｗork stays unchanged"
        self.assertEqual(g.sanitize(data, {"synthetic-project"})["observations"][0]["content"],
                         "Synthetic Ｗork stays unchanged")

    def test_private_terms_use_the_same_unicode_comparison(self):
        self.assertTrue(g.matches({"content": "ＲEＳＴＲＩＣＴＥＤ-host.example"}, ("restricted-host.example",)))
        self.assertTrue(g.matches({"content": "restricted\u200b-repo"}, ("restricted-repo",)))


from policy_fixture import enable_policy

def setUpModule():
    global cleanup_policy
    cleanup_policy = enable_policy()

def tearDownModule():
    cleanup_policy()
