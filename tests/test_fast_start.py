"""Matcher equivalence, receipt invalidation and opt-in synthetic timing."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import random
import selectors
import shutil
import sqlite3
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import test_filter
from test_filter import g, SCRIPT
from policy_fixture import enable_policy


class MatcherTests(unittest.TestCase):
    def test_compiled_matcher_agrees_with_legacy_unicode_substrings(self):
        rng = random.Random(712)
        alphabet = "abfiltr- .İßαаеіéＡ\u200b\u00ad\u0301\u034f😀"
        terms = ("filter-alpha", "aba", "ba", "İ", "ß", "[a].*", "é", "\u200b")
        matcher = g.compile_terms(terms)
        adversarial = ("ｆｉｌｔｅｒ-ａｌｐｈａ", "fіltеr-аlphа", "f\u200bilter-a\u0301lpha",
                       "xx[a].*yy", "İSS", "ababa", "", "\u034f")
        values = [*adversarial, *("".join(rng.choices(alphabet, k=rng.randrange(60)))
                                 for _ in range(1000))]
        for value in values:
            for row in ({"content": value, "number": 7}, {value: "safe", 8: None}):
                expected = any(g.filter_text(term) in g.filter_text(field)
                               for term in terms for field in (*row.keys(), *row.values())
                               if isinstance(field, str))
                self.assertEqual(g.matches(row, matcher), expected)
        for terms in ((), ("aba", "ba"), ("[a].*",), ("filter-alpha",)):
            matcher = g.compile_terms(terms)
            for value in values:
                expected = any(g.filter_text(term) in g.filter_text(value) for term in terms)
                self.assertEqual(g.matches({9: value}, matcher), expected)

    def test_each_field_is_normalized_once_with_compiled_policy(self):
        matcher = g.compile_terms(("synthetic-exclusion", "other-exclusion"))
        with patch.object(g, "filter_text", wraps=g.filter_text) as normalize:
            self.assertFalse(g.matches({"title": "Safe", "content": "Public", 7: None}, matcher))
        self.assertEqual(normalize.call_count, 4)

    def test_policy_hash_normalizes_terms_but_preserves_project_identity(self):
        first = g.policy_hash({"Public"}, g.compile_terms(("FILTER-ALPHA", "filter-beta")))
        equivalent = g.policy_hash({"Public"}, g.compile_terms(("filter-beta", "ｆｉｌｔｅｒ-ａｌｐｈａ")))
        self.assertEqual(first, equivalent)
        self.assertNotEqual(first, g.policy_hash({"Ｐublic"}, g.compile_terms(("filter-alpha", "filter-beta"))))

    def test_explicit_row_terms_preserve_local_project_exclusions(self):
        data = {"version": "0.2.0", "exported_at": "", "sessions": [
            {"id": "session", "project": "filter-alpha"}]}
        self.assertEqual(g.sanitize(data, {"filter-alpha"}, ("unmatched-term",))["sessions"], [])


@unittest.skipUnless(shutil.which("engram"), "requires installed Engram v3.3.2")
class ReceiptTests(unittest.TestCase):
    setUp = test_filter.StoreTests.setUp

    @property
    def receipt(self):
        return self.state / "filtered/audit-receipt.json"

    def start(self):
        with patch.object(g.subprocess, "call", return_value=0) as serve:
            self.assertEqual(g.mcp(self.state), 0)
            self.assertTrue(serve.called)

    def test_refresh_receipt_binds_final_snapshot_policy_version_and_counts(self):
        counts = g.refresh(self.state)
        receipt = json.loads(self.receipt.read_text())
        self.assertEqual(receipt["snapshot_sha256"], hashlib.sha256(
            (self.state / "filtered/engram.db").read_bytes()).hexdigest())
        self.assertEqual(receipt["policy_sha256"], g.policy_hash(
            {"synthetic-project", "other"}, g.compile_terms(g.load_terms())))
        self.assertEqual(receipt["reader_version"], g.VERSION)
        self.assertEqual(receipt["counts"], counts)
        self.assertGreater(receipt["audited_at"], 0)
        self.assertEqual(self.receipt.stat().st_mode & 0o077, 0)

    def test_valid_receipt_skips_full_audit_and_loads_policy_once(self):
        g.refresh(self.state)
        with patch.object(g, "audit", side_effect=AssertionError("unexpected audit")), \
             patch.object(g, "load_terms", wraps=g.load_terms) as load:
            self.start()
        self.assertEqual(load.call_count, 1)

    def test_missing_malformed_or_old_version_receipt_requires_audit(self):
        g.refresh(self.state)
        original = json.loads(self.receipt.read_text())
        variants = (None, "not JSON", "[]", json.dumps({**original, "reader_version": "old"}),
                    json.dumps({**original, "counts": {"matching_rows": 1}}))
        for value in variants:
            with self.subTest(receipt=value):
                if value is None:
                    self.receipt.unlink(missing_ok=True)
                else:
                    self.receipt.write_text(value)
                with patch.object(g, "audit", wraps=g.audit) as audit:
                    self.start()
                self.assertEqual(audit.call_count, 1)

    def test_changed_snapshot_or_allowlist_requires_audit(self):
        g.refresh(self.state)
        with contextlib.closing(sqlite3.connect(self.state / "filtered/engram.db")) as db:
            db.execute("UPDATE observations SET title='Changed synthetic title'")
            db.commit()
        with patch.object(g, "audit", wraps=g.audit) as audit:
            self.start()
        self.assertEqual(audit.call_count, 1)
        g.refresh(self.state)
        g.write_json(self.state / "allowed-projects.json", {"mode": "pinned", "projects": [
            "synthetic-project", "other", "new-safe-project"]})
        with patch.object(g, "audit", wraps=g.audit) as audit:
            self.start()
        self.assertEqual(audit.call_count, 1)

    def test_changed_terms_or_tampered_snapshot_cannot_serve_failing_audit(self):
        for change in ("terms", "snapshot", "allowlist"):
            with self.subTest(change=change):
                g.write_json(self.state / "blocked-terms.json", {"terms": ["filter-alpha", "filter-beta"]})
                g.write_json(self.state / "allowed-projects.json", {"mode": "auto", "projects": []})
                g.refresh(self.state)
                if change == "terms":
                    g.write_json(self.state / "blocked-terms.json", {"terms": ["Synthetic content"]})
                elif change == "allowlist":
                    g.write_json(self.state / "allowed-projects.json", {"mode": "pinned", "projects": []})
                else:
                    with contextlib.closing(sqlite3.connect(self.state / "filtered/engram.db")) as db:
                        db.execute("UPDATE observations SET content='filter-alpha'")
                        db.commit()
                with patch.object(g, "audit", wraps=g.audit) as audit, \
                     patch.object(g.subprocess, "call") as serve:
                    with self.assertRaises(ValueError):
                        g.mcp(self.state)
                self.assertEqual(audit.call_count, 1)
                self.assertFalse(serve.called)

    def test_uncheckpointed_wal_cannot_reuse_main_file_receipt(self):
        g.refresh(self.state)
        path = self.state / "filtered/engram.db"
        with contextlib.closing(sqlite3.connect(path)) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            # Simulate a receipt for the main file before a later WAL-only write.
            receipt = json.loads(self.receipt.read_text())
            receipt["snapshot_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            g.write_json(self.receipt, receipt)
            db.execute("UPDATE observations SET content='filter-alpha'")
            db.commit()
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), receipt["snapshot_sha256"])
            with patch.object(g.subprocess, "call") as serve:
                with self.assertRaises(ValueError):
                    g.mcp(self.state)
                self.assertFalse(serve.called)

    def test_refresh_loads_private_policy_once(self):
        with patch.object(g, "load_terms", wraps=g.load_terms) as load:
            g.refresh(self.state)
        self.assertEqual(load.call_count, 1)

    def test_explicit_export_and_audit_terms_preserve_local_project_policy(self):
        data = g.export_selected(self.source, {"filter-alpha"}, ("unmatched-term",))
        self.assertEqual(data["sessions"], [])
        g.refresh(self.state)
        g.write_json(self.state / "blocked-terms.json", {"terms": ["synthetic-project"]})
        with self.assertRaises(ValueError):
            g.audit(self.state / "filtered/engram.db", {"synthetic-project", "other"}, ("unmatched-term",))


@unittest.skipUnless(os.environ.get("ENGRAM_READER_BENCHMARK") == "1" and shutil.which("engram"),
                     "set ENGRAM_READER_BENCHMARK=1 for synthetic performance test")
class BenchmarkTests(unittest.TestCase):
    setUp = test_filter.StoreTests.setUp

    def test_large_synthetic_refresh_and_initialize(self):
        g.write_json(self.state / "blocked-terms.json", {"terms": [
            f"synthetic-exclusion-{i:04d}" for i in range(3000)]})
        with contextlib.closing(sqlite3.connect(self.source / "engram.db")) as db:
            db.row_factory = sqlite3.Row
            row = dict(db.execute("SELECT * FROM observations WHERE project='synthetic-project'").fetchone())
            db.execute("DELETE FROM observations")
            rows = [{**row, "id": i + 1, "sync_id": f"synthetic-sync-{i}", "title": f"Public note {i}",
                     "content": "Public Unicode Ｍemory café αβγ. " * 50} for i in range(2000)]
            columns = list(row)
            db.executemany("INSERT INTO observations (" + ",".join(columns) + ") VALUES (" +
                           ",".join("?" for _ in columns) + ")", [[r[k] for k in columns] for r in rows])
            db.commit()
        started = time.perf_counter()
        counts = g.refresh(self.state)
        refresh_seconds = time.perf_counter() - started
        self.assertEqual(counts["observations"], 2000)
        request = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "synthetic-benchmark", "version": "1"}}}
        started = time.perf_counter()
        with subprocess.Popen([sys.executable, "-B", str(SCRIPT), "--state", str(self.state), "mcp"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True) as process:
            try:
                process.stdin.write(json.dumps(request) + "\n")
                process.stdin.flush()
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(180), "initialize timeout")
                reply = json.loads(process.stdout.readline())
                initialize_seconds = time.perf_counter() - started
                self.assertIn("result", reply)
            finally:
                process.stdin.close()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        print(json.dumps({"terms": 3000, "observations": 2000, "refresh_seconds": refresh_seconds,
                          "initialize_seconds": initialize_seconds}), flush=True)
        self.assertLess(initialize_seconds, 3)


def setUpModule():
    global cleanup_policy
    cleanup_policy = enable_policy()


def tearDownModule():
    cleanup_policy()
