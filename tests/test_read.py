"""Reader regressions use only disposable synthetic stores."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import engram_reader_read as reader


class ReaderTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name)
        (self.state / "filtered").mkdir()
        self.policy_env = patch.dict(os.environ, {"ENGRAM_READER_BLOCKLIST": str(self.state / "blocked-terms.json")})
        self.policy_env.start()
        self.addCleanup(self.policy_env.stop)

        self.database = self.state / "filtered/engram.db"
        (self.state / "allowed-projects.json").write_text(json.dumps(
            {"mode": "pinned", "projects": ["coordination", "synthetic"]}))
        (self.state / "blocked-terms.json").write_text(json.dumps({"terms": ["restricted"]}))
        with sqlite3.connect(self.database) as db:
            db.execute("CREATE TABLE observations (id INTEGER PRIMARY KEY, project TEXT, "
                       "type TEXT, title TEXT, content TEXT, topic_key TEXT, updated_at TEXT, "
                       "deleted_at TEXT, future_text TEXT)")

    def add(self, identifier=1, **changes):
        row = {"id": identifier, "project": "coordination", "type": "decision",
               "title": "status/ready", "content": "Synthetic content", "topic_key": "plan/ready",
               "updated_at": "2026-10-11 08:00:00", "deleted_at": None, "future_text": ""}
        row.update(changes)
        with sqlite3.connect(self.database) as db:
            db.execute("INSERT INTO observations VALUES (?,?,?,?,?,?,?,?,?)", tuple(row.values()))

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = reader.main(list(args), state=self.state)
        return code, out.getvalue(), err.getvalue()

    def records(self, *args):
        code, out, err = self.run_cli(*args)
        self.assertEqual((code, err), (0, ""))
        return [json.loads(line) for line in out.splitlines() if line.startswith("{")]

    def test_connection_is_read_only_and_store_bytes_stay_unchanged(self):
        self.add()
        before = self.database.read_bytes()
        with contextlib.closing(reader.connect(self.state)) as db:
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("INSERT INTO observations(id) VALUES (2)")
        self.run_cli("search", "Synthetic")
        self.assertEqual(self.database.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.database.parent.iterdir()), ["engram.db"])

    def test_connection_explicitly_uses_immutable_read_only_uri(self):
        original = sqlite3.connect
        with patch.object(reader.sqlite3, "connect", wraps=original) as connect:
            with contextlib.closing(reader.connect(self.state)):
                pass
        self.assertTrue(connect.call_args.args[0].endswith("?mode=ro&immutable=1"))
        self.assertTrue(connect.call_args.kwargs["uri"])

    def test_search_matches_title_and_content_with_literal_parameters(self):
        self.add(1, title="Useful needle", content="another WORD")
        self.add(2, title="Needle", content="word", updated_at="2026-10-11 09:00:00")
        self.add(3, project="synthetic", title="Needle", content="word")
        self.assertEqual([r["id"] for r in self.records("search", "NEEDLE", "word",
                                                       "--project", "coordination")], [2, 1])
        for word in ("%' OR 1=1 --", "%", "_"):
            self.assertEqual(self.records("search", word), [])

    def test_every_field_and_unicode_disguises_are_withheld(self):
        variants = ("restricted", "ＲＥＳＴＲＩＣＴＥＤ", "re\u200bstricted", "rеstricted",
                    "re\u0301stricted", *reader.load_terms(self.state))
        for field in ("title", "content", "project", "topic_key", "type", "updated_at", "future_text"):
            for index, value in enumerate(variants, 1):
                with self.subTest(field=field, variant=index):
                    with sqlite3.connect(self.database) as db:
                        db.execute("DELETE FROM observations")
                    if field == "project":
                        (self.state / "allowed-projects.json").write_text(json.dumps(
                            {"projects": ["coordination", "synthetic", value]}))
                    self.add(**{field: value})
                    code, out, err = self.run_cli("show", "1")
                    self.assertEqual((code, err), (0, ""))
                    self.assertEqual(out, "not found\nwithheld: 1\n")

    def test_foreign_and_deleted_rows_never_print(self):
        self.add(1, project="foreign")
        self.add(2, deleted_at="2026-10-11")
        self.assertEqual(self.records("search", "Synthetic"), [])
        self.assertEqual(self.run_cli("show", "1")[1], "not found\nwithheld: 1\n")
        self.assertEqual(self.run_cli("show", "2")[1], "not found\nwithheld: 0\n")

    def test_withheld_rows_do_not_consume_limit(self):
        self.add(1)
        self.add(2, topic_key="restricted", updated_at="2026-10-11 09:00:00")
        self.assertEqual([r["id"] for r in self.records("search", "Synthetic", "--limit", "1")], [1])
        self.assertIn("withheld: 1", self.run_cli("search", "Synthetic", "--limit", "1")[1])

    def test_output_lengths_and_terminal_controls(self):
        self.add(content="x" * 21000, title="status/ready\x1b[31m\n")
        self.assertEqual(len(self.records("search", "x")[0]["snippet"]), 300)
        self.assertEqual(len(self.records("show", "1")[0]["content"]), 20000)
        self.assertNotIn("\x1b", self.run_cli("show", "1")[1])

    def test_recent_default_window_maximum_and_limit(self):
        self.add(1, updated_at="2000-01-01 00:00:00")
        for identifier in (2, 3):
            with sqlite3.connect(self.database) as db:
                stamp = db.execute("SELECT datetime('now', '-1 hour')").fetchone()[0]
            self.add(identifier, updated_at=stamp)
        self.assertEqual([r["id"] for r in self.records("recent", "--limit", "1")], [3])
        self.assertEqual(len(self.records("recent", "168", "--limit", "50")), 2)

    def test_plans_sort_urgency_then_time_and_skip_resolved_asks(self):
        with sqlite3.connect(self.database) as db:
            now = db.execute("SELECT datetime('now')").fetchone()[0]
            older = db.execute("SELECT datetime('now', '-1 hour')").fetchone()[0]
        titles = ["status/ok", "handoff/next", "decision/today", "ask-owner/review",
                  "blocker/build", "ask-owner/RESOLVED", "unrelated", "BLOCKER/latest"]
        for identifier, title in enumerate(titles, 1):
            self.add(identifier, title=title, updated_at=now)
        self.add(9, project="synthetic", title="blocker/foreign", updated_at=now)
        self.add(10, title="ask-owner/closed", content="RESOLVED: owner answered", updated_at=now)
        self.add(11, title="blocker/older", updated_at=older)
        self.assertEqual([r["id"] for r in self.records("plans")], [8, 5, 11, 4, 3, 2, 1])

    def test_invalid_arguments_do_not_echo_values(self):
        cases = [("delete", "restricted"), ("search",), ("search", "x" * 129),
                 ("search", *("x" for _ in range(17))), ("search", "x", "--project", ""),
                 ("search", "x", "--project", "x\n"), ("show", "0"), ("show", "1 OR 1=1"),
                 ("show", str(2**63)), ("recent", "0"), ("recent", "169"),
                 ("recent", "--limit", "51"), ("plans", "--limit", "0"),
                 ("search", "x", "--state", str(self.state)), ("recent", "restricted")]
        for args in cases:
            with self.subTest(case=cases.index(args)):
                self.assertEqual(self.run_cli(*args), (2, "", "Invalid arguments; output withheld.\n"))

    def test_missing_malformed_policy_and_exception_payload_fail_closed(self):
        self.add()
        with patch.object(reader, "connect", side_effect=ValueError("restricted memory text")):
            self.assertEqual(self.run_cli("show", "1"), (1, "", "Read failed; output withheld.\n"))
        for value in ('{"projects": "coordination"}', '{"projects": [null]}', "invalid"):
            (self.state / "allowed-projects.json").write_text(value)
            self.assertEqual(self.run_cli("show", "1"), (1, "", "Read failed; output withheld.\n"))
        (self.state / "allowed-projects.json").unlink()
        self.assertEqual(self.run_cli("show", "1")[0], 1)
        (self.state / "allowed-projects.json").write_text('{"projects": ["coordination"]}')
        (self.state / "blocked-terms.json").write_text('{"terms": "invalid"}')
        self.assertEqual(self.run_cli("show", "1"), (1, "", "Read failed; output withheld.\n"))

    def test_symlink_store_is_rejected(self):
        self.database.rename(self.state / "other.db")
        self.database.symlink_to(self.state / "other.db")
        self.assertEqual(self.run_cli("show", "1"), (1, "", "Read failed; output withheld.\n"))

    def test_read_cli_only_installer_and_installed_wrapper(self):
        self.add()
        home = self.state / "home"
        installed = home / ".local/share/engram-reader"
        installed.mkdir(parents=True)
        shutil.copytree(self.state / "filtered", installed / "filtered")
        for name in ("allowed-projects.json", "blocked-terms.json"):
            shutil.copy2(self.state / name, installed / name)
        script = Path(__file__).resolve().parents[1] / "scripts/install-engram-reader.sh"
        env = {**os.environ, "HOME": str(home)}
        env.pop("XDG_DATA_HOME", None)
        for _ in range(2):
            result = subprocess.run([str(script), "--read-cli-only"], env=env,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, "reader installation must succeed")
        wrapper = home / ".local/bin/engram-reader"
        result = subprocess.run([str(wrapper), "show", "1"], env=env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout.splitlines()[0])["id"], 1)
        self.assertFalse((home / ".engram").exists())
        self.assertFalse((home / ".client").exists())
        self.assertFalse((installed / "__pycache__").exists())


if __name__ == "__main__":
    unittest.main()


from policy_fixture import enable_policy

def setUpModule():
    global cleanup_policy
    cleanup_policy = enable_policy()

def tearDownModule():
    cleanup_policy()
