import contextlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/engram_reader.py"
spec = importlib.util.spec_from_file_location("integration", SCRIPT)
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


class FilterTests(unittest.TestCase):
    def test_exclusions_are_case_insensitive_substrings(self):
        for name in ["filter-alpha", "filter-beta", "my-filter-alpha-app", "/work/filter-beta-client", "", None]:
            self.assertFalse(g.allowed(name))
        self.assertTrue(g.allowed("synthetic-project"))

    def test_shared_session_content_is_dropped(self):
        data = {"version": "0.1.0", "exported_at": "", "sessions": [
            {"id": "safe", "project": "synthetic-project", "summary": "SECRET", "directory": "/private"},
            {"id": "foreign", "project": "filter-alpha", "summary": "SECRET"}],
            "observations": [
                {"id": 1, "session_id": "safe", "project": "synthetic-project"},
                {"id": 2, "session_id": "foreign", "project": "synthetic-project", "content": "SECRET"},
                {"id": 3, "session_id": "safe", "project": "filter-alpha", "content": "SECRET"},
                {"id": 4, "session_id": "safe", "project": None},
                {"id": 5, "session_id": "safe", "project": "synthetic-project", "deleted_at": "2026"}],
            "prompts": [{"session_id": "foreign", "project": "synthetic-project", "content": "SECRET"}],
            "relations": [{"reason": "SECRET"}], "prompt_tombstones": [{"project": "filter-alpha"}]}
        result = g.sanitize(data, {"synthetic-project"})
        self.assertEqual([r["id"] for r in result["observations"]], [1, 4])
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertEqual(result["observations"][1]["project"], "synthetic-project")

    def test_environment_disables_cloud_and_override(self):
        with patch.dict(os.environ, {"ENGRAM_CLOUD_TOKEN": "secret", "ENGRAM_PROJECT": "filter-alpha"}):
            env = g.environment(Path("/filtered"))
        self.assertNotIn("ENGRAM_CLOUD_TOKEN", env)
        self.assertNotIn("ENGRAM_PROJECT", env)
        self.assertEqual(env["ENGRAM_DATA_DIR"], "/filtered")
        self.assertEqual(env["ENGRAM_CLOUD_AUTOSYNC"], "0")


@unittest.skipUnless(shutil.which("engram"), "requires installed Engram v3.3.2")
class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.state = self.root / "state"
        self.state.mkdir()
        self.policy_env = patch.dict(os.environ, {"ENGRAM_READER_BLOCKLIST": str(self.state / "blocked-terms.json")})
        self.policy_env.start()
        self.addCleanup(self.policy_env.stop)
        g.write_json(self.state / "blocked-terms.json", {"terms": ["filter-alpha", "filter-beta"]})

        self.binary = shutil.which("engram")
        g.write_json(self.state / "installation.json", {"source": str(self.source), "engram": self.binary})
        for project in ["synthetic-project", "filter-alpha", "filter-beta-lab", "other"]:
            g.run_engram(self.binary, self.source, "save", "Synthetic fixture", "Synthetic content", "--project", project)
        # Create adversarial cross-project ownership using synthetic data only.
        with contextlib.closing(sqlite3.connect(self.source / "engram.db")) as db:
            db.execute("INSERT INTO sessions(id,project,directory,started_at,summary) "
                       "VALUES('foreign','filter-alpha','','2026-10-11','PRIVATE_FIXTURE')")
            db.execute("UPDATE observations SET session_id='foreign' WHERE project='other'")
            db.commit()

    def test_filtered_store_contains_zero_excluded_observations(self):
        counts = g.refresh(self.state)
        self.assertEqual(counts["excluded_rows"], 0)
        self.assertEqual(counts["observations"], 1)
        with contextlib.closing(g.connect(self.state / "filtered/engram.db")) as db:
            excluded = db.execute("SELECT count(*) FROM observations WHERE lower(project) LIKE '%filter-alpha%' "
                                  "OR lower(project) LIKE '%filter-beta%'").fetchone()[0]
            self.assertEqual(excluded, 0)
        self.assertEqual(g.refresh(self.state), counts)
        self.assertEqual(g.projects(self.source), sorted(["other", "synthetic-project"]))

    def test_legacy_path_projects_export_without_modifying_source(self):
        with contextlib.closing(sqlite3.connect(self.source / "engram.db")) as db:
            db.execute("UPDATE sessions SET project='/legacy/safe' WHERE project='synthetic-project'")
            db.execute("UPDATE observations SET project='/legacy/safe' WHERE project='synthetic-project'")
            db.commit()
        before = (self.source / "engram.db").read_bytes()
        counts = g.refresh(self.state)
        self.assertEqual(counts["observations"], 1)
        self.assertEqual((self.source / "engram.db").read_bytes(), before)
        self.assertIn("/legacy/safe", g.projects(self.state / "filtered"))

    def test_pinned_empty_policy_removes_old_rows(self):
        g.refresh(self.state)
        g.write_json(self.state / "allowed-projects.json", {"mode": "pinned", "projects": []})
        counts = g.refresh(self.state)
        self.assertEqual(counts["observations"], 0)
        self.assertEqual(counts["sessions"], 0)

    def test_source_deletion_propagates_and_invalid_policy_empties_snapshot(self):
        g.refresh(self.state)
        with contextlib.closing(sqlite3.connect(self.source / "engram.db")) as db:
            db.execute("UPDATE observations SET deleted_at='2026-10-11' WHERE project='synthetic-project'")
            db.commit()
        self.assertEqual(g.refresh(self.state)["observations"], 0)
        g.write_json(self.state / "allowed-projects.json", {"mode": "pinned", "projects": ["safe-filter-alpha"]})
        with self.assertRaises(ValueError):
            g.refresh(self.state)
        counts = g.audit(self.state / "filtered/engram.db", set())
        self.assertEqual([counts[k] for k in ("sessions", "observations", "user_prompts")], [0, 0, 0])

    def test_contaminated_store_cannot_start_mcp(self):
        g.refresh(self.state)
        with contextlib.closing(sqlite3.connect(self.state / "filtered/engram.db")) as db:
            db.execute("UPDATE observations SET project='filter-beta'")
            db.commit()
        result = subprocess.run(["python3", str(SCRIPT), "--state", str(self.state), "mcp"],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"Synthetic content", result.stderr)

    def test_install_is_idempotent_and_uninstall_preserves_settings(self):
        home = self.root / "home"
        (home / ".client").mkdir(parents=True)
        settings = home / ".client/settings.json"
        settings.write_text('{"mcpBoxServers": []}')
        original = settings.read_bytes()
        real_run = subprocess.run
        calls = []
        loaded = False

        def launch_run(command, **kwargs):
            nonlocal loaded
            if command[0] != "launchctl":
                return real_run(command, **kwargs)
            calls.append(command[1])
            code = 0
            if command[1] == "print":
                code = 0 if loaded else 1
            elif command[1] == "bootstrap":
                loaded = True
            elif command[1] == "bootout":
                loaded = False
            return subprocess.CompletedProcess(command, code)

        with patch.object(g.Path, "home", return_value=home), patch.object(g.subprocess, "run", side_effect=launch_run):
            with contextlib.redirect_stdout(__import__("io").StringIO()):
                self.assertEqual(g.install(self.state, self.source, self.binary), 0)
                first = (self.state / "mcp-candidate.json").read_bytes()
                self.assertEqual(g.install(self.state, self.source, self.binary), 0)
                self.assertEqual((self.state / "mcp-candidate.json").read_bytes(), first)
                g.uninstall(self.state)
        self.assertEqual(calls.count("bootstrap"), 1)
        self.assertFalse(loaded)
        self.assertFalse((self.state / "mcp-candidate.json").exists())
        self.assertEqual(settings.read_bytes(), original)
        self.assertTrue((self.state / "filtered/engram.db").exists())

    def test_mcp_initialize_and_read_tool_list(self):
        g.refresh(self.state)
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}]
        result = subprocess.run(["python3", str(SCRIPT), "--state", str(self.state), "mcp"],
                                input="".join(json.dumps(r) + "\n" for r in requests),
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        replies = {r["id"]: r for r in map(json.loads, result.stdout.splitlines()) if "id" in r}
        self.assertIn("result", replies[1])
        names = {t["name"] for t in replies[2]["result"]["tools"]}
        self.assertEqual(names, set(g.TOOLS.split(",")))
        self.assertFalse(list(self.state.glob("mcp-*")))


if __name__ == "__main__":
    unittest.main()


from policy_fixture import enable_policy

def setUpModule():
    global cleanup_policy
    cleanup_policy = enable_policy()

def tearDownModule():
    cleanup_policy()
