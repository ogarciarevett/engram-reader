"""The macOS worker sandbox has no store files or outbound network authority."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_connector import fixture
import connector_store as c


class WorkerTests(unittest.TestCase):
    def test_read_worker_receives_only_one_snapshot(self):
        result = c.restricted_worker({"operation": "read", "data": fixture("alice")["data"],
                                      "name": "mem_get_observation", "arguments": {"id": 1}})
        self.assertEqual(result["records"][0]["title"], "alice")

    def test_os_denies_foreign_file_write_and_network(self):
        with tempfile.TemporaryDirectory() as scratch:
            foreign = Path(scratch) / "foreign"
            foreign.write_text("synthetic foreign store")
            probe = '''import json, os, socket
results = []
for action in (lambda: open(os.environ["PROBE_FOREIGN"]).read(),
               lambda: open(os.environ["PROBE_WRITE"], "w").write("denied"),
               lambda: socket.socket().connect(("localhost", 9))):
    try:
        action()
        results.append(False)
    except PermissionError:
        results.append(True)
print(json.dumps(results))
'''
            command = c.worker_command()[:-1] + ["-c", probe]
            result = subprocess.run(command, env={"PROBE_FOREIGN": str(foreign),
                "PROBE_WRITE": str(Path(scratch) / "write")}, capture_output=True, text=True, timeout=10, cwd=Path(c.__file__).parent)
            self.assertEqual(result.returncode, 0, "sandbox probe must start")
            self.assertEqual(json.loads(result.stdout), [True, True, True])
            self.assertFalse((Path(scratch) / "write").exists())

    def test_staged_validator_rejects_filter_matches(self):
        doc = fixture()
        doc["data"]["observations"][0]["content"] = "filter-beta"
        with self.assertRaises(c.Rejected):
            c.restricted_worker({"operation": "validate", "export": doc})


from policy_fixture import enable_policy

def setUpModule():
    global cleanup_policy
    cleanup_policy = enable_policy()

def tearDownModule():
    cleanup_policy()
