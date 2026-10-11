"""Atomic tenant publication and read isolation, with synthetic data only."""
import concurrent.futures
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
from test_connector import fixture
import connector_store as c


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = c.TenantStore(self.root, b"s" * 32, upload_interval=0)
        self.alice = c.Principal("alice", frozenset({"engram:read", "engram:upload", "engram:account"}))
        self.bob = c.Principal("bob", self.alice.scopes)
        for p in (self.alice, self.bob):
            self.store.upload(p, json.dumps(fixture(p.subject)).encode())

    def test_collision_and_cache_isolation(self):
        for p in (self.alice, self.bob, self.alice):
            result = self.store.call(p, "mem_get_observation", {"id": 1})
            self.assertEqual(result["records"][0]["title"], p.subject)
            result["records"][0]["title"] = "mutated client copy"
        self.assertEqual(self.store.call(self.alice, "mem_get_observation", {"id": 1})["records"][0]["title"], "alice")

    def test_encryption_and_private_permissions(self):
        for path in self.root.rglob("*"):
            self.assertFalse(path.is_symlink())
            self.assertEqual(path.stat().st_mode & 0o077, 0)
            if path.is_file():
                self.assertNotIn(b"synthetic memory", path.read_bytes())
        self.assertNotEqual(self.store.tenant_key("alice"), self.store.tenant_key("bob"))

    def test_failed_staging_preserves_old_snapshot_and_cleans_temp(self):
        before = self.store.snapshot(self.alice)
        with patch.object(c.os, "replace", side_effect=OSError("synthetic failure")):
            with self.assertRaises(OSError):
                self.store.upload(self.alice, json.dumps(fixture("replacement")).encode())
        self.assertEqual(self.store.snapshot(self.alice), before)
        self.assertFalse(list(self.root.rglob("stage-*")))

    def test_publication_fsyncs_directory_after_replace(self):
        real_replace, real_fsync = os.replace, os.fsync
        events = []

        def replace(source, destination):
            real_replace(source, destination)
            events.append("replace")

        def fsync(fd):
            events.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            real_fsync(fd)

        with patch.object(c.os, "replace", side_effect=replace), patch.object(c.os, "fsync", side_effect=fsync):
            self.store.upload(self.alice, json.dumps(fixture("replacement")).encode())
        self.assertEqual(events, ["file", "replace", "directory"])

    def test_startup_removes_abandoned_stages_without_following_links(self):
        directory = self.store.directory("alice")
        stage = directory / "stage-abandoned"
        stage.mkdir()
        (stage / "snapshot.enc").write_bytes(b"synthetic encrypted staging bytes")
        outside = self.root / "unrelated"
        outside.mkdir()
        retained = outside / "retained"
        retained.write_bytes(b"synthetic unrelated bytes")
        (directory / "stage-linked").symlink_to(outside, target_is_directory=True)
        c.TenantStore(self.root, b"s" * 32)
        self.assertFalse(list(directory.glob("stage-*")))
        self.assertTrue(retained.exists())
        self.assertEqual(self.store.snapshot(self.alice)["observations"][0]["title"], "alice")

    def test_filter_checked_before_publication_and_on_reads(self):
        doc = fixture()
        doc["data"]["sessions"][0]["summary"] = "filter-alpha"
        with self.assertRaises(c.Rejected):
            self.store.upload(self.alice, json.dumps(doc).encode())
        self.assertEqual(self.store.call(self.alice, "mem_stats", {})["observations"], 1)
        self.store.policy = "new-policy"
        with self.assertRaises(c.Rejected):
            self.store.call(self.alice, "mem_stats", {})
        with self.assertRaises(c.Rejected):
            self.store.upload(self.alice, json.dumps(fixture()).encode())

    def test_concurrent_reads_observe_complete_snapshots(self):
        def read(_):
            return self.store.call(self.alice, "mem_get_observation", {"id": 1})["records"][0]["title"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            pending = [pool.submit(read, i) for i in range(40)]
            self.store.upload(self.alice, json.dumps(fixture("replacement")).encode())
            results = [f.result() for f in pending]
        self.assertTrue(set(results) <= {"alice", "replacement"})
        self.assertEqual(self.store.call(self.bob, "mem_get_observation", {"id": 1})["records"][0]["title"], "bob")

    def test_upload_scope_and_rate_limit(self):
        with self.assertRaises(c.Rejected):
            self.store.upload(c.Principal("alice", frozenset({"engram:read"})), b"{}")
        self.store.upload_interval = 900
        with self.assertRaises(c.RateLimited):
            self.store.upload(self.alice, json.dumps(fixture()).encode())

    def test_delete_disables_reads_and_uploads(self):
        self.store.delete(self.alice)
        for operation in (lambda: self.store.call(self.alice, "mem_stats", {}),
                          lambda: self.store.upload(self.alice, json.dumps(fixture()).encode())):
            with self.assertRaises(c.Rejected):
                operation()
        self.assertEqual(self.store.call(self.bob, "mem_stats", {})["observations"], 1)

    def test_empty_account_has_no_shared_default_data(self):
        fresh = c.Principal("new", self.alice.scopes)
        self.assertEqual(self.store.call(fresh, "mem_stats", {})["observations"], 0)

    def test_foreign_ciphertext_cannot_be_opened_with_another_tenant_key(self):
        source = self.store.directory("alice") / "snapshot.enc"
        destination = self.store.directory("bob") / "snapshot.enc"
        destination.write_bytes(source.read_bytes())
        with self.assertRaises(c.Rejected):
            self.store.call(self.bob, "mem_context", {})

    def test_delete_cancels_an_inflight_read(self):
        import threading
        started, release = threading.Event(), threading.Event()
        real_worker = c.restricted_worker

        def delayed(message, storage_root=None):
            started.set()
            release.wait(5)
            return real_worker(message, storage_root)

        with patch.object(c, "restricted_worker", side_effect=delayed), concurrent.futures.ThreadPoolExecutor() as pool:
            pending = pool.submit(self.store.call, self.alice, "mem_stats", {})
            self.assertTrue(started.wait(5))
            self.store.delete(self.alice)
            release.set()
            with self.assertRaises(c.Rejected):
                pending.result()


class StorageRootTests(unittest.TestCase):
    def test_sandbox_readable_roots_and_ancestors_rejected_before_mutation(self):
        roots = (Path(c.__file__).parent, Path(sys.prefix), Path(sys.base_prefix),
                 Path("/usr/lib"), Path("/System/Library"), Path("/dev"), Path("/"))
        with patch.object(c.Path, "mkdir") as mkdir, patch.object(c.os, "chmod") as chmod:
            for root in roots:
                with self.subTest(root=root), self.assertRaises(c.Rejected):
                    c.TenantStore(root / "synthetic-state" if root != Path("/") else root, b"s" * 32)
            self.assertFalse(mkdir.called)
            self.assertFalse(chmod.called)

    def test_symlink_parent_and_direct_worker_overlap_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            link = Path(scratch) / "code-link"
            link.symlink_to(Path(c.__file__).parent, target_is_directory=True)
            with patch.object(c.Path, "mkdir") as mkdir, patch.object(c.os, "chmod"):
                with self.assertRaises(c.Rejected):
                    c.TenantStore(link / "synthetic-state", b"s" * 32)
                self.assertFalse(mkdir.called)
        with self.assertRaises(c.Rejected):
            c.worker_command(Path(c.__file__).parent / "synthetic-state")


from policy_fixture import enable_policy

def setUpModule():
    global cleanup_policy
    cleanup_policy = enable_policy()

def tearDownModule():
    cleanup_policy()
