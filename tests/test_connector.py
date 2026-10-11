"""Connector boundaries, using only two synthetic users and colliding IDs."""
import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import connector_store as c


def fixture(user="alice"):
    return {"format": "engram-filtered-v1", "policy": c.POLICY,
            "filter_passed": True, "data": {
                "version": "0.2.0", "exported_at": "", "sessions": [
                    {"id": "same-session", "project": "Synthetic"}],
                "observations": [{"id": 1, "session_id": "same-session",
                    "project": "Synthetic", "title": user, "content": user + " synthetic memory"}],
                "prompts": []}}


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.alice = c.Principal("alice", frozenset({"engram:read"}))
        self.bob = c.Principal("bob", frozenset({"engram:read"}))

    def test_colliding_ids_stay_with_the_selected_snapshot(self):
        for who in ("alice", "bob"):
            result = c.read_tool(fixture(who)["data"], "mem_get_observation", {"id": 1})
            self.assertEqual(result["records"][0]["title"], who)

    def test_forged_tenant_input_is_rejected(self):
        for field in ("tenant", "user_id", "subject", "path", "url", "sql"):
            with self.subTest(field=field), self.assertRaises(c.Rejected):
                c.read_tool(fixture()["data"], "mem_stats", {field: "bob"})

    def test_wrong_scopes_are_rejected(self):
        for scopes in (set(), {"engram:upload"}, {"engram:account"}):
            with self.assertRaises(c.Rejected):
                c.require_scope(c.Principal("alice", frozenset(scopes)), "engram:read")

    def test_writes_and_unknown_tools_are_denied(self):
        for name in ("mem_save", "mem_delete", "execute_sql", "shell", "fetch", "unknown"):
            with self.assertRaises(c.Rejected):
                c.read_tool(fixture()["data"], name, {})

    def test_upload_byte_limit(self):
        with self.assertRaises(c.Rejected):
            c.validate_export(b" " * (c.MAX_UPLOAD + 1))

    def test_upload_record_limit(self):
        doc = fixture()
        doc["data"]["observations"] *= c.MAX_RECORDS + 1
        with self.assertRaises(c.Rejected):
            c.validate_export(json.dumps(doc).encode())

    def test_owner_filter_and_policy_are_mandatory(self):
        for change in ("content", "project", "policy", "filter_passed"):
            doc = fixture()
            if change in ("content", "project"):
                doc["data"]["observations"][0][change] = "filter-beta and filter-alpha"
            else:
                doc[change] = False
            with self.assertRaises(c.Rejected):
                c.validate_export(json.dumps(doc).encode())

    def test_duplicate_or_foreign_rows_are_denied(self):
        doc = fixture()
        doc["data"]["observations"].append(copy.deepcopy(doc["data"]["observations"][0]))
        with self.assertRaises(c.Rejected):
            c.validate_export(json.dumps(doc).encode())
        doc = fixture()
        doc["data"]["observations"][0]["session_id"] = "foreign"
        with self.assertRaises(c.Rejected):
            c.validate_export(json.dumps(doc).encode())

    def test_query_and_page_limits(self):
        with self.assertRaises(c.Rejected):
            c.read_tool(fixture()["data"], "mem_search", {"query": "x" * 2049})
        with self.assertRaises(c.Rejected):
            c.read_tool(fixture()["data"], "mem_context", {"limit": 21})

    def test_unknown_row_key_is_rejected(self):
        doc = fixture()
        doc["data"]["observations"][0]["secret_note"] = "synthetic extra field"
        with self.assertRaises(c.Rejected):
            c.validate_export(json.dumps(doc).encode())

    def test_owner_term_in_row_key_is_rejected(self):
        doc = fixture()
        doc["data"]["observations"][0]["filter-beta board"] = "synthetic value"
        with self.assertRaises(c.Rejected):
            c.validate_export(json.dumps(doc).encode())

    def test_session_redaction_is_required(self):
        for field, value in (("summary", "synthetic summary"), ("directory", "/synthetic/private")):
            doc = fixture()
            doc["data"]["sessions"][0][field] = value
            with self.subTest(field=field), self.assertRaises(c.Rejected):
                c.validate_export(json.dumps(doc).encode())

    def test_unicode_owner_terms_are_rejected_on_upload(self):
        for value in ("filter-alpha", "ｆｉｌｔｅｒ-ａｌｐｈａ", "f\u200bilter-alpha", "filter-\u00adalpha", "fіltеr-аlphа", "filter-a\u0301lpha"):
            for kind, field in (("observations", "content"), ("sessions", "project")):
                doc = fixture()
                doc["data"][kind][0][field] = value
                with self.subTest(value=value, kind=kind), self.assertRaises(c.Rejected):
                    c.validate_export(json.dumps(doc).encode())


from policy_fixture import enable_policy

def setUpModule():
    global cleanup_policy
    cleanup_policy = enable_policy()

def tearDownModule():
    cleanup_policy()
