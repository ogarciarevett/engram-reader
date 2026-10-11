"""Private policy configuration and the empty public default."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import engram_reader as reader


class ConfigTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.env = patch.dict(os.environ, {'XDG_CONFIG_HOME': str(self.root)}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def write_policy(self, path, terms):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({'terms': terms}))

    def test_public_default_is_empty_and_does_not_match_every_row(self):
        self.assertEqual(reader.DEFAULT_TERMS, ())
        self.assertEqual(reader.load_terms(self.root), ())
        self.assertFalse(reader.matches({'content': 'synthetic public memory'}, ()))
        self.assertTrue(reader.allowed('synthetic-project'))

    def test_xdg_private_config_loads_without_state_directory(self):
        self.write_policy(self.root / 'engram-reader/blocked-terms.json', [' FILTER-ALPHA '])
        self.assertEqual(reader.load_terms(self.root / 'unused'), ('filter-alpha',))
        self.assertFalse(reader.allowed('FILTER-ALPHA-project'))

    def test_environment_path_overrides_xdg_config(self):
        self.write_policy(self.root / 'engram-reader/blocked-terms.json', ['filter-beta'])
        explicit = self.root / 'private.json'
        self.write_policy(explicit, ['filter-alpha'])
        with patch.dict(os.environ, {'ENGRAM_READER_BLOCKLIST': str(explicit)}):
            self.assertEqual(reader.load_terms(self.root), ('filter-alpha',))
            self.assertTrue(reader.matches({'content': 'filter-alpha'}))
            self.assertFalse(reader.matches({'content': 'filter-beta'}))

    def test_explicit_missing_config_fails_closed(self):
        with patch.dict(os.environ, {'ENGRAM_READER_BLOCKLIST': str(self.root / 'missing.json')}):
            with self.assertRaises(ValueError):
                reader.load_terms(self.root)

    def test_symlink_and_malformed_config_fail_closed(self):
        target = self.root / 'target.json'
        self.write_policy(target, [])
        link = self.root / 'link.json'
        link.symlink_to(target)
        with patch.dict(os.environ, {'ENGRAM_READER_BLOCKLIST': str(link)}):
            with self.assertRaises(ValueError):
                reader.load_terms(self.root)
        for value in ('invalid', '{}', '{"terms":[""]}', '{"terms":[null]}'):
            target.write_text(value)
            with patch.dict(os.environ, {'ENGRAM_READER_BLOCKLIST': str(target)}):
                with self.assertRaises(ValueError):
                    reader.load_terms(self.root)

    def test_legacy_state_policy_is_not_loaded_implicitly(self):
        self.write_policy(self.root / 'blocked-terms.json', ['filter-alpha'])
        self.assertEqual(reader.load_terms(self.root), ())

    def test_sandbox_receives_private_terms_without_filesystem_access(self):
        import connector_store as store
        policy = self.root / 'private.json'
        self.write_policy(policy, ['filter-alpha'])
        result = __import__('subprocess').CompletedProcess([], 0, b'{"verified":true}', b'')
        with patch.dict(os.environ, {'ENGRAM_READER_BLOCKLIST': str(policy)}), \
             patch.object(store, 'worker_command', return_value=['synthetic-worker']), \
             patch.object(store.subprocess, 'run', return_value=result) as run:
            store.restricted_worker({'operation': 'validate', 'export': {}})
        message = json.loads(run.call_args.kwargs['input'])
        self.assertEqual(message['terms'], ['filter-alpha'])
        self.assertNotIn('ENGRAM_READER_BLOCKLIST', run.call_args.kwargs['env'])
