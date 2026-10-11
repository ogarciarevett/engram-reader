"""Cursor plugin contract and configured stdio command integration.

Contract source: https://cursor.com/docs/reference/plugins
Manifest fields, component discovery, skills format and MCP servers sections.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest
import test_filter

ROOT = Path(__file__).resolve().parents[1]


class PluginTests(unittest.TestCase):
    def manifest(self):
        return json.loads((ROOT / '.cursor-plugin/plugin.json').read_text())

    def test_manifest_matches_documented_cursor_field_contract(self):
        manifest = self.manifest()
        self.assertIsInstance(manifest, dict)
        self.assertRegex(manifest['name'], r'^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$')
        # The native Cursor format permits these documented optional fields.
        fields = {'name', 'description', 'version', 'license', 'keywords', 'skills', 'mcpServers'}
        self.assertLessEqual(set(manifest), fields)
        for field in ('description', 'version', 'license', 'skills', 'mcpServers'):
            self.assertIsInstance(manifest[field], str)
            self.assertTrue(manifest[field].strip())
        self.assertRegex(manifest['version'], r'^[0-9]+\.[0-9]+\.[0-9]+$')
        self.assertIsInstance(manifest['keywords'], list)
        self.assertTrue(all(isinstance(x, str) for x in manifest['keywords']))
        for field in ('skills', 'mcpServers'):
            path = Path(manifest[field])
            self.assertFalse(path.is_absolute())
            self.assertNotIn('..', path.parts)
            self.assertTrue((ROOT / path).exists())

    def test_components_discover_one_skill_and_one_stdio_server(self):
        manifest = self.manifest()
        skills = list((ROOT / manifest['skills']).glob('*/SKILL.md'))
        self.assertEqual(len(skills), 1)
        frontmatter = re.match(r'\A---\n(.*?)\n---\n', skills[0].read_text(), re.S)
        self.assertIsNotNone(frontmatter)
        metadata = dict(line.split(':', 1) for line in frontmatter[1].splitlines())
        self.assertEqual(metadata['name'].strip(), skills[0].parent.name)
        self.assertTrue(metadata['description'].strip())
        config = json.loads((ROOT / manifest['mcpServers']).read_text())
        self.assertEqual(set(config), {'mcpServers'})
        self.assertEqual(len(config['mcpServers']), 1)
        server = next(iter(config['mcpServers'].values()))
        self.assertEqual(server['type'], 'stdio')
        self.assertEqual(server['command'], 'engram-reader-mcp')
        self.assertEqual(server['args'], [])

    @unittest.skipUnless(shutil.which('engram'), 'requires installed Engram 3.3.2')
    def test_configured_plugin_command_initializes_six_read_tools(self):
        manifest = self.manifest()
        config = json.loads((ROOT / manifest['mcpServers']).read_text())
        server = next(iter(config['mcpServers'].values()))
        fixture = test_filter.StoreTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        test_filter.g.refresh(fixture.state)
        home = fixture.root / 'synthetic-home'
        home.mkdir()
        installed = home / '.local/share/engram-reader'
        shutil.copytree(fixture.state, installed)
        env = {**os.environ, 'HOME': str(home),
               'XDG_DATA_HOME': str(home / '.local/share'),
               'XDG_CONFIG_HOME': str(home / '.config'),
               'PATH': str(home / '.local/bin') + os.pathsep + os.environ.get('PATH', '')}
        setup = subprocess.run([str(ROOT / 'scripts/install-engram-reader.sh'), '--read-cli-only'],
                               env=env, capture_output=True, timeout=10)
        self.assertEqual(setup.returncode, 0)
        requests = [
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                'protocolVersion': '2024-11-05', 'capabilities': {},
                'clientInfo': {'name': 'synthetic-plugin-test', 'version': '1'}}},
            {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}}]
        response = subprocess.run([server['command'], *server['args']], env=env,
            input=''.join(json.dumps(x) + '\n' for x in requests),
            capture_output=True, text=True, timeout=30)
        self.assertEqual(response.returncode, 0)
        replies = {x['id']: x for x in map(json.loads, response.stdout.splitlines()) if 'id' in x}
        self.assertIn('result', replies[1])
        self.assertEqual({x['name'] for x in replies[2]['result']['tools']},
                         set(test_filter.g.TOOLS.split(',')))
        self.assertFalse((installed / '__pycache__').exists())
