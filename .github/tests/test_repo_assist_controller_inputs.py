"""Untrusted artifact paths never resolve in the credentialed controller."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / '.github/repo-assist-worker'))
import controller_inputs
from runtime import agent_mcp_configuration


class ControllerInputTests(unittest.TestCase):
    def test_snapshot_copies_regular_bytes_without_shared_writable_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / 'source', root / 'target'
            (source / 'nested').mkdir(parents=True)
            (source / 'nested/patch.diff').write_text('untrusted patch text')
            controller_inputs.snapshot_inputs(source, target)
            (source / 'nested/patch.diff').write_text('later modification')
            self.assertEqual((target / 'nested/patch.diff').read_text(), 'untrusted patch text')

    def test_symlink_and_special_file_cannot_read_controller_state(self):
        for kind in ('file-link', 'directory-link', 'fifo'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / 'source'
                source.mkdir()
                leaf = source / 'artifact'
                if kind == 'file-link':
                    leaf.symlink_to('/proc/self/environ')
                elif kind == 'directory-link':
                    leaf.symlink_to('/proc', target_is_directory=True)
                else:
                    os.mkfifo(leaf)
                with self.assertRaises(ValueError):
                    controller_inputs.snapshot_inputs(source, root / 'target')

    def test_snapshot_enforces_file_and_total_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()
            (source / 'large').write_bytes(b'x' * 10)
            with patch.object(controller_inputs, 'MAX_FILE_BYTES', 9), self.assertRaises(ValueError):
                controller_inputs.snapshot_inputs(source, root / 'file-limit')
            with patch.object(controller_inputs, 'MAX_BYTES', 9), self.assertRaises(ValueError):
                controller_inputs.snapshot_inputs(source, root / 'total-limit')

    def test_native_gateway_config_is_fixed_http_not_filtered_cli_config(self):
        native = {'mcpServers': {'safeoutputs': {'url': 'http://localhost:8080/mcp/safeoutputs',
                    'headers': {'Authorization': 'synthetic-native'}, 'tools': ['*']}}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'gateway-output.json'
            path.write_text(json.dumps(native))
            config = agent_mcp_configuration(path)
            self.assertEqual(config['mcpServers']['safeoutputs'], {'type': 'http',
                'url': 'http://awmg-mcpg:8080/mcp/safeoutputs', 'headers': {'Authorization': 'synthetic-native'}})
            self.assertEqual(config['mcpServers']['repository']['url'], 'http://repo-assist-tools:8081/mcp')
            for bad in ({'mcpServers': {}}, {'mcpServers': {'safeoutputs': {'command': 'bash'}}},
                        {'mcpServers': {'safeoutputs': {'url': 'http://evil.invalid:8080/mcp/safeoutputs'}}}):
                path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):
                    agent_mcp_configuration(path)
