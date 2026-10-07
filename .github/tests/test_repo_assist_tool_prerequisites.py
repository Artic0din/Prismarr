"""Verify tool downloads and launch-time integrity without external requests."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'repo-assist-worker'))
import tool_prerequisites as prerequisites


class ToolPrerequisiteTests(unittest.TestCase):
    def test_official_release_pin_is_fixed(self) -> None:
        self.assertEqual(prerequisites.JQ_VERSION, '1.8.1')
        self.assertEqual(prerequisites.JQ_URL,
                         'https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux-amd64')
        self.assertEqual(prerequisites.JQ_SHA256,
                         '020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d')

    def test_installer_verifies_bytes_before_atomic_executable_install(self) -> None:
        payload = b'fixture bytes, never executed'
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(prerequisites, 'JQ_SHA256', hashlib.sha256(payload).hexdigest()), \
             patch.object(prerequisites, 'urlopen', return_value=io.BytesIO(payload)) as download:
            cache = Path(directory)
            prerequisites.install_jq(cache)
            download.assert_called_once_with(prerequisites.JQ_URL, timeout=60)
            installed = prerequisites.require_jq(cache)
            self.assertEqual((installed / 'jq').read_bytes(), payload)
            self.assertEqual((installed / 'jq').stat().st_mode & 0o777, 0o555)
            self.assertEqual([path.name for path in installed.iterdir()], ['jq'])

    def test_corrupt_or_oversized_download_never_replaces_existing_tool(self) -> None:
        for payload in (b'corrupt release', b'x' * (prerequisites.MAX_JQ_BYTES + 1)):
            with self.subTest(length=len(payload)), tempfile.TemporaryDirectory() as directory, \
                 patch.object(prerequisites, 'urlopen', return_value=io.BytesIO(payload)):
                cache = Path(directory)
                tools = cache / 'repo-assist/bin'
                tools.mkdir(parents=True)
                (tools / 'jq').write_bytes(b'existing tool')
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    prerequisites.install_jq(cache)
                self.assertEqual((tools / 'jq').read_bytes(), b'existing tool')
                self.assertEqual([path.name for path in tools.iterdir()], ['jq'])

    def test_download_failure_never_creates_an_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(prerequisites, 'urlopen', side_effect=OSError('offline')):
            cache = Path(directory)
            with self.assertRaises(OSError):
                prerequisites.install_jq(cache)
            self.assertEqual(list((cache / 'repo-assist/bin').iterdir()), [])

    def test_launcher_rejects_missing_changed_nonexecutable_and_symlinked_jq(self) -> None:
        payload = b'valid fixture'
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(prerequisites, 'JQ_SHA256', hashlib.sha256(payload).hexdigest()):
            cache = Path(directory)
            tools = cache / 'repo-assist/bin'
            tools.mkdir(parents=True)
            binary = tools / 'jq'
            with self.assertRaises(ValueError):
                prerequisites.require_jq(cache)
            binary.write_bytes(payload)
            binary.chmod(0o644)
            with self.assertRaises(ValueError):
                prerequisites.require_jq(cache)
            binary.chmod(0o755)
            self.assertEqual(prerequisites.require_jq(cache), tools)
            binary.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                prerequisites.require_jq(cache)
            binary.write_bytes(payload)
            binary.rename(tools / 'original')
            binary.symlink_to(tools / 'original')
            with self.assertRaises(ValueError):
                prerequisites.require_jq(cache)

    def test_unreviewed_platform_is_rejected_before_download(self) -> None:
        with patch.object(prerequisites.platform, 'machine', return_value='aarch64'), \
             patch.object(prerequisites, 'urlopen') as download:
            with self.assertRaisesRegex(ValueError, 'Linux x86_64'):
                prerequisites.install_jq(Path('/unused'))
            download.assert_not_called()
