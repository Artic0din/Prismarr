"""Real local Git fixtures; only synthetic credentials, no network or models."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'repo-assist-worker'))
import publication_guard as guard

TOKEN = 'synthetic-oauth-publication-fixture-7cdbd25a'
GIT = '/usr/bin/git'


class PublicationGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / 'workspace'
        self.artifacts = self.root / 'artifacts'
        self.scratch = self.root / 'scratch'
        for directory in (self.workspace, self.artifacts, self.scratch):
            directory.mkdir()
        self.git('init', '--quiet')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.workspace / 'README.md').write_text('clean baseline\n')
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', 'Baseline')
        (self.artifacts / 'agent_output.json').write_text('{"items":[]}\n')

    def git(self, *arguments: str, data: bytes | None = None) -> bytes:
        return subprocess.run([GIT, '-C', str(self.workspace), *arguments],
            input=data, capture_output=True, check=True,
            env={'PATH': '/usr/bin:/bin', 'HOME': str(self.root),
                 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}, timeout=10).stdout

    def enforce(self) -> None:
        guard.enforce_publication(TOKEN, self.workspace, [self.artifacts], self.scratch)

    def blocked(self) -> None:
        with self.assertRaises(guard.PublicationBlocked) as failure:
            self.enforce()
        self.assertNotIn(TOKEN, str(failure.exception))
        self.assertFalse(self.artifacts.exists(), 'Unsafe upload root must be removed')
        self.assertEqual(list(self.scratch.iterdir()), [], 'Decoded objects must not remain')

    def test_clean_workspace_and_bundle_pass(self) -> None:
        self.git('bundle', 'create', str(self.artifacts / 'aw-clean.bundle'), '--all')
        self.enforce()
        self.assertTrue((self.artifacts / 'aw-clean.bundle').is_file())
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_untracked_document_token_blocks_and_removes_all_artifacts(self) -> None:
        (self.workspace / 'working-notes.md').write_text('private: ' + TOKEN)
        self.blocked()

    def test_modified_document_token_blocks(self) -> None:
        (self.workspace / 'README.md').write_text(TOKEN)
        self.blocked()

    def test_filename_token_blocks_without_diagnostic_disclosure(self) -> None:
        (self.workspace / TOKEN).write_text('clean content')
        self.blocked()

    def test_deleted_committed_blob_token_is_still_rejected(self) -> None:
        (self.workspace / 'README.md').write_text(TOKEN)
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', 'Model edit')
        self.git('reset', '--hard', 'HEAD~1')
        self.blocked()

    def test_unreachable_object_token_is_rejected(self) -> None:
        self.git('hash-object', '-w', '--stdin', data=TOKEN.encode())
        self.blocked()

    def test_commit_message_token_is_rejected(self) -> None:
        self.git('commit', '--quiet', '--allow-empty', '-m', TOKEN)
        self.blocked()

    def test_packed_workspace_object_token_is_rejected(self) -> None:
        self.git('commit', '--quiet', '--allow-empty', '-m', TOKEN)
        self.git('gc', '--quiet')
        self.blocked()

    def test_compressed_bundle_token_is_rejected(self) -> None:
        baseline = self.git('rev-parse', 'HEAD').decode().strip()
        (self.workspace / 'README.md').write_text(TOKEN)
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', 'Model edit')
        bundle = self.artifacts / 'aw-change.bundle'
        self.git('bundle', 'create', str(bundle), baseline + '..HEAD')
        self.assertNotIn(TOKEN.encode(), bundle.read_bytes())
        self.git('reset', '--hard', baseline)
        self.git('reflog', 'expire', '--expire=now', '--all')
        self.git('gc', '--prune=now', '--quiet')
        self.blocked()

    def test_clean_incremental_bundle_passes_with_base_objects(self) -> None:
        baseline = self.git('rev-parse', 'HEAD').decode().strip()
        (self.workspace / 'README.md').write_text('benign change')
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', 'Model edit')
        self.git('bundle', 'create', str(self.artifacts / 'aw-change.bundle'), baseline + '..HEAD')
        self.git('reset', '--hard', baseline)
        self.git('reflog', 'expire', '--expire=now', '--all')
        self.git('gc', '--prune=now', '--quiet')
        self.enforce()

    def test_malformed_bundle_is_rejected(self) -> None:
        (self.artifacts / 'aw-change.bundle').write_bytes(b'invalid compressed data')
        self.blocked()

    def test_artifact_symlink_is_rejected_without_reading_target(self) -> None:
        outside = self.root / 'outside'
        outside.write_text(TOKEN)
        (self.artifacts / 'link').symlink_to(outside)
        self.blocked()
        self.assertEqual(outside.read_text(), TOKEN)

    def test_artifact_root_symlink_is_removed_without_deleting_target(self) -> None:
        (self.artifacts / 'agent_output.json').unlink()
        self.artifacts.rmdir()
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'keep').write_text(TOKEN)
        self.artifacts.symlink_to(outside, target_is_directory=True)
        self.blocked()
        self.assertEqual((outside / 'keep').read_text(), TOKEN)

    def test_workspace_symlink_is_scanned_as_literal_without_following(self) -> None:
        (self.workspace / 'skill').symlink_to('../nonexistent-skill')
        self.enforce()
        (self.workspace / 'bad-skill').symlink_to('../' + TOKEN)
        self.blocked()

    def test_git_symlink_is_rejected(self) -> None:
        (self.workspace / '.git/objects/link').symlink_to(self.root)
        self.blocked()

    def test_git_alternates_are_rejected(self) -> None:
        (self.workspace / '.git/objects/info/alternates').write_text(str(self.root))
        self.blocked()

    def test_git_http_alternates_are_rejected(self) -> None:
        (self.workspace / '.git/objects/info/http-alternates').write_text('https://example.invalid')
        self.blocked()

    def test_git_worktree_indirection_is_rejected(self) -> None:
        (self.workspace / '.git').rename(self.root / 'other-git')
        (self.workspace / '.git').write_text('gitdir: ../other-git')
        self.blocked()

    def test_workspace_config_hooks_and_hostile_environment_are_not_executed(self) -> None:
        marker = self.root / 'executed'
        script = self.root / 'evil.sh'
        script.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nexit 1\n')
        script.chmod(0o755)
        self.git('config', 'core.fsmonitor', str(script))
        self.git('config', 'core.hooksPath', str(self.root))
        self.git('config', 'include.path', str(self.root / 'missing-config'))
        with patch.dict(os.environ, {'GIT_CONFIG_GLOBAL': str(script), 'GIT_EXEC_PATH': str(self.root),
                                    'GIT_OBJECT_DIRECTORY': str(self.root), 'GIT_CONFIG_COUNT': 'bogus'}):
            self.enforce()
        self.assertFalse(marker.exists())

    def test_oversized_file_is_rejected(self) -> None:
        with patch.object(guard, 'MAX_FILE_BYTES', 1024):
            (self.workspace / 'big').write_bytes(b'x' * 1025)
            self.blocked()

    def test_oversized_decompressed_object_is_rejected(self) -> None:
        self.git('hash-object', '-w', '--stdin', data=b'x' * 20000)
        with patch.object(guard, 'MAX_OBJECT_BYTES', 10000):
            self.blocked()

    def test_git_failure_is_fail_closed_without_external_diagnostic(self) -> None:
        with patch.object(guard, 'GIT', '/nonexistent/' + TOKEN):
            self.blocked()

    def test_unknown_object_store_entry_is_rejected(self) -> None:
        (self.workspace / '.git/objects/unrecognized').write_bytes(b'opaque data')
        self.blocked()

    def test_sha256_object_store_is_rejected_instead_of_skipped(self) -> None:
        directory = self.workspace / '.git/objects/aa'
        directory.mkdir(exist_ok=True)
        (directory / ('a' * 62)).write_bytes(b'compressed object')
        self.blocked()

    def test_orphan_pack_without_index_is_rejected(self) -> None:
        (self.workspace / '.git/objects/pack' / ('pack-' + 'a' * 40 + '.pack')).write_bytes(b'invalid')
        self.blocked()

    def test_invalid_paired_pack_and_index_are_rejected(self) -> None:
        for suffix in ('.pack', '.idx'):
            (self.workspace / '.git/objects/pack' / ('pack-' + 'a' * 40 + suffix)).write_bytes(b'invalid')
        self.blocked()

    def test_token_crossing_stream_chunk_boundary_is_rejected(self) -> None:
        (self.workspace / 'README.md').write_bytes(b'x' * (guard.CHUNK_BYTES - 5) + TOKEN.encode())
        self.blocked()

    def test_total_size_limit_is_fail_closed(self) -> None:
        with patch.object(guard, 'MAX_TOTAL_BYTES', 1):
            self.blocked()

    def test_file_count_limit_is_fail_closed(self) -> None:
        with patch.object(guard, 'MAX_FILES', 2):
            self.blocked()

    def test_expired_deadline_is_fail_closed(self) -> None:
        with patch.object(guard, 'MAX_SECONDS', -1):
            self.blocked()

    def test_nonregular_artifact_is_rejected_without_blocking(self) -> None:
        os.mkfifo(self.artifacts / 'fifo')
        self.blocked()

    def test_artifact_ancestor_symlink_cannot_remove_unrelated_data(self) -> None:
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'keep').write_text(TOKEN)
        link = self.root / 'link'
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(guard.PublicationBlocked):
            guard.enforce_publication(TOKEN, self.workspace, [link / 'keep'], self.scratch)
        self.assertEqual((outside / 'keep').read_text(), TOKEN)

    def test_invalid_upload_root_cannot_delete_workspace(self) -> None:
        with self.assertRaises(guard.PublicationBlocked):
            guard.enforce_publication(TOKEN, self.workspace, [self.workspace], self.scratch)
        self.assertTrue((self.workspace / 'README.md').is_file())

    def test_native_manifest_ignores_nonuploaded_skill_and_tls_symlinks(self) -> None:
        skills = self.artifacts / '.claude/skills'
        skills.mkdir(parents=True)
        (skills / 'trusted').symlink_to('/trusted/skill')
        proxy = self.artifacts / 'proxy-logs'
        proxy.mkdir()
        (proxy / 'proxy-tls').symlink_to('/trusted/tls')
        (proxy / 'gateway.log').write_text('clean proxy log')
        roots = guard.native_artifact_roots(self.artifacts, self.root / 'safeoutputs')
        guard.enforce_publication(TOKEN, self.workspace, roots, self.scratch)
        self.assertTrue((skills / 'trusted').is_symlink())
        self.assertTrue((proxy / 'proxy-tls').is_symlink())

    def test_native_manifest_scans_every_fallback_usage_location(self) -> None:
        for relative in (
            'sandbox/firewall-audit-logs/api-proxy-logs/token-usage.jsonl',
            'sandbox/firewall/logs/api-proxy-logs/token-usage.jsonl',
            'sandbox/firewall/audit/api-proxy-logs/token-usage.jsonl',
        ):
            with self.subTest(relative=relative):
                path = self.artifacts / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(TOKEN)
                roots = guard.native_artifact_roots(self.artifacts, self.root / 'safeoutputs')
                with self.assertRaises(guard.PublicationBlocked):
                    guard.enforce_publication(TOKEN, self.workspace, roots, self.scratch)
                self.assertFalse(path.exists())

    def test_native_manifest_checks_actual_upload_symlinks(self) -> None:
        proxy = self.artifacts / 'proxy-logs'
        proxy.mkdir()
        (proxy / 'gateway.log').symlink_to('/outside')
        roots = guard.native_artifact_roots(self.artifacts, self.root / 'safeoutputs')
        with self.assertRaises(guard.PublicationBlocked):
            guard.enforce_publication(TOKEN, self.workspace, roots, self.scratch)
        self.assertFalse((proxy / 'gateway.log').is_symlink())

    def test_native_manifest_checks_generated_bundles(self) -> None:
        bundle = self.artifacts / 'aw-result.bundle'
        bundle.write_bytes(b'invalid bundle')
        roots = guard.native_artifact_roots(self.artifacts, self.root / 'safeoutputs')
        with self.assertRaises(guard.PublicationBlocked):
            guard.enforce_publication(TOKEN, self.workspace, roots, self.scratch)
        self.assertFalse(bundle.exists())

    def test_native_manifest_root_symlink_is_rejected_without_following(self) -> None:
        (self.artifacts / 'agent_output.json').unlink()
        self.artifacts.rmdir()
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'agent_output.json').write_text(TOKEN)
        self.artifacts.symlink_to(outside, target_is_directory=True)
        roots = guard.native_artifact_roots(self.artifacts, self.root / 'safeoutputs')
        with self.assertRaises(guard.PublicationBlocked):
            guard.enforce_publication(TOKEN, self.workspace, roots, self.scratch)
        self.assertFalse(self.artifacts.is_symlink())
        self.assertEqual((outside / 'agent_output.json').read_text(), TOKEN)

    def test_native_cli_selects_manifest_and_preserves_nonuploaded_symlinks(self) -> None:
        skills = self.artifacts / '.claude/skills'
        skills.mkdir(parents=True)
        (skills / 'trusted').symlink_to('/trusted/skill')
        result = subprocess.run([sys.executable, str(Path(guard.__file__)),
            '--workspace', str(self.workspace), '--native-artifact-dir', str(self.artifacts),
            '--safeoutputs', str(self.root / 'safeoutputs'),
            '--scratch-parent', str(self.scratch)], capture_output=True, timeout=20,
            env={**os.environ, 'SECRET_CLAUDE_CODE_OAUTH_TOKEN': TOKEN})
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue((skills / 'trusted').is_symlink())

    def test_cli_diagnostics_never_print_secret_or_path(self) -> None:
        (self.workspace / TOKEN).write_text(TOKEN)
        result = subprocess.run([sys.executable, str(Path(guard.__file__)),
            '--workspace', str(self.workspace), '--artifact-root', str(self.artifacts),
            '--scratch-parent', str(self.scratch)], capture_output=True, timeout=20,
            env={**os.environ, 'SECRET_CLAUDE_CODE_OAUTH_TOKEN': TOKEN})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(TOKEN.encode(), result.stdout + result.stderr)
        self.assertFalse(self.artifacts.exists())


if __name__ == '__main__':
    unittest.main()
