"""Offline subscription receipts against the pinned gh-aw accounting pipeline."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / '.github/repo-assist-worker/usage.py'
COMPILER = Path(os.environ.get('REPO_ASSIST_COMPILER_SOURCE', ROOT / '.repo-assist-compiler'))


def final_result(**overrides):
    return {'type': 'result', 'subtype': 'success', 'is_error': False,
            'result': 'private answer that must not enter the receipt',
            'total_cost_usd': 99,
            'usage': {'input_tokens': 1, 'output_tokens': 1},
            'modelUsage': {
                'claude-sonnet-4-6': {'inputTokens': 1000, 'outputTokens': 100,
                    'cacheReadInputTokens': 2000, 'cacheCreationInputTokens': 500,
                    'webSearchRequests': 0, 'costUSD': 99}}, **overrides}


class UsageTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(MODULE.is_file(), 'subscription accounting module is missing')
        spec = importlib.util.spec_from_file_location('subscription_usage', MODULE)
        self.usage = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.usage)

    def test_final_model_usage_preserves_all_token_classes_without_cost_claim(self):
        receipt = self.usage.usage_records(json.dumps(final_result()))
        self.assertEqual(len(receipt), 1)
        self.assertEqual(receipt[0], {
            'source': 'claude_subscription_result', 'provider': 'anthropic',
            'model': 'claude-sonnet-4-6', 'input_tokens': 1000, 'output_tokens': 100,
            'cache_read_tokens': 2000, 'cache_write_tokens': 500,
            'input_tokens_include_cache': False})
        self.assertNotIn('99', json.dumps(receipt))
        self.assertNotIn('private', json.dumps(receipt))

    def test_multiple_models_are_counted_and_cumulative_results_not_summed(self):
        result = final_result()
        result['modelUsage']['claude-haiku-4-5-20251001'] = {
            'inputTokens': 200, 'outputTokens': 50, 'cacheReadInputTokens': 0,
            'cacheCreationInputTokens': 0, 'costUSD': 0.01}
        records = self.usage.usage_records(json.dumps(final_result()) + '\n' + json.dumps(result))
        self.assertEqual(len(records), 2)
        self.assertEqual(sum(row['input_tokens'] for row in records), 1200)

    def test_error_final_receipt_still_accounts_for_consumed_tokens(self):
        result = final_result(subtype='error_max_turns', is_error=True)
        self.assertEqual(self.usage.usage_records(json.dumps(result))[0]['output_tokens'], 100)

    def test_missing_malformed_and_zero_usage_are_unknown_never_zero(self):
        good = final_result()
        bad_results = [final_result(modelUsage={}), final_result(modelUsage=None),
                       final_result(modelUsage=[]), final_result(type='assistant')]
        for field in ('inputTokens', 'outputTokens', 'cacheReadInputTokens', 'cacheCreationInputTokens'):
            for value in (None, True, -1, '10', 1.5, float('inf'), 2**53):
                bad = json.loads(json.dumps(good))
                bad['modelUsage']['claude-sonnet-4-6'][field] = value
                bad_results.append(bad)
        bad_results.append(final_result(modelUsage={'claude-sonnet-4-6': {
            'inputTokens': 0, 'outputTokens': 0, 'cacheReadInputTokens': 0,
            'cacheCreationInputTokens': 0}}))
        for value in ('', '{', *(json.dumps(bad) for bad in bad_results)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.usage.usage_records(value)

    def test_last_result_missing_usage_does_not_reuse_earlier_receipt(self):
        with self.assertRaises(ValueError):
            self.usage.usage_records(json.dumps(final_result()) + '\n' + json.dumps(final_result(modelUsage={})))

    def test_truncated_tail_cannot_reuse_an_earlier_result(self):
        with self.assertRaises(ValueError):
            self.usage.usage_records(json.dumps(final_result()) + '\n{"type":"result"')

    def test_capture_limit_invalidates_any_preceding_complete_result(self):
        with tempfile.TemporaryDirectory() as directory:
            # Wait for the wrapper to relay the final result before overflowing.
            program = ('import sys,time; from pathlib import Path\nprint(' + repr(json.dumps(final_result()))
                       + ',flush=True)\nwhile not any(p.stat().st_size for p in Path('
                       + repr(directory) + ').glob("*.jsonl")): time.sleep(0.005)\nprint("x"*16384)')
            launcher = ('import sys; from pathlib import Path; import usage; '
                        'usage.MAX_CAPTURE_BYTES=4096; '
                        'sys.exit(usage.capture_cli(Path(sys.argv[1]),sys.argv[2:]))')
            result = subprocess.run([sys.executable, '-c', launcher, directory,
                sys.executable, '-c', program], capture_output=True, text=True,
                env={**os.environ, 'PYTHONPATH': str(MODULE.parent)}, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            files = list(Path(directory).glob('*.jsonl'))
            self.assertEqual(len(files), 1)
            with self.assertRaises(ValueError):
                self.usage.usage_records(files[0].read_text())

    def test_unknown_marker_replaces_stale_receipt_and_survives_invalid_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'token-usage.jsonl'
            self.assertTrue(self.usage.record_usage([json.dumps(final_result())], path))
            self.assertFalse(self.usage.record_usage(['incomplete'], path))
            self.assertEqual(path.read_text(), 'null\n')

    def test_all_detector_invocations_must_have_complete_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / 'capture'
            capture.mkdir()
            (capture / 'one.jsonl').write_text(json.dumps(final_result()))
            (capture / 'two.jsonl').write_text(json.dumps(final_result()))
            destination = root / 'usage.jsonl'
            self.assertTrue(self.usage.record_captures(capture, destination))
            self.assertEqual(len(destination.read_text().splitlines()), 2)
            (capture / 'two.jsonl').write_text('{"type":"assistant"}\n')
            self.assertFalse(self.usage.record_captures(capture, destination))
            self.assertEqual(destination.read_text(), 'null\n')
            (capture / 'two.jsonl').unlink()
            (capture / 'two.jsonl').symlink_to(capture / 'one.jsonl')
            self.assertFalse(self.usage.record_captures(capture, destination))

    def test_capture_preserves_stdout_stderr_exit_and_each_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            for code in (0, 7):
                program = 'import sys; print(' + repr(json.dumps(final_result())) + '); print("diagnostic",file=sys.stderr); sys.exit(' + str(code) + ')'
                result = subprocess.run([sys.executable, str(MODULE), 'capture', directory,
                    sys.executable, '-c', program], capture_output=True, text=True)
                self.assertEqual(result.returncode, code)
                self.assertEqual(json.loads(result.stdout), final_result())
                self.assertEqual(result.stderr, 'diagnostic\n')
            files = list(Path(directory).glob('*.jsonl'))
            self.assertEqual(len(files), 2)
            for path in files:
                self.assertEqual(json.loads(path.read_text()), final_result())

    def test_native_collector_coverage_and_daily_scanner_use_real_receipts(self):
        self.assertTrue((COMPILER / 'actions/setup/js/daily_aic_scan.cjs').is_file(),
                        'Build pinned compiler and set REPO_ASSIST_COMPILER_SOURCE')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ghaw = root / 'gh-aw'
            for component in ('agent', 'detection'):
                base = ghaw if component == 'agent' else ghaw / 'threat-detection'
                self.usage.record_usage([json.dumps(final_result())],
                    base / 'sandbox/firewall/logs/api-proxy-logs/token-usage.jsonl')
            # Execute native accounting collection, relocating its fixed /tmp path.
            # The unrelated activity-summary renderer has independent fixed paths.
            script = (COMPILER / 'actions/setup/sh/collect_usage_artifact_files.sh').read_text()
            script = script.replace('/tmp/gh-aw', str(ghaw))
            script = script.replace('node "${RUNNER_TEMP}/gh-aw/actions/generate_usage_activity_summary.cjs"', ':')
            collected = subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                env={**os.environ, 'RUNNER_TEMP': str(root / 'runner')})
            self.assertEqual(collected.returncode, 0, collected.stderr)
            unknown = root / 'unknown.jsonl'
            self.usage.begin_usage(unknown)
            result = subprocess.run(['node', str(ROOT / '.github/tests/repo_assist_usage_native.cjs'),
                str(COMPILER.resolve()), str(ghaw / 'usage'), str(unknown)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads(result.stdout)
            self.assertAlmostEqual(observed['measuredAIC'], 1.395)
            self.assertEqual(observed['unknownAIC'], 1000)
            self.assertEqual(observed['fiveUnknownRunsAIC'], 5000)
            self.assertTrue(observed['unknownSummaryOmitted'])


if __name__ == '__main__':
    unittest.main()
