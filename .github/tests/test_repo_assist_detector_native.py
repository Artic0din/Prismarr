"""Run the pinned native detector with local synthetic model/tool responses.

Set REPO_ASSIST_THREAT_DETECT_BINARY to the verified v0.5.2 Linux amd64 release.
No provider request or real credential is used. Claude's real argument contract
is separately exercised by test_repo_assist_controller_cli.py.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

WORKER = Path(__file__).resolve().parents[1] / 'repo-assist-worker'
PINNED_SHA256 = 'b4ecda6a8f1ee09913c40b58e5e9d3337d2173618d41b1bfdef9207e4e7959b9'
GOOD = {'prompt_injection': False, 'secret_leak': False,
        'malicious_patch': False, 'reasons': []}


class NativeDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = os.environ.get('REPO_ASSIST_THREAT_DETECT_BINARY')
        if not binary:
            raise unittest.SkipTest('Set REPO_ASSIST_THREAT_DETECT_BINARY for pinned native integration')
        cls.binary = Path(binary).resolve()
        if hashlib.sha256(cls.binary.read_bytes()).hexdigest() != PINNED_SHA256:
            raise AssertionError('Native integration binary differs from pinned v0.5.2 release')

    def run_native(self, verdict, *, omit_required_input=False, correct_rejected=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts, home, binaries = [root / name for name in ('input', 'home', 'bin')]
            for path in (artifacts / 'aw-prompts', home, binaries):
                path.mkdir(parents=True)
            prompt = 'Assess the synthetic maintenance output without making changes.'
            (artifacts / 'aw-prompts/prompt.txt').write_text(prompt)
            (artifacts / 'aw-prompts/prompt-template.txt').write_text(prompt)
            if not omit_required_input:
                (artifacts / 'agent_output.json').write_text('{"items":[]}')
            model = root / 'model.py'
            model.write_text(f'''import http.client, json, os, sys, time
from pathlib import Path
from urllib.parse import urlsplit
assert os.environ['CLAUDE_CODE_OAUTH_TOKEN'] == 'synthetic-controller-only'
assert not any(name.startswith('THREAT_DETECTION_') for name in os.environ)
prompt = sys.stdin.read()
assert 'Integration workflow' in prompt
assert 'Native context must survive.' in prompt
assert 'aw-prompts/prompt.txt' in prompt
print(json.dumps({{'type':'system','subtype':'init'}}), flush=True)
config = json.loads(Path(sys.argv[1]).read_text())
endpoint = urlsplit(config['mcpServers']['detector_result']['url'])
assert endpoint.hostname == '127.0.0.1'
verdicts = [{verdict!r}] + ([{GOOD!r}] if {correct_rejected!r} else [])
for index, verdict in enumerate(verdicts):
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=3)
    payload = {{'jsonrpc':'2.0','id':index+1,'method':'tools/call','params':{{'name':'report_result','arguments':verdict}}}}
    connection.request('POST', '/mcp', json.dumps(payload), {{'Content-Type':'application/json','Accept':'application/json, text/event-stream'}})
    response = connection.getresponse()
    assert response.status == 200, response.status
    result = json.loads(response.read())
    assert 'result' in result, result
    if index < len(verdicts) - 1:
        assert result['result']['isError'], result
        print(json.dumps({{'type':'correction','message':'native rejection reached the model'}}), flush=True)
    else:
        assert not result['result']['isError'], result
    connection.close()
time.sleep(2)
print(json.dumps({{'type':'result','subtype':'success','is_error':False,'result':'done'}}), flush=True)
''')
            wrapper = binaries / 'claude'
            wrapper.write_text(f'''#!{sys.executable}
import json, os, sys
from pathlib import Path
sys.path.insert(0, {str(WORKER)!r})
import detector_controller as adapter
adapter.validate_native_arguments(sys.argv[1:])
adapter.NATIVE_BINARY = {str(self.binary)!r}
adapter.controller_command = lambda config: [sys.executable, {str(model)!r}, str(config)]
context = adapter.native_context(dict(os.environ))
Path({str(root / 'context.json')!r}).write_text(json.dumps(context.eligibility))
try:
    raise SystemExit(adapter.capture_controller(context, Path({str(root / 'captures')!r})))
except (OSError, ValueError):
    raise SystemExit(1)
''')
            wrapper.chmod(0o755)
            output = root / 'result.json'
            result = subprocess.run([str(self.binary), '--engine', 'claude', '--model',
                                     'claude-sonnet-4-6', '--max-turns', '20',
                                     '--engine-timeout', '10s', '--output', str(output), str(artifacts)],
                                    cwd=home, capture_output=True, text=True, timeout=15,
                                    env={'PATH': f'{binaries}:/usr/local/bin:/usr/bin:/bin',
                                         'HOME': str(home), 'GITHUB_WORKSPACE': str(home),
                                         'CLAUDE_CODE_OAUTH_TOKEN': 'synthetic-controller-only',
                                         'GH_AW_DETECTION_CONTINUE_ON_ERROR': 'false',
                                         'HAS_PATCH': 'false', 'WORKFLOW_NAME': 'Integration workflow',
                                         'WORKFLOW_DESCRIPTION': 'Native context must survive.'})
            published = json.loads(output.read_text()) if output.exists() else None
            context_file = root / 'context.json'
            eligibility = json.loads(context_file.read_text()) if context_file.exists() else None
            captures = [path.read_text() for path in (root / 'captures').glob('*.jsonl')]
            return result, published, eligibility, captures

    def test_real_native_invocation_and_private_sink_accept_clean_report(self):
        result, published, eligibility, captures = self.run_native(GOOD)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({key: published[key] for key in GOOD}, GOOD)
        self.assertEqual(eligibility['THREAT_DETECTION_ELIGIBLE_MALICIOUS_PATCH'], 'false')
        self.assertEqual(len(captures), 1)
        self.assertIn('"subtype": "init"', captures[0])
        self.assertNotIn('"type": "result"', captures[0], 'native sink should terminate the model early')
        self.assertNotIn('synthetic-controller-only', result.stdout + result.stderr)

    def test_real_native_eligibility_rejects_patch_verdict_without_patch(self):
        result, published, eligibility, _ = self.run_native({**GOOD, 'malicious_patch': True,
                                                            'reasons': ['Synthetic patch threat']})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIsNone(published)
        self.assertEqual(eligibility['THREAT_DETECTION_ELIGIBLE_MALICIOUS_PATCH'], 'false')

    def test_real_native_threat_exit_and_public_reason_redaction_survive_bridge(self):
        result, published, eligibility, _ = self.run_native({**GOOD, 'secret_leak': True,
                                                            'reasons': ['Synthetic private evidence']})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(published['secret_leak'], True)
        self.assertEqual(published['reasons'], [])
        self.assertEqual(eligibility['THREAT_DETECTION_ELIGIBLE_SECRET_LEAK'], 'true')

    def test_rejected_native_verdict_can_be_corrected_in_session(self):
        result, published, _, captures = self.run_native({**GOOD, 'malicious_patch': True,
                                                         'reasons': ['Synthetic patch threat']},
                                                        correct_rejected=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({key: published[key] for key in GOOD}, GOOD)
        self.assertIn('native rejection reached the model', captures[0])

    def test_real_native_strict_input_policy_prevents_model_launch(self):
        result, published, eligibility, captures = self.run_native(GOOD, omit_required_input=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIsNone(published)
        self.assertIsNone(eligibility)
        self.assertEqual(captures, [])
        self.assertIn('reason=config_error', result.stderr)


if __name__ == '__main__':
    unittest.main()
