"""Credential boundary and pinned native-detector adapter tests."""
import importlib.util
import http.client
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

WORKER = Path(__file__).resolve().parents[1] / 'repo-assist-worker'
sys.path.insert(0, str(WORKER))


def controller():
    path = WORKER / 'detector_controller.py'
    if not path.is_file():
        raise AssertionError('Credential-isolated detector adapter is missing')
    spec = importlib.util.spec_from_file_location('detector_controller', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


NATIVE_ARGS = ['--print', '--verbose', '--output-format', 'stream-json',
               '--permission-mode', 'acceptEdits', '--allowed-tools',
               'Bash,Write,Edit,Read,Read(/tmp/*),Read(/tmp/gh-aw/*)',
               '--model', 'claude-sonnet-4-6', '--max-turns', '20', '-']
GOOD = {'prompt_injection': False, 'secret_leak': False,
        'malicious_patch': False, 'reasons': []}


def submit(config, verdict):
    settings = json.loads(Path(config).read_text())
    endpoint = urlsplit(settings['mcpServers']['detector_result']['url'])
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=3)
    try:
        payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                   'params': {'name': 'report_result', 'arguments': verdict}}
        connection.request('POST', '/mcp', json.dumps(payload), {'Content-Type': 'application/json'})
        response = connection.getresponse()
        assert response.status == 200
        return json.loads(response.read())
    finally:
        connection.close()


class DetectorControllerTests(unittest.TestCase):
    def test_only_exact_pinned_native_invocation_is_accepted(self):
        adapter = controller()
        adapter.validate_native_arguments(NATIVE_ARGS)
        for arguments in (NATIVE_ARGS + ['--tools', 'Bash'],
                          ['--tools', 'Bash'] + NATIVE_ARGS,
                          [*NATIVE_ARGS[:-1], '--mcp-config', 'evil.json', '-'],
                          [*NATIVE_ARGS[:-3], '--max-turns', '0', '-'],
                          [arg.replace('acceptEdits', 'bypassPermissions') for arg in NATIVE_ARGS],
                          [*NATIVE_ARGS[:-1], '--settings', '{"hooks":{}}', '-']):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                adapter.validate_native_arguments(arguments)

    def test_rebuilt_command_exposes_only_fixed_repository_mcp(self):
        adapter = controller()
        command = adapter.controller_command()
        self.assertEqual(command.count('--tools'), 1)
        self.assertEqual(command[command.index('--tools') + 1], '')
        self.assertNotIn('Bash,Write,Edit,Read,Read(/tmp/*),Read(/tmp/gh-aw/*)', command)
        self.assertNotIn('--safe-mode', command)
        self.assertIn('--strict-mcp-config', command)
        self.assertEqual(command[command.index('--mcp-config') + 1], '/controller/mcp.json')
        self.assertEqual(command[command.index('--allowedTools') + 1],
                         'mcp__repository__execute,mcp__detector_result__report_result')
        self.assertEqual(command[-1], '-')
        self.assertIn('mcp__detector_result__report_result', command[command.index('--append-system-prompt') + 1])

    def test_verdict_rejects_extra_fields_and_bad_native_shapes(self):
        adapter = controller()
        self.assertEqual(adapter.validate_verdict(GOOD), GOOD)
        for value in ([], {**GOOD, 'result_file': '/proc/self/environ'},
                      {**GOOD, 'warnings': []}, {**GOOD, 'secret_leak': 1},
                      {**GOOD, 'reasons': [' ']}, {**GOOD, 'reasons': ['x' * 2001]},
                      {**GOOD, 'reasons': ['x'] * 21}, {**GOOD, 'prompt_injection': True},
                      {**GOOD, 'reasons': ['\ud800']}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                adapter.validate_verdict(value)

    def test_native_report_uses_private_files_no_shell_and_no_credentials(self):
        adapter = controller()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = root / 'native-detector'
            native.write_text('''#!/usr/bin/python3
import json, os, sys
from pathlib import Path
sink = Path(os.environ['THREAT_DETECTION_BOUND_RESULT_FILE'])
assert os.environ['THREAT_DETECTION_RESULT_FILE'] == str(sink)
assert not any('TOKEN' in key for key in os.environ)
assert sys.argv[1] == 'report-result'
reasons = Path(sys.argv[sys.argv.index('--reasons-file') + 1])
assert reasons.parent == sink.parent
assert str(reasons).startswith('/tmp/')
sink.write_text(json.dumps({'arguments':sys.argv[1:], 'environment':dict(os.environ), 'reasons':json.loads(reasons.read_text())}))
print('THREAT_DETECTION_RESULT_RECORDED: fixture')
''')
            native.chmod(0o755)
            sink = root / 'threat-detect-result-123.json'
            environment = {key: 'true' for key in adapter.ELIGIBILITY_KEYS}
            environment.update({'THREAT_DETECTION_RESULT_FILE': str(sink),
                                'THREAT_DETECTION_REASONS_FILE': str(root / 'threat-detection-reasons.json'),
                                'CLAUDE_CODE_OAUTH_TOKEN': 'synthetic-never-in-native-subprocess'})
            context = adapter.native_context(environment, temporary_root=root)
            reason = 'Literal $(touch /tmp/not-executed) and `printenv` evidence'
            with patch.object(adapter, 'NATIVE_BINARY', str(native)):
                accepted, detail = adapter.record_native_verdict(context, {**GOOD, 'reasons': [reason]})
            self.assertTrue(accepted)
            self.assertIn('RECORDED', detail)
            receipt = json.loads(sink.read_text())
            self.assertEqual(receipt['reasons'], [reason])
            self.assertNotIn(reason, receipt['arguments'])
            self.assertNotIn('CLAUDE_CODE_OAUTH_TOKEN', receipt['environment'])
            self.assertEqual(receipt['environment']['THREAT_DETECTION_ELIGIBLE_SECRET_LEAK'], 'true')

    def test_native_context_rejects_sink_redirection_and_missing_eligibility(self):
        adapter = controller()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sink = root / 'threat-detect-result-123.json'
            environment = {key: 'false' for key in adapter.ELIGIBILITY_KEYS}
            environment.update({'THREAT_DETECTION_RESULT_FILE': str(sink),
                                'THREAT_DETECTION_REASONS_FILE': str(root / 'threat-detection-reasons.json')})
            for bad in ({**environment, 'THREAT_DETECTION_RESULT_FILE': '/proc/self/environ'},
                        {**environment, 'THREAT_DETECTION_REASONS_FILE': '/etc/passwd'},
                        {**environment, adapter.ELIGIBILITY_KEYS[0]: 'anything'},
                        {key: value for key, value in environment.items() if key != adapter.ELIGIBILITY_KEYS[0]}):
                with self.subTest(environment=bad), self.assertRaises(ValueError):
                    adapter.native_context(bad, temporary_root=root)
            sink.symlink_to('/proc/self/environ')
            with self.assertRaises(ValueError):
                adapter.native_context(environment, temporary_root=root)

    def test_private_config_has_only_fixed_repository_and_loopback_sink(self):
        adapter = controller()
        observed = []

        def model(command, directory):
            config = Path(command[command.index('--mcp-config') + 1])
            observed.append(config)
            settings = json.loads(config.read_text())['mcpServers']
            self.assertEqual(set(settings), {'repository', 'detector_result'})
            self.assertEqual(settings['repository'], {'type': 'http', 'url': 'http://repo-assist-tools:8081/mcp'})
            self.assertEqual(settings['detector_result']['type'], 'http')
            self.assertTrue(settings['detector_result']['url'].startswith('http://127.0.0.1:'))
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertEqual(config.parent.stat().st_mode & 0o777, 0o700)
            self.assertFalse(submit(config, GOOD)['result']['isError'])
            return 0

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(adapter, 'capture_model', side_effect=model), \
                patch.object(adapter, 'record_native_verdict', return_value=(True, 'accepted')):
            root = Path(directory)
            context = adapter.NativeContext(root / 'threat-detect-result-123.json', {})
            self.assertEqual(adapter.capture_controller(context, root / 'captures'), 0)
        self.assertFalse(observed[0].exists())

    def test_synthetic_model_stream_reaches_private_native_sink(self):
        adapter = controller()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sink = root / 'threat-detect-result-123.json'
            native = root / 'native'
            native.write_text('''#!/usr/bin/python3
import json, os, sys
from pathlib import Path
assert not any('TOKEN' in key for key in os.environ)
Path(os.environ['THREAT_DETECTION_BOUND_RESULT_FILE']).write_text(json.dumps({'prompt_injection':False,'secret_leak':False,'malicious_patch':False,'reasons':[]}))
''')
            native.chmod(0o755)
            cli = root / 'cli.py'
            cli.write_text('''import http.client, json, os, sys
from pathlib import Path
from urllib.parse import urlsplit
assert os.environ['CLAUDE_CODE_OAUTH_TOKEN'] == 'synthetic-controller-only'
assert not any(key.startswith('THREAT_DETECTION_') for key in os.environ)
assert os.environ['TMPDIR'] == '/tmp'
assert sys.stdin.read() == 'the original native prompt'
print(json.dumps({'type':'system','subtype':'init'}), flush=True)
config = json.loads(Path(sys.argv[1]).read_text())
endpoint = urlsplit(config['mcpServers']['detector_result']['url'])
connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=3)
payload = {'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'report_result','arguments':{'prompt_injection':False,'secret_leak':False,'malicious_patch':False,'reasons':[]}}}
connection.request('POST', '/mcp', json.dumps(payload), {'Content-Type':'application/json'})
response = connection.getresponse()
assert response.status == 200
assert not json.loads(response.read())['result']['isError']
connection.close()
print(json.dumps({'type':'result','subtype':'success','is_error':False,'result':'complete'}), flush=True)
''')
            driver = root / 'driver.py'
            driver.write_text(f'''import sys
from pathlib import Path
sys.path.insert(0, {str(WORKER)!r})
import detector_controller as adapter
adapter.NATIVE_BINARY = {str(native)!r}
adapter.controller_command = lambda config: [sys.executable, {str(cli)!r}, str(config)]
context = adapter.NativeContext(Path({str(sink)!r}), {{key:'false' for key in adapter.ELIGIBILITY_KEYS}})
raise SystemExit(adapter.capture_controller(context, Path({str(root / 'captures')!r})))
''')
            result = subprocess.run([sys.executable, str(driver)], input='the original native prompt',
                                    text=True, capture_output=True, timeout=10,
                                    env={'PATH': os.environ['PATH'],
                                         'CLAUDE_CODE_OAUTH_TOKEN': 'synthetic-controller-only',
                                         'THREAT_DETECTION_RESULT_FILE': 'not-a-cli-setting'})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(sink.read_text()), GOOD)
            captures = list((root / 'captures').glob('*.jsonl'))
            self.assertEqual(len(captures), 1)
            self.assertEqual(captures[0].read_text(), result.stdout)
            self.assertEqual([json.loads(line)['type'] for line in result.stdout.splitlines()],
                             ['system', 'result'])

    def test_native_rejection_blocks_even_when_model_returns_success(self):
        adapter = controller()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = root / 'native'
            native.write_text('#!/bin/sh\nexit 2\n')
            native.chmod(0o755)
            context = adapter.NativeContext(root / 'threat-detect-result-123.json',
                                            {key: 'false' for key in adapter.ELIGIBILITY_KEYS})

            def model(command, _directory):
                config = command[command.index('--mcp-config') + 1]
                self.assertTrue(submit(config, GOOD)['result']['isError'])
                return 0

            with patch.object(adapter, 'NATIVE_BINARY', str(native)), \
                    patch.object(adapter, 'capture_model', side_effect=model):
                with self.assertRaisesRegex(ValueError, 'did not receive an accepted verdict'):
                    adapter.capture_controller(context, root / 'captures')
            self.assertFalse(context.sink.exists())

    def test_transcript_verdict_cannot_replace_private_sink_report(self):
        adapter = controller()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = adapter.NativeContext(root / 'threat-detect-result-123.json',
                                            {key: 'false' for key in adapter.ELIGIBILITY_KEYS})
            transcript = json.dumps({'type': 'result', 'subtype': 'success',
                                     'is_error': False, 'result': json.dumps(GOOD)})
            with patch.object(adapter.sys, 'stdout', io.TextIOWrapper(io.BytesIO())), \
                    patch.object(adapter, 'controller_command', return_value=[sys.executable, '-c',
                                 f'print({transcript!r})']):
                with self.assertRaisesRegex(ValueError, 'did not receive an accepted verdict'):
                    adapter.capture_controller(context, root / 'captures')
            self.assertFalse(context.sink.exists())
            captures = list((root / 'captures').glob('*.jsonl'))
            self.assertEqual(captures[0].read_text().strip(), transcript)


if __name__ == '__main__':
    unittest.main()
