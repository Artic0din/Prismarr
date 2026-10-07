"""Subscription worker boundaries; no model or real credential calls."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
WORKER = ROOT / '.github/repo-assist-worker'
sys.path.insert(0, str(WORKER))
from runtime import (AGENT_IMAGE, CLI_IMAGE, agent_command, confinement,
                     detector_environment, model_environment, tool_environment, mount, read_detector_result,
                     require_auth, require_completion)
spec = importlib.util.spec_from_file_location('subscription_worker', WORKER / 'repo-assist-worker.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)
from repo_assist_agent_fixture import exercise_agent_lifecycle, fixture_jq


class WorkerTests(unittest.TestCase):
    def test_mandatory_docker_mode_fails_when_jq_prerequisite_is_missing(self):
        with patch.dict(os.environ, {'REPO_ASSIST_REQUIRE_DOCKER': '1'}, clear=True), \
             self.assertRaisesRegex(AssertionError, 'Stage pinned jq'):
            fixture_jq(self)

    def test_lifecycle_reports_missing_local_jq_without_keyerror(self):
        def fake_docker(command, **_kwargs):
            return subprocess.CompletedProcess(command, 1 if command[:2] == ['docker', 'inspect'] else 0)
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(subprocess, 'run', side_effect=fake_docker), \
             self.assertRaises(unittest.SkipTest):
            exercise_agent_lifecycle(self, worker, WORKER)

    def test_missing_jq_blocks_both_modes_before_any_container_starts(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Path(directory)
            cli = runner / 'repo-assist-cli/node_modules/.bin'
            cli.mkdir(parents=True)
            (cli / 'claude').write_text('fixture never executed')
            for mode in ('agent', 'detection'):
                with self.subTest(mode=mode), patch.dict(os.environ, {
                        'CLAUDE_CODE_OAUTH_TOKEN': 'synthetic', 'RUNNER_TEMP': str(runner),
                        'RUNNER_TOOL_CACHE': str(runner / 'missing')}, clear=True), \
                     patch.object(worker, 'docker') as docker, \
                     patch.object(worker.subprocess, 'run') as execute:
                    with self.assertRaisesRegex(ValueError, 'jq installation'):
                        worker.run(mode)
                    docker.assert_not_called()
                    execute.assert_not_called()

    def test_authentication_rejects_missing_or_competing_credentials(self):
        for env in ({}, {'CLAUDE_CODE_OAUTH_TOKEN': ' '},
                    {'CLAUDE_CODE_OAUTH_TOKEN': 'synthetic', 'ANTHROPIC_API_KEY': 'bad'}):
            with self.assertRaises(ValueError) as error:
                require_auth(env)
            self.assertNotIn('synthetic', str(error.exception))
        require_auth({'CLAUDE_CODE_OAUTH_TOKEN': 'synthetic'})

    def test_worker_environment_is_explicit_allowlist(self):
        values = model_environment()[1::2]
        self.assertIn('CLAUDE_CODE_OAUTH_TOKEN', values)
        for name in ('GH_TOKEN', 'GITHUB_TOKEN', 'RUNNER_TEMP', 'ACTIONS_', 'REPO_ASSIST_READ_TOKEN'):
            self.assertFalse(any(v.startswith(name) for v in values))
        self.assertIn('ENABLE_CLAUDEAI_MCP_SERVERS=false', values)

    def test_detector_keeps_native_strict_input_policy_and_context(self):
        environment = {'HAS_PATCH': 'true', 'WORKFLOW_NAME': 'Repo Assist',
                       'WORKFLOW_DESCRIPTION': 'Daily maintenance',
                       'GH_AW_DETECTION_CONTINUE_ON_ERROR': 'true', 'GITHUB_TOKEN': 'excluded'}
        values = detector_environment(environment)[1::2]
        self.assertIn('GH_AW_DETECTION_CONTINUE_ON_ERROR=false', values)
        for value in ('HAS_PATCH=true', 'WORKFLOW_NAME=Repo Assist', 'WORKFLOW_DESCRIPTION=Daily maintenance'):
            self.assertIn(value, values)
        self.assertFalse(any('excluded' in value for value in values))
        with self.assertRaises(ValueError):
            detector_environment({**environment, 'HAS_PATCH': 'unexpected'})

    def test_confinement_and_mount_contract(self):
        args = confinement('worker', 'isolated')
        for flag in ('--read-only', '--cap-drop', '--security-opt', '--memory', '--pids-limit'):
            self.assertIn(flag, args)
        self.assertIn('no-new-privileges', args)
        self.assertNotIn('--privileged', args)
        self.assertNotIn('host', args)
        for image in (AGENT_IMAGE, CLI_IMAGE):
            self.assertRegex(image, r'@sha256:[0-9a-f]{64}$')
        self.assertIn('readonly', mount(Path('/tmp/input'), '/input')[1])
        for source in ('relative', '/tmp/comma,escape'):
            with self.assertRaises(ValueError):
                mount(Path(source), '/input')

    def test_cli_options_preserve_oauth_and_disable_project_customization(self):
        args = agent_command()
        for absent in ('--bare', '--prompt-file', '--dangerously-skip-permissions'):
            self.assertNotIn(absent, args)
        self.assertIn('--strict-mcp-config', args)
        self.assertEqual(args[args.index('--mcp-config') + 1], '/controller/mcp.json')
        self.assertEqual(args[args.index('--tools') + 1], '')
        self.assertEqual(args.count('--tools'), 1)
        self.assertEqual(args[args.index('--allowedTools') + 1], 'mcp__repository__execute,mcp__safeoutputs')
        self.assertEqual(args[args.index('--setting-sources') + 1], '')
        self.assertEqual(args[args.index('--max-turns') + 1], '60')
        self.assertTrue(json.loads(args[args.index('--settings') + 1])['disableAllHooks'])
        instructions = args[args.index('--append-system-prompt') + 1]
        self.assertIn('Select exactly one eligible maintenance task', instructions)
        self.assertIn('repository_calls_started, not model turns', instructions)
        self.assertIn('Publishable paths are only README.md, CHANGELOG.md and Markdown files under docs/', instructions)

    def test_repository_container_never_inherits_host_credentials(self):
        values = tool_environment()[1::2]
        self.assertTrue(all('=' in value for value in values))
        self.assertFalse(any('TOKEN' in value or 'ANTHROPIC' in value or 'CLAUDE' in value for value in values))
        self.assertNotIn('AWF_CLI_PROXY_URL=http://repo-assist-cli:11000', model_environment())

    def test_last_result_is_authoritative(self):
        good = {'type': 'result', 'subtype': 'success', 'is_error': False, 'result': 'done'}
        self.assertEqual(require_completion(json.dumps(good)), good)
        for bad in ({**good, 'result': ' '}, {**good, 'is_error': True},
                    {**good, 'subtype': 'error_max_turns'}, {'type': 'result'}):
            with self.assertRaises(ValueError):
                require_completion(json.dumps(good) + '\n' + json.dumps(bad))
        for missing in ('', 'invalid json', '{"type":"assistant"}'):
            with self.assertRaises(ValueError):
                require_completion(missing)
        with self.assertRaises(ValueError):
            require_completion(json.dumps(good) + '\n{"type":"result"')

    def test_detector_requires_complete_verdict_and_hides_reasons(self):
        good = {'prompt_injection': False, 'secret_leak': False, 'malicious_patch': False, 'reasons': []}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'result.json'
            for bad in ({}, {**good, 'secret_leak': 'false'}, {**good, 'safe': True},
                        {**good, 'reasons': ['']}, {**good, 'reasons': ['x'] * 21}):
                path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):
                    read_detector_result(path)
            path.write_text(json.dumps({**good, 'secret_leak': True, 'reasons': ['private detail']}))
            self.assertEqual(read_detector_result(path), {**good, 'secret_leak': True})
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                read_detector_result(link)

    def test_detector_preserves_bounded_native_advisory_warnings(self):
        good = {'prompt_injection': False, 'secret_leak': False, 'malicious_patch': False, 'reasons': []}
        warning = {'field': 'template', 'code': 'missing_optional', 'message': 'Optional input missing'}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'result.json'
            path.write_text(json.dumps({**good, 'warnings': [warning]}))
            self.assertEqual(read_detector_result(path)['warnings'], [warning])
            for invalid in ('wrong', [{}], [{**warning, 'extra': 'unknown'}],
                            [{**warning, 'message': 'x' * 2001}], [warning] * 21):
                path.write_text(json.dumps({**good, 'warnings': invalid}))
                with self.assertRaises(ValueError):
                    read_detector_result(path)

    def test_unsafe_artifacts_block_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'log').write_text('synthetic-oauth')
            (root / 'patch.bundle').write_bytes(b'header synthetic-oauth')
            (root / 'link').symlink_to(root / 'log')
            with self.assertRaises(ValueError):
                worker.scrub_artifacts('synthetic-oauth', [root])
            self.assertEqual((root / 'log').read_text(), '[REDACTED]')
            self.assertFalse((root / 'patch.bundle').exists())
            self.assertFalse((root / 'link').exists())

    def test_agent_cleanup_scrubs_writable_workspace_before_artifacts(self):
        secret = 'synthetic-oauth-for-workspace-scrub'
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            runner = base / 'runner'
            artifacts = base / 'gh-aw'
            workspace = base / 'workspace'
            for path in (runner / 'gh-aw/safeoutputs', artifacts / 'mcp-logs', workspace / 'docs'):
                path.mkdir(parents=True)
            (artifacts / 'agent-step-summary.md').write_text('clean')
            (workspace / 'docs' / 'notes.md').write_text(f'echo {secret}')
            (artifacts / 'mcp-logs' / 'session.log').write_text('ok')
            roots = [p for p in artifacts.glob('*') if p.is_file() or p.is_symlink()]
            roots += [artifacts / name for name in ('mcp-logs', 'proxy-logs', 'threat-detection', 'sandbox/firewall')]
            roots.append(runner / 'gh-aw/safeoutputs')
            roots.append(workspace.resolve())
            with self.assertRaises(ValueError):
                worker.scrub_artifacts(secret, roots)
            self.assertNotIn(secret, (workspace / 'docs' / 'notes.md').read_text())
            self.assertIn('[REDACTED]', (workspace / 'docs' / 'notes.md').read_text())
            exported = '\n'.join(path.read_text() for path in workspace.rglob('*') if path.is_file())
            self.assertNotIn(secret, exported)

    def test_root_symlink_does_not_follow_outside_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'outside').mkdir()
            (root / 'outside/keep').write_text('synthetic')
            (root / 'link').symlink_to(root / 'outside', target_is_directory=True)
            with self.assertRaises(ValueError):
                worker.scrub_artifacts('synthetic', [root / 'link'])
            self.assertEqual((root / 'outside/keep').read_text(), 'synthetic')

    def test_cli_readiness_checks_http_without_docker_healthcheck(self):
        state = json.dumps([{'State': {'Running': True}}])
        with patch.object(worker, 'docker', return_value=state), patch.object(worker.time, 'sleep') as sleep, \
             patch.object(worker.subprocess, 'run', side_effect=[subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 0)]) as probe:
            worker.wait_ready('cli')
        self.assertEqual(probe.call_count, 2)
        sleep.assert_called_once_with(1)
        self.assertIn('http://127.0.0.1:11000/health', probe.call_args.args[0][-1])

    def test_cli_proxy_maps_localhost_to_ipv4_loopback(self):
        self.assertEqual(worker.CLI_PROXY_CREATE_ARGS, ('--add-host', 'localhost:127.0.0.1'))

    def test_cli_readiness_fails_closed(self):
        state = json.dumps([{'State': {'Running': True}}])
        with patch.object(worker, 'docker', return_value=state), patch.object(worker.time, 'sleep'), \
             patch.object(worker.time, 'monotonic', side_effect=[0, *range(61)]), \
             patch.object(worker.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaises(RuntimeError):
                worker.wait_ready('cli')

    def test_cli_readiness_retries_slow_probe_within_overall_deadline(self):
        state = json.dumps([{'State': {'Running': True}}])
        with patch.object(worker, 'docker', return_value=state), patch.object(worker.time, 'sleep'), \
             patch.object(worker.subprocess, 'run', side_effect=[
                 subprocess.TimeoutExpired(['docker', 'exec'], 5),
                 subprocess.CompletedProcess([], 0)]) as probe:
            worker.wait_ready('cli')
        self.assertEqual(probe.call_count, 2)

    def test_host_git_config_is_restored_without_following_model_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.git').mkdir()
            path = root / '.git/config'
            path.write_text('[core]\n\tbare = false\n')
            original = worker.trusted_git_config(root)
            outside = root / 'outside'
            outside.write_text('unchanged')
            path.unlink()
            path.symlink_to(outside)
            worker.restore_git_config(root, original)
            self.assertFalse(path.is_symlink())
            self.assertEqual(outside.read_text(), 'unchanged')
            self.assertIn('hooksPath = /dev/null', path.read_text())
            self.assertNotIn('trusted-config', ' '.join(p.name for p in (root / '.git').iterdir()))

    def test_original_workspace_is_guarded_before_restoration_even_when_blocked(self):
        calls = []
        def guard(*args):
            calls.append('guard')
            raise ValueError('blocked')
        with patch.dict(os.environ, {'CLAUDE_CODE_OAUTH_TOKEN': 'synthetic'}), \
             patch.object(worker, 'enforce_publication', side_effect=guard), \
             patch.object(worker, 'restore_git_config', side_effect=lambda *args: calls.append('restore')):
            with self.assertRaises(ValueError):
                worker.finalize_outputs('agent', Path('/workspace'), b'trusted', Path('/runner'))
        self.assertEqual(calls, ['guard', 'restore'])


class DockerTests(unittest.TestCase):
    def require_docker(self):
        available = shutil.which('docker') and subprocess.run(['docker', 'info'], capture_output=True).returncode == 0
        if not available:
            if os.environ.get('REPO_ASSIST_REQUIRE_DOCKER') == '1':
                self.fail('Docker isolation tests are mandatory in CI')
            self.skipTest('Docker unavailable in editing workspace')

    def test_complete_agent_lifecycle_without_model(self):
        self.require_docker()
        exercise_agent_lifecycle(self, worker, WORKER)

    def test_real_container_has_restricted_filesystem_and_network(self):
        self.require_docker()
        subprocess.run(['docker', 'pull', AGENT_IMAGE], check=True, capture_output=True)
        network = 'repo-assist-offline-isolation'
        container = network + '-worker'
        subprocess.run(['docker', 'network', 'create', '--internal', '--opt',
                        'com.docker.network.bridge.gateway_mode_ipv4=isolated', network], check=True, capture_output=True)
        try:
            with tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                probe = '''import os,pathlib,socket
assert os.getuid()!=0
assert not pathlib.Path('/var/run/docker.sock').exists()
try:
 pathlib.Path('/etc/escape').write_text('denied')
except OSError: pass
else: raise AssertionError('writable root')
for host in ('169.254.169.254','1.1.1.1'):
 try: socket.create_connection((host,443),timeout=1).close()
 except OSError: pass
 else: raise AssertionError('unrestricted network')
pathlib.Path('/work/proof').write_text('confined')
'''
                args = confinement(container, network) + mount(work, '/work', writable=True)
                args += ['--entrypoint', 'python3', AGENT_IMAGE, '-c', probe]
                subprocess.run(args, check=True, capture_output=True)
                subprocess.run(['docker', 'start', '--attach', container], check=True, capture_output=True, timeout=30)
                self.assertEqual((work / 'proof').read_text(), 'confined')
        finally:
            subprocess.run(['docker', 'rm', '--force', container], capture_output=True)
            subprocess.run(['docker', 'network', 'rm', network], capture_output=True)

    def test_complete_detector_lifecycle_without_model(self):
        self.require_docker()
        jq = fixture_jq(self)
        subprocess.run(['docker', 'pull', AGENT_IMAGE], check=True, capture_output=True)
        with tempfile.TemporaryDirectory() as directory:
            runner = Path(directory)
            validation = runner / 'cache/repo-assist/bin'
            validation.mkdir(parents=True)
            shutil.copy2(jq, validation / 'jq')
            cli = runner / 'repo-assist-cli/node_modules/.bin'
            cli.mkdir(parents=True)
            (cli / 'claude').write_text('fixture never executed')
            source = Path('/tmp/gh-aw/threat-detection')
            if source.exists():
                self.fail('Refusing to overwrite existing detector state')
            source.mkdir(parents=True)
            (source / 'agent_output.json').write_text('{"items":[]}')
            detector = runner / 'threat-detect'
            detector.write_text('''#!/usr/bin/env python3
import json,os,socket,sys,threading
from pathlib import Path
sys.path.insert(0,'/trusted')
from detector_sink import ResultServer
private=ResultServer(lambda verdict: (True,'fixture accepted'))
thread=threading.Thread(target=private.serve_forever,daemon=True)
thread.start()
assert private.server_address[0]=='127.0.0.1'
assert os.environ['CLAUDE_CODE_OAUTH_TOKEN']=='synthetic-only-no-model-call'
for name in ('GH_TOKEN','GITHUB_TOKEN','ACTIONS_RUNTIME_TOKEN','RUNNER_TEMP',
             'ANTHROPIC_API_KEY','ANTHROPIC_AUTH_TOKEN','ANTHROPIC_BASE_URL'):
 assert name not in os.environ
assert os.environ['GH_AW_DETECTION_CONTINUE_ON_ERROR']=='false'
assert os.environ['HAS_PATCH']=='false'
assert Path('/input/agent_output.json').read_text()=='{"items":[]}'
assert not Path('/repo').exists()
assert not Path('/controller/mcp.json').is_symlink()
from urllib.request import Request,urlopen
probe="""import os,json,subprocess
from pathlib import Path
assert 'CLAUDE_CODE_OAUTH_TOKEN' not in os.environ
assert not Path('/controller').exists()
assert not Path('/output').exists()
assert Path('/input/agent_output.json').read_text()=='{\"items\":[]}'
scratch=Path('/tmp/gh-aw/agent/detector.json')
scratch.write_text('{\"number\":1}')
jq=subprocess.run(['jq','-er','.number',str(scratch)],capture_output=True,text=True,timeout=10)
assert jq.returncode==0 and jq.stdout.strip()=='1', (jq.stdout,jq.stderr)
try: Path('/opt/validation/jq').open('ab').close()
except OSError: pass
else: raise AssertionError('detector jq mount is writable')
try: Path('/opt/validation/write-probe').write_text('denied')
except OSError: pass
else: raise AssertionError('detector validation mount is writable')
for path in Path('/proc').glob('[0-9]*/environ'):
 try: data=path.read_bytes()
 except OSError: continue
 assert b'CLAUDE_CODE_OAUTH_TOKEN=' not in data
try: Path('/repo/escape').write_text('denied')
except OSError: pass
else: raise AssertionError('writable detector repository')
print('credential-free detector repository')
"""
probe += "\\nimport socket\\ntry: socket.create_connection(("+repr(socket.gethostbyname(socket.gethostname()))+","+str(private.server_address[1])+"),timeout=1).close()\\nexcept OSError: pass\\nelse: raise AssertionError('repository can reach private controller verdict sink')\\n"
import shlex
request=Request('http://repo-assist-tools:8081/mcp',data=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call',
 'params':{'name':'execute','arguments':{'command':'python3 -c '+shlex.quote(probe)}}}).encode(),
 headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream'})
with urlopen(request,timeout=40) as response: result=json.load(response)['result']
assert not result.get('isError'), result
assert 'credential-free detector repository' in json.dumps(result)
assert 'maintenance_progress' not in json.loads(result['content'][0]['text'])
private.shutdown()
private.server_close()
thread.join(timeout=2)
Path('/output/detection_result.json').write_text(json.dumps({'prompt_injection':False,'secret_leak':False,'malicious_patch':False,'reasons':[]}))
''')
            detector.chmod(0o755)
            env = {**os.environ, 'RUNNER_TEMP': str(runner), 'RUNNER_TOOL_CACHE': str(runner / 'cache'),
                   'GITHUB_WORKSPACE': str(runner),
                   'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1',
                   'CLAUDE_CODE_OAUTH_TOKEN': 'synthetic-only-no-model-call',
                   'PATH': str(runner) + ':' + os.environ['PATH']}
            try:
                # Exercise the public launcher with a synthetic credential, while
                # retaining Docker setup diagnostics that production intentionally hides.
                probe = '''import importlib.util,subprocess,sys
sys.path.insert(0,sys.argv[1])
spec=importlib.util.spec_from_file_location('worker',sys.argv[1]+'/repo-assist-worker.py')
worker=importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)
try: worker.run('detection')
except subprocess.CalledProcessError as error:
 print(error.stderr, file=sys.stderr)
 raise
'''
                result = subprocess.run([sys.executable, '-c', probe, str(WORKER)],
                                        capture_output=True, text=True, env=env, timeout=180)
                log = source / 'detection.log'
                self.assertEqual(result.returncode, 0, result.stderr + (log.read_text() if log.exists() else ''))
                self.assertFalse(read_detector_result(source / 'detection_result.json')['secret_leak'])
                self.assertFalse((source.parent / 'agent/detector.json').exists())
            finally:
                shutil.rmtree(source)
