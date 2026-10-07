"""Verify real official Claude tool dispatch, with no credentials or egress."""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / '.github/repo-assist-worker'))
from runtime import AGENT_IMAGE, agent_command, confinement, mount


class PinnedControllerTests(unittest.TestCase):
    def test_official_cli_exposes_only_fixed_http_mcp_in_isolated_network(self) -> None:
        self.exercise_controller(agent_command(), detector=False)

    def test_official_detector_cli_exposes_repository_and_result_mcp_only(self) -> None:
        from detector_controller import controller_command
        self.exercise_controller(controller_command(), detector=True)

    def exercise_controller(self, command: list[str], detector: bool) -> None:
        cli_root = ROOT / '.github/repo-assist-cli'
        cli = cli_root / 'node_modules/.bin/claude'
        required = os.environ.get('REPO_ASSIST_REQUIRE_CLI') == '1'
        if not cli.is_file():
            if required:
                self.fail('Run npm ci --prefix .github/repo-assist-cli before the mandatory controller fixture')
            self.skipTest('Pinned Repo Assist CLI is not installed')
        lock = json.loads((cli_root / 'package-lock.json').read_text())
        version = lock['packages']['node_modules/@anthropic-ai/claude-code']['version']
        installed = json.loads((cli_root / 'node_modules/@anthropic-ai/claude-code/package.json').read_text())
        self.assertEqual(installed['version'], version)
        fixture = ROOT / '.github/tests/repo_assist_controller_cli_fixture.py'
        docker = shutil.which('docker')
        docker_available = docker and subprocess.run([docker, 'info'], capture_output=True, timeout=30).returncode == 0
        unshare = shutil.which('unshare')
        namespace_available = unshare and subprocess.run(
            [unshare, '--user', '--map-root-user', '--net', '/bin/true'],
            env={'PATH': os.defpath}, capture_output=True, timeout=15).returncode == 0
        if not docker_available and not namespace_available:
            if required:
                self.fail('Docker or a Linux user/network namespace is required for the controller fixture')
            self.skipTest('Network isolation unavailable in editing workspace')
        with tempfile.TemporaryDirectory(prefix='controller-cli-input-') as directory:
            inputs = Path(directory)
            command_file = inputs / 'command.json'
            command_file.write_text(json.dumps({'command': command, 'version': version, 'detector': detector}))
            if docker_available:
                result = self.run_docker(cli_root, fixture, inputs)
            else:
                result = subprocess.run([unshare, '--user', '--map-root-user', '--net', sys.executable,
                    str(fixture), str(command_file), '--cli', str(cli), '--bring-up-loopback',
                    '--repository-server', str(ROOT / '.github/repo-assist-worker/repository_mcp.py'),
                    '--detector-sink', str(ROOT / '.github/repo-assist-worker/detector_sink.py')],
                    env={'PATH': os.defpath}, capture_output=True, text=True, timeout=150)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        proof = json.loads(result.stdout)
        self.assertEqual(proof['version'], version)
        expected_tools = ['mcp__repository__execute', 'mcp__detector_result__report_result' if detector else 'mcp__safeoutputs__noop']
        expected_calls = [['/mcp/repository', 'execute'],
                          ['/mcp/detector_result', 'report_result'] if detector else ['/mcp/safeoutputs', 'noop']]
        self.assertEqual(proof['tools'], sorted(expected_tools))
        self.assertEqual(proof['mcp_calls'], sorted(expected_calls))
        rejected = ['Bash', 'Read', 'Write', 'Agent', 'WebFetch'] + (['mcp__repository__report_result'] if detector else [])
        self.assertEqual(proof['forbidden_calls_rejected'], rejected)
        self.assertTrue(proof['untrusted_customizations_ignored'])
        self.assertEqual(proof['network'], 'loopback-only')
        self.assertEqual(proof['live_provider_calls'], 0)
        self.assertEqual(proof['auth'], 'synthetic-oauth')
        self.assertEqual(proof['repository_transport'], 'production-server')
        self.assertTrue(proof['repository_report_unavailable'])
        self.assertEqual(proof['detector_report_transport'], 'private-controller-server' if detector else None)

    def run_docker(self, cli_root: Path, fixture: Path, inputs: Path) -> subprocess.CompletedProcess[str]:
        subprocess.run(['docker', 'pull', AGENT_IMAGE], check=True, capture_output=True, timeout=180)
        name = 'repo-assist-controller-fixture-' + secrets.token_hex(8)
        args = confinement(name, 'none')
        args += mount(cli_root / 'node_modules', '/opt/claude/node_modules')
        args += mount(fixture, '/fixture.py') + mount(inputs, '/input')
        args += mount(ROOT / '.github/repo-assist-worker/repository_mcp.py', '/repository_mcp.py')
        args += mount(ROOT / '.github/repo-assist-worker/detector_sink.py', '/detector_sink.py')
        args += ['--workdir', '/tmp', '--entrypoint', 'python3', AGENT_IMAGE,
                 '/fixture.py', '/input/command.json', '--repository-server', '/repository_mcp.py',
                 '--detector-sink', '/detector_sink.py']
        try:
            subprocess.run(args, check=True, capture_output=True, text=True, timeout=30)
            return subprocess.run(['docker', 'start', '--attach', name],
                                  capture_output=True, text=True, timeout=150)
        finally:
            subprocess.run(['docker', 'rm', '--force', name], capture_output=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
