"""Parse production arguments with the locked official CLI, without model access."""
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


# --help alone does not validate unknown options in Claude Code 2.1.273. An
# intentionally unknown final option stops after parsing the production flags,
# before authentication/model execution. The earlier-unknown control proves this
# check would catch an unsupported production flag. Docker also denies all egress.
SMOKE = r'''import json,os,subprocess
from pathlib import Path
for name in ('CLAUDE_CODE_OAUTH_TOKEN','ANTHROPIC_API_KEY','ANTHROPIC_AUTH_TOKEN',
             'ANTHROPIC_BASE_URL','GH_TOKEN','GITHUB_TOKEN','REPO_ASSIST_READ_TOKEN'):
 assert name not in os.environ, name
Path(os.environ['HOME']).mkdir()
config=json.loads(Path('/input/command.json').read_text())
command=config['command']
def cli(arguments):
 return subprocess.run(arguments,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=30)
version=cli([command[0],'--version'])
assert version.returncode==0, version.stderr
assert version.stdout.strip()==config['version']+' (Claude Code)', version.stdout
help_result=cli([*command,'--help'])
assert help_result.returncode==0, help_result.stderr
assert 'Usage: claude' in help_result.stdout
sentinel='--repo-assist-parser-stop'
for arguments in (command,[*command,'--safe-mode']):
 result=cli([*arguments,sentinel])
 assert result.returncode==1, (result.returncode,result.stdout,result.stderr)
 assert result.stdout=='', result.stdout
 assert result.stderr.strip()=="error: unknown option '"+sentinel+"'", result.stderr
control='--repo-assist-unsupported-control'
result=cli([*command,control,sentinel])
assert result.returncode==1 and result.stderr.strip()=="error: unknown option '"+control+"'", result.stderr
print('Verified locked Claude version, help, production arguments, --restricted/--safe-mode and parser control; no model execution')
'''


class PinnedCliTests(unittest.TestCase):
    def test_official_cli_parses_production_options_without_credentials_or_network(self):
        cli_root = ROOT / '.github/repo-assist-cli'
        required = os.environ.get('REPO_ASSIST_REQUIRE_CLI') == '1'
        if not (cli_root / 'node_modules/.bin/claude').is_file():
            if required:
                self.fail('Run npm ci --prefix .github/repo-assist-cli before the mandatory CLI smoke')
            self.skipTest('Pinned Repo Assist CLI is not installed')
        available = shutil.which('docker') and subprocess.run(['docker', 'info'], capture_output=True).returncode == 0
        if not available:
            if required:
                self.fail('Docker is required for the credential-free CLI smoke')
            self.skipTest('Docker unavailable in editing workspace')
        lock = json.loads((cli_root / 'package-lock.json').read_text())
        version = lock['packages']['node_modules/@anthropic-ai/claude-code']['version']
        installed = json.loads((cli_root / 'node_modules/@anthropic-ai/claude-code/package.json').read_text())
        self.assertEqual(installed['version'], version)
        subprocess.run(['docker', 'pull', AGENT_IMAGE], check=True, capture_output=True)
        name = 'repo-assist-cli-smoke-' + secrets.token_hex(8)
        with tempfile.TemporaryDirectory() as directory:
            inputs = Path(directory)
            (inputs / 'mcp.json').write_text('{"mcpServers":{}}')
            (inputs / 'command.json').write_text(json.dumps({'command': agent_command(), 'version': version}))
            args = confinement(name, 'none')
            # Mount only public installed packages and empty test inputs. No
            # repository, runner HOME, credential/config directory or Docker socket.
            args += mount(cli_root / 'node_modules', '/opt/claude/node_modules') + mount(inputs, '/input')
            args += ['--env', 'HOME=/tmp/claude-home', '--env', 'CLAUDE_CONFIG_DIR=/tmp/claude-home',
                     '--env', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1', '--env', 'DISABLE_AUTOUPDATER=1',
                     '--env', 'DISABLE_TELEMETRY=1', '--env', 'DISABLE_ERROR_REPORTING=1',
                     '--workdir', '/tmp', '--entrypoint', 'python3', AGENT_IMAGE, '-c', SMOKE]
            try:
                subprocess.run(args, check=True, capture_output=True, text=True, timeout=60)
                result = subprocess.run(['docker', 'start', '--attach', name],
                                        capture_output=True, text=True, timeout=180)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('no model execution', result.stdout)
            finally:
                subprocess.run(['docker', 'rm', '--force', name], capture_output=True, timeout=30)
