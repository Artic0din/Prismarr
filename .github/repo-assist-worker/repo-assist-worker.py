#!/usr/bin/env python3
"""Run subscription Claude in a whole-process container, never on the runner."""
import ipaddress
import json
import os
from pathlib import Path
import resource
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from runtime import (AGENT_IMAGE, CLI_IMAGE, agent_command, agent_mcp_configuration, confinement,
                     detector_environment, model_environment, tool_environment, mount,
                     read_detector_result, require_auth, require_completion)
from controller_inputs import snapshot_inputs
from publication_guard import enforce_publication, native_artifact_roots
from tool_prerequisites import require_jq
from usage import begin_usage, record_captures, record_usage

MAX_LOG_BYTES = 32 * 1024 * 1024
# Use the tunnel's IPv4 loopback listener for local gh readiness requests.
CLI_PROXY_CREATE_ARGS = ('--add-host', 'localhost:127.0.0.1')


def docker(*arguments: str) -> str:
    result = subprocess.run(['docker', *arguments], check=True, capture_output=True,
                            text=True, timeout=120)
    return result.stdout.strip()


def capture_limit() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG_BYTES, MAX_LOG_BYTES))


def evidence(mode: str, state: str) -> None:
    path = Path('/tmp/gh-aw/agent_execution.json' if mode == 'agent'
                else '/tmp/gh-aw/threat-detection/execution.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({'version': 1, 'component': mode,
        'run_id': int(os.environ['GITHUB_RUN_ID']),
        'run_attempt': int(os.environ['GITHUB_RUN_ATTEMPT']), 'state': state}) + '\n')


def wait_ready(name: str, gateway_ip: str | None = None, tools: bool = False) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        state = json.loads(docker('inspect', name))[0]['State']
        if not state['Running']:
            raise RuntimeError('Trusted proxy stopped before model execution')
        if state.get('Health', {}).get('Status') in (None, 'healthy'):
            if tools:
                command = ['python3', '-c',
                    'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8081/health",timeout=1).close()']
            elif gateway_ip is None:
                # The CLI image has no HEALTHCHECK; Compose normally supplies it.
                command = ['node', '-e',
                    "const r=require('http').get('http://127.0.0.1:11000/health',"
                    "s=>{s.resume();process.exit(s.statusCode===200?0:1)});"
                    "r.setTimeout(1000,()=>{r.destroy();process.exit(1)});"
                    "r.on('error',()=>process.exit(1));"]
            else:
                command = ['python3', '-c',
                    'import socket,sys; socket.create_connection((sys.argv[1],8080),timeout=1).close()',
                    gateway_ip]
            try:
                probe = subprocess.run(['docker', 'exec', name, *command], capture_output=True, timeout=5)
            except subprocess.TimeoutExpired:
                probe = None
            if probe is not None and probe.returncode == 0:
                return
        time.sleep(1)
    raise RuntimeError('Trusted proxy did not become healthy')


def scrub_artifacts(secret: str, roots: list[Path]) -> None:
    needle, rejected = secret.encode(), False
    for root in roots:
        paths = root.rglob('*') if root.is_dir() and not root.is_symlink() else [root]
        for path in paths:
            if path.is_symlink():
                path.unlink()
                rejected = True
                continue
            if not path.is_file():
                continue
            if secret in str(path) or path.stat().st_size > 64 * 1024 * 1024:
                path.unlink()
                rejected = True
                continue
            data = path.read_bytes()
            if needle in data:
                rejected = True
                if path.suffix == '.bundle':
                    path.unlink()
                else:
                    path.write_bytes(data.replace(needle, b'[REDACTED]'))
    if rejected:
        raise ValueError('Unsafe model artifacts removed; publishing blocked')


def cleanup(arguments: list[str]) -> None:
    try:
        subprocess.run(['docker', *arguments], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        # Scrubbing must still run if Docker itself stops responding.
        pass


def trusted_git_config(workspace: Path) -> bytes:
    git_dir = workspace / '.git'
    config = git_dir / 'config'
    if git_dir.is_symlink() or not git_dir.is_dir() or config.is_symlink() or not config.is_file():
        raise ValueError('Expected a regular trusted checkout')
    if config.stat().st_size > 65536:
        raise ValueError('Git configuration exceeds the trusted snapshot limit')
    return config.read_bytes()


def restore_git_config(workspace: Path, config: bytes) -> None:
    git_dir = workspace / '.git'
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise ValueError('Worker changed the Git directory boundary')
    # Replace the leaf atomically, never follow a model-created config symlink.
    temporary = git_dir / ('.trusted-config-' + secrets.token_hex(8))
    try:
        temporary.write_bytes(config + b'\n[core]\n\thooksPath = /dev/null\n')
        temporary.replace(git_dir / 'config')
    finally:
        temporary.unlink(missing_ok=True)


def finalize_outputs(mode: str, workspace: Path, git_config: bytes | None, runner: Path) -> None:
    secret = os.environ['CLAUDE_CODE_OAUTH_TOKEN']
    artifacts = Path('/tmp/gh-aw')
    if mode == 'agent':
        try:
            # Check original metadata and decoded objects before restoring config.
            roots = native_artifact_roots(artifacts, runner / 'gh-aw/safeoutputs')
            enforce_publication(secret, workspace, roots, runner)
        finally:
            if git_config is not None:
                restore_git_config(workspace, git_config)
    else:
        roots = [p for p in artifacts.glob('*') if p.is_file() or p.is_symlink()]
        roots += [artifacts / name for name in ('mcp-logs', 'proxy-logs', 'threat-detection', 'sandbox/firewall')]
        roots.append(runner / 'gh-aw/safeoutputs')
        scrub_artifacts(secret, roots)


def run(mode: str) -> None:
    require_auth(dict(os.environ))
    trusted = Path(__file__).resolve().parent
    runner = Path(os.environ['RUNNER_TEMP']).resolve()
    cli = runner / 'repo-assist-cli'
    if not (cli / 'node_modules/.bin/claude').is_file():
        raise ValueError('Locked Claude installation is missing')
    validation = require_jq(Path(os.environ['RUNNER_TOOL_CACHE']).resolve())
    network = 'repo-assist-' + secrets.token_hex(8)
    worker, gateway, cli_proxy, tool_worker = (f'{network}-{part}' for part in ('controller', 'egress', 'cli', 'tools'))
    created: list[str] = []
    attached: list[str] = []
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve()
    git_config = trusted_git_config(workspace) if mode == 'agent' else None
    evidence(mode, 'not_started')

    def interrupted(_signum: int, _frame: object) -> None:
        raise InterruptedError('Worker interrupted')

    signal.signal(signal.SIGTERM, interrupted)
    with tempfile.TemporaryDirectory(prefix='repo-assist-worker-', dir=runner) as scratch:
        output = Path(scratch) / 'output'
        output.mkdir()
        controller = Path(scratch) / 'controller'
        controller.mkdir()
        inputs = Path(scratch) / 'inputs'
        if mode == 'agent':
            # The reviewed overlay keeps safeoutputs in the native converter's
            # persistent HTTP config; the gateway's raw output is temporary.
            config = agent_mcp_configuration(runner / 'gh-aw/mcp-config/mcp-servers.json')
        else:
            snapshot_inputs(Path('/tmp/gh-aw/threat-detection'), inputs)
            config = {'mcpServers': {'repository': {'type': 'http', 'url': 'http://repo-assist-tools:8081/mcp'}}}
        (controller / 'mcp.json').write_text(json.dumps(config))
        try:
            # Docker permits an explicit endpoint address only with explicit IPAM.
            docker('network', 'create', '--internal', '--subnet', '172.29.240.0/24', '--opt',
                   'com.docker.network.bridge.gateway_mode_ipv4=isolated', network)
            subnet = json.loads(docker('network', 'inspect', network))[0]['IPAM']['Config'][0]['Subnet']
            gateway_ip = str(ipaddress.ip_network(subnet).network_address + 2)
            args = confinement(gateway, network)
            args += ['--network-alias', 'repo-assist-egress', '--ip', gateway_ip,
                     '--sysctl', 'net.ipv4.ip_forward=0', '--entrypoint', 'python3']
            args += mount(trusted / 'repo-assist-egress.py', '/trusted/egress.py')
            args += [AGENT_IMAGE, '/trusted/egress.py', '--listen', gateway_ip]
            subprocess.run(args, check=True, capture_output=True, timeout=120)
            created.append(gateway)
            docker('network', 'connect', 'bridge', gateway)
            docker('start', gateway)
            wait_ready(gateway, gateway_ip)
            if mode == 'agent':
                for sidecar in ('awmg-mcpg', 'awmg-cli-proxy'):
                    docker('network', 'connect', network, sidecar)
                    attached.append(sidecar)
                args = confinement(cli_proxy, network)
                args += list(CLI_PROXY_CREATE_ARGS)
                args += ['--network-alias', 'repo-assist-cli',
                         '--tmpfs', '/var/log/cli-proxy:rw,nosuid,nodev,size=32m,mode=1777',
                         '--tmpfs', '/tmp/proxy-tls:rw,nosuid,nodev,size=1m,mode=1777',
                         '--env', 'AWF_DIFC_PROXY_HOST=awmg-cli-proxy',
                         '--env', 'AWF_DIFC_PROXY_PORT=18443', '--env', 'GH_TOKEN',
                         '--env', 'GITHUB_REPOSITORY=' + os.environ['GITHUB_REPOSITORY']]
                args += mount(Path('/tmp/gh-aw/difc-proxy-tls/ca.crt'), '/tmp/proxy-tls/ca.crt')
                args += [CLI_IMAGE]
                proxy_env = {**os.environ, 'GH_TOKEN': os.environ['REPO_ASSIST_READ_TOKEN']}
                subprocess.run(args, check=True, capture_output=True, timeout=120, env=proxy_env)
                created.append(cli_proxy)
                docker('start', cli_proxy)
                wait_ready(cli_proxy)

            args = confinement(tool_worker, network) + ['--network-alias', 'repo-assist-tools',
                                                      '--entrypoint', '/bin/bash']
            args += tool_environment() + mount(trusted, '/trusted') + mount(validation, '/opt/validation')
            if mode == 'agent':
                args += mount(workspace, str(workspace), writable=True)
                tool_root = str(workspace)
            else:
                args += mount(workspace, '/repo') + mount(inputs, '/input')
                tool_root = '/repo'
            args += ['--workdir', tool_root, AGENT_IMAGE, '-c',
                     'mkdir -p /tmp/gh-aw/agent /tmp/repository-home "$HOME" && exec "$@"',
                     'repo-assist-tools', 'python3', '/trusted/repository_mcp.py',
                     '--host', '0.0.0.0', '--workspace', tool_root]
            if mode == 'agent':
                args += ['--maintenance']
            subprocess.run(args, check=True, capture_output=True, timeout=120)
            created.append(tool_worker)
            docker('start', tool_worker)
            wait_ready(tool_worker, tools=True)

            args = confinement(worker, network) + ['--interactive', '--entrypoint', '/bin/bash']
            args += model_environment() + mount(cli, '/opt/claude') + mount(trusted, '/trusted')
            args += mount(controller, '/controller')
            if mode == 'agent':
                args += ['--workdir', '/tmp', AGENT_IMAGE, '-c',
                         'mkdir -p "$HOME" /tmp/controller; cd /tmp/controller; exec "$@"',
                         'repo-assist', *agent_command()]
                prompt_path, timeout = Path('/tmp/gh-aw/aw-prompts/prompt.txt'), 3300
            else:
                detector = shutil.which('threat-detect')
                if not detector:
                    raise ValueError('Pinned native threat detector is missing')
                args += detector_environment(dict(os.environ))
                args += mount(inputs, '/input')
                args += mount(output, '/output', writable=True)
                args += mount(Path(detector).resolve(), '/opt/threat-detect')
                args += ['--env', 'GITHUB_WORKSPACE=/tmp/controller', '--workdir', '/tmp', AGENT_IMAGE, '-c',
                         'mkdir -p "$HOME" /tmp/controller; cd /tmp/controller; exec /opt/threat-detect --engine claude '
                         '--model claude-sonnet-4-6 --max-turns 20 --engine-timeout 7m '
                         '--output /output/detection_result.json /input']
                prompt_path, timeout = Path('/dev/null'), 480
            subprocess.run(args, check=True, capture_output=True, timeout=120)
            created.append(worker)
            usage_path = Path('/tmp/gh-aw/sandbox/firewall/logs/api-proxy-logs/token-usage.jsonl')
            detector_usage = Path('/tmp/gh-aw/threat-detection/sandbox/firewall/logs/api-proxy-logs/token-usage.jsonl')
            begin_usage(usage_path)
            if mode == 'detection':
                begin_usage(detector_usage)
            evidence(mode, 'started')
            if mode == 'agent':
                Path('/tmp/gh-aw/agent_cli_start_ms.txt').write_text(str(int(time.time() * 1000)))
            capture = Path(scratch) / 'capture.log'
            try:
                with prompt_path.open('rb') as prompt, capture.open('wb') as log:
                    result = subprocess.run(['docker', 'start', '--attach', '--interactive', worker],
                        stdin=prompt, stdout=log, stderr=subprocess.STDOUT, timeout=timeout,
                        preexec_fn=capture_limit)
            finally:
                text = capture.read_text(errors='replace') if capture.exists() else ''
                destination = Path('/tmp/gh-aw/agent-stdio.log' if mode == 'agent'
                                   else '/tmp/gh-aw/threat-detection/detection.log')
                destination.write_text(text.replace(os.environ['CLAUDE_CODE_OAUTH_TOKEN'], '[REDACTED]'))
                if mode == 'agent':
                    record_usage([text], usage_path)
                else:
                    record_captures(output / 'claude-usage', usage_path)
                    shutil.copyfile(usage_path, detector_usage)
            if mode == 'agent':
                Path('/tmp/gh-aw/agent_execution_exit_code.txt').write_text(str(result.returncode))
                if result.returncode != 0:
                    raise RuntimeError('Claude worker failed')
                require_completion(text)
            else:
                verdict = read_detector_result(output / 'detection_result.json')
                Path('/tmp/gh-aw/threat-detection/detection_result.json').write_text(json.dumps(verdict))
                for name in ('detection_usage.json', 'detection_usage.jsonl'):
                    path = output / name
                    if path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_LOG_BYTES:
                        shutil.copyfile(path, Path('/tmp/gh-aw/threat-detection') / name)
                if result.returncode != 0:
                    raise RuntimeError('Independent detector failed')
        finally:
            for name in reversed(created):
                cleanup(['rm', '--force', name])
            for name in reversed(attached):
                cleanup(['network', 'disconnect', '--force', network, name])
            cleanup(['network', 'rm', network])
            finalize_outputs(mode, workspace, git_config, runner)


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ('agent', 'detection'):
            raise ValueError('Expected agent or detection mode')
        run(sys.argv[1])
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        # External diagnostics can contain a credential; never echo them here.
        print('Subscription worker failed; publishing blocked', file=sys.stderr)
        raise SystemExit(1)
