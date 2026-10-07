#!/usr/bin/env python3
"""Adapt pinned native threat detection to a credential-isolated Claude CLI.

The native detector owns prompt construction, eligibility and its private sink.
The credential-free repository MCP server runs repository commands. A private
loopback MCP sink accepts only structured verdicts for native validation;
repository commands cannot access this listener or its private filesystem.
"""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading

from detector_sink import ResultServer
from usage import MAX_CAPTURE_BYTES

NATIVE_BINARY = '/opt/threat-detect'
MODEL = 'claude-sonnet-4-6'
MAX_TURNS = '20'
ELIGIBILITY_KEYS = ('THREAT_DETECTION_ELIGIBLE_PROMPT_INJECTION',
                    'THREAT_DETECTION_ELIGIBLE_SECRET_LEAK',
                    'THREAT_DETECTION_ELIGIBLE_MALICIOUS_PATCH')
FLAGS = ('prompt_injection', 'secret_leak', 'malicious_patch')
SYSTEM_PROMPT = (
    'The native threat-detection prompt remains authoritative for the analysis. '
    'Local built-in tools are unavailable. Use mcp__repository__execute for all '
    'repository and artifact reads; the repository is /repo and the detector '
    'artifacts are /input in that separate tool environment. The controller '
    'working directory is not the repository. For the final verdict, call '
    'mcp__detector_result__report_result with explicit prompt_injection, '
    'secret_leak, malicious_patch booleans and a reasons array of strings. '
    'This structured tool replaces the prompt\'s shell threat_detection_result '
    'command and reasons-file steps. It transports the verdict into the same '
    'native validated result sink. Never run the reporting shell command or '
    'write a local result or reasons file. Correct any validation error returned '
    'by the reporting tool and retry. Stop after the verdict is accepted.'
)


@dataclass(frozen=True)
class NativeContext:
    sink: Path
    eligibility: dict[str, str]


def validate_native_arguments(arguments: list[str]) -> None:
    # gh-aw-threat-detection v0.5.2 pkg/engine/engine.go: claudeArgs.
    # Repeated --tools values accumulate in Claude; never append an override.
    expected = ['--print', '--verbose', '--output-format', 'stream-json',
                '--permission-mode', 'acceptEdits', '--allowed-tools',
                'Bash,Write,Edit,Read,Read(/tmp/*),Read(/tmp/gh-aw/*)',
                '--model', MODEL, '--max-turns', MAX_TURNS, '-']
    if arguments != expected:
        raise ValueError('Unreviewed native detector CLI invocation')


def controller_command(config: Path = Path('/controller/mcp.json')) -> list[str]:
    settings = json.dumps({'disableAllHooks': True, 'disableClaudeAiConnectors': True})
    return ['/opt/claude/node_modules/.bin/claude', '--print', '--verbose',
            '--no-chrome', '--restricted', '--setting-sources', '', '--settings', settings,
            '--disable-slash-commands', '--strict-mcp-config',
            '--mcp-config', str(config), '--tools', '',
            '--allowedTools', 'mcp__repository__execute,mcp__detector_result__report_result',
            '--permission-mode', 'dontAsk',
            '--model', MODEL, '--max-turns', MAX_TURNS, '--output-format', 'stream-json',
            '--append-system-prompt', SYSTEM_PROMPT, '-']


def native_context(environment: dict[str, str], temporary_root: Path = Path('/tmp')) -> NativeContext:
    sink = Path(environment.get('THREAT_DETECTION_RESULT_FILE', ''))
    reasons = Path(environment.get('THREAT_DETECTION_REASONS_FILE', ''))
    if (sink.parent != temporary_root
            or re.fullmatch(r'threat-detect-result-[0-9]+\.json', sink.name) is None
            or sink.is_symlink() or sink.exists()
            or reasons != temporary_root / 'threat-detection-reasons.json'):
        raise ValueError('Invalid native detector result-sink context')
    eligibility = {key: environment.get(key, '') for key in ELIGIBILITY_KEYS}
    if any(value not in ('true', 'false') for value in eligibility.values()):
        raise ValueError('Native detector eligibility context is missing or malformed')
    return NativeContext(sink, eligibility)


def validate_verdict(value: object) -> dict:
    if (not isinstance(value, dict) or set(value) != {*FLAGS, 'reasons'}
            or any(type(value[key]) is not bool for key in FLAGS)):
        raise ValueError('Detector verdict has an invalid schema')
    reasons = value['reasons']
    if (not isinstance(reasons, list) or len(reasons) > 20
            or any(not isinstance(reason, str) or not reason.strip() or len(reason) > 2000
                   or any(0xD800 <= ord(char) <= 0xDFFF for char in reason) for reason in reasons)
            or (any(value[key] for key in FLAGS) and not reasons)):
        raise ValueError('Detector verdict has invalid reasons')
    return value


def record_native_verdict(context: NativeContext, value: object) -> tuple[bool, str]:
    verdict = validate_verdict(value)
    environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
                   'THREAT_DETECTION_RESULT_FILE': str(context.sink),
                   'THREAT_DETECTION_BOUND_RESULT_FILE': str(context.sink),
                   **context.eligibility}
    fd, name = tempfile.mkstemp(prefix='controller-reasons-', suffix='.json', dir=context.sink.parent)
    reasons_path = Path(name)
    try:
        with os.fdopen(fd, 'w') as reasons:
            json.dump(verdict['reasons'], reasons)
        arguments = [NATIVE_BINARY, 'report-result']
        arguments += [f'--{key.replace("_", "-")}={str(verdict[key]).lower()}' for key in FLAGS]
        arguments += ['--reasons-file', str(reasons_path)]
        result = subprocess.run(arguments, env=environment, capture_output=True,
                                text=True, timeout=10, check=False)
        return result.returncode == 0, (result.stdout + result.stderr)[:2000]
    finally:
        reasons_path.unlink(missing_ok=True)


def capture_controller(context: NativeContext, directory: Path) -> int:
    server = ResultServer(lambda verdict: record_native_verdict(context, verdict))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='detector-controller-', dir='/tmp') as private:
            config = Path(private) / 'mcp.json'
            config.write_text(json.dumps({'mcpServers': {
                'repository': {'type': 'http', 'url': 'http://repo-assist-tools:8081/mcp'},
                'detector_result': {'type': 'http', 'url': server.url},
            }}))
            config.chmod(0o600)
            result = capture_model(controller_command(config), directory)
            if not server.reported.is_set():
                raise ValueError('Native detector did not receive an accepted verdict')
            return result
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def capture_model(command: list[str], directory: Path) -> int:
    directory.mkdir(parents=True, exist_ok=True)
    fd, _ = tempfile.mkstemp(prefix='claude-', suffix='.jsonl', dir=directory)
    # Native result-tool variables and its executable PATH are not CLI features.
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith('THREAT_DETECTION_')}
    environment.update({'PATH': '/opt/claude/node_modules/.bin:/usr/local/bin:/usr/bin:/bin',
                        'TMPDIR': '/tmp'})
    with os.fdopen(fd, 'wb', buffering=0) as capture:
        with subprocess.Popen(command, env=environment, stdout=subprocess.PIPE) as child:
            size = 0
            try:
                while data := os.read(child.stdout.fileno(), 65536):
                    size += len(data)
                    if size > MAX_CAPTURE_BYTES:
                        capture.seek(0)
                        capture.truncate()
                        raise ValueError('Usage capture exceeds limit')
                    capture.write(data)
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                return child.wait()
            finally:
                if child.poll() is None:
                    child.kill()


def main(arguments: list[str]) -> int:
    validate_native_arguments(arguments)
    context = native_context(dict(os.environ))
    return capture_controller(context, Path('/output/claude-usage'))


if __name__ == '__main__':
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, subprocess.SubprocessError):
        print('Credential-isolated detector controller failed; publishing blocked', file=sys.stderr)
        raise SystemExit(1)
