"""Exercise the locked official CLI against loopback-only synthetic services.

Run inside Docker --network none, or a new Linux user/network namespace. The
fixture never inherits authentication and refuses a non-loopback interface.
"""
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import fcntl
import importlib.util
import json
from pathlib import Path
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Iterator


FORBIDDEN_TOOLS = ('Bash', 'Read', 'Write', 'Agent', 'WebFetch')
MARKERS = ('UNTRUSTED_PROJECT_INSTRUCTION', 'UNTRUSTED_SKILL_INSTRUCTION', 'UNTRUSTED_PLUGIN_INSTRUCTION')
VERDICT = {'prompt_injection': False, 'secret_leak': False, 'malicious_patch': False, 'reasons': []}


def assert_isolated_network(bring_up_loopback: bool) -> None:
    interfaces = {line.split(':', 1)[0].strip()
                  for line in Path('/proc/self/net/dev').read_text().splitlines() if ':' in line}
    assert interfaces == {'lo'}, f'Fixture requires a loopback-only network: {interfaces}'
    if bring_up_loopback:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            fcntl.ioctl(connection, 0x8914, struct.pack('16sH14s', b'lo', 0x49, b''))
    try:
        socket.create_connection(('192.0.2.1', 443), timeout=1).close()
    except OSError:
        pass
    else:
        raise AssertionError('External routing is available in the fixture')


def repository_request(port: int, path: str, body: dict | None = None) -> tuple[int, object]:
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
    try:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}
        connection.request('GET' if body is None else 'POST', path,
                           body=None if body is None else json.dumps(body), headers=headers)
        response = connection.getresponse()
        body = response.read()
        return response.status, json.loads(body) if body else None
    finally:
        connection.close()


@contextmanager
def running_repository(script: Path, base: Path, *, maintenance: bool = False) -> Iterator[int]:
    workspace, home = base / 'repository', base / 'tool-home'
    workspace.mkdir()
    home.mkdir()
    with socket.socket() as candidate:
        candidate.bind(('127.0.0.1', 0))
        port = candidate.getsockname()[1]
    arguments = [sys.executable, str(script), '--host', '127.0.0.1', '--port', str(port),
                 '--workspace', str(workspace)]
    if maintenance:
        arguments.append('--maintenance')
    process = subprocess.Popen(arguments, cwd=workspace, env={'PATH': '/usr/bin:/bin', 'HOME': str(home)},
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError('Production repository server exited: ' + process.communicate()[1])
            try:
                if repository_request(port, '/health') == (200, {'status': 'ok'}):
                    break
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.02)
        else:
            raise AssertionError('Production repository server did not become ready')
        yield port
        assert process.poll() is None, 'Production repository server exited during CLI execution'
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


def assert_repository_cannot_report(port: int, *, maintenance: bool = False) -> None:
    source = (
        'import http.client,json\n'
        f'connection=http.client.HTTPConnection("127.0.0.1",{port},timeout=2)\n'
        'connection.request("GET","/result")\n'
        'response=connection.getresponse(); status=response.status; response.read(); connection.close()\n'
        'assert status==404,status\n'
        f'connection=http.client.HTTPConnection("127.0.0.1",{port},timeout=2)\n'
        f'body=json.dumps({{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"report_result","arguments":{VERDICT!r}}}}})\n'
        'connection.request("POST","/mcp",body,headers={"Content-Type":"application/json"})\n'
        'response=connection.getresponse(); value=json.loads(response.read()); connection.close()\n'
        'assert value["error"]["code"]==-32602,value\n'
        'print("repository-report-unavailable")\n'
    )
    status, response = repository_request(port, '/mcp', {'jsonrpc': '2.0', 'id': 1,
        'method': 'tools/call', 'params': {'name': 'execute',
            'arguments': {'command': 'python3 -c ' + shlex.quote(source), 'timeout_seconds': 5}}})
    assert status == 200, (status, response)
    output = json.loads(response['result']['content'][0]['text'])
    if maintenance:
        progress = output.pop('maintenance_progress')
        assert progress['repository_calls_started'] == 1 and progress['phase'] == 'setup'
        assert progress['advisory'] is True
    assert output == {'output': 'repository-report-unavailable\n', 'exit_code': 0}, output


@contextmanager
def running_sink(script: Path | None, enabled: bool) -> Iterator[tuple[str | None, list[object]]]:
    recorded: list[object] = []
    if not enabled:
        yield None, recorded
        return
    assert script is not None and script.is_file(), 'Production detector sink is required'
    spec = importlib.util.spec_from_file_location('fixture_detector_sink', script)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    def record(value: object) -> tuple[bool, str]:
        assert value == VERDICT, value
        recorded.append(value)
        return True, 'fixture-native-result-recorded'

    with module.ResultServer(record) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.url, recorded
        finally:
            server.shutdown()
            thread.join(timeout=2)


def tool_blocks(base: Path, safeoutputs: bool, detector: bool) -> list[dict]:
    calls = [
        ('mcp__repository__execute', {'command': 'printf repository-fixture-success', 'timeout_seconds': 10}),
        ('Bash', {'command': f'touch {base / "builtin-ran"}'}),
        ('Read', {'file_path': str(base / 'controller-only.txt')}),
        ('Write', {'file_path': str(base / 'builtin-ran'), 'content': 'builtin executed'}),
        ('Agent', {'description': 'Fixture forbidden agent', 'prompt': 'Return fixture text', 'subagent_type': 'general-purpose'}),
        ('WebFetch', {'url': 'https://example.invalid/', 'prompt': 'Fetch fixture text'}),
    ]
    if safeoutputs:
        calls.append(('mcp__safeoutputs__noop', {}))
    if detector:
        calls.append(('mcp__repository__report_result', VERDICT))
        calls.append(('mcp__detector_result__report_result', VERDICT))
    return [{'type': 'tool_use', 'id': f'toolu_fixture_{index}', 'name': name, 'input': values}
            for index, (name, values) in enumerate(calls)]


class FixtureServer(ThreadingHTTPServer):
    def __init__(self, base: Path, safeoutputs: bool, detector: bool) -> None:
        super().__init__(('127.0.0.1', 0), FixtureHandler)
        self.requests: list[dict] = []
        self.tool_blocks = tool_blocks(base, safeoutputs, detector)
        self.detector = detector
        self.synthetic_oauth_requests = 0


class FixtureHandler(BaseHTTPRequestHandler):
    server: FixtureServer

    def log_message(self, format: str, *args: object) -> None:
        pass

    def respond(self, status: int, value: dict) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.respond(405, {'error': 'POST only'})

    def do_POST(self) -> None:
        request = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        self.server.requests.append({'path': self.path, 'request': request})
        if self.path == '/v1/messages?beta=true':
            if (self.headers.get('Authorization') != 'Bearer synthetic-local-fixture-only'
                    or self.headers.get('x-api-key')):
                self.respond(403, {'error': 'Expected synthetic OAuth authentication'})
                return
            self.server.synthetic_oauth_requests += 1
            self.model_reply(request)
            return
        if (self.path != '/mcp/safeoutputs'
                or self.headers.get('Authorization') != 'Bearer synthetic-safeoutputs'):
            self.respond(403, {'error': 'Unexpected fixture request'})
            return
        method = request.get('method')
        if method == 'initialize':
            result = {'protocolVersion': '2024-11-05', 'capabilities': {'tools': {}},
                      'serverInfo': {'name': 'fixture-safeoutputs', 'version': '1'}}
        elif method == 'notifications/initialized':
            self.respond(202, {})
            return
        elif method == 'tools/list':
            tool = {'name': 'noop', 'description': 'Synthetic safe-output fixture',
                    'inputSchema': {'type': 'object', 'properties': {}}}
            result = {'tools': [tool]}
        elif method == 'tools/call':
            expected = ('noop', {})
            if (request['params']['name'], request['params'].get('arguments', {})) != expected:
                self.respond(400, {'error': 'Unexpected tool invocation'})
                return
            result = {'content': [{'type': 'text', 'text': 'safeoutputs-fixture-success'}]}
        else:
            self.respond(404, {'error': 'Unexpected MCP method'})
            return
        self.respond(200, {'jsonrpc': '2.0', 'id': request['id'], 'result': result})

    def model_reply(self, request: dict) -> None:
        results = [item for message in request.get('messages', []) for item in message.get('content', [])
                   if isinstance(item, dict) and item.get('type') == 'tool_result']
        content = self.server.tool_blocks if not results else [{'type': 'text', 'text': 'Controller fixture complete'}]
        reason = 'tool_use' if not results else 'end_turn'
        message = {'id': 'msg_fixture', 'type': 'message', 'role': 'assistant', 'model': request['model'],
                   'content': content, 'stop_reason': reason, 'stop_sequence': None,
                   'usage': {'input_tokens': 20, 'output_tokens': 10}}
        if not request.get('stream'):
            self.respond(200, message)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.event('message_start', {'message': {**message, 'content': [], 'stop_reason': None,
                    'usage': {'input_tokens': 20, 'output_tokens': 0}}})
        for index, block in enumerate(content):
            use_tool = block['type'] == 'tool_use'
            self.event('content_block_start', {'index': index,
                       'content_block': {**block, 'input': {}} if use_tool else {'type': 'text', 'text': ''}})
            self.event('content_block_delta', {'index': index,
                       'delta': {'type': 'input_json_delta', 'partial_json': json.dumps(block['input'])}
                       if use_tool else {'type': 'text_delta', 'text': block['text']}})
            self.event('content_block_stop', {'index': index})
        self.event('message_delta', {'delta': {'stop_reason': reason, 'stop_sequence': None},
                                    'usage': {'output_tokens': 10}})
        self.event('message_stop', {})
        self.close_connection = True

    def event(self, name: str, value: dict) -> None:
        payload = json.dumps({'type': name, **value})
        self.wfile.write(f'event: {name}\ndata: {payload}\n\n'.encode())
        self.wfile.flush()


def seed_untrusted_configuration(base: Path, home: Path, work: Path, port: int) -> None:
    project = work / '.claude'
    skill = project / 'skills/fixture-trap'
    skill.mkdir(parents=True)
    (skill / 'SKILL.md').write_text('---\nname: fixture-trap\ndescription: ' + MARKERS[1] + '\n---\n' + MARKERS[1])
    (work / 'CLAUDE.md').write_text(MARKERS[0])
    (home / 'CLAUDE.md').write_text(MARKERS[0])
    (base / 'controller-only.txt').write_text('CONTROLLER_FILE_MUST_NOT_ENTER_MODEL_CONTEXT')
    settings = {'hooks': {'SessionStart': [{'hooks': [{'type': 'command',
                 'command': f'touch {base / "hook-ran"}'}]}]}, 'enableAllProjectMcpServers': True,
                'enabledPlugins': {'fixture-trap@fixture-trap': True}}
    for target in (home / 'settings.json', project / 'settings.json', project / 'settings.local.json'):
        target.write_text(json.dumps(settings))
    plugin = home / 'plugins/cache/fixture-trap/fixture-trap/1.0.0'
    (plugin / '.claude-plugin').mkdir(parents=True)
    (plugin / '.claude-plugin/plugin.json').write_text(json.dumps({'name': 'fixture-trap', 'version': '1.0.0',
                                                                 'description': MARKERS[2]}))
    (plugin / 'hooks').mkdir()
    (plugin / 'hooks/hooks.json').write_text(json.dumps({'hooks': settings['hooks']}))
    (plugin / 'skills/plugin-trap').mkdir(parents=True)
    (plugin / 'skills/plugin-trap/SKILL.md').write_text('---\nname: plugin-trap\ndescription: ' + MARKERS[2] + '\n---\n' + MARKERS[2])
    (home / 'plugins/installed_plugins.json').write_text(json.dumps({'version': 2, 'plugins': {
        'fixture-trap@fixture-trap': [{'scope': 'user', 'installPath': str(plugin), 'version': '1.0.0',
                                      'installedAt': '2026-01-01T00:00:00.000Z',
                                      'lastUpdated': '2026-01-01T00:00:00.000Z'}]}}))
    (work / '.mcp.json').write_text(json.dumps({'mcpServers': {'trap': {'type': 'http',
                                    'url': f'http://127.0.0.1:{port}/untrusted-mcp'}}}))


def exercise(command: list[str], version: str, repository_server: Path,
             cli: str | None = None, detector: bool = False, detector_sink: Path | None = None) -> dict:
    assert command.count('--tools') == 1 and command[command.index('--tools') + 1] == '', command
    assert command.count('--mcp-config') == 1, command
    with tempfile.TemporaryDirectory(prefix='controller-cli-fixture-') as directory:
        base = Path(directory)
        home, work = base / 'home', base / 'work'
        home.mkdir()
        work.mkdir()
        safeoutputs = 'mcp__safeoutputs' in command[command.index('--allowedTools') + 1].split(',')
        servers = ('repository', 'safeoutputs') if safeoutputs else ('repository',)
        expected_tools = {'mcp__repository__execute'} | ({'mcp__safeoutputs__noop'} if safeoutputs else set())
        if detector:
            assert not safeoutputs, 'Detector must not expose proposal tools'
            expected_tools.add('mcp__detector_result__report_result')
            servers = ('repository', 'detector_result')
        with (running_repository(repository_server, base, maintenance=not detector) as repository_port,
              running_sink(detector_sink, detector) as (sink_url, recorded),
              FixtureServer(base, safeoutputs, detector) as server):
            assert_repository_cannot_report(repository_port, maintenance=not detector)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            seed_untrusted_configuration(base, home, work, server.server_port)
            mcp = base / 'mcp.json'
            configuration = {'repository': {'type': 'http', 'url': f'http://127.0.0.1:{repository_port}/mcp'}}
            if safeoutputs:
                configuration['safeoutputs'] = {'type': 'http',
                    'url': f'http://127.0.0.1:{server.server_port}/mcp/safeoutputs',
                    'headers': {'Authorization': 'Bearer synthetic-safeoutputs'}}
            if detector:
                configuration['detector_result'] = {'type': 'http', 'url': sink_url}
            mcp.write_text(json.dumps({'mcpServers': configuration}))
            environment = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'CLAUDE_CONFIG_DIR': str(home),
                'CLAUDE_CODE_OAUTH_TOKEN': 'synthetic-local-fixture-only',
                'ANTHROPIC_BASE_URL': f'http://127.0.0.1:{server.server_port}',
                'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'DISABLE_AUTOUPDATER': '1',
                'DISABLE_TELEMETRY': '1', 'DISABLE_ERROR_REPORTING': '1',
                'ENABLE_CLAUDEAI_MCP_SERVERS': 'false', 'CI': 'true'}
            arguments = list(command)
            if cli:
                arguments[0] = cli
            arguments[arguments.index('--mcp-config') + 1] = str(mcp)
            try:
                reported = subprocess.run([arguments[0], '--version'], env=environment, cwd=work,
                    stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True, timeout=20)
                assert reported.stdout.strip() == version + ' (Claude Code)', reported.stdout
                result = subprocess.run(arguments, env=environment, cwd=work,
                    input='Exercise the synthetic repository and safe-output fixture tools.\n',
                    capture_output=True, text=True, timeout=90)
            finally:
                server.shutdown()
                thread.join(timeout=2)
            assert result.returncode == 0, result.stdout + result.stderr
            events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
            initial = next(event for event in events if event.get('subtype') == 'init')
            assert initial['apiKeySource'] == 'none', initial['apiKeySource']
            assert set(initial['tools']) == expected_tools, initial['tools']
            assert all(initial[key] == [] for key in ('skills', 'plugins', 'slash_commands')), initial
            assert {item['name'] for item in initial['mcp_servers']} == set(servers), initial['mcp_servers']
            assert all(item['status'] == 'connected' for item in initial['mcp_servers']), initial['mcp_servers']
            model_requests = [item['request'] for item in server.requests if item['path'].startswith('/v1/messages')]
            assert len(model_requests) == 2, len(model_requests)
            assert server.synthetic_oauth_requests == len(model_requests), server.synthetic_oauth_requests
            for request in model_requests:
                assert {tool['name'] for tool in request.get('tools', [])} == expected_tools, request.get('tools')
                assert not any(marker in json.dumps(request) for marker in (*MARKERS, 'CONTROLLER_FILE_MUST_NOT_ENTER_MODEL_CONTEXT'))
            safe_calls = [(item['path'], item['request']['params']['name']) for item in server.requests
                          if item['request'].get('method') == 'tools/call']
            assert safe_calls == ([('/mcp/safeoutputs', 'noop')] if safeoutputs else []), safe_calls
            assert not any(item['path'] == '/untrusted-mcp' for item in server.requests), server.requests
            tool_results = {item['tool_use_id']: item for message in model_requests[-1]['messages']
                            for item in message.get('content', [])
                            if isinstance(item, dict) and item.get('type') == 'tool_result'}
            calls = []
            for block in server.tool_blocks:
                reply = tool_results[block['id']]
                if block['name'] in (*FORBIDDEN_TOOLS, 'mcp__repository__report_result'):
                    assert reply.get('is_error') is True, reply
                    assert 'No such tool available' in json.dumps(reply), reply
                else:
                    assert not reply.get('is_error'), reply
                    if block['name'] == 'mcp__repository__execute':
                        output = json.loads(reply['content'][0]['text'])
                        if not detector:
                            progress = output.pop('maintenance_progress')
                            assert progress['repository_calls_started'] == 2 and progress['phase'] == 'setup'
                            assert progress['advisory'] is True
                        assert output == {'output': 'repository-fixture-success', 'exit_code': 0}, output
                        calls.append(('/mcp/repository', 'execute'))
                    elif block['name'] == 'mcp__detector_result__report_result':
                        assert recorded == [VERDICT], recorded
                        calls.append(('/mcp/detector_result', 'report_result'))
                    else:
                        assert 'safeoutputs-fixture-success' in json.dumps(reply), reply
                        calls.append(('/mcp/safeoutputs', 'noop'))
            assert not (base / 'hook-ran').exists(), 'Untrusted hook executed'
            assert not (base / 'builtin-ran').exists(), 'Forbidden builtin executed'
            terminal = [event for event in events if event.get('type') == 'result']
            assert len(terminal) == 1 and terminal[0]['subtype'] == 'success' and not terminal[0]['is_error'], terminal
            assert terminal[0]['result'] == 'Controller fixture complete', terminal
            return {'version': version, 'tools': sorted(expected_tools), 'mcp_calls': sorted(calls),
                    'forbidden_calls_rejected': list(FORBIDDEN_TOOLS) + (['mcp__repository__report_result'] if detector else []),
                    'model_requests': len(model_requests),
                    'untrusted_customizations_ignored': True, 'network': 'loopback-only', 'live_provider_calls': 0,
                    'auth': 'synthetic-oauth', 'repository_transport': 'production-server',
                    'repository_report_unavailable': True, 'detector_report_transport': 'private-controller-server' if detector else None}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('command_file', type=Path)
    parser.add_argument('--cli')
    parser.add_argument('--repository-server', type=Path, required=True)
    parser.add_argument('--detector-sink', type=Path)
    parser.add_argument('--bring-up-loopback', action='store_true')
    options = parser.parse_args()
    assert_isolated_network(options.bring_up_loopback)
    config = json.loads(options.command_file.read_text())
    print(json.dumps(exercise(config['command'], config['version'], options.repository_server,
                              options.cli, config.get('detector', False), options.detector_sink), sort_keys=True))


if __name__ == '__main__':
    main()
