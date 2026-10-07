"""Controller-private MCP transport for one native threat-detector verdict.

This listener cannot execute commands, read paths, or configure destinations.
It binds only controller loopback, outside the repository container's network
namespace. The sole callback is trusted native verdict validation/reporting.
"""
from collections.abc import Callable
import http.server
import json
import socket
import socketserver
import subprocess
import threading

MAX_REQUEST_BYTES = 1024 * 1024
REQUEST_SECONDS = 15
REPORT_TOOL = {
    'name': 'report_result',
    'description': 'Submit the threat-detection verdict to the native validator. Correct any returned validation error before retrying.',
    'inputSchema': {
        'type': 'object', 'additionalProperties': False,
        'properties': {
            'prompt_injection': {'type': 'boolean'}, 'secret_leak': {'type': 'boolean'},
            'malicious_patch': {'type': 'boolean'},
            'reasons': {'type': 'array', 'maxItems': 20,
                        'items': {'type': 'string', 'minLength': 1, 'maxLength': 2000}},
        },
        'required': ['prompt_injection', 'secret_leak', 'malicious_patch', 'reasons'],
    },
}


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def reject_constant(_value: str) -> object:
    raise ValueError('Non-finite JSON value')


class ResultServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

    def __init__(self, report: Callable[[object], tuple[bool, str]]) -> None:
        self.report = report
        self.reported = threading.Event()
        self.report_lock = threading.Lock()
        self.connections = threading.BoundedSemaphore(8)
        super().__init__(('127.0.0.1', 0), ResultHandler)

    @property
    def url(self) -> str:
        return f'http://127.0.0.1:{self.server_address[1]}/mcp'

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self.connections.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.connections.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connections.release()

    def handle_error(self, _request: socket.socket, _client_address: tuple[str, int]) -> None:
        pass

    def dispatch(self, value: object) -> dict | None:
        if (not isinstance(value, dict) or value.get('jsonrpc') != '2.0'
                or not isinstance(value.get('method'), str)
                or ('id' in value and type(value['id']) not in (int, str))
                or not isinstance(value.get('params', {}), dict)):
            return {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Invalid Request'}}
        if 'id' not in value:
            return None
        response = {'jsonrpc': '2.0', 'id': value['id']}
        method, params = value['method'], value.get('params', {})
        if method == 'initialize':
            response['result'] = {'protocolVersion': '2025-03-26', 'capabilities': {'tools': {}},
                                  'serverInfo': {'name': 'detector_result', 'version': '1.0.0'}}
        elif method == 'ping':
            response['result'] = {}
        elif method == 'tools/list':
            response['result'] = {'tools': [REPORT_TOOL]}
        elif method == 'tools/call' and params.get('name') == 'report_result':
            with self.report_lock:
                accepted, detail = False, 'A verdict has already been recorded'
                if not self.reported.is_set():
                    try:
                        accepted, detail = self.report(params.get('arguments'))
                    except (OSError, ValueError, subprocess.SubprocessError):
                        detail = 'Native verdict validation failed; correct the report and retry'
                    if accepted:
                        self.reported.set()
                response['result'] = {'content': [{'type': 'text', 'text': detail[:2000]}],
                                      'isError': not accepted}
        else:
            response['error'] = {'code': -32601, 'message': 'Method or tool is not available'}
        return response


class ResultHandler(http.server.BaseHTTPRequestHandler):
    server: ResultServer

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(REQUEST_SECONDS)
        self.deadline = threading.Timer(REQUEST_SECONDS, self.expire)
        self.deadline.daemon = True
        self.deadline.start()

    def expire(self) -> None:
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self) -> None:
        self.deadline.cancel()
        super().finish()

    def log_message(self, _format: str, *args: object) -> None:
        pass

    def respond(self, status: int, value: object = None) -> None:
        body = json.dumps(value).encode() if value is not None else b''
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self) -> None:
        self.respond(405)

    def do_DELETE(self) -> None:
        self.respond(405)

    def do_OPTIONS(self) -> None:
        self.respond(405)

    def do_POST(self) -> None:
        if self.path != '/mcp':
            self.respond(404)
            return
        if (self.headers.get('Origin') is not None
                or self.headers.get('Host') != f'127.0.0.1:{self.server.server_address[1]}'):
            self.respond(403)
            return
        length_header = self.headers.get_all('Content-Length', [])
        if (len(length_header) != 1 or not length_header[0].isdigit()
                or self.headers.get('Transfer-Encoding') is not None
                or self.headers.get_content_type() != 'application/json'):
            self.respond(400)
            return
        size = int(length_header[0])
        if not 0 < size <= MAX_REQUEST_BYTES:
            self.respond(413)
            return
        try:
            body = self.rfile.read(size)
            if len(body) != size:
                raise ValueError('Incomplete request')
            value = json.loads(body, object_pairs_hook=strict_object, parse_constant=reject_constant)
            result = self.server.dispatch(value)
        except (ValueError, UnicodeError, RecursionError):
            self.respond(400)
            return
        self.respond(202 if result is None else 200, result)
