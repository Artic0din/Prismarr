#!/usr/bin/env python3
"""Credential-free repository tools over stateless MCP Streamable HTTP.

Run only inside the dedicated, disposable tool container. The shell is arbitrary
code execution, not a sandbox: container mounts, networks and resource limits are
the security boundary. Never mount credentials or a container-control socket here.
"""

import argparse
import http.server
import json
import math
import os
from pathlib import Path
import selectors
import signal
import socket
import socketserver
import subprocess
import threading
import time
from typing import Callable, Union, cast
from urllib.parse import urlsplit


JSON = Union[None, bool, int, float, str, list["JSON"], dict[str, "JSON"]]
PROTOCOL_VERSION = "2025-03-26"
MAX_REQUEST_BYTES = 64 * 1024
MAX_COMMAND_BYTES = 32 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_BATCH_SIZE = 16
MAX_CONNECTIONS = 8
MAX_EXECUTIONS = 2
MAX_COMMAND_SECONDS = 60
REQUEST_SECONDS = 70
IO_SECONDS = 5
CLEANUP_SECONDS = 0.25
SETUP_CALLS = 10
FINALIZATION_CALLS = 30
TOOL: dict[str, JSON] = {
    "name": "execute",
    "description": (
        "Run Bash commands in the isolated repository tool container. Read, search, "
        "edit and validate repository files here. GitHub reads use the trusted gh "
        "wrapper. Return combined stdout/stderr and exit status; no interactive input. "
        "The detector workspace is mounted read-only."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "minLength": 1, "maxLength": MAX_COMMAND_BYTES},
            "timeout_seconds": {"type": "number", "exclusiveMinimum": 0,
                                "maximum": MAX_COMMAND_SECONDS, "default": 30},
            "cwd": {"type": "string", "description": "Directory within the repository workspace"},
        },
        "required": ["command"],
        "additionalProperties": False,
    },
}


def rpc_error(request_id: JSON, code: int, message: str) -> dict[str, JSON]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def tool_result(output: bytes = b"", exit_code: int | None = None,
                error: str | None = None) -> dict[str, JSON]:
    value: dict[str, JSON] = {"output": output.decode("utf-8", errors="replace"),
                              "exit_code": exit_code}
    if error:
        value["error"] = error
    return {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=True)}],
            "isError": bool(error) or exit_code != 0}


def command_environment() -> dict[str, str]:
    proxy = os.environ.get("AWF_CLI_PROXY_URL", "http://repo-assist-cli:11000")
    parsed = urlsplit(proxy)
    if (len(proxy) > 2048 or parsed.scheme != "http" or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or any(ord(char) <= 32 or ord(char) >= 127 for char in proxy)
            or parsed.port == 0):
        raise ValueError("invalid credential-free CLI proxy URL")
    return {
        "HOME": "/tmp/repository-home",
        "PATH": "/trusted/bin:/opt/validation:/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "CI": "true",
        "AWF_CLI_PROXY_URL": proxy,
        "GIT_AUTHOR_NAME": "Repo Assist",
        "GIT_COMMITTER_NAME": "Repo Assist",
        "GIT_AUTHOR_EMAIL": "repo-assist@users.noreply.github.com",
        "GIT_COMMITTER_EMAIL": "repo-assist@users.noreply.github.com",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_VALUE_0": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "PYTHONNOUSERSITE": "1",
    }


def validated_arguments(arguments: JSON, workspace: Path) -> tuple[str, float, Path]:
    if not isinstance(arguments, dict) or set(arguments) - {"command", "timeout_seconds", "cwd"}:
        raise ValueError("execute accepts command, timeout_seconds and cwd only")
    command = arguments.get("command")
    timeout = arguments.get("timeout_seconds", 30)
    cwd = arguments.get("cwd", ".")
    if (not isinstance(command, str) or not command.strip() or "\x00" in command
            or len(command.encode("utf-8")) > MAX_COMMAND_BYTES):
        raise ValueError("command must be a nonempty string of at most 32768 UTF-8 bytes")
    if (type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 0 < timeout <= MAX_COMMAND_SECONDS):
        raise ValueError("timeout_seconds must be greater than zero and at most 60")
    if not isinstance(cwd, str) or not cwd or "\x00" in cwd or len(cwd) > 4096:
        raise ValueError("cwd must be a directory inside the workspace")
    try:
        directory = (workspace / cwd).resolve(strict=True)
        directory.relative_to(workspace)
        if not directory.is_dir():
            raise ValueError
    except (ValueError, OSError, RuntimeError):
        raise ValueError("cwd must be a directory inside the workspace") from None
    return command, float(timeout), directory


def kill_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def execute_command(command: str, timeout: float, directory: Path,
                    environment: dict[str, str], *,
                    on_started: Callable[[], None] | None = None) -> dict[str, JSON]:
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            ["/bin/bash", "--noprofile", "--norc", "-c", command], cwd=directory,
            env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, start_new_session=True, close_fds=True,
        )
    except OSError:
        return tool_result(error="command could not start")
    if on_started is not None:
        on_started()
    assert process.stdout is not None
    output = bytearray()
    error = None
    exited_at = None
    try:
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                now = time.monotonic()
                if now >= deadline:
                    error = "command timed out"
                    break
                if process.poll() is not None:
                    if exited_at is None:
                        exited_at = now
                        kill_group(process)
                    elif now - exited_at >= CLEANUP_SECONDS:
                        error = "command descendants kept output open"
                        break
                for key, _ in selector.select(min(0.05, deadline - now)):
                    chunk = os.read(key.fd, min(64 * 1024, MAX_OUTPUT_BYTES - len(output) + 1))
                    if not chunk:
                        selector.unregister(process.stdout)
                        break
                    remaining = MAX_OUTPUT_BYTES - len(output)
                    output.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        error = "output limit exceeded"
                        break
                if error:
                    break
            if not error:
                remaining_time = deadline - time.monotonic()
                try:
                    process.wait(timeout=max(0, remaining_time))
                except subprocess.TimeoutExpired:
                    error = "command timed out"
    except OSError:
        error = "command output could not be read"
    finally:
        # Closing pipes is bounded even when a child has escaped the original
        # process group. The outer container lifetime bounds such descendants.
        kill_group(process)
        process.stdout.close()
        try:
            process.wait(timeout=CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            error = error or "command cleanup timed out"
    return tool_result(bytes(output), process.returncode, error)


def strict_object(pairs: list[tuple[str, JSON]]) -> dict[str, JSON]:
    value: dict[str, JSON] = {}
    for key, entry in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = entry
    return value


def reject_constant(value: str) -> JSON:
    raise ValueError("non-finite JSON number")


class RepositoryServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = MAX_CONNECTIONS

    def __init__(self, address: tuple[str, int], workspace: Path, *,
                 maintenance: bool = False) -> None:
        self.workspace = workspace.resolve(strict=True)
        if not self.workspace.is_dir():
            raise ValueError("workspace must be a directory")
        self.environment = command_environment()
        self.maintenance = maintenance
        self.repository_calls_started = 0
        self.progress_lock = threading.Lock()
        self.connection_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.execution_slots = threading.BoundedSemaphore(MAX_EXECUTIONS)
        super().__init__(address, RepositoryHandler)

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self.connection_slots.acquire(blocking=False):
            try:
                request.settimeout(0.1)
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n"
                                b"Content-Length: 0\r\n\r\n")
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.connection_slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connection_slots.release()

    def handle_error(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        # Request bodies and shell commands must never enter HTTP diagnostics.
        return

    def record_execution_started(self) -> None:
        with self.progress_lock:
            self.repository_calls_started += 1

    def with_maintenance_progress(self, result: dict[str, JSON]) -> dict[str, JSON]:
        if not self.maintenance:
            return result
        with self.progress_lock:
            count = self.repository_calls_started
        if count <= SETUP_CALLS:
            phase = "setup"
            guidance = "Complete setup and select a bounded maintenance task."
        elif count < FINALIZATION_CALLS:
            phase = "focused_work"
            guidance = "Stay focused on the selected work and its required validation."
        else:
            phase = "finalization"
            guidance = ("Finish validation and path cleanup, then complete the report, memory, "
                        "and proposals. Do not start a new investigation.")
        content = cast(list[dict[str, str]], result["content"])
        value = json.loads(content[0]["text"])
        value["maintenance_progress"] = {
            "repository_calls_started": count,
            "phase": phase,
            "guidance": guidance,
            "advisory": True,
        }
        content[0]["text"] = json.dumps(value, ensure_ascii=True)
        return result

    def dispatch(self, value: JSON, deadline: float) -> dict[str, JSON] | None:
        if (isinstance(value, dict) and value.get("jsonrpc") == "2.0" and "method" not in value
                and type(value.get("id")) in (str, int) and ("result" in value) != ("error" in value)):
            error = value.get("error")
            if ("result" in value or isinstance(error, dict) and type(error.get("code")) is int
                    and isinstance(error.get("message"), str)):
                return None
        if (not isinstance(value, dict) or value.get("jsonrpc") != "2.0"
                or not isinstance(value.get("method"), str)
                or ("id" in value and type(value["id"]) not in (str, int))
                or not isinstance(value.get("params", {}), dict)):
            return rpc_error(None, -32600, "Invalid Request")
        method = value["method"]
        if "id" not in value:
            return None
        request_id = value["id"]
        params = value.get("params", {})
        assert isinstance(params, dict)
        if time.monotonic() >= deadline:
            return rpc_error(request_id, -32000, "Request deadline exceeded")
        if method == "initialize":
            info = params.get("clientInfo")
            if (not isinstance(params.get("protocolVersion"), str)
                    or not isinstance(params.get("capabilities"), dict)
                    or not isinstance(info, dict) or not isinstance(info.get("name"), str)
                    or not isinstance(info.get("version"), str)):
                return rpc_error(request_id, -32602, "Invalid initialization parameters")
            result: dict[str, JSON] = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "repository", "version": "1.0.0"},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": [TOOL]}
        elif method == "tools/call":
            if params.get("name") != "execute":
                return rpc_error(request_id, -32602, "Unknown tool")
            try:
                command, timeout, directory = validated_arguments(params.get("arguments"), self.workspace)
            except (ValueError, UnicodeError):
                return rpc_error(request_id, -32602, "Invalid execute arguments or cwd")
            if not self.execution_slots.acquire(blocking=False):
                result = tool_result(error="repository executor is busy; retry after the current command")
            else:
                try:
                    result = execute_command(command, min(timeout, max(0, deadline - time.monotonic())),
                                             directory, self.environment,
                                             on_started=(self.record_execution_started
                                                         if self.maintenance else None))
                finally:
                    self.execution_slots.release()
            result = self.with_maintenance_progress(result)
        else:
            return rpc_error(request_id, -32601, "Method not found")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}


class RepositoryHandler(http.server.BaseHTTPRequestHandler):
    server: RepositoryServer
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(IO_SECONDS)
        self.deadline = time.monotonic() + REQUEST_SECONDS
        self.watchdog = threading.Timer(REQUEST_SECONDS, self.expire_connection)
        self.watchdog.daemon = True
        self.watchdog.start()

    def expire_connection(self) -> None:
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self) -> None:
        self.watchdog.cancel()
        super().finish()

    def log_message(self, format: str, *args: object) -> None:
        return

    def respond(self, status: int, value: JSON = None) -> None:
        body = b"" if value is None else json.dumps(value, ensure_ascii=True).encode("utf-8")
        self.close_connection = True
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            if status == 405:
                self.send_header("Allow", "POST")
            self.end_headers()
            if body:
                self.wfile.write(body)
        except OSError:
            pass

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        # Only a private, non-browser controller is expected on this network.
        if "Origin" in self.headers:
            self.respond(403, {"error": "Browser origins are not permitted"})
            return False
        return True

    def do_GET(self) -> None:
        if self.path == "/health":
            self.respond(200, {"status": "ok"})
        elif self.path == "/mcp":
            self.respond(405)
        else:
            self.respond(404)

    def do_DELETE(self) -> None:
        self.respond(405 if self.path == "/mcp" else 404)

    def do_OPTIONS(self) -> None:
        self.respond(405 if self.path == "/mcp" else 404)

    def do_POST(self) -> None:
        if self.path != "/mcp":
            self.respond(404)
            return
        if (self.headers.get("MCP-Protocol-Version", PROTOCOL_VERSION) != PROTOCOL_VERSION
                or len(self.headers.get_all("MCP-Protocol-Version", [])) > 1):
            self.respond(400, rpc_error(None, -32600, "Unsupported protocol version"))
            return
        if self.headers.get_content_type() != "application/json":
            self.respond(415)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (self.headers.get("Transfer-Encoding") or len(lengths) != 1
                or len(lengths[0]) > 10 or not lengths[0].isascii() or not lengths[0].isdigit()):
            self.respond(400, rpc_error(None, -32600, "A single Content-Length is required"))
            return
        length = int(lengths[0])
        if length > MAX_REQUEST_BYTES:
            self.respond(413)
            return
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError
            value: JSON = json.loads(body.decode("utf-8"), object_pairs_hook=strict_object,
                                     parse_constant=reject_constant)
        except (ValueError, UnicodeError, RecursionError, OSError):
            self.respond(400, rpc_error(None, -32700, "Invalid JSON request"))
            return
        if isinstance(value, list):
            if not value or len(value) > MAX_BATCH_SIZE or any(
                    isinstance(item, dict) and item.get("method") == "initialize" for item in value):
                self.respond(400, rpc_error(None, -32600, "Invalid request batch"))
                return
            results: list[JSON] = []
            for item in value:
                result = self.server.dispatch(item, self.deadline)
                if result is not None:
                    results.append(result)
            self.respond(200, results) if results else self.respond(202)
        else:
            result = self.server.dispatch(value, self.deadline)
            if result is None:
                self.respond(202)
            else:
                error = result.get("error")
                invalid = isinstance(error, dict) and error.get("code") == -32600
                self.respond(400 if invalid else 200, result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--workspace", type=Path, default=Path("/workspace"))
    parser.add_argument("--maintenance", action="store_true",
                        help="Include advisory maintenance progress in execute results")
    args = parser.parse_args()
    try:
        server = RepositoryServer((args.host, args.port), args.workspace,
                                  maintenance=args.maintenance)
    except (ValueError, OSError):
        parser.error("invalid workspace, address or CLI proxy configuration")
    with server:
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
