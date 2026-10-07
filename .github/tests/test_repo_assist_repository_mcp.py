"""Exercise the repository MCP boundary over real local HTTP and subprocesses."""

import http.client
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "repo-assist-worker" / "repository_mcp.py"


class RepositoryMCPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(SOURCE.is_file(), "repository MCP server must exist")
        spec = importlib.util.spec_from_file_location("repository_mcp", SOURCE)
        assert spec is not None and spec.loader is not None
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.server = self.module.RepositoryServer(("127.0.0.1", 0), self.workspace)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.cleanup)

    def cleanup(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.directory.cleanup()

    def enable_maintenance(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.server = self.module.RepositoryServer(("127.0.0.1", 0), self.workspace,
                                                   maintenance=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def request(self, value: object = None, *, path: str = "/mcp", method: str = "POST",
                headers: dict[str, str] | None = None, raw: bytes | None = None
                ) -> tuple[int, dict[str, str], object]:
        body = raw if raw is not None else json.dumps(value).encode()
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            actual_headers = {"Content-Type": "application/json",
                              "Accept": "application/json, text/event-stream"}
            actual_headers.update(headers or {})
            connection.request(method, path, body=body if method == "POST" else None,
                               headers=actual_headers)
            response = connection.getresponse()
            data = response.read()
            value = (json.loads(data) if response.getheader("Content-Type") == "application/json"
                     else data.decode()) if data else None
            return response.status, dict(response.getheaders()), value
        finally:
            connection.close()

    def rpc(self, method: str, params: object = None, request_id: object = 1
            ) -> tuple[int, dict[str, str], object]:
        return self.request({"jsonrpc": "2.0", "id": request_id,
                             "method": method, "params": params or {}})

    def execute(self, command: str, **options: object) -> dict:
        status, _, response = self.rpc("tools/call", {
            "name": "execute", "arguments": {"command": command, **options}})
        self.assertEqual(status, 200)
        self.assertIsInstance(response, dict)
        return response["result"]

    def test_initialize_negotiates_official_http_protocol(self) -> None:
        for version in ("2025-03-26", "2025-06-18", "2024-11-05"):
            with self.subTest(version=version):
                status, headers, body = self.rpc("initialize", {
                    "protocolVersion": version, "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}})
                self.assertEqual(status, 200)
                self.assertEqual(headers["Content-Type"], "application/json")
                self.assertEqual(body["result"]["protocolVersion"], "2025-03-26")
                self.assertEqual(body["result"]["serverInfo"]["name"], "repository")
                self.assertEqual(body["result"]["capabilities"], {"tools": {"listChanged": False}})
                self.assertNotIn("Mcp-Session-Id", headers)

    def test_notifications_are_accepted_without_response_body(self) -> None:
        for method in ("notifications/initialized", "notifications/cancelled", "notifications/progress"):
            status, _, body = self.request({"jsonrpc": "2.0", "method": method})
            self.assertEqual((status, body), (202, None))

    def test_tools_list_exposes_one_constrained_execute_tool(self) -> None:
        _, _, body = self.rpc("tools/list")
        tool, = body["result"]["tools"]
        self.assertEqual(tool["name"], "execute")
        self.assertEqual(tool["inputSchema"]["required"], ["command"])
        self.assertEqual(tool["inputSchema"]["properties"]["timeout_seconds"]["maximum"], 60)
        self.assertFalse(tool["inputSchema"]["additionalProperties"])

    def test_real_bash_execution_returns_bounded_combined_output_and_exit(self) -> None:
        result = self.execute("printf 'out'; printf 'err' >&2; exit 7")
        value = json.loads(result["content"][0]["text"])
        self.assertEqual(value["output"], "outerr")
        self.assertEqual(value["exit_code"], 7)
        self.assertTrue(result["isError"])

    def test_detector_execution_has_no_maintenance_progress(self) -> None:
        result = self.execute("printf detector")
        self.assertEqual(json.loads(result["content"][0]["text"]),
                         {"output": "detector", "exit_code": 0})
        self.assertNotIn("maintenance_progress", json.dumps(result))

    def test_maintenance_counts_and_phases_preserve_finalization_execution(self) -> None:
        self.enable_maintenance()
        for count in range(1, 33):
            with self.subTest(repository_calls_started=count):
                command = ("printf validated > final-validation.txt; cat final-validation.txt"
                           if count == 32 else "printf repository-output")
                result = self.execute(command)
                value = json.loads(result["content"][0]["text"])
                self.assertFalse(result["isError"])
                self.assertEqual(value["output"], "validated" if count == 32 else "repository-output")
                self.assertEqual(value["exit_code"], 0)
                progress = value["maintenance_progress"]
                self.assertEqual(progress["repository_calls_started"], count)
                self.assertTrue(progress["advisory"])
                self.assertEqual(set(progress), {"repository_calls_started", "phase",
                                                 "guidance", "advisory"})
                if count <= 10:
                    self.assertEqual(progress["phase"], "setup")
                    self.assertIn("select", progress["guidance"].lower())
                elif count < 30:
                    self.assertEqual(progress["phase"], "focused_work")
                    self.assertIn("selected", progress["guidance"].lower())
                else:
                    self.assertEqual(progress["phase"], "finalization")
                    for topic in ("validation", "path", "report", "memory", "proposal",
                                  "new investigation"):
                        self.assertIn(topic, progress["guidance"].lower())
        self.assertEqual((self.workspace / "final-validation.txt").read_text(), "validated")

    def test_invalid_maintenance_execute_arguments_do_not_increment_count(self) -> None:
        self.enable_maintenance()
        for arguments in ({}, {"command": ""}, {"command": "true", "cwd": ".."},
                          {"command": "true", "timeout_seconds": 0},
                          {"command": "true", "environment": {"TOKEN": "x"}}):
            with self.subTest(arguments=arguments):
                _, _, response = self.rpc("tools/call", {"name": "execute", "arguments": arguments})
                self.assertEqual(response["error"]["code"], -32602)
                self.assertEqual(response["error"]["message"], "Invalid execute arguments or cwd")
                self.assertEqual(set(response["error"]), {"code", "message"})
        result = self.execute("true")
        self.assertEqual(json.loads(result["content"][0]["text"])
                         ["maintenance_progress"]["repository_calls_started"], 1)

    def test_failed_maintenance_commands_still_count(self) -> None:
        self.enable_maintenance()
        result = self.execute("printf failed; exit 7")
        value = json.loads(result["content"][0]["text"])
        self.assertTrue(result["isError"])
        self.assertEqual(value["exit_code"], 7)
        self.assertEqual(value["output"], "failed")
        self.assertEqual(value["maintenance_progress"]["repository_calls_started"], 1)
        result = self.execute("sleep 5", timeout_seconds=0.1)
        value = json.loads(result["content"][0]["text"])
        self.assertTrue(result["isError"])
        self.assertEqual(value["error"], "command timed out")
        self.assertEqual(value["maintenance_progress"]["repository_calls_started"], 2)

    def test_command_that_cannot_start_does_not_increment_maintenance_count(self) -> None:
        self.enable_maintenance()
        with patch.object(self.module.subprocess, "Popen", side_effect=OSError):
            result = self.execute("true")
        value = json.loads(result["content"][0]["text"])
        self.assertTrue(result["isError"])
        self.assertEqual(value["error"], "command could not start")
        self.assertEqual(value["maintenance_progress"]["repository_calls_started"], 0)
        result = self.execute("true")
        self.assertEqual(json.loads(result["content"][0]["text"])
                         ["maintenance_progress"]["repository_calls_started"], 1)

    def test_concurrent_maintenance_counts_executions_once_and_excludes_busy_requests(self) -> None:
        self.enable_maintenance()
        with ThreadPoolExecutor(max_workers=self.module.MAX_EXECUTIONS) as pool:
            futures = [pool.submit(self.execute,
                                   f"touch started-{index}; "
                                   "while [ ! -f release ]; do sleep 0.01; done",
                                   timeout_seconds=3)
                       for index in range(self.module.MAX_EXECUTIONS)]
            try:
                deadline = time.monotonic() + 2
                while len(list(self.workspace.glob("started-*"))) != self.module.MAX_EXECUTIONS:
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                for _ in range(3):
                    result = self.execute("touch should-not-run")
                    value = json.loads(result["content"][0]["text"])
                    self.assertTrue(result["isError"])
                    self.assertIn("busy", value["error"])
                    self.assertEqual(value["maintenance_progress"]["repository_calls_started"],
                                     self.module.MAX_EXECUTIONS)
                self.assertFalse((self.workspace / "should-not-run").exists())
            finally:
                (self.workspace / "release").touch()
            for future in futures:
                result = future.result(timeout=4)
                self.assertFalse(result["isError"])
                self.assertEqual(json.loads(result["content"][0]["text"])
                                 ["maintenance_progress"]["repository_calls_started"],
                                 self.module.MAX_EXECUTIONS)
        result = self.execute("true")
        self.assertEqual(json.loads(result["content"][0]["text"])
                         ["maintenance_progress"]["repository_calls_started"],
                         self.module.MAX_EXECUTIONS + 1)

    def test_maintenance_count_is_local_to_each_server(self) -> None:
        self.enable_maintenance()
        self.execute("true")
        self.execute("true")
        first_server = self.server
        second_server = self.module.RepositoryServer(("127.0.0.1", 0), self.workspace,
                                                     maintenance=True)
        thread = threading.Thread(target=second_server.serve_forever, daemon=True)
        thread.start()
        try:
            self.server = second_server
            result = self.execute("true")
            self.assertEqual(json.loads(result["content"][0]["text"])
                             ["maintenance_progress"]["repository_calls_started"], 1)
            self.server = first_server
            result = self.execute("true")
            self.assertEqual(json.loads(result["content"][0]["text"])
                             ["maintenance_progress"]["repository_calls_started"], 3)
        finally:
            self.server = first_server
            second_server.shutdown()
            second_server.server_close()
            thread.join(timeout=3)

    def test_shell_can_read_and_write_the_workspace(self) -> None:
        result = self.execute("printf hello > result.txt; cat result.txt; pwd")
        self.assertFalse(result["isError"])
        self.assertEqual((self.workspace / "result.txt").read_text(), "hello")
        self.assertIn(str(self.workspace), result["content"][0]["text"])

    def test_cwd_is_resolved_beneath_workspace(self) -> None:
        subdirectory = self.workspace / "subdirectory"
        subdirectory.mkdir()
        (self.workspace / "outside").symlink_to(self.root, target_is_directory=True)
        for cwd in ("subdirectory", str(subdirectory)):
            self.assertFalse(self.execute("pwd", cwd=cwd)["isError"])
        for cwd in ("..", "outside", "/tmp", "missing", "x\x00y", 7):
            with self.subTest(cwd=cwd):
                _, _, result = self.rpc("tools/call", {"name": "execute", "arguments": {
                    "command": "touch escaped", "cwd": cwd}})
                self.assertEqual(result["error"]["code"], -32602)
        self.assertFalse((self.root / "escaped").exists())

    def test_argument_validation_rejects_unbounded_and_unknown_inputs(self) -> None:
        for arguments in ({}, {"command": ""}, {"command": 1}, {"command": "x\x00y"},
                          {"command": "x" * (32 * 1024 + 1)},
                          *({"command": "true", "timeout_seconds": value}
                            for value in (0, -1, 61, True, "2")),
                          {"command": "true", "environment": {"TOKEN": "x"}}):
            with self.subTest(arguments=str(arguments)[:100]):
                _, _, body = self.rpc("tools/call", {"name": "execute", "arguments": arguments})
                self.assertEqual(body["error"]["code"], -32602)

    def test_inherited_environment_is_not_given_to_shell(self) -> None:
        with patch.dict(os.environ, {"CLAUDE_CODE_OAUTH_TOKEN": "fake-oauth-canary",
                                     "ANTHROPIC_API_KEY": "fake-api-canary",
                                     "GITHUB_TOKEN": "fake-github-canary",
                                     "ACTIONS_RUNTIME_TOKEN": "fake-runtime-canary",
                                     "BASH_ENV": "/does/not/exist",
                                     "PYTHONPATH": "/attacker",
                                     "PATH": "/attacker"}):
            result = self.execute("/usr/bin/env")
        content = result["content"][0]["text"]
        for marker in ("canary", "BASH_ENV", "PYTHONPATH", "/attacker"):
            self.assertNotIn(marker, content)
        self.assertIn("PATH=/trusted/bin:", content)

    def test_output_limit_stops_a_noisy_process(self) -> None:
        started = time.monotonic()
        result = self.execute("/usr/bin/yes noisy", timeout_seconds=2)
        value = json.loads(result["content"][0]["text"])
        self.assertTrue(result["isError"])
        self.assertEqual(value["error"], "output limit exceeded")
        self.assertLessEqual(len(value["output"].encode()), self.module.MAX_OUTPUT_BYTES)
        self.assertLess(time.monotonic() - started, 3)

    def test_deadline_kills_process_group(self) -> None:
        started = time.monotonic()
        result = self.execute("sleep 5 & wait", timeout_seconds=0.15)
        value = json.loads(result["content"][0]["text"])
        self.assertEqual(value["error"], "command timed out")
        self.assertLess(time.monotonic() - started, 2)

    def test_detached_child_holding_output_does_not_hold_request_open(self) -> None:
        started = time.monotonic()
        # Wait until the child has actually left our process group; otherwise
        # immediate cleanup can legitimately kill it before setsid executes.
        result = self.execute("setsid sh -c 'touch detached-ready; sleep 1' & "
                              "while [ ! -f detached-ready ]; do sleep 0.01; done; exit 0",
                              timeout_seconds=0.2)
        self.assertLess(time.monotonic() - started, 0.8)
        self.assertTrue(result["isError"])

    def test_concurrent_execution_has_a_fixed_limit_and_no_queue(self) -> None:
        results = []
        threads = [threading.Thread(target=lambda index=index: results.append(
            self.execute(f"touch started-{index}; sleep 1", timeout_seconds=2)))
                   for index in range(self.module.MAX_EXECUTIONS)]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + 2
        while len(list(self.workspace.glob("started-*"))) != self.module.MAX_EXECUTIONS:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        started = time.monotonic()
        result = self.execute("touch should-not-run")
        self.assertTrue(result["isError"])
        self.assertIn("busy", result["content"][0]["text"])
        self.assertFalse((self.workspace / "should-not-run").exists())
        self.assertLess(time.monotonic() - started, 0.5)
        for thread in threads:
            thread.join(timeout=3)
        self.assertEqual(len(results), self.module.MAX_EXECUTIONS)

    def test_health_and_unsupported_routes_do_not_expose_files(self) -> None:
        self.assertEqual(self.request(method="GET", path="/health")[0], 200)
        self.assertEqual(self.request(method="GET")[0], 405)
        for path in ("/etc/passwd", "/health?file=/etc/passwd", "/mcp/../etc/passwd", "http://example.com"):
            self.assertEqual(self.request(method="GET", path=path)[0], 404)

    def test_origin_headers_are_rejected(self) -> None:
        for method in ("POST", "GET", "DELETE", "OPTIONS", "PUT", "PATCH", "HEAD"):
            status, _, _ = self.request({"jsonrpc": "2.0", "id": 1, "method": "ping"},
                                       method=method, headers={"Origin": "https://attacker.example"})
            self.assertEqual(status, 403)

    def test_invalid_json_and_rpc_are_errors(self) -> None:
        for raw in (b"{", b"null", b"[]", b'{"jsonrpc":"2.0","id":1,"method":7}',
                    b'{"jsonrpc":"2.0","id":true,"method":"ping"}',
                    b'{"jsonrpc":"2.0","id":1,"method":"ping","params":NaN}',
                    b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}'):
            with self.subTest(raw=raw):
                status, _, body = self.request(raw=raw)
                self.assertEqual(status, 400)
                self.assertIn("error", body)

    def test_oversized_request_is_rejected_before_execution(self) -> None:
        status, _, _ = self.request(raw=b" " * (self.module.MAX_REQUEST_BYTES + 1))
        self.assertEqual(status, 413)

    def test_unsupported_content_type_and_protocol_are_rejected(self) -> None:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        self.assertEqual(self.request(payload, headers={"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.request(payload, headers={"MCP-Protocol-Version": "9999"})[0], 400)

    def test_json_rpc_errors_keep_request_ids(self) -> None:
        _, _, body = self.rpc("unknown", request_id="request-4")
        self.assertEqual(body["id"], "request-4")
        self.assertEqual(body["error"]["code"], -32601)
        _, _, body = self.rpc("tools/call", {"name": "read", "arguments": {}})
        self.assertEqual(body["error"]["code"], -32602)

    def test_batch_of_requests_and_notifications(self) -> None:
        status, _, body = self.request([
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "method": "ping", "id": 1},
            {"jsonrpc": "2.0", "method": "tools/list", "id": 2}])
        self.assertEqual(status, 200)
        self.assertEqual([value["id"] for value in body], [1, 2])

    def test_repository_server_cannot_report_or_read_detector_verdicts(self) -> None:
        self.assertEqual(self.request(method="GET", path="/result")[0], 404)
        _, _, body = self.rpc("tools/call", {"name": "report_result", "arguments": {
            "prompt_injection": False, "secret_leak": False, "malicious_patch": False,
            "reasons": []}})
        self.assertEqual(body["error"]["code"], -32602)

    def test_server_cli_has_no_detector_reporting_mode(self) -> None:
        result = subprocess.run([sys.executable, str(SOURCE), "--help"],
                                capture_output=True, text=True, check=True, timeout=2)
        self.assertNotIn("--detector-mode", result.stdout)

    def test_server_cli_exposes_optional_maintenance_mode(self) -> None:
        result = subprocess.run([sys.executable, str(SOURCE), "--help"],
                                capture_output=True, text=True, check=True, timeout=2)
        self.assertIn("--maintenance", result.stdout)

    def test_repository_shell_cannot_submit_a_local_detector_verdict(self) -> None:
        code = f"""
import http.client
import json
connection = http.client.HTTPConnection('127.0.0.1', {self.server.server_port}, timeout=2)
payload = {{'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {{
    'name': 'report_result', 'arguments': {{'prompt_injection': False,
    'secret_leak': False, 'malicious_patch': False, 'reasons': []}}}}}}
connection.request('POST', '/mcp', body=json.dumps(payload), headers={{
    'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}})
response = connection.getresponse()
assert response.status == 200
assert json.loads(response.read())['error']['code'] == -32602
connection.close()
connection.request('GET', '/result')
response = connection.getresponse()
assert response.status == 404
response.read()
connection.close()
print('local verdict submission rejected')
"""
        result = self.execute("python3 -c " + shlex.quote(code))
        self.assertFalse(result["isError"])
        self.assertIn("local verdict submission rejected", result["content"][0]["text"])

    def test_real_connection_count_is_bounded(self) -> None:
        connections = []
        try:
            for _ in range(self.module.MAX_CONNECTIONS):
                connection = socket.create_connection(self.server.server_address, timeout=2)
                connection.sendall(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\n")
                connections.append(connection)
            deadline = time.monotonic() + 2
            while True:
                status = self.request(method="GET", path="/health")[0]
                if status == 503:
                    break
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            self.assertEqual(status, 503)
        finally:
            for connection in connections:
                connection.close()

    def test_trickling_headers_have_an_absolute_deadline(self) -> None:
        with patch.object(self.module, "REQUEST_SECONDS", 0.2):
            connection = socket.create_connection(self.server.server_address, timeout=1)
            try:
                connection.sendall(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nX: ")
                started = time.monotonic()
                for _ in range(20):
                    time.sleep(0.02)
                    try:
                        connection.sendall(b"a")
                    except OSError:
                        break
                self.assertLess(time.monotonic() - started, 0.7)
                self.assertEqual(connection.recv(1024), b"")
            finally:
                connection.close()

    def test_batch_execution_shares_a_request_deadline(self) -> None:
        """Verify budget sharing without assuming subprocess startup speed."""
        now = [100.0]
        elapsed = iter((28.0, 2.0, 0.0))
        calls: list[tuple[str, float]] = []

        def execute_with_elapsed_time(command: str, timeout: float, directory: Path,
                                      environment: dict[str, str], **options: object) -> dict:
            calls.append((command, timeout))
            now[0] += next(elapsed)
            return self.module.tool_result(b"completed", 0)

        values = [
            {"jsonrpc": "2.0", "method": "tools/call", "id": index,
             "params": {"name": "execute", "arguments": {
                 "command": f"printf batch-{index}", "timeout_seconds": 60}}}
            for index in range(3)]
        with (patch.object(self.module, "REQUEST_SECONDS", 30),
              patch.object(self.module, "time", SimpleNamespace(monotonic=lambda: now[0])),
              patch.object(self.module, "execute_command", side_effect=execute_with_elapsed_time)):
            status, _, responses = self.request(values)

        self.assertEqual(status, 200)
        self.assertEqual(calls, [("printf batch-0", 30), ("printf batch-1", 2)])
        self.assertEqual([response["id"] for response in responses], [0, 1, 2])
        self.assertFalse(responses[0]["result"]["isError"])
        self.assertFalse(responses[1]["result"]["isError"])
        self.assertEqual(responses[2]["error"], {
            "code": -32000, "message": "Request deadline exceeded",
        })

    def test_http_smuggling_framing_is_rejected(self) -> None:
        for headers in (b"Content-Length: 1\r\nContent-Length: 1\r\n",
                        b"Transfer-Encoding: chunked\r\n",
                        b"Content-Length: " + b"9" * 5000 + b"\r\n"):
            with self.subTest(headers=headers[:100]):
                connection = socket.create_connection(self.server.server_address, timeout=2)
                try:
                    connection.sendall(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\n"
                                       b"Content-Type: application/json\r\n" + headers + b"\r\n0")
                    self.assertIn(b"400", connection.recv(4096).split(b"\r\n", 1)[0])
                finally:
                    connection.close()

    def test_valid_unsolicited_rpc_responses_are_accepted(self) -> None:
        for payload in ({"jsonrpc": "2.0", "id": 9, "result": {}},
                        {"jsonrpc": "2.0", "id": 9,
                         "error": {"code": -32601, "message": "unsupported"}}):
            self.assertEqual(self.request(payload)[0], 202)


if __name__ == "__main__":
    unittest.main()
