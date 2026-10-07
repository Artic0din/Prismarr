"""Local HTTP contract tests for the gh wrapper; no credentials or model calls."""

import base64
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import pty
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import time
import tempfile
import threading
from typing import Iterator
import unittest

ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / ".github/repo-assist-worker/bin/gh"


@contextmanager
def proxy(response: bytes, status: int = 200,
          headers: dict[str, str] | None = None, delay: float = 0,
          advertised_length: int | None = None) -> Iterator[tuple[str, queue.Queue[tuple[str, dict[str, str], bytes]]]]:
    requests: queue.Queue[tuple[str, dict[str, str], bytes]] = queue.Queue()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.put((self.path, dict(self.headers), body))
            time.sleep(delay)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response) if advertised_length is None else advertised_length))
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(response)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def reply(stdout: str = "", stderr: str = "", exit_code: int = 0) -> bytes:
    return json.dumps({"stdout": stdout, "stderr": stderr, "exitCode": exit_code}).encode()


class CLITransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name) / "work dir \u2603"
        self.work.mkdir()
        self.bin = Path(self.directory.name) / "bin"
        self.bin.mkdir()
        (self.bin / "python3").symlink_to(shutil.which("python3"))
        self.environment = {
            "PATH": str(self.bin), "HOME": str(self.work), "LC_ALL": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def run_gh(self, url: str, args: list[str] | None = None, stdin: bytes = b"",
               environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run([str(WRAPPER), *(args or [])], cwd=self.work, input=stdin,
                              env={**self.environment, "AWF_CLI_PROXY_URL": url,
                                   **(environment or {})}, capture_output=True, timeout=5)

    def test_python_only_transport_preserves_argv_cwd_binary_stdin_and_output(self) -> None:
        args = ["api", "", "line one\nline two", 'a "quote"', "space tab\t", "\\", "\u2603"]
        stdin = b"\x00\xffbinary\n\n"
        with proxy(reply("stdout \u2603\n\n", "stderr \u2603\n\n", 17)) as (url, requests):
            result = self.run_gh(url, args, stdin)
            self.assertEqual(result.returncode, 17, result.stderr)
            self.assertEqual(result.stdout, "stdout \u2603\n\n".encode())
            self.assertEqual(result.stderr, "stderr \u2603\n\n".encode())
            path, headers, body = requests.get_nowait()
            self.assertEqual(path, "/exec")
            self.assertEqual(headers["Content-Type"], "application/json")
            self.assertEqual(json.loads(body), {
                "args": args, "cwd": str(self.work),
                "stdin": base64.b64encode(stdin).decode("ascii"),
            })

    def test_proxy_environment_cannot_reroute_internal_request(self) -> None:
        with proxy(reply("direct")) as (url, requests), proxy(reply("wrong")) as (trap, intercepted):
            environment = {key: trap for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                                                  "http_proxy", "https_proxy", "all_proxy")}
            environment.update({"NO_PROXY": "", "no_proxy": ""})
            result = self.run_gh(url + "/", environment=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"direct")
            self.assertEqual(requests.qsize(), 1)
            self.assertTrue(intercepted.empty())

    def test_empty_argument_vector_and_empty_streams(self) -> None:
        with proxy(reply()) as (url, requests):
            result = self.run_gh(url)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))
            self.assertEqual(json.loads(requests.get_nowait()[2])["args"], [])

    def test_http_error_is_reported_without_emitting_success_payload(self) -> None:
        for status in (400, 403, 413, 500):
            with self.subTest(status=status), proxy(json.dumps({"error": "policy rejected"}).encode(), status) as (url, _):
                result = self.run_gh(url)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertIn(str(status).encode(), result.stderr)
                self.assertIn(b"policy rejected", result.stderr)

    def test_non_json_http_error_is_safe_and_meaningful(self) -> None:
        with proxy(b"<html>upstream issue</html>", 502) as (url, _):
            result = self.run_gh(url)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"HTTP 502", result.stderr)
            self.assertNotIn(b"<html>", result.stderr)

    def test_malformed_success_fails_before_emitting_partial_output(self) -> None:
        bad_payloads = [b"not json", b"[]", b"null", b"{}", b"\xff", b'{"stdout":"x"}']
        for field, bad_values in (("stdout", (None, 3, [])), ("stderr", (None, 3, [])),
                                  ("exitCode", (None, True, "0", -1, 256, 0.5))):
            for bad in bad_values:
                value = json.loads(reply("do not emit", "do not emit"))
                value[field] = bad
                bad_payloads.append(json.dumps(value).encode())
        for payload in bad_payloads:
            with self.subTest(payload=payload), proxy(payload) as (url, _):
                result = self.run_gh(url)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"invalid response", result.stderr)
                self.assertNotIn(b"do not emit", result.stderr)
                self.assertNotIn(b"Traceback", result.stderr)

    def test_redirect_is_never_followed(self) -> None:
        with proxy(reply("redirected")) as (target, target_requests):
            with proxy(b"", 307, {"Location": target + "/exec"}) as (url, _):
                result = self.run_gh(url)
                self.assertEqual(result.returncode, 1)
                self.assertIn(b"HTTP 307", result.stderr)
                self.assertTrue(target_requests.empty())

    def test_invalid_url_fails_without_disclosing_credentials(self) -> None:
        for url in ("file:///tmp/proxy", "http://", "http://user:private@127.0.0.1",
                    "http://127.0.0.1?secret=private", "http://127.0.0.1/#private",
                    "http://127.0.0.1:invalid", "http://127.0.0.1\nprivate"):
            with self.subTest(url=url):
                result = self.run_gh(url)
                self.assertEqual(result.returncode, 1)
                self.assertIn(b"AWF_CLI_PROXY_URL", result.stderr)
                self.assertNotIn(b"private", result.stderr)
                self.assertNotIn(b"Traceback", result.stderr)

    def test_interactive_stdin_is_not_read(self) -> None:
        primary, secondary = pty.openpty()
        self.addCleanup(os.close, primary)
        self.addCleanup(os.close, secondary)
        with proxy(reply("tty")) as (url, requests):
            result = subprocess.run([str(WRAPPER)], stdin=secondary, capture_output=True,
                                    timeout=3, cwd=self.work,
                                    env={**self.environment, "AWF_CLI_PROXY_URL": url})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(requests.get_nowait()[2])["stdin"], "")

    def test_truncated_response_is_rejected_even_when_json_is_complete(self) -> None:
        with proxy(reply("do not emit"), advertised_length=10000) as (url, _):
            result = self.run_gh(url)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"incomplete response", result.stderr)

    def test_surrogate_response_is_rejected_before_emitting_any_stream(self) -> None:
        with proxy(reply("do not emit", "\ud800")) as (url, _):
            result = self.run_gh(url)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"invalid response", result.stderr)

    def test_maximum_exit_code_is_preserved(self) -> None:
        with proxy(reply(exit_code=255)) as (url, _):
            result = self.run_gh(url)
            self.assertEqual(result.returncode, 255, result.stderr)

    def python_entry(self, statements: str) -> list[str]:
        return [sys.executable, "-c",
                f"import runpy,sys; m=runpy.run_path({str(WRAPPER)!r}); "
                f"g=m['main'].__globals__; sys.argv=[{str(WRAPPER)!r}]; "
                + statements + "; sys.exit(m['main']())"]

    def test_oversized_stdin_is_rejected_before_request(self) -> None:
        with proxy(reply()) as (url, requests):
            result = subprocess.run(self.python_entry("g['MAX_STDIN_BYTES']=1024"),
                                    input=b"x" * 1025, capture_output=True, timeout=5,
                                    env={**self.environment, "AWF_CLI_PROXY_URL": url})
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"stdin exceeds", result.stderr)
            self.assertTrue(requests.empty())

    def test_oversized_request_is_rejected_before_request(self) -> None:
        with proxy(reply()) as (url, requests):
            result = subprocess.run(self.python_entry(
                "g['MAX_REQUEST_BYTES']=1024; sys.argv += ['x' * 1024]"),
                input=b"", capture_output=True, timeout=5,
                env={**self.environment, "AWF_CLI_PROXY_URL": url})
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"request exceeds", result.stderr)
            self.assertTrue(requests.empty())

    def test_oversized_response_is_rejected_before_emitting_output(self) -> None:
        with proxy(reply("x" * 2048)) as (url, _):
            result = subprocess.run(self.python_entry("g['MAX_RESPONSE_BYTES']=1024"),
                                    input=b"", capture_output=True, timeout=5,
                                    env={**self.environment, "AWF_CLI_PROXY_URL": url})
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"response exceeds", result.stderr)

    def test_deadline_bounds_stdin_that_remains_open(self) -> None:
        with proxy(reply()) as (url, requests):
            process = subprocess.Popen(self.python_entry("g['TIMEOUT_SECONDS']=0.15"),
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       env={**self.environment, "AWF_CLI_PROXY_URL": url})
            try:
                process.wait(timeout=3)
                stdout, stderr = process.communicate()
                self.assertEqual(process.returncode, 1)
                self.assertEqual(stdout, b"")
                self.assertIn(b"timed out", stderr)
                self.assertTrue(requests.empty())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_deadline_bounds_slow_http_response(self) -> None:
        with proxy(reply("late"), delay=0.3) as (url, requests):
            result = subprocess.run(self.python_entry("g['TIMEOUT_SECONDS']=0.15"),
                                    input=b"", capture_output=True, timeout=3,
                                    env={**self.environment, "AWF_CLI_PROXY_URL": url})
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"timed out", result.stderr)
            self.assertEqual(requests.qsize(), 1)

    def test_unavailable_proxy_does_not_expose_url_or_traceback(self) -> None:
        with proxy(reply()) as (url, _):
            pass
        result = self.run_gh(url)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"unavailable", result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
