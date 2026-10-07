"""Private controller MCP sink exposes no repository or process capabilities."""
import http.client
import importlib.util
import json
from pathlib import Path
import sys
import threading
import unittest

WORKER = Path(__file__).resolve().parents[1] / 'repo-assist-worker'
GOOD = {'prompt_injection': False, 'secret_leak': False, 'malicious_patch': False, 'reasons': []}


class PrivateSinkTests(unittest.TestCase):
    def setUp(self):
        path = WORKER / 'detector_sink.py'
        self.assertTrue(path.is_file(), 'Private controller result sink is missing')
        spec = importlib.util.spec_from_file_location('detector_sink', path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        self.reports = []
        self.accept = False

        def report(value):
            self.reports.append(value)
            return self.accept, 'accepted' if self.accept else 'native eligibility rejected this verdict'

        self.server = module.ResultServer(report)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        if hasattr(self, 'server'):
            self.server.shutdown()
            self.server.server_close()
            self.thread.join()

    def request(self, payload, *, method='POST', path='/mcp', headers=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        connection.request(method, path, body, {'Content-Type': 'application/json', **(headers or {})})
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response.status, json.loads(data) if data else None

    def rpc(self, method, params=None):
        return self.request({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})

    def test_listener_is_loopback_only_and_tool_list_contains_only_report(self):
        self.assertEqual(self.server.server_address[0], '127.0.0.1')
        self.assertTrue(self.server.url.startswith('http://127.0.0.1:'))
        status, payload = self.rpc('tools/list')
        self.assertEqual(status, 200)
        self.assertEqual([tool['name'] for tool in payload['result']['tools']], ['report_result'])
        for tool in ('execute', 'Read', 'Bash', 'write_file'):
            _, payload = self.rpc('tools/call', {'name': tool, 'arguments': {'command': 'printenv'}})
            self.assertIn('error', payload)
        self.assertEqual(self.reports, [])

    def test_native_rejection_returns_tool_error_and_allows_correction(self):
        params = {'name': 'report_result', 'arguments': GOOD}
        _, payload = self.rpc('tools/call', params)
        self.assertTrue(payload['result']['isError'])
        self.assertFalse(self.server.reported.is_set())
        self.accept = True
        _, payload = self.rpc('tools/call', params)
        self.assertFalse(payload['result']['isError'])
        self.assertTrue(self.server.reported.is_set())
        _, payload = self.rpc('tools/call', params)
        self.assertTrue(payload['result']['isError'])
        self.assertEqual(self.reports, [GOOD, GOOD])

    def test_unknown_paths_methods_origins_and_oversize_requests_are_rejected(self):
        for method in ('GET', 'DELETE', 'OPTIONS'):
            self.assertIn(self.request({}, method=method)[0], (404, 405))
        self.assertEqual(self.request({}, path='/result')[0], 404)
        self.assertEqual(self.request({}, headers={'Origin': 'https://evil.example'})[0], 403)
        self.assertEqual(self.request({}, headers={'Host': 'evil.example'})[0], 403)
        # Rejection happens at the length header before the body is consumed.
        # Sending a megabyte concurrently with connection close races TCP reset.
        self.assertEqual(self.request(b'', headers={'Content-Length': str(1024 * 1024 + 1)})[0], 413)
        self.assertEqual(self.request(b'{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}')[0], 400)
        self.assertEqual(self.reports, [])


if __name__ == '__main__':
    unittest.main()
