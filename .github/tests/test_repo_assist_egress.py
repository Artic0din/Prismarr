"""Offline tests: real TCP tunnels, generated ClientHello, no live credentials."""

import asyncio
import contextlib
import importlib.util
import io
from pathlib import Path
import socket
import ssl
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "repo-assist-worker/repo-assist-egress.py"
spec = importlib.util.spec_from_file_location("claude_egress", SCRIPT)
assert spec is not None and spec.loader is not None
proxy = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = proxy
spec.loader.exec_module(proxy)


def hello(host: str | None = "api.anthropic.com") -> bytes:
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    stream = context.wrap_bio(incoming, outgoing, server_hostname=host)
    try:
        stream.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.received = bytearray()
        self.upstream_count = 0
        self.clients: list[asyncio.StreamWriter] = []
        self.backend = await asyncio.start_server(self.echo, "127.0.0.1", 0)
        address = self.backend.sockets[0].getsockname()

        class LocalGateway(proxy.Gateway):
            async def connect_upstream(inner) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
                self.upstream_count += 1
                return await asyncio.open_connection(*address)

        self.gateway = LocalGateway(proxy.Limits(setup_seconds=0.3, idle_seconds=0.15, tunnel_seconds=1))
        self.server = await asyncio.start_server(self.gateway.handle, "127.0.0.1", 0, limit=8192)
        self.address = self.server.sockets[0].getsockname()

    async def asyncTearDown(self) -> None:
        for writer in self.clients:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
        self.server.close()
        self.backend.close()
        await self.server.wait_closed()
        await self.backend.wait_closed()
        await asyncio.sleep(0.01)

    async def echo(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while data := await reader.read(8192):
                self.received.extend(data)
                writer.write(data)
                await writer.drain()
        except OSError:
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def client(self, request: bytes = b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n") -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection(*self.address)
        self.clients.append(writer)
        writer.write(request)
        await writer.drain()
        return reader, writer

    async def tunnel(self, handshake: bytes | None = None) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await self.client()
        self.assertIn(b"200", await reader.readuntil(b"\r\n\r\n"))
        writer.write(hello() if handshake is None else handshake)
        await writer.drain()
        return reader, writer

    async def test_operates_without_python311_timeout_api(self) -> None:
        with patch.object(asyncio, "timeout", None, create=True):
            handshake = hello()
            reader, _ = await self.tunnel(handshake)
            self.assertEqual(await reader.readexactly(len(handshake)), handshake)
            self.assertEqual(await asyncio.wait_for(reader.read(), 0.6), b"")

    async def test_real_tls_authentication_remains_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key, cert = Path(directory) / "key", Path(directory) / "cert"
            await asyncio.to_thread(subprocess.run, [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-keyout", str(key), "-out", str(cert), "-subj", "/CN=api.anthropic.com",
                "-addext", "subjectAltName=DNS:api.anthropic.com",
            ], check=True, capture_output=True)
            server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_tls.load_cert_chain(cert, key)
            client_tls = ssl.create_default_context(cafile=str(cert))
            address = self.backend.sockets[0].getsockname()
            self.backend.close()
            await self.backend.wait_closed()
            self.backend = await asyncio.start_server(self.echo, *address, ssl=server_tls)
            payload = b"POST /fixture HTTP/1.1\r\nAuthorization: Bearer offline-fixture\r\n\r\n"

            def exchange() -> bytes:
                with socket.create_connection(self.address, timeout=2) as connection:
                    connection.sendall(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n")
                    response = bytearray()
                    while not response.endswith(b"\r\n\r\n"):
                        data = connection.recv(1)
                        if not data:
                            raise AssertionError("CONNECT closed before response")
                        response.extend(data)
                    self.assertIn(b"200", response)
                    with client_tls.wrap_socket(connection, server_hostname="api.anthropic.com") as tls:
                        tls.sendall(payload)
                        result = bytearray()
                        while len(result) < len(payload):
                            data = tls.recv(len(payload) - len(result))
                            if not data:
                                raise AssertionError("TLS tunnel closed before response")
                            result.extend(data)
                        self.assertEqual(tls.getpeercert()["subjectAltName"], (("DNS", "api.anthropic.com"),))
                        return bytes(result)

            self.assertEqual(await asyncio.to_thread(exchange), payload)
            self.assertEqual(self.received, payload)

    async def test_malformed_or_hidden_client_hello_fails_closed(self) -> None:
        def vector(data: bytes, width: int = 2) -> bytes:
            return len(data).to_bytes(width, "big") + data

        sni = b"\x00\x00" + vector(vector(b"\x00" + vector(b"api.anthropic.com")))
        fixed = b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x00\x2f\x01\x00"
        proxy.check_client_hello(fixed + vector(sni))
        for extensions in (sni + sni, sni + b"\xfe\x0d\x00\x00", sni + b"\xff\xce\x00\x00",
                           sni[:-1], sni + b"\x00", b""):
            body = fixed + vector(extensions)
            handshake = b"\x01" + vector(body, 3)
            record = b"\x16\x03\x01" + vector(handshake)
            reader, _ = await self.tunnel(record)
            self.assertEqual(await reader.read(), b"")
        for record in (b"\x16\x03\x01\x40\x01", b"\x16\x03\x00\x00\x01\x00",
                       b"\x16\x03\x01\x00\x04\x01\xff\xff\xff"):
            reader, _ = await self.tunnel(record)
            self.assertEqual(await reader.read(), b"")
        self.assertEqual(self.upstream_count, 0)

    async def test_byte_budget_covers_both_directions_and_connections(self) -> None:
        handshake = hello()
        self.gateway.limits = proxy.Limits(tunnel_bytes=2 * len(handshake), total_bytes=2 * len(handshake))
        reader, writer = await self.tunnel(handshake)
        self.assertEqual(await reader.readexactly(len(handshake)), handshake)
        writer.write(b"must-not-reach-upstream")
        await writer.drain()
        self.assertEqual(await reader.read(), b"")
        self.assertEqual(self.received, handshake)
        refused, _ = await self.client()
        with contextlib.suppress(ConnectionResetError):
            self.assertEqual(await refused.read(), b"")
        self.assertEqual(self.upstream_count, 1)

    async def test_client_disconnect_cleans_up_tunnel(self) -> None:
        reader, writer = await self.tunnel()
        await reader.readexactly(len(hello()))
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        self.assertEqual(self.gateway.active, 0)

    async def test_matching_tls_hello_and_payload_forward_unchanged(self) -> None:
        handshake = hello()
        reader, writer = await self.tunnel(handshake)
        self.assertEqual(await reader.readexactly(len(handshake)), handshake)
        data = b"encrypted-fixture-data\x00\xff"
        writer.write(data)
        await writer.drain()
        self.assertEqual(await reader.readexactly(len(data)), data)
        self.assertEqual(self.received, handshake + data)
        self.assertEqual(self.upstream_count, 1)

    async def test_denied_authorities_never_dial(self) -> None:
        targets = [b"evil.test:443", b"127.0.0.1:443", b"[::1]:443", b"api.anthropic.com:80",
                   b"api.anthropic.com.evil:443", b"api.anthropic.com.:443", b"user@api.anthropic.com:443",
                   b"api.anthropic.com:0443", b"api.anthropic.com%00:443", b"https://api.anthropic.com:443",
                   b"api.anthropic.com:443/path", b"api.anthropic.com:443\t"]
        for target in targets:
            with self.subTest(target=target):
                reader, _ = await self.client(b"CONNECT " + target + b" HTTP/1.1\r\n\r\n")
                self.assertIn(b"403", await reader.read())
        self.assertEqual(self.upstream_count, 0)

    async def test_plain_http_and_ambiguous_headers_rejected(self) -> None:
        requests = [b"GET https://api.anthropic.com HTTP/1.1\r\n\r\n",
                    b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: evil.test\r\n\r\n",
                    b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\nHost: api.anthropic.com:443\r\n\r\n",
                    b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nContent-Length: 2\r\n\r\nxx",
                    b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n folded: bad\r\n\r\n",
                    b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nX: " + b"a" * 9000 + b"\r\n\r\n"]
        for request in requests:
            reader, _ = await self.client(request)
            self.assertIn(b"403", await reader.read())
        self.assertEqual(self.upstream_count, 0)

    async def test_wrong_missing_or_plaintext_sni_never_dials(self) -> None:
        for handshake in (hello("evil.test"), hello(None), hello("api.anthropic.com."), b"GET / HTTP/1.1\r\n\r\n"):
            reader, _ = await self.tunnel(handshake)
            self.assertEqual(await reader.read(), b"")
        self.assertEqual(self.upstream_count, 0)

    async def test_fragmented_tls_record_and_pipelined_hello(self) -> None:
        handshake = hello()
        payload = handshake[5:]
        fragmented = b"".join(b"\x16\x03\x01" + len(part).to_bytes(2, "big") + part
                              for part in (payload[:2], payload[2:41], payload[41:]))
        reader, writer = await self.client()
        await reader.readuntil(b"\r\n\r\n")
        for start in range(0, len(fragmented), 7):
            writer.write(fragmented[start:start + 7])
            await writer.drain()
        self.assertEqual(await reader.readexactly(len(fragmented)), fragmented)
        writer.close()
        reader, _ = await self.client(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n" + handshake)
        await reader.readuntil(b"\r\n\r\n")
        self.assertEqual(await reader.readexactly(len(handshake)), handshake)

    async def test_header_and_hello_deadlines_close(self) -> None:
        reader, _ = await self.client(b"CONNECT ")
        self.assertIn(b"403", await asyncio.wait_for(reader.read(), 0.8))
        reader, _ = await self.client()
        await reader.readuntil(b"\r\n\r\n")
        self.assertEqual(await asyncio.wait_for(reader.read(), 0.8), b"")
        self.assertEqual(self.upstream_count, 0)

    async def test_idle_and_lifetime_deadlines_close(self) -> None:
        handshake = hello()
        reader, _ = await self.tunnel(handshake)
        await reader.readexactly(len(handshake))
        self.assertEqual(await asyncio.wait_for(reader.read(), 0.6), b"")
        self.gateway.limits = proxy.Limits(setup_seconds=0.3, idle_seconds=2, tunnel_seconds=0.1)
        reader, _ = await self.tunnel(handshake)
        await reader.readexactly(len(handshake))
        self.assertEqual(await asyncio.wait_for(reader.read(), 0.6), b"")

    async def test_byte_budgets_fail_closed(self) -> None:
        handshake = hello()
        self.gateway.limits = proxy.Limits(tunnel_bytes=len(handshake) - 1)
        reader, _ = await self.tunnel(handshake)
        self.assertEqual(await reader.read(), b"")
        self.assertEqual(self.received, b"")
        self.gateway.limits = proxy.Limits(total_bytes=len(handshake) - 1)
        reader, _ = await self.tunnel(handshake)
        self.assertEqual(await reader.read(), b"")
        self.assertEqual(self.received, b"")

    async def test_concurrency_cap_and_slot_release(self) -> None:
        self.gateway.limits = proxy.Limits(connections=1, setup_seconds=0.3)
        reader, writer = await self.client()
        await reader.readuntil(b"\r\n\r\n")
        refused, _ = await self.client()
        with contextlib.suppress(ConnectionResetError):
            self.assertEqual(await refused.read(), b"")
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.03)
        accepted, _ = await self.client()
        self.assertIn(b"200", await accepted.readuntil(b"\r\n\r\n"))

    async def test_rejected_values_are_never_logged(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            reader, _ = await self.client(b"CONNECT attacker.test:443 HTTP/1.1\r\nX-Token: sentinel-secret\r\n\r\n")
            await reader.read()
        self.assertEqual(output.getvalue(), "")

    async def test_command_help_is_bounded(self) -> None:
        result = await asyncio.to_thread(subprocess.run, [sys.executable, str(SCRIPT), "--help"],
                                         capture_output=True, text=True, check=True)
        self.assertLess(len(result.stdout), 3000)

    async def test_real_resolver_path_rejects_nonpublic_addresses(self) -> None:
        gateway = proxy.Gateway()
        loop = asyncio.get_running_loop()
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "192.0.2.1"):
            with patch.object(loop, "getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]) as resolver:
                with self.assertRaises(ValueError):
                    await gateway.connect_upstream()
                self.assertEqual(resolver.call_args.args, ("api.anthropic.com", 443))


if __name__ == "__main__":
    unittest.main()
