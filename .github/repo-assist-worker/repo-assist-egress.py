#!/usr/bin/env python3
"""Credential-free CONNECT gateway. Never terminate TLS or log client input."""

import argparse
import asyncio
import contextlib
from dataclasses import dataclass
import ipaddress
import re
import socket
import time

HOST = "api.anthropic.com"
AUTHORITY = f"{HOST}:443".encode("ascii")
HEADER_LIMIT = 8192
HELLO_LIMIT = 65536


@dataclass(frozen=True)
class Limits:
    connections: int = 8
    tunnel_bytes: int = 32 * 1024 * 1024
    total_bytes: int = 512 * 1024 * 1024
    setup_seconds: float = 20
    idle_seconds: float = 300
    tunnel_seconds: float = 1800


class Cursor:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def take(self, size: int) -> bytes:
        end = self.position + size
        if end > len(self.data):
            raise ValueError("Invalid TLS length")
        result = self.data[self.position:end]
        self.position = end
        return result

    def vector(self, size: int) -> bytes:
        return self.take(int.from_bytes(self.take(size), "big"))

    def remaining(self) -> int:
        return len(self.data) - self.position


def check_connect(header: bytes) -> None:
    if len(header) > HEADER_LIMIT or not header.endswith(b"\r\n\r\n"):
        raise ValueError("Invalid CONNECT")
    lines = header[:-4].split(b"\r\n")
    parts = lines[0].split(b" ")
    if (len(parts) != 3 or parts[0] != b"CONNECT" or parts[1].lower() != AUTHORITY
            or parts[2] not in (b"HTTP/1.0", b"HTTP/1.1")):
        raise ValueError("Denied CONNECT")
    names: set[bytes] = set()
    for line in lines[1:]:
        key, separator, value = line.partition(b":")
        if not separator or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
            raise ValueError("Invalid header")
        key = key.lower()
        if key in names or any(byte < 32 and byte != 9 or byte > 126 for byte in value):
            raise ValueError("Invalid header")
        names.add(key)
        if key in (b"content-length", b"transfer-encoding", b"proxy-authorization"):
            raise ValueError("Denied header")
        if key == b"host" and value.strip().lower() != AUTHORITY:
            raise ValueError("Denied Host")


def check_client_hello(body: bytes) -> None:
    cursor = Cursor(body)
    if cursor.take(2) not in (b"\x03\x01", b"\x03\x02", b"\x03\x03"):
        raise ValueError("Invalid TLS version")
    cursor.take(32)
    if len(cursor.vector(1)) > 32:
        raise ValueError("Invalid session ID")
    suites = cursor.vector(2)
    if len(suites) < 2 or len(suites) % 2 or not cursor.vector(1):
        raise ValueError("Invalid TLS parameters")
    extensions = Cursor(cursor.vector(2))
    if cursor.remaining():
        raise ValueError("Invalid ClientHello")
    found_sni = False
    seen: set[int] = set()
    while extensions.remaining():
        kind = int.from_bytes(extensions.take(2), "big")
        value = extensions.vector(2)
        if kind in seen or kind in (0xFE0D, 0xFFCE):
            raise ValueError("Duplicate or encrypted TLS extension")
        seen.add(kind)
        if kind == 0:
            names = Cursor(value)
            entries = Cursor(names.vector(2))
            if names.remaining() or entries.take(1) != b"\0":
                raise ValueError("Invalid SNI")
            if entries.vector(2).lower() != HOST.encode("ascii") or entries.remaining():
                raise ValueError("Denied SNI")
            found_sni = True
    if not found_sni:
        raise ValueError("Missing SNI")


async def read_client_hello(reader: asyncio.StreamReader) -> bytes:
    raw, handshake = bytearray(), bytearray()
    while len(raw) < HELLO_LIMIT:
        header = await reader.readexactly(5)
        size = int.from_bytes(header[3:], "big")
        if (header[0] != 22 or header[1:3] not in (b"\x03\x01", b"\x03\x02", b"\x03\x03")
                or not 0 < size <= 16384 or len(raw) + size + 5 > HELLO_LIMIT):
            raise ValueError("Invalid TLS record")
        data = await reader.readexactly(size)
        raw.extend(header + data)
        handshake.extend(data)
        if len(handshake) >= 4:
            expected = 4 + int.from_bytes(handshake[1:4], "big")
            if handshake[0] != 1 or expected > HELLO_LIMIT:
                raise ValueError("Invalid handshake")
            if len(handshake) >= expected:
                if len(handshake) != expected:
                    raise ValueError("Trailing handshake data")
                check_client_hello(bytes(handshake[4:]))
                return bytes(raw)
    raise ValueError("ClientHello too large")


async def close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(OSError, asyncio.TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), 1)


class Gateway:
    def __init__(self, limits: Limits = Limits()) -> None:
        self.limits = limits
        self.active = 0
        self.transferred = 0

    async def connect_upstream(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        records = await asyncio.get_running_loop().getaddrinfo(
            HOST, 443, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        addresses = list(dict.fromkeys(record[4][0] for record in records))
        if not addresses or any(not ipaddress.ip_address(ip).is_global
                                or ipaddress.ip_address(ip).is_multicast for ip in addresses):
            raise ValueError("Denied DNS answer")
        for address in addresses:
            try:
                # Numeric destinations pin the validated answer; never resolve a second time.
                return await asyncio.open_connection(address, 443, family=socket.AF_INET)
            except OSError:
                continue
        raise OSError("Upstream unavailable")

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self.active >= self.limits.connections or self.transferred >= self.limits.total_bytes:
            writer.close()
            return
        self.active += 1
        upstream: asyncio.StreamWriter | None = None
        accepted = False
        used = 0
        activity = time.monotonic()

        def charge(size: int) -> None:
            nonlocal used, activity
            if (used + size > self.limits.tunnel_bytes
                    or self.transferred + size > self.limits.total_bytes):
                raise ValueError("Byte budget exhausted")
            used += size
            self.transferred += size
            activity = time.monotonic()

        async def pump(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
            while data := await source.read(16384):
                charge(len(data))
                destination.write(data)
                await destination.drain()

        async def idle_watch() -> None:
            while (remaining := self.limits.idle_seconds - (time.monotonic() - activity)) > 0:
                await asyncio.sleep(remaining)

        async def establish() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            nonlocal upstream, accepted
            check_connect(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            accepted = True
            handshake = await read_client_hello(reader)
            charge(len(handshake))
            remote, upstream = await self.connect_upstream()
            upstream.write(handshake)
            await upstream.drain()
            return remote, upstream

        async def relay(remote: asyncio.StreamReader, target: asyncio.StreamWriter) -> None:
            tasks = [asyncio.create_task(pump(reader, target)),
                     asyncio.create_task(pump(remote, writer)), asyncio.create_task(idle_watch())]
            try:
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        try:
            remote, target = await asyncio.wait_for(establish(), self.limits.setup_seconds)
            await asyncio.wait_for(relay(remote, target), self.limits.tunnel_seconds)
        except (ValueError, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            if not accepted:
                writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        finally:
            if upstream is not None:
                await close(upstream)
            await close(writer)
            self.active -= 1


async def serve(host: str, port: int) -> None:
    gateway = Gateway()
    server = await asyncio.start_server(gateway.handle, host, port, limit=HEADER_LIMIT, backlog=16)
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="0.0.0.0", type=ipaddress.IPv4Address)
    parser.add_argument("--port", default=8080, type=int)
    options = parser.parse_args()
    if not 1 <= options.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(serve(str(options.listen), options.port))


if __name__ == "__main__":
    main()
