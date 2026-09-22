"""Shared test harness: run a real server in-process on throwaway ports.

The old suite drove a subprocess and slept between steps, which made it
slow and intermittently flaky. Running the server inside the test event
loop means a test can await a specific line instead of guessing how long
it will take to arrive.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import subprocess
import sys
import tempfile
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from meshircd import config as config_module  # noqa: E402
from meshircd.logsetup import configure  # noqa: E402
from meshircd.server import Server  # noqa: E402

TEST_PASSWORD = "test-password-not-a-real-one"


def make_cert(directory: str, common_name: str = "localhost") -> tuple[str, str]:
    cert = os.path.join(directory, f"{common_name}.crt")
    key = os.path.join(directory, f"{common_name}.key")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
         "-out", cert, "-days", "1", "-nodes", "-subj", f"/CN={common_name}"],
        check=True, capture_output=True,
    )
    return cert, key


def free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestServer:
    """A running Server plus the ports it is listening on."""

    def __init__(self, workdir: str, **overrides):
        self.workdir = workdir
        self.port = free_port()
        self.tls_port = free_port()
        self.cert, self.key = make_cert(workdir)

        listeners = (
            config_module.Listener(host="127.0.0.1", port=self.port),
            config_module.Listener(host="127.0.0.1", port=self.tls_port, tls=True),
        )
        cfg = config_module.Config(
            server=config_module.ServerInfo(name="irc.test", network="TestNet"),
            listeners=listeners,
            tls=config_module.TLSConfig(cert=self.cert, key=self.key),
            cloak=config_module.CloakConfig(secret="deterministic-test-secret"),
            logging=config_module.LogConfig(level="CRITICAL"),
            storage_path=os.path.join(workdir, "test.db"),
        )
        for key, value in overrides.items():
            if key == "limits":
                cfg = replace(cfg, limits=replace(cfg.limits, **value))
            elif key == "server_info":
                cfg = replace(cfg, server=replace(cfg.server, **value))
            else:
                cfg = replace(cfg, **{key: value})
        self.config = cfg
        self._server = None

    @property
    def server(self) -> Server:
        # Created lazily so a test can adjust `config` first without
        # leaking a Server (and its open database) that is never started.
        if self._server is None:
            self._server = Server(self.config, configure("CRITICAL", "text"))
        return self._server

    @server.setter
    def server(self, value):
        if self._server is not None and self._server is not value:
            self._server.storage.close()
        self._server = value

    async def start(self):
        self.server.load_state()
        await self.server.start()
        return self

    async def stop(self):
        await self.server.shutdown("test over")


class Conn:
    """A test client speaking raw IRC, with awaitable expectations."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.lines: list[str] = []
        self._task = asyncio.create_task(self._pump())

    async def _pump(self):
        try:
            while True:
                raw = await self.reader.readline()
                if not raw:
                    return
                self.lines.append(raw.decode("utf-8", errors="replace").rstrip("\r\n"))
        except (ConnectionResetError, asyncio.CancelledError, OSError, ssl.SSLError):
            return

    def send(self, *lines: str):
        for line in lines:
            self.writer.write((line + "\r\n").encode())

    async def flush(self):
        try:
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError, ssl.SSLError):
            pass

    async def expect(self, predicate, timeout: float = 4.0) -> str:
        """Wait until a received line satisfies `predicate`; return it."""
        if isinstance(predicate, str):
            needle = predicate
            predicate = lambda line: needle in line  # noqa: E731
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        index = 0
        while loop.time() < deadline:
            while index < len(self.lines):
                if predicate(self.lines[index]):
                    return self.lines[index]
                index += 1
            await asyncio.sleep(0.01)
        raise AssertionError(
            f"timed out waiting for match; received:\n" + "\n".join(self.lines[-40:])
        )

    async def settle(self, quiet: float = 0.25, timeout: float = 2.0):
        """Wait until no new line has arrived for `quiet` seconds."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        count = len(self.lines)
        stable_since = loop.time()
        while loop.time() < deadline:
            await asyncio.sleep(0.02)
            if len(self.lines) != count:
                count = len(self.lines)
                stable_since = loop.time()
            elif loop.time() - stable_since >= quiet:
                return
        return

    def has(self, needle: str) -> bool:
        return any(needle in line for line in self.lines)

    def numerics(self) -> set[str]:
        found = set()
        for line in self.lines:
            parts = line.split(" ")
            if len(parts) > 1 and parts[0].startswith(":") and parts[1].isdigit():
                found.add(parts[1])
        return found

    def clear(self):
        self.lines.clear()

    async def close(self):
        self._task.cancel()
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except (ConnectionError, OSError, ssl.SSLError, asyncio.CancelledError):
            pass


async def connect(test_server: TestServer, tls: bool = False, client_cert=None) -> Conn:
    context = None
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if client_cert:
            context.load_cert_chain(client_cert[0], client_cert[1])
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", test_server.tls_port if tls else test_server.port, ssl=context
    )
    return Conn(reader, writer)


async def register(conn: Conn, nick: str, caps: str = "", tls_wait: bool = True) -> Conn:
    if caps:
        conn.send("CAP LS 302", f"CAP REQ :{caps}")
    conn.send(f"NICK {nick}", f"USER {nick} 0 * :{nick} Realname")
    if caps:
        conn.send("CAP END")
    await conn.flush()
    if tls_wait:
        await conn.expect(" 001 ")
    return conn


def temp_dir() -> str:
    return tempfile.mkdtemp(prefix="meshircd-test-")
