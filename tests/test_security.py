"""Security and resource-exhaustion behaviour.

Each test here corresponds to a way a hostile or broken client could
otherwise consume the server or see something it should not.
"""

from __future__ import annotations

import asyncio
import base64
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402
from harness import TEST_PASSWORD, TestServer, connect, register  # noqa: E402
from test_integration import ServerCase  # noqa: E402

from meshircd.connection import is_trusted_proxy, read_proxy_header  # noqa: E402
from meshircd.connection import ProxyProtocolError  # noqa: E402


class TestFlooding(ServerCase):
    overrides = {"limits": {"flood_burst": 25, "flood_refill_per_sec": 1, "max_channels_per_client": 10}}

    async def test_burst_sender_is_disconnected(self):
        conn = await self.client("flooder")
        for index in range(80):
            conn.send(f"PING :{index}")
        await conn.flush()
        await conn.expect("Excess Flood")

    async def test_unparseable_garbage_still_costs_tokens(self):
        # Checked before parsing, so a flood of junk counts against the
        # budget rather than being free.
        conn = await self.client("junk")
        for index in range(80):
            conn.send(f"!!!!!!! {index}")
        await conn.flush()
        await conn.expect("Excess Flood")


class TestLineLimits(ServerCase):
    async def test_oversized_line_is_rejected(self):
        conn = await self.client("big")
        conn.clear()
        conn.send("PRIVMSG #x :" + "A" * 9000)
        await conn.flush()
        await conn.expect("too long")

    async def test_pipelining_is_not_mistaken_for_an_oversized_line(self):
        # Several commands in one TCP write is legitimate. Checking the
        # buffer size before draining complete lines would disconnect
        # these clients -- a bug this code has had before.
        conn = await connect(self.ts)
        self.conns.append(conn)
        conn.send("NICK bulk", "USER bulk 0 * :Bulk", *[f"PRIVMSG #x :{'A' * 400}" for _ in range(5)])
        await conn.flush()
        await conn.expect(" 001 ")
        self.assertFalse(conn.has("too long"))

    async def test_outbound_lines_are_truncated_to_the_limit(self):
        alice = await self.client("alice")
        bob = await self.client("bob")
        for conn in (alice, bob):
            conn.send("JOIN #t")
            await conn.flush()
            await conn.expect(" 366 ")
        alice.clear()
        # 480 characters is a legal inbound line that exceeds 512 once the
        # sender's hostmask is prepended -- exactly why truncation exists.
        bob.send("PRIVMSG #t :" + "Z" * 480)
        await bob.flush()
        line = await alice.expect("ZZZ")
        self.assertLessEqual(len(line.encode()) + 2, 512, f"{len(line) + 2} bytes")


class TestConnectionLimits(ServerCase):
    overrides = {"limits": {"max_connections_per_ip": 3, "flood_burst": 60, "max_channels_per_client": 10}}

    async def test_per_ip_limit_and_recovery(self):
        conns = []
        for index in range(3):
            conns.append(await self.client(f"user{index}"))
        extra = await connect(self.ts)
        self.conns.append(extra)
        await extra.expect("Too many connections")

        await conns[0].close()
        self.conns.remove(conns[0])
        await asyncio.sleep(0.3)
        # The counter must decrement, or the slot is leaked forever.
        recovered = await self.client("recovered")
        self.assertFalse(recovered.has("Too many connections"))


class TestRegistrationDeadline(ServerCase):
    overrides = {"limits": {"registration_timeout": 1, "max_channels_per_client": 10, "flood_burst": 30}}

    async def test_silent_connection_is_reaped(self):
        # A connection that never registers must not hold a slot: this is
        # the slow-loris case.
        conn = await connect(self.ts)
        self.conns.append(conn)
        await asyncio.sleep(2.0)
        self.assertEqual(len(self.ts.server.clients), 0, "unregistered connection was not reaped")


class TestPrivacy(ServerCase):
    async def test_real_ip_never_appears_in_relayed_traffic(self):
        alice = await self.client("alice")
        bob = await self.client("bob")
        for conn in (alice, bob):
            conn.send("JOIN #priv")
            await conn.flush()
            await conn.expect(" 366 ")
        bob.clear()
        alice.send("PRIVMSG #priv :hello", "PART #priv :bye")
        await alice.flush()
        await bob.expect("PART")
        for line in bob.lines:
            self.assertNotIn("127.0.0.1", line, f"real address leaked: {line}")

    async def test_cloaked_host_is_stable_for_one_client(self):
        alice = await self.client("alice")
        await alice.settle()
        welcome = next(l for l in alice.lines if " 001 " in l)
        host = welcome.split("@")[-1]
        alice.clear()
        alice.send("JOIN #h")
        await alice.flush()
        join = await alice.expect(" JOIN ")
        self.assertIn(host, join)


class TestSASL(ServerCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.ts.server.accounts.create("testacct", TEST_PASSWORD)

    def payload(self, account: str, password: str) -> str:
        return base64.b64encode(f"\0{account}\0{password}".encode()).decode()

    async def test_sasl_not_offered_over_plaintext(self):
        conn = await connect(self.ts)
        self.conns.append(conn)
        conn.send("CAP LS 302")
        await conn.flush()
        line = await conn.expect(" CAP ")
        self.assertNotIn("sasl", line, "SASL must not be advertised without TLS")

    async def test_sasl_refused_over_plaintext_even_if_forced(self):
        # Hiding the capability is not the only enforcement: a client that
        # ignores CAP LS and tries anyway must still be refused.
        conn = await connect(self.ts)
        self.conns.append(conn)
        conn.send("CAP LS 302", "CAP REQ :sasl", "AUTHENTICATE PLAIN")
        await conn.flush()
        await conn.expect(" 904 ")

    async def test_sasl_offered_over_tls(self):
        conn = await connect(self.ts, tls=True)
        self.conns.append(conn)
        conn.send("CAP LS 302")
        await conn.flush()
        line = await conn.expect(" CAP ")
        self.assertIn("sasl", line)

    async def test_successful_login_precedes_the_welcome(self):
        conn = await connect(self.ts, tls=True)
        self.conns.append(conn)
        conn.send("CAP LS 302", "CAP REQ :sasl", "AUTHENTICATE PLAIN")
        await conn.flush()
        await conn.expect("AUTHENTICATE +")
        conn.send(f"AUTHENTICATE {self.payload('testacct', TEST_PASSWORD)}")
        await conn.flush()
        await conn.expect(" 903 ")
        conn.send("NICK alice", "USER alice 0 * :A", "CAP END")
        await conn.flush()
        await conn.expect(" 001 ")
        # The IRCv3 spec requires the SASL result before 001.
        order = [i for i, l in enumerate(conn.lines) if " 903 " in l or " 001 " in l]
        self.assertLess(order[0], order[1])

    async def test_wrong_password_does_not_kill_the_connection(self):
        conn = await connect(self.ts, tls=True)
        self.conns.append(conn)
        conn.send("CAP LS 302", "CAP REQ :sasl", "AUTHENTICATE PLAIN")
        await conn.flush()
        await conn.expect("AUTHENTICATE +")
        conn.send(f"AUTHENTICATE {self.payload('testacct', 'wrong-password')}")
        await conn.flush()
        await conn.expect(" 904 ")
        conn.send("NICK anon", "USER anon 0 * :A", "CAP END")
        await conn.flush()
        await conn.expect(" 001 ")

    async def test_account_is_independent_of_nickname(self):
        conn = await connect(self.ts, tls=True)
        self.conns.append(conn)
        conn.send("CAP LS 302", "CAP REQ :sasl", "AUTHENTICATE PLAIN")
        await conn.flush()
        await conn.expect("AUTHENTICATE +")
        conn.send(f"AUTHENTICATE {self.payload('testacct', TEST_PASSWORD)}")
        await conn.flush()
        await conn.expect(" 903 ")
        conn.send("NICK notthataccount", "USER x 0 * :X", "CAP END")
        await conn.flush()
        await conn.expect(" 001 ")
        conn.clear()
        conn.send("WHOIS notthataccount")
        await conn.flush()
        await conn.expect(" 318 ")
        self.assertTrue(any(" 330 " in l and "testacct" in l for l in conn.lines))

    async def test_repeated_failures_close_the_link(self):
        conn = await connect(self.ts, tls=True)
        self.conns.append(conn)
        conn.send("CAP LS 302", "CAP REQ :sasl")
        await conn.flush()
        for _ in range(6):
            conn.send("AUTHENTICATE PLAIN")
            await conn.flush()
            conn.send(f"AUTHENTICATE {self.payload('testacct', 'wrong')}")
            await conn.flush()
            await asyncio.sleep(0.05)
        await conn.expect("Too many authentication failures", timeout=6)

    async def test_login_does_not_stall_other_clients(self):
        # scrypt is ~30ms and blocking; if it ran on the event loop it
        # would freeze every other connection for its duration.
        other = await self.client("pinger")
        auth = await connect(self.ts, tls=True)
        self.conns.append(auth)
        auth.send("CAP LS 302", "CAP REQ :sasl", "AUTHENTICATE PLAIN")
        await auth.flush()
        await auth.expect("AUTHENTICATE +")

        other.clear()
        loop = asyncio.get_running_loop()
        auth.send(f"AUTHENTICATE {self.payload('testacct', TEST_PASSWORD)}")
        other.send("PING :latency")
        start = loop.time()
        await asyncio.gather(auth.flush(), other.flush())
        await other.expect("latency")
        elapsed = (loop.time() - start) * 1000
        self.assertLess(elapsed, 25, f"event loop stalled for {elapsed:.1f}ms during a login")


class TestProxyProtocol(unittest.IsolatedAsyncioTestCase):
    async def feed(self, data: bytes):
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        return reader

    async def test_v1(self):
        result = await read_proxy_header(
            await self.feed(b"PROXY TCP4 203.0.113.7 10.0.0.1 56324 6667\r\nNICK a\r\n")
        )
        self.assertEqual(result, ("203.0.113.7", 56324))

    async def test_v2_ipv4_and_ipv6(self):
        import ipaddress

        sig = b"\r\n\r\n\x00\r\nQUIT\n"
        body = (
            ipaddress.IPv4Address("198.51.100.4").packed
            + ipaddress.IPv4Address("10.0.0.1").packed
            + (12345).to_bytes(2, "big") + (6667).to_bytes(2, "big")
        )
        result = await read_proxy_header(
            await self.feed(sig + bytes([0x21, 0x11]) + len(body).to_bytes(2, "big") + body)
        )
        self.assertEqual(result, ("198.51.100.4", 12345))

    async def test_missing_header_is_rejected(self):
        # A connection with no header on a proxy listener is not something
        # to guess about: guessing would let a client choose its own IP.
        with self.assertRaises(ProxyProtocolError):
            await read_proxy_header(await self.feed(b"NICK alice\r\n"))

    def test_trust_list(self):
        self.assertTrue(is_trusted_proxy("127.0.0.1", ("127.0.0.1/32",)))
        self.assertTrue(is_trusted_proxy("10.1.2.3", ("10.0.0.0/8",)))
        self.assertFalse(is_trusted_proxy("8.8.8.8", ("127.0.0.1/32",)))
        self.assertFalse(is_trusted_proxy("not-an-ip", ("127.0.0.1/32",)))


class TestOperators(ServerCase):
    async def asyncSetUp(self):
        from dataclasses import replace

        from meshircd import config as config_module
        from meshircd.accounts import new_hash

        self.dir = harness.temp_dir()
        self.ts = TestServer(self.dir)
        salt, digest = new_hash("oper-password-here")
        block = config_module.OperConfig(
            name="admin", salt=salt, password_hash=digest, host_mask="*!*@*", tls_only=False
        )
        self.ts.config = replace(self.ts.config, opers=(block,))
        await self.ts.start()
        self.conns = []

    async def oper(self, nick="admin"):
        conn = await self.client(nick)
        conn.send("OPER admin oper-password-here")
        await conn.flush()
        await conn.expect(" 381 ")
        return conn

    async def test_wrong_password_is_refused(self):
        conn = await self.client("alice")
        conn.send("OPER admin totally-wrong")
        await conn.flush()
        await conn.expect(" 491 ")

    async def test_oper_grants_privileges(self):
        conn = await self.oper()
        self.assertTrue(conn.has("+ow"))

    async def test_operators_see_the_real_address(self):
        await self.client("target")
        admin = await self.oper()
        admin.clear()
        admin.send("WHOIS target")
        await admin.flush()
        await admin.expect(" 318 ")
        self.assertTrue(any("127.0.0.1" in l for l in admin.lines))

    async def test_kill_disconnects_a_user(self):
        victim = await self.client("victim")
        admin = await self.oper()
        admin.send("KILL victim :misbehaving")
        await admin.flush()
        await victim.expect("Killed by admin")

    async def test_kline_bans_and_disconnects(self):
        victim = await self.client("victim")
        admin = await self.oper()
        admin.send("KLINE 60 *@127.0.0.1 :test ban")
        await admin.flush()
        await victim.expect("Banned")
        # The operator who issued the ban matches it too, and must not
        # have disconnected themselves.
        admin.send("PING :still-here")
        await admin.flush()
        await admin.expect("still-here")
        admin.clear()
        admin.send("STATS k")
        await admin.flush()
        await admin.expect(" 219 ")
        self.assertTrue(any(" 216 " in l for l in admin.lines))
        admin.send("UNKLINE *@127.0.0.1")
        await admin.flush()
        await admin.expect("removed")

    async def test_refuses_a_ban_matching_everything(self):
        admin = await self.oper()
        admin.clear()
        admin.send("KLINE *!*@* :oops")
        await admin.flush()
        await admin.expect("Refusing")

    async def test_non_oper_cannot_use_oper_commands(self):
        conn = await self.client("alice")
        conn.clear()
        conn.send("KILL alice :x", "KLINE *@1.2.3.4 :x", "REHASH", "WALLOPS :x")
        await conn.flush()
        await conn.settle()
        self.assertEqual(len([l for l in conn.lines if " 481 " in l]), 4)

    async def test_user_cannot_set_oper_mode_on_themselves(self):
        conn = await self.client("alice")
        conn.clear()
        conn.send("MODE alice +o")
        await conn.flush()
        await conn.settle()
        self.assertFalse(conn.has("+o"), "a user must not be able to oper themselves via MODE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
