"""Durability: state an operator configured must survive a restart.

The in-memory version of this server lost every channel topic, mode, ban
and operator grant whenever the process stopped. These tests hold that
line: they start a server, configure something, stop it, start a fresh
Server object against the same database, and check what came back.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import ssl
import subprocess
import sys
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402
from harness import TEST_PASSWORD, Conn, TestServer, connect, register  # noqa: E402

from meshircd.logsetup import configure  # noqa: E402
from meshircd.server import Server  # noqa: E402


class RestartCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dir = harness.temp_dir()
        self.ts = TestServer(self.dir)
        await self.ts.start()
        self.conns: list[Conn] = []

    async def asyncTearDown(self):
        for conn in self.conns:
            await conn.close()
        await self.ts.stop()
        shutil.rmtree(self.dir, ignore_errors=True)

    async def client(self, nick=None, tls=False) -> Conn:
        conn = await connect(self.ts, tls=tls)
        self.conns.append(conn)
        if nick:
            await register(conn, nick)
        return conn

    async def restart(self):
        """Stop the server and bring a fresh one up on the same database
        and ports, exactly as a real restart would."""
        for conn in self.conns:
            await conn.close()
        self.conns.clear()
        await self.ts.server.shutdown("restarting for test")
        await asyncio.sleep(0.2)
        self.ts.server = Server(self.ts.config, configure("CRITICAL", "text"))
        self.ts.server.load_state()
        await self.ts.server.start()
        await asyncio.sleep(0.1)


class TestChannelPersistence(RestartCase):
    async def test_topic_modes_key_and_bans_survive(self):
        alice = await self.client("alice")
        alice.send(
            "JOIN #perm",
            "TOPIC #perm :this must survive",
            "MODE #perm +tn",
            "MODE #perm +k hunter2",
            "MODE #perm +b troll!*@*",
        )
        await alice.flush()
        await alice.expect("MODE #perm +b")

        await self.restart()

        fresh = await self.client("fresh")
        fresh.send("JOIN #perm")
        await fresh.flush()
        await fresh.expect(" 475 ")  # the key still applies

        fresh.clear()
        fresh.send("JOIN #perm hunter2")
        await fresh.flush()
        await fresh.expect(" 366 ")
        self.assertTrue(
            any(" 332 " in l and "this must survive" in l for l in fresh.lines),
            "topic did not survive the restart",
        )

        fresh.clear()
        fresh.send("MODE #perm", "MODE #perm b")
        await fresh.flush()
        await fresh.expect(" 368 ")
        modes = next(l for l in fresh.lines if " 324 " in l)
        self.assertIn("t", modes)
        self.assertIn("n", modes)
        self.assertTrue(
            any(" 367 " in l and "troll" in l for l in fresh.lines),
            "ban list did not survive the restart",
        )

    async def test_unconfigured_channels_are_not_stored(self):
        # Otherwise the table becomes an unbounded log of every throwaway
        # channel any unauthenticated user ever created.
        alice = await self.client("alice")
        alice.send("JOIN #ephemeral")
        await alice.flush()
        await alice.expect(" 366 ")
        alice.send("PART #ephemeral")
        await alice.flush()
        await asyncio.sleep(0.2)
        self.assertEqual(
            self.ts.server.storage.stats()["channels"], 0,
            "an unconfigured channel must not be persisted",
        )

    async def test_empty_configured_channel_still_enforces_its_modes(self):
        alice = await self.client("alice")
        alice.send("JOIN #held", "MODE #held +k secret")
        await alice.flush()
        await alice.expect("MODE #held +k")
        alice.send("PART #held")
        await alice.flush()
        await asyncio.sleep(0.2)

        bob = await self.client("bob")
        bob.send("JOIN #held")
        await bob.flush()
        await bob.expect(" 475 ")


class TestAccountPersistence(RestartCase):
    async def test_account_and_op_grant_survive(self):
        self.ts.server.accounts.create("owner", TEST_PASSWORD)

        import base64

        conn = await connect(self.ts, tls=True)
        self.conns.append(conn)
        payload = base64.b64encode(f"\0owner\0{TEST_PASSWORD}".encode()).decode()
        conn.send("CAP LS 302", "CAP REQ :sasl", "AUTHENTICATE PLAIN")
        await conn.flush()
        await conn.expect("AUTHENTICATE +")
        conn.send(f"AUTHENTICATE {payload}")
        await conn.flush()
        await conn.expect(" 903 ")
        conn.send("NICK owner", "USER owner 0 * :Owner", "CAP END")
        await conn.flush()
        await conn.expect(" 001 ")
        # Creating the channel auto-ops the founder, and setting a topic
        # is what makes the channel worth storing at all.
        conn.send("JOIN #owned", "TOPIC #owned :owned channel")
        await conn.flush()
        await conn.expect("TOPIC #owned")

        await self.restart()

        # The account still exists and still authenticates.
        self.assertEqual(
            self.ts.server.accounts.verify("owner", TEST_PASSWORD), "owner"
        )
        # And the recorded op grant came back with the channel.
        channel = self.ts.server.find_channel("#owned")
        self.assertIsNotNone(channel, "configured channel did not survive")
        self.assertEqual(channel.access.get("owner"), "o")

        conn2 = await connect(self.ts, tls=True)
        self.conns.append(conn2)
        conn2.send("CAP LS 302", "CAP REQ :sasl", "AUTHENTICATE PLAIN")
        await conn2.flush()
        await conn2.expect("AUTHENTICATE +")
        conn2.send(f"AUTHENTICATE {payload}")
        await conn2.flush()
        await conn2.expect(" 903 ")
        conn2.send("NICK owner", "USER owner 0 * :Owner", "CAP END")
        await conn2.flush()
        await conn2.expect(" 001 ")
        conn2.clear()
        conn2.send("JOIN #owned")
        await conn2.flush()
        await conn2.expect(" 366 ")
        self.assertTrue(
            any(" 353 " in l and "@owner" in l for l in conn2.lines),
            "operator status was not restored from the account",
        )

    async def test_an_unauthenticated_user_cannot_seize_a_configured_channel(self):
        # A channel with recorded access must not hand out op to whoever
        # happens to join it while it is empty.
        self.ts.server.accounts.create("owner", TEST_PASSWORD)
        channel, _ = self.ts.server.get_or_create_channel("#claimed")
        channel.topic = "configured"
        channel.access["owner"] = "o"
        self.ts.server.persist_channel(channel)

        await self.restart()

        stranger = await self.client("stranger")
        stranger.send("JOIN #claimed")
        await stranger.flush()
        await stranger.expect(" 366 ")
        self.assertFalse(
            any(" 353 " in l and "@stranger" in l for l in stranger.lines),
            "a stranger was auto-opped in a channel that already has an owner",
        )


class TestServerBanPersistence(RestartCase):
    async def test_bans_survive_and_expiry_is_honoured(self):
        self.ts.server.add_server_ban("K", "*@198.51.100.5", "spam", "admin", None)
        self.ts.server.add_server_ban("K", "*@198.51.100.6", "temp", "admin", -1)

        await self.restart()

        masks = {b["mask"] for b in self.ts.server.server_bans}
        self.assertIn("*!*@198.51.100.5", masks)
        self.assertNotIn("*!*@198.51.100.6", masks, "an expired ban must not come back")

    async def test_dline_blocks_before_registration(self):
        self.ts.server.add_server_ban("D", "127.0.0.1", "blocked", "admin", None)
        conn = await connect(self.ts)
        self.conns.append(conn)
        await conn.expect("Banned")


class TestCertFP(unittest.IsolatedAsyncioTestCase):
    """SASL EXTERNAL end to end.

    Requires tls.client_ca, because Python's ssl module cannot accept a
    client certificate it is unable to verify. Here the client's own
    self-signed certificate is the trust anchor.
    """

    async def asyncSetUp(self):
        from meshircd import config as config_module

        self.dir = harness.temp_dir()
        self.client_cert, self.client_key = harness.make_cert(self.dir, "clientcert")
        self.ts = TestServer(self.dir)
        self.ts.config = replace(
            self.ts.config,
            tls=replace(
                self.ts.config.tls, request_client_cert=True, client_ca=self.client_cert
            ),
        )
        await self.ts.start()
        self.conns: list[Conn] = []

        self.ts.server.accounts.create("certuser", TEST_PASSWORD)
        with open(self.client_cert) as handle:
            der = ssl.PEM_cert_to_DER_cert(handle.read())
        import hashlib

        self.fingerprint = hashlib.sha256(der).hexdigest()
        self.ts.server.accounts.add_fingerprint("certuser", self.fingerprint)

    async def asyncTearDown(self):
        for conn in self.conns:
            await conn.close()
        await self.ts.stop()
        shutil.rmtree(self.dir, ignore_errors=True)

    async def test_external_authenticates_with_no_password(self):
        conn = await connect(
            self.ts, tls=True, client_cert=(self.client_cert, self.client_key)
        )
        self.conns.append(conn)
        conn.send("CAP LS 302", "CAP REQ :sasl", "AUTHENTICATE EXTERNAL")
        await conn.flush()
        await conn.expect("AUTHENTICATE +")
        conn.send("AUTHENTICATE +")
        await conn.flush()
        await conn.expect(" 903 ")
        conn.send("NICK certuser", "USER c 0 * :C", "CAP END")
        await conn.flush()
        await conn.expect(" 001 ")

    async def test_external_without_a_certificate_is_refused(self):
        conn = await connect(self.ts, tls=True)
        self.conns.append(conn)
        conn.send("CAP LS 302", "CAP REQ :sasl", "AUTHENTICATE EXTERNAL")
        await conn.flush()
        await conn.expect(" 904 ")

    async def test_unregistered_fingerprint_is_refused(self):
        self.ts.server.accounts.remove_fingerprint(self.fingerprint)
        conn = await connect(
            self.ts, tls=True, client_cert=(self.client_cert, self.client_key)
        )
        self.conns.append(conn)
        conn.send("CAP LS 302", "CAP REQ :sasl", "AUTHENTICATE EXTERNAL")
        await conn.flush()
        await conn.expect("AUTHENTICATE +")
        conn.send("AUTHENTICATE +")
        await conn.flush()
        await conn.expect(" 904 ")


if __name__ == "__main__":
    unittest.main(verbosity=2)
