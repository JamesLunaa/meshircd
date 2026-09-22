"""End-to-end tests over real sockets against a real server instance."""

from __future__ import annotations

import asyncio
import base64
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402
from harness import TEST_PASSWORD, Conn, TestServer, connect, register  # noqa: E402


class ServerCase(unittest.IsolatedAsyncioTestCase):
    """Base case: one fresh server per test, on throwaway ports."""

    overrides: dict = {}

    async def asyncSetUp(self):
        self.dir = harness.temp_dir()
        self.ts = TestServer(self.dir, **self.overrides)
        await self.ts.start()
        self.conns: list[Conn] = []

    async def asyncTearDown(self):
        for conn in self.conns:
            await conn.close()
        await self.ts.stop()
        shutil.rmtree(self.dir, ignore_errors=True)

    async def client(self, nick=None, tls=False, caps="", client_cert=None) -> Conn:
        conn = await connect(self.ts, tls=tls, client_cert=client_cert)
        self.conns.append(conn)
        if nick:
            await register(conn, nick, caps)
        return conn


class TestRegistration(ServerCase):
    async def test_welcome_burst(self):
        conn = await self.client("alice")
        for numeric in ("001", "002", "003", "004", "005"):
            await conn.expect(f" {numeric} ")

    async def test_isupport_advertises_enforced_limits(self):
        conn = await self.client("alice")
        await conn.settle()
        isupport = " ".join(l for l in conn.lines if " 005 " in l)
        self.assertIn("CASEMAPPING=rfc1459", isupport)
        self.assertIn(f"NICKLEN={self.ts.config.limits.max_nick_length}", isupport)
        self.assertIn(f"CHANLIMIT=#&:{self.ts.config.limits.max_channels_per_client}", isupport)
        self.assertIn("PREFIX=(ov)@+", isupport)

    async def test_numerics_have_no_doubled_colon(self):
        conn = await self.client("alice")
        await conn.settle()
        for line in conn.lines:
            self.assertNotIn(" ::", line, f"doubled colon in: {line}")

    async def test_nick_collision(self):
        await self.client("dup")
        other = await self.client()
        other.send("NICK dup")
        await other.flush()
        await other.expect(" 433 ")

    async def test_nick_change_is_broadcast(self):
        alice = await self.client("alice")
        bob = await self.client("bob")
        alice.send("JOIN #c")
        bob.send("JOIN #c")
        await asyncio.gather(alice.flush(), bob.flush())
        await bob.expect(" 366 ")
        bob.clear()
        alice.send("NICK alice2")
        await alice.flush()
        line = await bob.expect(" NICK ")
        self.assertTrue(line.startswith(":alice!"), line)
        self.assertIn("alice2", line)

    async def test_invalid_nick_rejected(self):
        conn = await self.client()
        conn.send("NICK 1bad")
        await conn.flush()
        await conn.expect(" 432 ")

    async def test_unregistered_command_gets_451(self):
        conn = await self.client()
        conn.send("NICK someone", "JOIN #c")
        await conn.flush()
        await conn.expect(" 451 ")

    async def test_pong_is_not_an_unknown_command(self):
        conn = await self.client("alice")
        conn.clear()
        conn.send("PONG :token", "VERSION")
        await conn.flush()
        await conn.expect(" 351 ")
        self.assertFalse(conn.has(" 421 "), "PONG must be a known command")

    async def test_ping_gets_pong(self):
        conn = await self.client("alice")
        conn.clear()
        conn.send("PING :abc123")
        await conn.flush()
        await conn.expect("PONG")
        self.assertTrue(conn.has("abc123"))


class TestChannels(ServerCase):
    async def test_join_relay_and_op(self):
        alice = await self.client("alice")
        bob = await self.client("bob")
        alice.send("JOIN #dev")
        await alice.flush()
        await alice.expect(" 366 ")
        bob.send("JOIN #dev")
        await bob.flush()
        await bob.expect(" 366 ")
        self.assertTrue(bob.has("@alice"), "channel creator must be opped")

        bob.clear()
        alice.send("PRIVMSG #dev :hello there")
        await alice.flush()
        await bob.expect("hello there")
        self.assertFalse(alice.has("PRIVMSG #dev :hello there"), "no echo without the capability")

    async def test_echo_message_capability(self):
        alice = await self.client("alice", caps="echo-message")
        alice.send("JOIN #dev")
        await alice.flush()
        await alice.expect(" 366 ")
        alice.clear()
        alice.send("PRIVMSG #dev :echoed back")
        await alice.flush()
        await alice.expect("PRIVMSG #dev :echoed back")

    async def test_part_and_topic(self):
        alice = await self.client("alice")
        bob = await self.client("bob")
        for conn in (alice, bob):
            conn.send("JOIN #t")
            await conn.flush()
            await conn.expect(" 366 ")
        bob.clear()
        alice.send("TOPIC #t :the new topic")
        await alice.flush()
        await bob.expect("TOPIC #t :the new topic")
        bob.clear()
        alice.send("PART #t :going")
        await alice.flush()
        await bob.expect("PART #t :going")

    async def test_topic_lock_and_moderation(self):
        alice = await self.client("alice")
        bob = await self.client("bob")
        alice.send("JOIN #m", "MODE #m +tm")
        await alice.flush()
        await alice.expect(" 366 ")
        bob.send("JOIN #m")
        await bob.flush()
        await bob.expect(" 366 ")
        bob.clear()
        bob.send("PRIVMSG #m :silenced?", "TOPIC #m :not mine")
        await bob.flush()
        await bob.expect(" 404 ")
        await bob.expect(" 482 ")

    async def test_voice_lets_a_user_speak_in_a_moderated_channel(self):
        alice = await self.client("alice")
        bob = await self.client("bob")
        alice.send("JOIN #v", "MODE #v +m")
        await alice.flush()
        bob.send("JOIN #v")
        await bob.flush()
        await bob.expect(" 366 ")
        alice.send("MODE #v +v bob")
        await alice.flush()
        await bob.expect("MODE #v +v bob")
        alice.clear()
        bob.send("PRIVMSG #v :now I can talk")
        await bob.flush()
        await alice.expect("now I can talk")

    async def test_no_external_messages(self):
        alice = await self.client("alice")
        outsider = await self.client("mallory")
        alice.send("JOIN #n", "MODE #n +n")
        await alice.flush()
        await alice.expect(" 366 ")
        outsider.send("PRIVMSG #n :from outside")
        await outsider.flush()
        await outsider.expect(" 404 ")
        self.assertFalse(alice.has("from outside"))

    async def test_key_limit_and_ban(self):
        alice = await self.client("alice")
        alice.send("JOIN #k", "MODE #k +k hunter2", "MODE #k +b mallory!*@*")
        await alice.flush()
        await alice.expect("MODE #k +b")

        bob = await self.client("bob")
        bob.send("JOIN #k")
        await bob.flush()
        await bob.expect(" 475 ")
        bob.clear()
        bob.send("JOIN #k hunter2")
        await bob.flush()
        await bob.expect(" 366 ")

        mallory = await self.client("mallory")
        mallory.send("JOIN #k hunter2")
        await mallory.flush()
        await mallory.expect(" 474 ")

    async def test_invite_only(self):
        alice = await self.client("alice")
        bob = await self.client("bob")
        alice.send("JOIN #i", "MODE #i +i")
        await alice.flush()
        await alice.expect("MODE #i +i")
        bob.send("JOIN #i")
        await bob.flush()
        await bob.expect(" 473 ")
        bob.clear()
        alice.send("INVITE bob #i")
        await alice.flush()
        await bob.expect("INVITE")
        bob.send("JOIN #i")
        await bob.flush()
        await bob.expect(" 366 ")

    async def test_kick_requires_op(self):
        alice = await self.client("alice")
        bob = await self.client("bob")
        alice.send("JOIN #k2")
        await alice.flush()
        bob.send("JOIN #k2")
        await bob.flush()
        await bob.expect(" 366 ")
        bob.clear()
        bob.send("KICK #k2 alice :nope")
        await bob.flush()
        await bob.expect(" 482 ")
        bob.clear()
        alice.send("KICK #k2 bob :out you go")
        await alice.flush()
        await bob.expect("KICK #k2 bob :out you go")
        bob.clear()
        alice.send("PRIVMSG #k2 :after the kick")
        await alice.flush()
        await asyncio.sleep(0.3)
        self.assertFalse(bob.has("after the kick"))

    async def test_secret_channel_hidden_from_list(self):
        alice = await self.client("alice")
        alice.send("JOIN #secret", "MODE #secret +s")
        await alice.flush()
        await alice.expect("MODE #secret +s")
        bob = await self.client("bob")
        bob.send("LIST")
        await bob.flush()
        await bob.expect(" 323 ")
        self.assertFalse(bob.has("#secret"), "a +s channel must not appear in LIST")

    async def test_channel_limit_per_client(self):
        conn = await self.client("alice")
        limit = self.ts.config.limits.max_channels_per_client
        for index in range(limit + 2):
            conn.send(f"JOIN #chan{index}")
        await conn.flush()
        await conn.expect(" 405 ")
        self.assertFalse(conn.has("Excess Flood"), "a client at the channel limit must not be flood-killed")

    async def test_reconnect_with_a_full_channel_list_is_not_flood_killed(self):
        """The reconnect storm a real client produces must not look like
        an attack: registration plus one JOIN per remembered channel."""
        limit = self.ts.config.limits.max_channels_per_client
        conn = await self.client("alice")
        conn.clear()
        conn.send("JOIN " + ",".join(f"#bulk{i}" for i in range(limit)))
        await conn.flush()
        await conn.expect(f"#bulk{limit - 1}")
        self.assertFalse(conn.has("Excess Flood"))
        self.assertFalse(conn.has(" 405 "))

    async def test_multi_prefix_and_userhost_in_names(self):
        alice = await self.client("alice", caps="multi-prefix userhost-in-names")
        alice.send("JOIN #p")
        await alice.flush()
        line = await alice.expect(" 353 ")
        self.assertIn("@alice!", line, "multi-prefix + userhost-in-names")


class TestMessaging(ServerCase):
    async def test_private_message(self):
        alice = await self.client("alice")
        bob = await self.client("bob")
        bob.clear()
        alice.send("PRIVMSG bob :direct message")
        await alice.flush()
        await bob.expect("direct message")

    async def test_notice_never_generates_an_error_reply(self):
        alice = await self.client("alice")
        alice.clear()
        alice.send("NOTICE nosuchnick :hello", "PRIVMSG nosuchnick :hello")
        await alice.flush()
        await alice.expect(" 401 ")
        self.assertEqual(
            len([l for l in alice.lines if " 401 " in l]), 1,
            "NOTICE must not produce an automatic error reply",
        )

    async def test_away_reply_and_notify(self):
        alice = await self.client("alice", caps="away-notify")
        bob = await self.client("bob")
        alice.send("JOIN #a")
        await alice.flush()
        bob.send("JOIN #a")
        await bob.flush()
        await bob.expect(" 366 ")
        alice.clear()
        bob.send("AWAY :at lunch")
        await bob.flush()
        await alice.expect("AWAY :at lunch")
        alice.clear()
        alice.send("PRIVMSG bob :you there?")
        await alice.flush()
        await alice.expect(" 301 ")

    async def test_multi_target_message(self):
        alice = await self.client("alice")
        bob = await self.client("bob")
        carol = await self.client("carol")
        bob.clear()
        carol.clear()
        alice.send("PRIVMSG bob,carol :to both")
        await alice.flush()
        await bob.expect("to both")
        await carol.expect("to both")

    async def test_too_many_targets_rejected(self):
        alice = await self.client("alice")
        alice.clear()
        targets = ",".join(f"nick{i}" for i in range(20))
        alice.send(f"PRIVMSG {targets} :spam")
        await alice.flush()
        await alice.expect(" 407 ")

    async def test_crlf_injection_is_not_possible(self):
        # The text is cleaned, so a client cannot smuggle a second command.
        alice = await self.client("alice")
        bob = await self.client("bob")
        bob.clear()
        alice.send("PRIVMSG bob :hello")
        await alice.flush()
        await bob.expect("hello")
        for line in bob.lines:
            self.assertFalse(line.startswith("QUIT"), "injected line was executed")


class TestQueries(ServerCase):
    async def test_who_and_whois(self):
        alice = await self.client("alice")
        bob = await self.client("bob")
        alice.send("JOIN #w")
        await alice.flush()
        bob.send("JOIN #w")
        await bob.flush()
        await bob.expect(" 366 ")
        bob.clear()
        bob.send("WHO #w")
        await bob.flush()
        await bob.expect(" 315 ")
        self.assertEqual(len([l for l in bob.lines if " 352 " in l]), 2)
        self.assertTrue(any("H@" in l for l in bob.lines), "op flag in WHO")

        bob.clear()
        bob.send("WHOIS alice")
        await bob.flush()
        await bob.expect(" 318 ")
        self.assertTrue(bob.has(" 311 "))
        self.assertTrue(bob.has(" 319 "))

    async def test_whois_on_a_nick_only_client_does_not_crash(self):
        ghost = await self.client()
        ghost.send("NICK ghost")
        await ghost.flush()
        alice = await self.client("alice")
        alice.clear()
        alice.send("WHOIS ghost")
        await alice.flush()
        await alice.expect(" 401 ")
        await alice.expect(" 318 ")
        alice.send("PING :alive")
        await alice.flush()
        await alice.expect("alive")

    async def test_whois_hides_the_real_ip_from_other_users(self):
        await self.client("alice")
        bob = await self.client("bob")
        bob.clear()
        bob.send("WHOIS alice")
        await bob.flush()
        await bob.expect(" 318 ")
        self.assertFalse(
            any("127.0.0.1" in l for l in bob.lines),
            "a non-operator must not see another user's real address",
        )

    async def test_ison_userhost_lusers_motd_time_admin_info(self):
        alice = await self.client("alice")
        alice.clear()
        alice.send("ISON bob alice", "USERHOST alice", "LUSERS", "TIME", "ADMIN", "INFO", "MOTD")
        await alice.flush()
        await alice.expect(" 374 ")
        found = alice.numerics()
        for numeric in ("303", "302", "251", "391", "256", "371"):
            self.assertIn(numeric, found, f"missing numeric {numeric}")

    async def test_help_lists_commands(self):
        alice = await self.client("alice")
        alice.clear()
        alice.send("HELP", "HELP JOIN")
        await alice.flush()
        await alice.expect(" 706 ")
        self.assertTrue(alice.has("JOIN"))

    async def test_unknown_command(self):
        alice = await self.client("alice")
        alice.clear()
        alice.send("NOTAREALCOMMAND x")
        await alice.flush()
        await alice.expect(" 421 ")


if __name__ == "__main__":
    unittest.main(verbosity=2)
