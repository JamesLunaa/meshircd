"""Unit tests: parsing, validation, cloaking, storage, config, output limits.

These need no socket and no event loop, so they run first and fail fast.
"""

from __future__ import annotations

import os
import shutil
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402,F401  (inserts src/ on the path)

from meshircd import config as config_module  # noqa: E402
from meshircd.accounts import AccountStore, AccountError, new_hash, verify_config_password  # noqa: E402
from meshircd.channel import Channel  # noqa: E402
from meshircd.client import Client  # noqa: E402
from meshircd.cloak import Cloaker  # noqa: E402
from meshircd.logsetup import redact  # noqa: E402
from meshircd.protocol import Message, ParseError, casefold, parse, truncate_utf8  # noqa: E402
from meshircd.storage import Storage  # noqa: E402
from meshircd.validation import (  # noqa: E402
    clean_text, is_valid_channel, is_valid_key, is_valid_nick, mask_matches,
    normalise_mask, sanitise_username,
)


class TestParsing(unittest.TestCase):
    def test_basic(self):
        msg = parse("PRIVMSG #chan :hello world")
        self.assertEqual(msg.command, "PRIVMSG")
        self.assertEqual(msg.params, ["#chan", "hello world"])

    def test_source_and_tags(self):
        msg = parse("@time=2026-01-01T00:00:00.000Z;x=a\\sb :n!u@h JOIN #c")
        self.assertEqual(msg.tags["x"], "a b")
        self.assertEqual(msg.source, "n!u@h")
        self.assertEqual(msg.command, "JOIN")

    def test_trailing_may_contain_colons(self):
        self.assertEqual(parse("PRIVMSG #c :a :b :c").params[1], "a :b :c")

    def test_empty_trailing_is_preserved(self):
        self.assertEqual(parse("PRIVMSG #c :").params, ["#c", ""])

    def test_repeated_spaces_tolerated(self):
        self.assertEqual(parse("  JOIN   #a  key ").params, ["#a", "key"])

    def test_command_is_uppercased(self):
        self.assertEqual(parse("privmsg #c :x").command, "PRIVMSG")

    def test_empty_line_rejected(self):
        for bad in ("", "   ", ":only-a-source"):
            with self.assertRaises(ParseError):
                parse(bad)

    def test_round_trip(self):
        for line in ("PRIVMSG #c :hello world", "JOIN #c", "MODE #c +o nick"):
            self.assertEqual(parse(line).format(), line)

    def test_force_trailing(self):
        self.assertEqual(
            Message("001", ["nick", "Welcome"], force_trailing=True).format(),
            "001 nick :Welcome",
        )

    def test_casefold_is_rfc1459(self):
        self.assertEqual(casefold("Foo[]\\~"), casefold("foo{}|^"))
        self.assertNotEqual(casefold("a"), casefold("b"))

    def test_truncate_never_splits_a_character(self):
        raw = ("é" * 100).encode()
        cut = truncate_utf8(raw, 51)
        self.assertLessEqual(len(cut), 51)
        cut.decode("utf-8")  # must not raise


class TestValidation(unittest.TestCase):
    def test_nicks(self):
        for good in ("alice", "Foo[]", "a-b_c", "x" * 30):
            self.assertTrue(is_valid_nick(good, 30), good)
        for bad in ("", "1abc", "-abc", "a b", "a\rb", "x" * 31, "a,b", "a:b"):
            self.assertFalse(is_valid_nick(bad, 30), bad)

    def test_channels(self):
        for good in ("#dev", "&local", "#a.b-c"):
            self.assertTrue(is_valid_channel(good, 50), good)
        for bad in ("", "#", "dev", "#a b", "#a,b", "#a\x07b", "#" + "x" * 50):
            self.assertFalse(is_valid_channel(bad, 50), bad)

    def test_username_is_sanitised_not_trusted(self):
        self.assertEqual(sanitise_username("bad user;DROP"), "~baduserDROP")
        self.assertEqual(sanitise_username(""), "~user")
        self.assertTrue(sanitise_username("x" * 100).startswith("~"))
        self.assertLessEqual(len(sanitise_username("x" * 100)), 17)

    def test_crlf_is_stripped_from_text(self):
        # Without this, a client could inject a whole extra protocol line.
        self.assertEqual(clean_text("hi\r\nQUIT :bye", 100), "hiQUIT :bye")
        self.assertEqual(clean_text("a\x00b", 100), "ab")

    def test_mask_normalisation(self):
        self.assertEqual(normalise_mask("bad"), "bad!*@*")
        self.assertEqual(normalise_mask("*@1.2.3.4"), "*!*@1.2.3.4")
        self.assertEqual(normalise_mask("a!b@c"), "a!b@c")

    def test_mask_matching_is_case_insensitive(self):
        self.assertTrue(mask_matches("*!*@*.ip", "Alice!u@ab.cd.ef.ip"))
        self.assertFalse(mask_matches("bob!*@*", "alice!u@h"))

    def test_keys(self):
        self.assertTrue(is_valid_key("hunter2"))
        for bad in ("", "a b", "a,b", "x" * 33):
            self.assertFalse(is_valid_key(bad), bad)


class TestCloaking(unittest.TestCase):
    def setUp(self):
        self.cloaker = Cloaker("a-secret")

    def test_stable_across_instances(self):
        self.assertEqual(self.cloaker.cloak("1.2.3.4"), Cloaker("a-secret").cloak("1.2.3.4"))

    def test_depends_on_the_secret(self):
        self.assertNotEqual(self.cloaker.cloak("1.2.3.4"), Cloaker("other").cloak("1.2.3.4"))

    def test_never_contains_the_address(self):
        for address in ("203.0.113.45", "2001:db8::1"):
            self.assertNotIn(address, self.cloaker.cloak(address))

    def test_same_network_shares_a_suffix(self):
        a = self.cloaker.cloak("203.0.113.1").split(".")
        b = self.cloaker.cloak("203.0.113.2").split(".")
        c = self.cloaker.cloak("203.0.200.1").split(".")
        self.assertEqual(a[1:], b[1:], "same /24 must share the broader segments")
        self.assertNotEqual(a[1], c[1], "different /24 must differ")
        self.assertEqual(a[2], c[2], "same /16 must share the broadest segment")

    def test_ipv6(self):
        self.assertTrue(self.cloaker.cloak("2001:db8::1").endswith(".ip6"))

    def test_disabled_passes_through(self):
        self.assertEqual(Cloaker("k", enabled=False).cloak("1.2.3.4"), "1.2.3.4")


class TestRedaction(unittest.TestCase):
    def test_credentials_never_logged(self):
        # AUTHENTICATE carries the SASL password base64-encoded: encoding,
        # not encryption. It must not reach a log file.
        self.assertEqual(redact("AUTHENTICATE AGFsaWNlAHNlY3JldA=="), "AUTHENTICATE [redacted]")
        self.assertEqual(redact("PASS hunter2"), "PASS [redacted]")
        self.assertEqual(redact("OPER admin s3cret"), "OPER admin [redacted]")
        self.assertEqual(redact("@t=1 :n!u@h PASS hunter2"), "PASS [redacted]")

    def test_ordinary_traffic_is_untouched(self):
        for line in ("PRIVMSG #x :hello", "JOIN #chan key"):
            self.assertEqual(redact(line), line)


class TestChannel(unittest.TestCase):
    def test_key_hidden_from_non_members(self):
        channel = Channel("#c")
        channel.key = "hunter2"
        self.assertIn("hunter2", channel.mode_string(for_member=True)[1])
        self.assertNotIn("hunter2", channel.mode_string(for_member=False)[1])

    def test_ban_exception_overrides_ban(self):
        channel = Channel("#c")
        channel.add_list_entry("b", "bad!*@*", "op")
        self.assertTrue(channel.is_banned("bad!x@y"))
        channel.add_list_entry("e", "bad!x@*", "op")
        self.assertFalse(channel.is_banned("bad!x@y"))

    def test_only_configured_channels_persist(self):
        channel = Channel("#c")
        self.assertFalse(channel.worth_persisting())
        channel.topic = "something"
        self.assertTrue(channel.worth_persisting())

    def test_state_round_trip(self):
        channel = Channel("#Dev")
        channel.modes = {"n", "t"}
        channel.key = "k"
        channel.limit = 5
        restored = Channel.from_state(
            {**channel.to_state(), "lists": {"b": [{"mask": "m", "setter": "s", "set_at": 1}]},
             "access": {"alice": "o"}}
        )
        self.assertEqual(restored.modes, {"n", "t"})
        self.assertEqual(restored.key, "k")
        self.assertEqual(restored.limit, 5)
        self.assertEqual(restored.lists["b"], [("m", "s", 1)])
        self.assertEqual(restored.access, {"alice": "o"})


class FakeTransport:
    def __init__(self, buffered=0):
        self.buffered = buffered
        self.aborted = False

    def get_write_buffer_size(self):
        return self.buffered

    def abort(self):
        self.aborted = True


class FakeWriter:
    def __init__(self, buffered=0):
        self.transport = FakeTransport(buffered)
        self.written = []

    def write(self, data):
        self.written.append(data)


def fake_client(buffered=0):
    """A Client wired to a fake transport.

    The send-queue guard depends on the OS write buffer filling, which is
    too kernel- and timing-dependent to assert on over a real socket.
    """
    import logging

    quiet = logging.getLogger("test")
    quiet.setLevel(logging.CRITICAL)
    server = SimpleNamespace(
        config=config_module.Config(),
        cloaker=Cloaker("test"),
        log=quiet,
    )
    writer = FakeWriter(buffered)
    return Client(server, None, writer, "203.0.113.9", 1234), writer


class TestClientOutput(unittest.TestCase):
    def test_long_lines_truncated_to_the_rfc_limit(self):
        client, writer = fake_client()
        client.send("A" * 900)
        self.assertEqual(len(writer.written[0]), 512)
        self.assertTrue(writer.written[0].endswith(b"\r\n"))

    def test_truncation_keeps_valid_utf8(self):
        client, writer = fake_client()
        client.send("e" * 400 + "é" * 100)
        writer.written[0][:-2].decode("utf-8")  # must not raise

    def test_short_lines_pass_through_unchanged(self):
        client, writer = fake_client()
        client.send("PING :hello")
        self.assertEqual(writer.written, [b"PING :hello\r\n"])

    def test_sendq_overflow_aborts_the_connection(self):
        client, writer = fake_client(config_module.Config().limits.max_sendq_bytes + 1)
        client.send("PRIVMSG #x :should never be written")
        self.assertTrue(writer.transport.aborted)
        self.assertEqual(writer.written, [])
        self.assertTrue(client.killed)
        client.send("still nothing")
        self.assertEqual(writer.written, [])

    def test_tags_are_filtered_by_capability(self):
        client, writer = fake_client()
        client.nick = "alice"
        client.send(Message("PRIVMSG", ["#x", "hi"], source="s"), account="alice")
        self.assertNotIn(b"account", writer.written[-1])
        client.caps = {"account-tag"}
        client.send(Message("PRIVMSG", ["#x", "hi"], source="s"), account="alice")
        self.assertIn(b"@account=alice", writer.written[-1])

    def test_numeric_colon_is_not_doubled(self):
        client, writer = fake_client()
        client.nick = "alice"
        client.send_numeric("001", ":Welcome home")
        self.assertIn(b" 001 alice :Welcome home\r\n", writer.written[-1])

    def test_hostmask_is_cloaked_but_real_host_is_available(self):
        client, _ = fake_client()
        client.nick, client.user = "alice", "~alice"
        self.assertNotIn("203.0.113.9", client.hostmask)
        self.assertIn("203.0.113.9", client.real_hostmask)


class TestAccounts(unittest.TestCase):
    def setUp(self):
        self.dir = harness.temp_dir()
        self.store = AccountStore(Storage(os.path.join(self.dir, "a.db")))

    def tearDown(self):
        self.store.storage.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_create_and_verify(self):
        self.store.create("Alice", "correct-horse-battery")
        self.assertEqual(self.store.verify("ALICE", "correct-horse-battery"), "Alice")
        self.assertIsNone(self.store.verify("alice", "wrong"))

    def test_weak_passwords_rejected(self):
        with self.assertRaises(AccountError):
            self.store.create("bob", "short")

    def test_duplicate_rejected_case_insensitively(self):
        self.store.create("alice", "correct-horse-battery")
        with self.assertRaises(AccountError):
            self.store.create("ALICE", "correct-horse-battery")

    def test_locked_account_cannot_authenticate(self):
        self.store.create("alice", "correct-horse-battery")
        self.store.set_locked("alice", True)
        self.assertIsNone(self.store.verify("alice", "correct-horse-battery"))
        self.store.set_locked("alice", False)
        self.assertEqual(self.store.verify("alice", "correct-horse-battery"), "alice")

    def test_missing_account_costs_the_same_as_a_wrong_password(self):
        # Returning early for an unknown name would let an attacker
        # enumerate valid account names by timing alone.
        import time

        self.store.create("alice", "correct-horse-battery")
        start = time.perf_counter()
        self.store.verify("alice", "wrong")
        real = time.perf_counter() - start
        start = time.perf_counter()
        self.store.verify("nosuchaccount", "wrong")
        missing = time.perf_counter() - start
        self.assertGreater(missing / real, 0.5, f"real={real:.4f}s missing={missing:.4f}s")

    def test_certfp(self):
        self.store.create("alice", "correct-horse-battery")
        fingerprint = "ab" * 32
        self.store.add_fingerprint("alice", fingerprint.upper())
        self.assertEqual(self.store.verify_fingerprint(fingerprint), "alice")
        self.assertIsNone(self.store.verify_fingerprint("cd" * 32))
        with self.assertRaises(AccountError):
            self.store.add_fingerprint("alice", "too-short")

    def test_config_password_hashing(self):
        salt, digest = new_hash("operpassword")
        self.assertTrue(verify_config_password("operpassword", salt, digest))
        self.assertFalse(verify_config_password("wrong", salt, digest))
        self.assertFalse(verify_config_password("anything", "", ""))


class TestStorage(unittest.TestCase):
    def setUp(self):
        self.dir = harness.temp_dir()
        self.path = os.path.join(self.dir, "s.db")
        self.storage = Storage(self.path)

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_database_is_not_world_readable(self):
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_channel_round_trip(self):
        self.storage.save_channel(
            {"name_lower": "#c", "name": "#C", "topic": "t", "modes": "nt", "key": "k"}
        )
        self.storage.add_channel_list_entry("#c", "b", "bad!*@*", "op")
        self.storage.set_channel_access("#c", "alice", "o")
        loaded = self.storage.load_channels()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["topic"], "t")
        self.assertEqual(loaded[0]["lists"]["b"][0]["mask"], "bad!*@*")
        self.assertEqual(loaded[0]["access"], {"alice": "o"})

    def test_expired_bans_are_dropped_on_load(self):
        self.storage.add_server_ban("K", "a!*@*", "r", "op", 1)  # expired in 1970
        self.storage.add_server_ban("K", "b!*@*", "r", "op", None)
        masks = {b["mask"] for b in self.storage.load_server_bans()}
        self.assertEqual(masks, {"b!*@*"})

    def test_pruning_removes_only_stale_channels(self):
        self.storage.save_channel({"name_lower": "#c", "name": "#c", "topic": "t"})
        self.assertEqual(self.storage.prune_channels(3600), 0)
        self.assertEqual(self.storage.prune_channels(-1), 1)

    def test_newer_schema_refuses_to_start(self):
        self.storage._execute("UPDATE meta SET value='999' WHERE key='schema_version'")
        self.storage.close()
        with self.assertRaises(RuntimeError):
            Storage(self.path)


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.dir = harness.temp_dir()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, text: str) -> str:
        path = os.path.join(self.dir, "ircd.toml")
        with open(path, "w") as handle:
            handle.write(text)
        return path

    def test_defaults_are_loopback_only(self):
        cfg = config_module.Config()
        self.assertEqual([l.host for l in cfg.listeners], ["127.0.0.1"])
        self.assertTrue(cfg.cloak.enabled)
        self.assertEqual(cfg.opers, ())

    def test_unknown_section_is_an_error(self):
        path = self.write("[nonsense]\nx = 1\n")
        with self.assertRaises(config_module.ConfigError):
            config_module.load(path)

    def test_unknown_setting_is_an_error(self):
        path = self.write("[limits]\nnot_a_real_limit = 1\n")
        with self.assertRaises(config_module.ConfigError):
            config_module.load(path)

    def test_tls_listener_without_cert_is_rejected(self):
        path = self.write('[[listen]]\nhost="127.0.0.1"\nport=1\ntls=true\n')
        with self.assertRaises(config_module.ConfigError):
            config_module.load(path)

    def test_duplicate_listener_is_rejected(self):
        path = self.write(
            '[[listen]]\nhost="127.0.0.1"\nport=1\n[[listen]]\nhost="127.0.0.1"\nport=1\n'
        )
        with self.assertRaises(config_module.ConfigError):
            config_module.load(path)

    def test_oper_block_requires_a_hash(self):
        path = self.write('[[oper]]\nname="admin"\n')
        with self.assertRaises(config_module.ConfigError):
            config_module.load(path)

    def test_valid_config_loads(self):
        path = self.write(
            '[server]\nname="irc.example.org"\n'
            '[[listen]]\nhost="127.0.0.1"\nport=6667\n'
            '[cloak]\nsecret="abc"\n'
        )
        cfg = config_module.load(path)
        self.assertEqual(cfg.server.name, "irc.example.org")
        self.assertFalse(cfg.cloak_secret_ephemeral)

    def test_generated_cloak_secret_is_flagged(self):
        cfg = config_module.load(self.write('[server]\nname="irc.example.org"\n'))
        self.assertTrue(cfg.cloak_secret_ephemeral)


if __name__ == "__main__":
    unittest.main(verbosity=2)
