"""The server object: registries, connection lifecycle, command dispatch.

The learning version of this code kept ``clients``, ``nicks`` and
``channels`` as module-level globals. That works for one process that runs
until you Ctrl-C it, and fails at everything else: configuration cannot be
reloaded, two instances cannot coexist, and a handler cannot be tested
without opening a socket. Everything mutable now hangs off this object.

Concurrency model: one asyncio task per connection, single-threaded, no
locks. The event loop is the mutual exclusion -- only one coroutine runs
between await points, so the registries below cannot be observed
half-updated. The corollary is that *nothing blocking may run on the loop*.
The two things that genuinely block (scrypt hashing, SQLite writes) are
pushed to threads; everything else must stay non-blocking or it stalls
every connected client at once.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import ssl
import time

from . import numerics
from .accounts import AccountStore
from .channel import Channel
from .client import Client, close_writer
from .cloak import Cloaker
from .config import Config
from .connection import (
    ClientTimeout,
    ProtocolViolation,
    ProxyProtocolError,
    is_trusted_proxy,
    read_lines,
    read_proxy_header,
)
from .logsetup import redact
from .protocol import ParseError, casefold, parse
from .storage import Storage
from .tlsctx import ReloadableTLS, peer_fingerprint
from .validation import mask_matches, normalise_mask

VERSION = "1.0.0"

# Channels nobody has touched in this long are dropped from the database.
CHANNEL_RETENTION_SECONDS = 90 * 24 * 3600
MAINTENANCE_INTERVAL = 300


class Server:
    def __init__(self, config: Config, log: logging.Logger | None = None):
        self.config = config
        self.log = log or logging.getLogger("ircd")

        self.storage = Storage(config.storage_path)
        self.accounts = AccountStore(self.storage)
        self.cloaker = Cloaker(
            config.cloak.secret, config.cloak.suffix, enabled=config.cloak.enabled
        )

        # --- live registries -------------------------------------------
        self.clients: set[Client] = set()
        self.nicks: dict[str, Client] = {}       # casefolded nick -> Client
        self.channels: dict[str, Channel] = {}   # casefolded name -> Channel
        self.connections_per_ip: dict[str, int] = {}

        # --- durable state loaded at startup ---------------------------
        self.server_bans: list[dict] = []

        self.created_at = time.time()
        self.motd: list[str] = []
        self.tls: ReloadableTLS | None = None
        self._servers: list[asyncio.AbstractServer] = []
        self._tasks: set[asyncio.Task] = set()
        self._shutdown = asyncio.Event()
        self._isupport_cache: list[list[str]] | None = None

        # Counters, for LUSERS and operator visibility.
        self.peak_connections = 0
        self.total_connections = 0
        self.registered_count = 0

    # --- startup / shutdown ---------------------------------------------

    def load_state(self):
        """Restore durable state. Runs before any listener is opened."""
        for state in self.storage.load_channels():
            channel = Channel.from_state(state)
            self.channels[channel.key_lower] = channel
        self.server_bans = self.storage.load_server_bans()
        self.load_motd()
        self.log.info(
            "restored %d channel(s), %d server ban(s) from %s",
            len(self.channels), len(self.server_bans), self.config.storage_path,
        )

    def load_motd(self):
        path = self.config.server.motd_file
        if not path:
            self.motd = []
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                self.motd = [line.rstrip("\n")[:400] for line in handle]
        except OSError as exc:
            self.log.warning("could not read motd file %s: %s", path, exc)
            self.motd = []

    async def start(self):
        config = self.config
        if config.cloak.enabled and config.cloak_secret_ephemeral:
            self.log.warning(
                "no cloak.secret configured -- generated a temporary one. "
                "Every user's cloaked host will CHANGE on restart and "
                "cloak-based bans will stop matching. Set cloak.secret in %s",
                config.source_path or "your config file",
            )
        if not config.opers:
            self.log.info("no [[oper]] blocks configured: no one can use OPER")

        listeners = config.resolved_listeners()
        if any(l.tls for l in listeners):
            self.tls = ReloadableTLS(config.tls)

        for listener in listeners:
            context = self.tls.context if listener.tls else None
            try:
                server = await asyncio.start_server(
                    self._make_handler(listener),
                    listener.host,
                    listener.port,
                    ssl=context,
                    # Let the OS queue connections while we are busy rather
                    # than refusing them.
                    backlog=256,
                    reuse_address=True,
                )
            except OSError as exc:
                raise RuntimeError(f"cannot listen on {listener.label}: {exc}") from None
            self._servers.append(server)
            for sock in server.sockets:
                self.log.info(
                    "listening on %s%s%s",
                    sock.getsockname(),
                    " [TLS]" if listener.tls else "",
                    " [PROXY]" if listener.proxy_protocol else "",
                )

        self._spawn(self._maintenance_loop(), "maintenance")

    def install_signal_handlers(self, loop: asyncio.AbstractEventLoop):
        for sig, handler in (
            (signal.SIGTERM, self.request_shutdown),
            (signal.SIGINT, self.request_shutdown),
            (signal.SIGHUP, self.rehash),
        ):
            try:
                loop.add_signal_handler(sig, handler)
            except (NotImplementedError, AttributeError):
                pass  # not available on this platform

    def request_shutdown(self):
        if not self._shutdown.is_set():
            self.log.info("shutdown requested")
            self._shutdown.set()

    async def serve_forever(self):
        await self._shutdown.wait()
        await self.shutdown()

    async def shutdown(self, message: str = "Server shutting down"):
        """Graceful stop: refuse new connections, tell everyone why, then
        flush durable state. Clients get a real ERROR line instead of a
        silent reset, so they can reconnect cleanly rather than retrying
        into a black hole."""
        self.log.info("shutting down: %s", message)
        for server in self._servers:
            server.close()
        for server in self._servers:
            with contextlib.suppress(Exception):
                await server.wait_closed()

        for client in list(self.clients):
            client.send_raw(f"ERROR :Closing Link: {message}")
            with contextlib.suppress(Exception):
                await client.drain()
            client.abort()

        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        self.persist_all()
        self.storage.close()
        self.log.info("shutdown complete")

    def _spawn(self, coro, name: str):
        task = asyncio.create_task(coro, name=name)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def rehash(self):
        """SIGHUP: re-read the MOTD and reload the TLS certificate.

        Deliberately narrow. Re-reading the whole config would mean
        rebinding listeners and re-deriving the cloak secret underneath
        live connections; the two things that actually change on a running
        server are the certificate (renewed by ACME) and the MOTD.
        """
        self.log.info("rehash: reloading motd and tls certificate")
        self.load_motd()
        if self.tls is not None:
            try:
                if self.tls.reload():
                    self.log.info("rehash: tls certificate reloaded")
                else:
                    self.log.info("rehash: tls certificate unchanged")
            except (ssl.SSLError, OSError) as exc:
                # Keep serving with the old certificate rather than dying
                # halfway through somebody's renewal.
                self.log.error("rehash: tls reload FAILED, keeping old cert: %s", exc)
        self.notify_opers(f"Rehash completed by signal on {self.config.server.name}")

    # --- maintenance -----------------------------------------------------

    async def _maintenance_loop(self):
        while True:
            try:
                await asyncio.sleep(MAINTENANCE_INTERVAL)
                self.expire_server_bans()
                self.persist_all()
                pruned = await asyncio.to_thread(
                    self.storage.prune_channels, CHANNEL_RETENTION_SECONDS
                )
                if pruned:
                    self.log.info("pruned %d stale channel record(s)", pruned)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.log.exception("maintenance cycle failed")

    def persist_all(self):
        for channel in list(self.channels.values()):
            self.persist_channel(channel)

    def persist_channel(self, channel: Channel):
        """Write a channel's configured state, or forget it if there is
        nothing configured worth keeping."""
        try:
            if channel.worth_persisting():
                self.storage.save_channel(channel.to_state())
                for kind, entries in channel.lists.items():
                    existing = {m for m, _, _ in entries}
                    for mask, setter, _ in entries:
                        self.storage.add_channel_list_entry(
                            channel.key_lower, kind, mask, setter
                        )
                    del existing
                for account, level in channel.access.items():
                    self.storage.set_channel_access(channel.key_lower, account, level)
                channel.dirty = False
            else:
                self.storage.forget_channel(channel.key_lower)
        except Exception:
            self.log.exception("could not persist channel %s", channel.name)

    def expire_server_bans(self):
        now = time.time()
        before = len(self.server_bans)
        self.server_bans = [
            b for b in self.server_bans if not b["expires_at"] or b["expires_at"] > now
        ]
        if len(self.server_bans) != before:
            self.storage.load_server_bans()  # also deletes expired rows

    # --- registry helpers -------------------------------------------------

    def find_client(self, nick: str) -> Client | None:
        client = self.nicks.get(casefold(nick))
        return client if client is not None and client.registered else None

    def find_any_client(self, nick: str) -> Client | None:
        """Including clients that have sent NICK but not finished
        registering. Only the nick-collision check should use this."""
        return self.nicks.get(casefold(nick))

    def find_channel(self, name: str) -> Channel | None:
        return self.channels.get(casefold(name))

    def get_or_create_channel(self, name: str) -> tuple[Channel, bool]:
        key = casefold(name)
        channel = self.channels.get(key)
        if channel is not None:
            return channel, False
        channel = Channel(name)
        self.channels[key] = channel
        return channel, True

    def maybe_drop_channel(self, channel: Channel):
        """Remove an empty channel from memory unless it holds configured
        state worth keeping across the gap until someone rejoins."""
        if channel.members:
            return
        if channel.worth_persisting():
            self.persist_channel(channel)
            # Keep it in memory too, so the next JOIN finds its modes
            # without a database round trip on the event loop.
            return
        self.channels.pop(channel.key_lower, None)

    def set_nick(self, client: Client, nick: str):
        if client.nick:
            self.nicks.pop(casefold(client.nick), None)
        self.nicks[casefold(nick)] = client
        client.nick = nick

    def common_peers(self, client: Client, include_self: bool = True) -> set[Client]:
        """Everyone sharing at least one channel with this client."""
        peers: set[Client] = set()
        for key in client.channels:
            channel = self.channels.get(key)
            if channel:
                peers.update(channel.members)
        if include_self:
            peers.add(client)
        else:
            peers.discard(client)
        return peers

    def broadcast(self, recipients, message, skip=None, require_cap: str | None = None):
        for recipient in recipients:
            if recipient is skip:
                continue
            if require_cap and not recipient.has_cap(require_cap):
                continue
            recipient.send(message)

    def notify_opers(self, text: str):
        """Server notice to every operator. The operational equivalent of
        a log line that should be visible without shell access."""
        self.log.info("opers: %s", text)
        for client in self.clients:
            if client.is_oper and client.registered:
                client.send_notice(f"*** {text}")

    # --- server bans -------------------------------------------------------

    def add_server_ban(
        self, kind: str, mask: str, reason: str, setter: str, duration: int | None
    ):
        expires = int(time.time() + duration) if duration else None
        mask = normalise_mask(mask) if kind == "K" else mask
        self.storage.add_server_ban(kind, mask, reason, setter, expires)
        self.server_bans = [b for b in self.server_bans if not (b["kind"] == kind and b["mask"] == mask)]
        self.server_bans.append(
            {"kind": kind, "mask": mask, "reason": reason, "setter": setter,
             "set_at": int(time.time()), "expires_at": expires}
        )

    def remove_server_ban(self, kind: str, mask: str) -> bool:
        if kind == "K":
            mask = normalise_mask(mask)
        removed = self.storage.remove_server_ban(kind, mask)
        self.server_bans = [
            b for b in self.server_bans if not (b["kind"] == kind and b["mask"] == mask)
        ]
        return removed

    def find_ip_ban(self, ip: str) -> dict | None:
        """D-lines: checked before registration, so a banned address never
        gets to allocate client state at all."""
        now = time.time()
        for ban in self.server_bans:
            if ban["kind"] != "D":
                continue
            if ban["expires_at"] and ban["expires_at"] <= now:
                continue
            if mask_matches(ban["mask"], ip):
                return ban
        return None

    def find_user_ban(self, hostmask: str, ip: str) -> dict | None:
        """K-lines: checked at registration, when user@host is known."""
        now = time.time()
        for ban in self.server_bans:
            if ban["kind"] != "K":
                continue
            if ban["expires_at"] and ban["expires_at"] <= now:
                continue
            if mask_matches(ban["mask"], hostmask) or mask_matches(ban["mask"], ip):
                return ban
        return None

    # --- ISUPPORT ----------------------------------------------------------

    def isupport_tokens(self) -> list[str]:
        limits = self.config.limits
        return [
            f"NETWORK={self.config.server.network}",
            "CHANTYPES=#&",
            "CHANMODES=beI,k,l,imnpst",
            "PREFIX=(ov)@+",
            f"NICKLEN={limits.max_nick_length}",
            f"CHANNELLEN={limits.max_channel_length}",
            f"TOPICLEN={limits.max_topic_length}",
            f"KICKLEN={limits.max_kick_length}",
            f"AWAYLEN={limits.max_away_length}",
            f"CHANLIMIT=#&:{limits.max_channels_per_client}",
            f"MAXLIST=beI:{limits.max_bans_per_channel}",
            f"MODES={6}",
            f"TARGMAX=PRIVMSG:{limits.max_targets_per_message},"
            f"NOTICE:{limits.max_targets_per_message}",
            "CASEMAPPING=rfc1459",
            "LINELEN=512",
            "SAFELIST",
            "EXCEPTS=e",
            "INVEX=I",
            "ELIST=CMNTU",
            "UTF8ONLY",
        ]

    def isupport_lines(self) -> list[list[str]]:
        """ISUPPORT is capped at 13 tokens per 005 line by convention, so
        the whole set has to be chunked."""
        if self._isupport_cache is None:
            tokens = self.isupport_tokens()
            self._isupport_cache = [tokens[i : i + 13] for i in range(0, len(tokens), 13)]
        return self._isupport_cache

    # --- connection lifecycle ----------------------------------------------

    def _make_handler(self, listener):
        async def handler(reader, writer):
            await self.handle_connection(reader, writer, listener)

        return handler

    async def handle_connection(self, reader, writer, listener):
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "unknown"
        port = peer[1] if peer and len(peer) > 1 else 0

        # IPv4-mapped IPv6 (::ffff:1.2.3.4) must be normalised, or per-IP
        # limits and D-lines would see the same host as two addresses.
        if ip.startswith("::ffff:") and ip.count(".") == 3:
            ip = ip[7:]

        if listener.proxy_protocol:
            if not is_trusted_proxy(ip, self.config.trusted_proxies):
                self.log.warning("PROXY listener: rejecting untrusted peer %s", ip)
                await close_writer(writer)
                return
            try:
                result = await read_proxy_header(reader)
            except ProxyProtocolError as exc:
                self.log.warning("PROXY header from %s rejected: %s", ip, exc)
                await close_writer(writer)
                return
            if result is not None:
                ip, port = result

        # --- admission control, before any state is allocated ------------
        if ban := self.find_ip_ban(ip):
            writer.write(f"ERROR :Closing Link: Banned ({ban['reason']})\r\n".encode())
            with contextlib.suppress(Exception):
                await writer.drain()
            await close_writer(writer)
            return

        limits = self.config.limits
        if len(self.clients) >= limits.max_connections:
            writer.write(b"ERROR :Closing Link: Server is full, try again later\r\n")
            with contextlib.suppress(Exception):
                await writer.drain()
            await close_writer(writer)
            self.log.warning("connection from %s refused: server full", ip)
            return
        if self.connections_per_ip.get(ip, 0) >= limits.max_connections_per_ip:
            writer.write(b"ERROR :Closing Link: Too many connections from your host\r\n")
            with contextlib.suppress(Exception):
                await writer.drain()
            await close_writer(writer)
            return

        self.connections_per_ip[ip] = self.connections_per_ip.get(ip, 0) + 1
        client = Client(self, reader, writer, ip, port, listener)
        self.clients.add(client)
        self.total_connections += 1
        self.peak_connections = max(self.peak_connections, len(self.clients))

        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is not None:
            client.tls = True
            client.tls_version = ssl_object.version()
            cipher = ssl_object.cipher()
            client.tls_cipher = cipher[0] if cipher else None
            client.certfp = peer_fingerprint(ssl_object)
            self.log.info(
                "connected %s [TLS %s %s]%s (total=%d)",
                client, client.tls_version, client.tls_cipher,
                " [certfp]" if client.certfp else "", len(self.clients),
            )
        else:
            self.log.info("connected %s (total=%d)", client, len(self.clients))

        try:
            await self._read_loop(client, reader)
        except ConnectionResetError:
            client.quit_reason = client.quit_reason or "Connection reset by peer"
        except ClientTimeout as exc:
            client.quit_reason = str(exc)
            self.log.info("%s: %s", client, exc)
        except ProtocolViolation as exc:
            client.quit_reason = str(exc)
            self.log.warning("protocol violation from %s: %s", client, exc)
            client.send_raw(f"ERROR :Closing Link: {exc}")
        except asyncio.CancelledError:
            client.quit_reason = "Server shutting down"
            raise
        except Exception:
            self.log.exception("unhandled error on connection %s", client)
            client.quit_reason = "Internal server error"
        finally:
            self.remove_client(client, client.quit_reason or "Connection closed")
            self.clients.discard(client)
            remaining = self.connections_per_ip.get(ip, 1) - 1
            if remaining <= 0:
                self.connections_per_ip.pop(ip, None)
            else:
                self.connections_per_ip[ip] = remaining
            await close_writer(writer)
            self.log.info("disconnected %s (total=%d)", client, len(self.clients))

    async def _read_loop(self, client: Client, reader):
        from .commands import dispatch

        log_raw = self.config.logging.log_raw_lines
        async for line in read_lines(client, reader):
            if log_raw:
                self.log.debug("recv %s: %s", client, redact(line))

            if not client.consume_flood_token():
                client.send_raw("ERROR :Closing Link: (Excess Flood)")
                client.quit_reason = "Excess Flood"
                self.log.warning("flood kill: %s", client)
                break

            client.last_active = time.monotonic()

            try:
                message = parse(line)
            except ParseError:
                continue

            await dispatch(self, client, message)

            await client.drain()
            if client.should_close or client.killed:
                break

    # --- registration -------------------------------------------------------

    def try_complete_registration(self, client: Client):
        """Finish registration once every prerequisite is met.

        Three conditions, and the third is the subtle one: a client that
        started capability negotiation must not be welcomed until CAP END,
        or a SASL exchange in progress would have its 900/903 replies
        arrive after 001, which the IRCv3 spec forbids.
        """
        if client.registered or client.nick is None or client.user is None:
            return
        if client.cap_negotiating:
            return

        config = self.config
        if config.server.password_hash and client.account is None:
            from .accounts import verify_config_password

            supplied = client.password_sent or ""
            if not verify_config_password(
                supplied, config.server.password_salt, config.server.password_hash
            ):
                client.send_numeric(numerics.ERR_PASSWDMISMATCH, ":Password incorrect")
                client.send_raw("ERROR :Closing Link: Password incorrect")
                client.disconnect("Bad server password")
                return

        if ban := self.find_user_ban(client.real_hostmask, client.ip):
            client.send_numeric(
                numerics.ERR_YOUREBANNEDCREEP, f":You are banned: {ban['reason']}"
            )
            client.send_raw(f"ERROR :Closing Link: Banned ({ban['reason']})")
            client.disconnect("K-lined")
            return

        client.registered = True
        self.registered_count += 1
        name = config.server.name

        client.send_numeric(
            numerics.RPL_WELCOME,
            f":Welcome to the {config.server.network} IRC Network, {client.hostmask}",
        )
        client.send_numeric(
            numerics.RPL_YOURHOST, f":Your host is {name}, running version meshircd-{VERSION}"
        )
        client.send_numeric(
            numerics.RPL_CREATED,
            ":This server was created " + time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.created_at)),
        )
        client.send_numeric(
            numerics.RPL_MYINFO, name, f"meshircd-{VERSION}", "iowsx", "beIimnpstkl", "beIkl"
        )
        for chunk in self.isupport_lines():
            client.send_numeric(numerics.RPL_ISUPPORT, *chunk, ":are supported by this server")

        from .commands.queries import send_lusers, send_motd

        send_lusers(self, client)
        send_motd(self, client)

        if client.modes:
            client.send_from(client.hostmask, "MODE", client.nick, "+" + "".join(sorted(client.modes)))

        self.log.info(
            "registered %s as %s%s", client, client.hostmask,
            f" (account {client.account})" if client.account else "",
        )

    # --- teardown ------------------------------------------------------------

    def remove_client(self, client: Client, reason: str):
        """Shared cleanup for QUIT, kill, timeout and plain disconnect.

        Safe to call twice: every operation is a discard or a guarded pop,
        so a second call after an explicit QUIT does nothing.
        """
        peers: set[Client] = set()
        for key in list(client.channels):
            channel = self.channels.get(key)
            if channel is None:
                continue
            peers.update(channel.members)
            channel.remove_member(client)
            self.maybe_drop_channel(channel)
        client.channels.clear()
        peers.discard(client)

        if client.nick and self.nicks.get(casefold(client.nick)) is client:
            self.nicks.pop(casefold(client.nick), None)

        if peers and client.registered:
            from .protocol import Message

            quit_message = Message(
                command="QUIT", params=[reason], source=client.hostmask, force_trailing=True
            )
            self.broadcast(peers, quit_message)

    # --- introspection --------------------------------------------------------

    def stats(self) -> dict:
        return {
            "clients": len(self.clients),
            "registered": sum(1 for c in self.clients if c.registered),
            "unknown": sum(1 for c in self.clients if not c.registered),
            "invisible": sum(1 for c in self.clients if c.registered and c.is_invisible),
            "opers": sum(1 for c in self.clients if c.is_oper),
            "channels": len(self.channels),
            "peak": self.peak_connections,
            "total_connections": self.total_connections,
            "uptime_seconds": int(time.time() - self.created_at),
        }
