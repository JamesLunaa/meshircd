"""A connected client.

The distinction this class exists to make explicit: a TCP connection is not
an IRC client, and an IRC client is not a registered user. A connection can
sit here having sent nothing, or having sent NICK but not USER, and in both
cases it is present in ``server.clients`` but must not be visible to other
users, receive messages, or count as anyone in particular.

All outbound traffic funnels through :meth:`send`, which is where three
protections live that would be easy to forget at individual call sites:
per-client capability decoration, the RFC line-length cap, and the send
queue bound.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

from . import numerics
from .protocol import MAX_LINE_BYTES, Message, casefold, truncate_utf8


def _isotime() -> str:
    # IRCv3 server-time: always UTC, always milliseconds.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + (
        f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"
    )


class Client:
    def __init__(self, server, reader, writer, ip: str, port: int, listener=None):
        self.server = server
        self.reader = reader
        self.writer = writer
        self.listener = listener

        self.ip = ip
        self.port = port
        self.connected_at = time.time()
        self.last_active = time.monotonic()

        # --- IRC identity ---------------------------------------------
        self.nick: str | None = None
        self.user: str | None = None
        self.realname: str | None = None
        self.registered = False
        self.modes: set[str] = set()
        self.channels: set[str] = set()  # casefolded keys into server.channels
        self.away: str | None = None
        self.account: str | None = None
        self.oper_name: str | None = None

        # --- connection / negotiation ---------------------------------
        self.tls = False
        self.tls_version: str | None = None
        self.tls_cipher: str | None = None
        self.certfp: str | None = None
        self.cap_negotiating = False
        self.cap_version = 301
        self.caps: set[str] = set()
        self.sasl_mechanism: str | None = None
        self.sasl_buffer: str = ""
        self.sasl_failures = 0
        self.password_sent: str | None = None

        # --- liveness / limits ----------------------------------------
        self.ping_pending: str | None = None
        self.flood_tokens = float(server.config.limits.flood_burst)
        self.flood_last = time.monotonic()
        self.should_close = False
        self.killed = False
        self.quit_reason: str | None = None
        self.sent_bytes = 0
        self.recv_bytes = 0

        self._cloaked_host: str | None = None

    # --- identity -------------------------------------------------------

    @property
    def host(self) -> str:
        """The host other users see. Cloaked unless disabled or opered."""
        if self._cloaked_host is None:
            self._cloaked_host = self.server.cloaker.cloak(self.ip)
        return self._cloaked_host

    @property
    def real_host(self) -> str:
        return self.ip

    @property
    def hostmask(self) -> str:
        return f"{self.nick or '*'}!{self.user or '*'}@{self.host}"

    @property
    def real_hostmask(self) -> str:
        """Uncloaked form. Only ever shown to operators and to the client
        about itself -- never broadcast."""
        return f"{self.nick or '*'}!{self.user or '*'}@{self.ip}"

    @property
    def is_oper(self) -> bool:
        return "o" in self.modes

    @property
    def is_invisible(self) -> bool:
        return "i" in self.modes

    @property
    def nick_lower(self) -> str:
        return casefold(self.nick) if self.nick else ""

    @property
    def idle_seconds(self) -> int:
        return int(time.monotonic() - self.last_active)

    def __str__(self):
        label = self.nick or "*"
        return f"{label}[{self.ip}:{self.port}]"

    def __repr__(self):
        return f"<Client {self}{' registered' if self.registered else ''}>"

    # --- capabilities ---------------------------------------------------

    def has_cap(self, name: str) -> bool:
        return name in self.caps

    # --- output ---------------------------------------------------------

    def send(self, message: Message | str, **tags: str):
        """Queue one message for this client.

        Accepts a Message (preferred: it can be decorated per recipient) or
        a pre-rendered string. Extra keyword tags are attached only if the
        client negotiated the capability that defines them.
        """
        if self.killed:
            return

        if isinstance(message, str):
            line = message
            if self.has_cap("server-time"):
                line = f"@time={_isotime()} {line}"
        else:
            out_tags = dict(message.tags)
            for key, value in tags.items():
                out_tags[key.replace("_", "-")] = value
            if self.has_cap("server-time"):
                out_tags.setdefault("time", _isotime())
            if not self.has_cap("message-tags"):
                # Without message-tags a client may not have negotiated the
                # vocabulary for arbitrary tags; keep only the ones its own
                # capabilities cover.
                allowed = {"time"} if self.has_cap("server-time") else set()
                if self.has_cap("account-tag"):
                    allowed.add("account")
                out_tags = {k: v for k, v in out_tags.items() if k in allowed}
            line = Message(
                command=message.command,
                params=message.params,
                source=message.source,
                tags=out_tags,
                force_trailing=message.force_trailing,
            ).format()

        self._write_line(line)

    def send_raw(self, line: str):
        """Send exactly this line, with no tag decoration. For protocol
        framing (ERROR, PING) that must not vary by capability."""
        if not self.killed:
            self._write_line(line)

    def _write_line(self, line: str):
        raw = line.encode("utf-8", errors="replace")

        # Tags do not count against the 512-byte message limit; the limit
        # applies to the message proper. Split them so a long tag section
        # cannot silently eat the message.
        if raw.startswith(b"@"):
            tagpart, sep, rest = raw.partition(b" ")
            body = truncate_utf8(rest, MAX_LINE_BYTES - 2)
            raw = tagpart + sep + body
        else:
            raw = truncate_utf8(raw, MAX_LINE_BYTES - 2)

        transport = getattr(self.writer, "transport", None)
        if transport is not None:
            buffered = transport.get_write_buffer_size()
            if buffered > self.server.config.limits.max_sendq_bytes:
                self.killed = True
                self.quit_reason = "Max SendQ exceeded"
                self.server.log.warning(
                    "sendq exceeded (%d bytes) for %s, aborting", buffered, self
                )
                # abort(), not close(): close() would try to flush a buffer
                # this client has already proven it is not draining.
                transport.abort()
                return

        try:
            self.writer.write(raw + b"\r\n")
            self.sent_bytes += len(raw) + 2
        except (ConnectionResetError, BrokenPipeError, RuntimeError, OSError):
            # The peer vanished between the buffer check and the write; its
            # own coroutine runs the cleanup.
            self.killed = True

    def send_from(self, source: str, command: str, *params: str, **tags: str):
        self.send(Message(command=command, params=list(params), source=source), **tags)

    def send_numeric(self, code: str, *params: str):
        """Send a numeric reply.

        Call sites write the final parameter with a leading ':' because
        that is how it appears in the RFC. The colon is a *wire* marker,
        not part of the text, so it is stripped here and re-applied by the
        formatter -- otherwise it would be emitted twice.
        """
        values = [self.nick or "*", *params]
        if len(values) > 1 and values[-1].startswith(":"):
            values[-1] = values[-1][1:]
        self.send(
            Message(
                command=code,
                params=values,
                source=self.server.config.server.name,
                force_trailing=True,
            )
        )

    def send_notice(self, text: str):
        """A server NOTICE to this client. Used for anything advisory that
        has no numeric of its own."""
        self.send(
            Message(
                command="NOTICE",
                params=[self.nick or "*", text],
                source=self.server.config.server.name,
                force_trailing=True,
            )
        )

    async def drain(self):
        if self.killed:
            return
        try:
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError):
            self.killed = True

    # --- rate limiting ---------------------------------------------------

    def consume_flood_token(self, cost: float = 1.0) -> bool:
        """Token bucket. False once the client has spent its burst and is
        sending faster than the sustainable refill rate.

        Operators are exempt: an oper running a script to clean up an abuse
        incident is the last connection that should be throttled.
        """
        if self.is_oper:
            return True
        limits = self.server.config.limits
        now = time.monotonic()
        elapsed = now - self.flood_last
        self.flood_last = now
        self.flood_tokens = min(
            float(limits.flood_burst),
            self.flood_tokens + elapsed * limits.flood_refill_per_sec,
        )
        if self.flood_tokens < cost:
            return False
        self.flood_tokens -= cost
        return True

    # --- shutdown --------------------------------------------------------

    def disconnect(self, reason: str):
        """Ask the read loop to stop. The loop performs the actual cleanup
        so that there is exactly one teardown path."""
        self.quit_reason = reason
        self.should_close = True

    def abort(self):
        transport = getattr(self.writer, "transport", None)
        self.killed = True
        if transport is not None:
            transport.abort()


async def close_writer(writer):
    """Close a stream writer without letting a dead peer raise."""
    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionError, OSError, asyncio.CancelledError):
        pass
