"""Byte-stream level concerns: line framing, idle detection, PROXY headers.

Everything here operates on raw bytes, before anything has been parsed as
an IRC message. The resource protections that belong at this level are the
ones about the *stream* rather than about any particular command.
"""

from __future__ import annotations

import asyncio
import ipaddress

from .protocol import MAX_LINE_BYTES, MAX_TAG_BYTES


class ProtocolViolation(Exception):
    """The peer broke basic protocol hygiene. Always fatal to the link."""


class ClientTimeout(Exception):
    """The peer went silent and did not answer our PING probe."""


class ProxyProtocolError(Exception):
    """A PROXY header was expected but could not be parsed."""


# A tagged line may legitimately be much longer than 512 bytes, because the
# tag section has its own separate budget.
MAX_TOTAL_LINE = MAX_LINE_BYTES + MAX_TAG_BYTES + 2


async def read_lines(client, reader: asyncio.StreamReader):
    """Yield complete IRC lines from a stream.

    TCP gives us a byte stream, not messages: one command can arrive split
    across several segments, and several commands can arrive in one. This
    turns that back into one line at a time.

    Three protections live here:

    - **Line length.** A client sending an endless line with no CRLF would
      otherwise grow the buffer forever. Note the ordering: every *complete*
      line is drained first, and only an unterminated remainder that is
      already over the limit is a violation. Checking the buffer size before
      draining would disconnect clients for legitimate pipelining, which is
      a bug this code has had before.

    - **Idle timeout.** A connection that simply stops sending holds its
      slot indefinitely. After `ping_interval` of silence we probe with
      PING; if `ping_timeout` passes with no response at all, the link is
      dead and gets reaped.

    - **Registration deadline.** An unregistered connection gets a much
      shorter leash than an established one, because it has not yet proved
      it is a client at all. This is what stops a slow-loris style hold of
      many connection slots.
    """
    limits = client.server.config.limits
    buf = b""

    while True:
        if client.registered:
            timeout = limits.ping_timeout if client.ping_pending else limits.ping_interval
        else:
            # Unregistered: one short deadline, no PING grace.
            timeout = limits.registration_timeout

        try:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        except asyncio.TimeoutError:
            if not client.registered:
                raise ClientTimeout("Registration timeout")
            if client.ping_pending:
                raise ClientTimeout("Ping timeout")
            token = client.server.config.server.name
            client.ping_pending = token
            client.send_raw(f"PING :{token}")
            await client.drain()
            continue

        if not chunk:
            if buf.strip():
                yield buf.decode("utf-8", errors="replace")
            return

        client.recv_bytes += len(chunk)
        client.ping_pending = None  # any byte at all counts as life
        buf += chunk

        while b"\r\n" in buf or b"\n" in buf:
            # Tolerate a bare LF: some scripts and netcat sessions send it,
            # and rejecting them helps nobody.
            if b"\r\n" in buf and (b"\n" not in buf or buf.index(b"\r\n") <= buf.index(b"\n")):
                raw_line, _, buf = buf.partition(b"\r\n")
            else:
                raw_line, _, buf = buf.partition(b"\n")
                raw_line = raw_line.rstrip(b"\r")
            if len(raw_line) > MAX_TOTAL_LINE:
                raise ProtocolViolation("Input line was too long")
            if raw_line:
                yield raw_line.decode("utf-8", errors="replace")

        if len(buf) > MAX_TOTAL_LINE:
            raise ProtocolViolation("Input line was too long")


# --- PROXY protocol -----------------------------------------------------
#
# When the server sits behind a TLS terminator or a TCP load balancer, every
# connection appears to come from the proxy. PROXY protocol is how the proxy
# tells us the original address, which per-IP limits and D-lines need.
#
# This is only ever read on a listener that explicitly enables it AND from a
# peer inside trusted_proxies. The header lets whoever sends it choose the
# client's apparent address, so trusting it from an arbitrary peer would
# hand every attacker a way to forge their IP.

_PROXY_V2_SIG = b"\r\n\r\n\x00\r\nQUIT\n"


def is_trusted_proxy(ip: str, trusted: tuple[str, ...]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in trusted:
        try:
            if address in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


async def read_proxy_header(reader: asyncio.StreamReader, timeout: float = 5.0):
    """Read a PROXY v1 or v2 header. Returns (ip, port) or None for LOCAL.

    Raises ProxyProtocolError if the header is absent or malformed -- on a
    proxy-protocol listener, a connection without a header is not something
    to guess about.
    """
    try:
        head = await asyncio.wait_for(reader.readexactly(12), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
        raise ProxyProtocolError("no PROXY header") from exc

    if head == _PROXY_V2_SIG:
        try:
            meta = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
            raise ProxyProtocolError("truncated PROXY v2 header") from exc
        version_command = meta[0]
        family = meta[1]
        length = int.from_bytes(meta[2:4], "big")
        if length > 536:
            raise ProxyProtocolError("PROXY v2 address block too long")
        try:
            body = await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
            raise ProxyProtocolError("truncated PROXY v2 body") from exc

        if (version_command >> 4) != 0x2:
            raise ProxyProtocolError("unsupported PROXY protocol version")
        if (version_command & 0x0F) == 0x0:  # LOCAL: proxy's own health check
            return None
        if family == 0x11 and length >= 12:  # TCP over IPv4
            return str(ipaddress.IPv4Address(body[0:4])), int.from_bytes(body[8:10], "big")
        if family == 0x21 and length >= 36:  # TCP over IPv6
            return str(ipaddress.IPv6Address(body[0:16])), int.from_bytes(body[32:34], "big")
        raise ProxyProtocolError(f"unsupported PROXY v2 address family 0x{family:02x}")

    if not head.startswith(b"PROXY "):
        raise ProxyProtocolError("not a PROXY header")

    rest = bytearray(head)
    while not rest.endswith(b"\r\n"):
        if len(rest) > 107:  # v1 maximum header length
            raise ProxyProtocolError("PROXY v1 header too long")
        try:
            byte = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
            raise ProxyProtocolError("truncated PROXY v1 header") from exc
        rest += byte

    fields = bytes(rest[:-2]).decode("ascii", errors="replace").split(" ")
    if len(fields) >= 2 and fields[1] == "UNKNOWN":
        return None
    if len(fields) < 6:
        raise ProxyProtocolError("malformed PROXY v1 header")
    try:
        return str(ipaddress.ip_address(fields[2])), int(fields[4])
    except ValueError as exc:
        raise ProxyProtocolError(f"malformed PROXY v1 address: {exc}") from None
