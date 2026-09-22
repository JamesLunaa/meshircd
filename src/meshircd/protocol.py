"""IRC wire format: parsing and serialisation.

A full line, in the most general form this server accepts, is:

    [@tags] [:source] COMMAND [param]* [:trailing]

- ``@tags`` is the IRCv3 message-tags prefix. Clients only send tags when
  they have negotiated a capability that defines them; we parse them
  unconditionally so that an unexpected tag never desynchronises the rest
  of the line.
- ``:source`` is optional and, in client->server traffic, almost always
  absent. We parse it defensively and then ignore it: a client does not get
  to choose the source we relay its messages under.
- Parameters are space-separated. The last one may be a *trailing*
  parameter, introduced by ``:``, which is the only parameter allowed to
  contain spaces or to be empty.

The parser is deliberately tolerant of the things real clients do wrong
(repeated spaces, a bare ``:`` with nothing after it) and strict about the
things that would let a malformed line be interpreted two different ways.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Tag values use a small escape alphabet so that ';', ' ' and CR/LF can
# appear in a value without terminating the tag list or the line itself.
_TAG_UNESCAPE = {"\\:": ";", "\\s": " ", "\\\\": "\\", "\\r": "\r", "\\n": "\n"}
_TAG_ESCAPE = {";": "\\:", " ": "\\s", "\\": "\\\\", "\r": "\\r", "\n": "\\n"}

MAX_LINE_BYTES = 512  # RFC 1459 message length, CRLF included.
MAX_TAG_BYTES = 8191  # IRCv3 message-tags limit for the tag section alone.


class ParseError(ValueError):
    """The line could not be interpreted as an IRC message at all."""


def unescape_tag_value(value: str) -> str:
    out = []
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value):
            pair = value[i : i + 2]
            # An undefined escape drops the backslash and keeps the
            # character, per the IRCv3 spec -- it is not an error.
            out.append(_TAG_UNESCAPE.get(pair, pair[1]))
            i += 2
        elif value[i] == "\\":
            i += 1  # trailing lone backslash is dropped
        else:
            out.append(value[i])
            i += 1
    return "".join(out)


def escape_tag_value(value: str) -> str:
    return "".join(_TAG_ESCAPE.get(c, c) for c in value)


@dataclass
class Message:
    command: str
    params: list[str] = field(default_factory=list)
    source: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    # Render the last parameter as a trailing parameter (':text') even when
    # it would survive as a plain word. Numerics and any command carrying
    # free text set this: clients treat the trailing parameter as "the
    # message", and a one-word reason that arrives without the colon is a
    # steady source of client-side parsing differences.
    force_trailing: bool = False

    def param(self, index: int, default: str = "") -> str:
        """Positional parameter access that never raises."""
        return self.params[index] if index < len(self.params) else default

    def format(self, with_tags: bool = True) -> str:
        parts = []
        if with_tags and self.tags:
            rendered = []
            for key, value in self.tags.items():
                rendered.append(f"{key}={escape_tag_value(value)}" if value else key)
            parts.append("@" + ";".join(rendered))
        if self.source:
            parts.append(f":{self.source}")
        parts.append(self.command)
        if self.params:
            *leading, last = self.params
            parts.extend(leading)
            # The last parameter needs the ':' marker whenever it could not
            # survive a round trip as a plain word.
            if self.force_trailing or last == "" or " " in last or last.startswith(":"):
                parts.append(f":{last}")
            else:
                parts.append(last)
        return " ".join(parts)

    def __str__(self) -> str:
        return self.format()


def parse(line: str) -> Message:
    """Parse one IRC line. Raises ParseError if there is no command."""
    line = line.strip("\r\n")

    tags: dict[str, str] = {}
    if line.startswith("@"):
        tagpart, _, line = line.partition(" ")
        if len(tagpart.encode("utf-8", "replace")) > MAX_TAG_BYTES:
            raise ParseError("tag section too long")
        for item in tagpart[1:].split(";"):
            if not item:
                continue
            key, sep, value = item.partition("=")
            if key:
                tags[key] = unescape_tag_value(value) if sep else ""
        line = line.lstrip(" ")

    source = None
    if line.startswith(":"):
        sourcepart, _, line = line.partition(" ")
        source = sourcepart[1:]
        line = line.lstrip(" ")

    if not line:
        raise ParseError("no command")

    # Split off the trailing parameter before tokenising, so that its
    # spaces are never mistaken for parameter separators.
    trailing = None
    if line.startswith(":"):
        trailing = line[1:]
        line = ""
    else:
        head, sep, tail = line.partition(" :")
        if sep:
            trailing = tail
            line = head

    words = [w for w in line.split(" ") if w]
    if not words:
        raise ParseError("no command")

    command = words[0].upper()
    params = words[1:]
    if trailing is not None:
        params.append(trailing)

    return Message(command=command, params=params, source=source, tags=tags)


# RFC 1459 "scandinavian" casemapping. Nicknames and channel names compare
# case-insensitively, but []\~ fold to {}|^ rather than to themselves --
# the characters were considered case pairs when the protocol was written.
# "Foo[" and "foo{" are therefore the SAME name here, which a plain
# str.lower() would get wrong. This is the mapping we advertise in
# ISUPPORT CASEMAPPING, so it must stay consistent with what we enforce.
_CASEMAP = str.maketrans("[]\\~", "{}|^")


def casefold(value: str) -> str:
    return value.lower().translate(_CASEMAP)


def truncate_utf8(raw: bytes, limit: int) -> bytes:
    """Cut a byte string to at most `limit` bytes without splitting a
    multi-byte character in half."""
    if len(raw) <= limit:
        return raw
    return raw[:limit].decode("utf-8", errors="ignore").encode("utf-8")
