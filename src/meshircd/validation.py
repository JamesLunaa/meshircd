"""Validation of the identifiers clients supply.

Every one of these runs on attacker-controlled input from an
unauthenticated connection, so the rule is allow-list rather than
deny-list: state what a name may contain, and reject everything else.
A deny-list here would have to anticipate every character that breaks the
wire format, and it only takes one miss for a nick containing a space or a
CRLF to let a client forge protocol messages.
"""

from __future__ import annotations

import fnmatch
import re

# RFC 2812 special characters, plus the ones real networks settled on.
NICK_SPECIAL = frozenset("[]\\`_^{|}-")
CHANNEL_PREFIXES = "#&"
# Forbidden anywhere in a channel name: the two that would break the wire
# format, the list separator, and BEL (a legacy channel-key separator).
CHANNEL_FORBIDDEN = frozenset(" ,\x07:\r\n\x00")

_USER_RE = re.compile(r"^[A-Za-z0-9._\-\[\]\\`^{|}]+$")


def is_valid_nick(nick: str, max_length: int) -> bool:
    if not nick or len(nick) > max_length:
        return False
    # A leading digit would make a nick ambiguous with a numeric reply, and
    # '-' first is reserved.
    if nick[0].isdigit() or nick[0] == "-":
        return False
    return all(c.isalnum() and c.isascii() or c in NICK_SPECIAL for c in nick)


def is_valid_channel(name: str, max_length: int) -> bool:
    if len(name) < 2 or len(name) > max_length:
        return False
    if name[0] not in CHANNEL_PREFIXES:
        return False
    return not any(c in CHANNEL_FORBIDDEN for c in name[1:])


def is_valid_username(user: str) -> bool:
    return bool(user) and len(user) <= 32 and bool(_USER_RE.match(user))


def sanitise_username(user: str) -> str:
    """Make a client-supplied USER value safe to put in a hostmask.

    Clients send arbitrary text here. Rather than rejecting the connection
    over it, strip to the allowed set and mark it as unverified with a
    leading '~', which is what every network does and what users expect to
    see.
    """
    cleaned = "".join(c for c in user if _USER_RE.match(c))[:16]
    return "~" + (cleaned or "user")


def is_valid_mask(mask: str) -> bool:
    """A nick!user@host glob, as used by +b and K-lines."""
    if not mask or len(mask) > 128:
        return False
    if any(c in mask for c in " \r\n\x00,"):
        return False
    return True


def normalise_mask(mask: str) -> str:
    """Expand shorthand into a full nick!user@host mask.

    Operators type 'baduser' or '*@1.2.3.4'; both should mean what the
    person obviously intended rather than silently never matching.
    """
    if "!" in mask:
        nick, _, rest = mask.partition("!")
        user, _, host = rest.partition("@")
        return f"{nick or '*'}!{user or '*'}@{host or '*'}"
    if "@" in mask:
        user, _, host = mask.partition("@")
        return f"*!{user or '*'}@{host or '*'}"
    return f"{mask}!*@*"


def mask_matches(mask: str, hostmask: str) -> bool:
    return fnmatch.fnmatch(hostmask.lower(), mask.lower())


def is_valid_key(key: str) -> bool:
    """A channel key travels as a middle parameter, so it may not contain a
    space, and an empty key would silently mean 'no key'."""
    return bool(key) and len(key) <= 32 and not any(c in key for c in " ,\r\n\x00:")


def clean_text(text: str, limit: int) -> str:
    """Strip characters that cannot appear in a parameter, and truncate."""
    return text.replace("\r", "").replace("\n", "").replace("\x00", "")[:limit]
