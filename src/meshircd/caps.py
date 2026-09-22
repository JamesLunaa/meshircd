"""IRCv3 capabilities.

A capability is a negotiated agreement that the server may send a client
something the original protocol had no room for. The rule that makes the
whole mechanism safe is that nothing changes until the client asks: a
client that negotiates nothing must see exactly the RFC 1459 stream it
would have seen from a 1993 server.

Only capabilities that are actually implemented are listed. Advertising
one we do not honour is worse than not advertising it, because the client
will change its own behaviour on the strength of the claim.
"""

from __future__ import annotations

# name -> short description of what it changes, for documentation and for
# the operator-facing HELP output.
CAPABILITIES: dict[str, str] = {
    # Names all prefixes a member holds in NAMES/WHO ("@+nick"), instead of
    # only the highest one.
    "multi-prefix": "show all membership prefixes",
    # nick!user@host in NAMES, saving the client a WHO round trip.
    "userhost-in-names": "full hostmask in NAMES",
    # Attaches the message's origin time, so a client reconnecting through
    # a bouncer can order history correctly.
    "server-time": "timestamp every message",
    # Permits arbitrary message tags on inbound and outbound messages.
    "message-tags": "arbitrary message tags",
    # Tags each message with the sender's authenticated account.
    "account-tag": "sender account as a tag",
    # ACCOUNT messages when someone in a shared channel logs in or out.
    "account-notify": "notify on login/logout",
    # AWAY messages when someone in a shared channel changes away state.
    "away-notify": "notify on away changes",
    # JOIN carries the joiner's account and realname.
    "extended-join": "account and realname in JOIN",
    # CHGHOST when a user's visible host changes under them.
    "chghost": "notify on host changes",
    # The sender receives a copy of its own message, so the client can show
    # exactly what the server relayed rather than guessing.
    "echo-message": "echo own messages back",
    # INVITE is shown to channel operators.
    "invite-notify": "notify operators of invites",
    # Lets the server announce capabilities appearing or disappearing.
    "cap-notify": "notify on capability changes",
    # SASL authentication. Advertised only over TLS.
    "sasl": "authenticate with SASL",
}

# Capabilities that require an encrypted connection to even be offered.
TLS_ONLY = frozenset({"sasl"})

# Values advertised alongside a capability when the client asked for
# CAP LS 302 (which is what signals it can parse "cap=value").
CAP_VALUES = {"sasl": "PLAIN,EXTERNAL"}


def available_for(client) -> dict[str, str]:
    """The capability set this particular connection may negotiate."""
    return {
        name: CAP_VALUES.get(name, "")
        for name in CAPABILITIES
        if name not in TLS_ONLY or client.tls
    }


def render_ls(client) -> str:
    """Render the CAP LS list, with values only for CAP LS 302 clients."""
    offered = available_for(client)
    parts = []
    for name in sorted(offered):
        value = offered[name]
        if value and client.cap_version >= 302:
            parts.append(f"{name}={value}")
        else:
            parts.append(name)
    return " ".join(parts)
