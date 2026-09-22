"""Message delivery: PRIVMSG, NOTICE, TAGMSG, AWAY."""

from __future__ import annotations

from .. import numerics
from ..protocol import Message
from ..validation import clean_text
from . import command


def _deliver_to_channel(server, client, channel, command_name: str, text: str, tags: dict):
    """Relay a message to a channel, or explain why we will not."""
    is_member = channel.has_member(client)

    # +n: no messages from outside the channel. Without it, anyone can
    # spam a channel they were banned from simply by not joining it.
    if not is_member and "n" in channel.modes:
        return f":Cannot send to channel (+n)"
    # +m: moderated. Only voiced members and ops may speak.
    if "m" in channel.modes and not channel.is_voiced(client) and not client.is_oper:
        return ":Cannot send to channel (+m)"
    # A banned user cannot talk its way around the ban either.
    if is_member and channel.is_banned(client.hostmask) and not channel.is_voiced(client):
        return ":Cannot send to channel (+b)"
    if not is_member and not channel.is_voiced(client) and channel.is_banned(client.hostmask):
        return ":Cannot send to channel (+b)"

    outgoing = Message(
        command=command_name, params=[channel.name, text], source=client.hostmask,
        tags=tags, force_trailing=True,
    )
    extra = {"account": client.account} if client.account else {}
    for member in channel.members:
        if member is client:
            # echo-message: the sender gets its own message back, so the
            # client displays exactly what the server relayed rather than
            # optimistically rendering what it hoped was sent.
            if member.has_cap("echo-message"):
                member.send(outgoing, **extra)
            continue
        member.send(outgoing, **extra)
    return None


def _deliver_to_user(server, client, target, command_name: str, text: str, tags: dict):
    outgoing = Message(
        command=command_name, params=[target.nick, text], source=client.hostmask,
        tags=tags, force_trailing=True,
    )
    extra = {"account": client.account} if client.account else {}
    target.send(outgoing, **extra)
    if client.has_cap("echo-message"):
        client.send(outgoing, **extra)


def _route(server, client, msg, command_name: str, quiet: bool):
    """Shared PRIVMSG/NOTICE routing.

    `quiet` is what separates the two commands: a NOTICE must never
    generate an automatic reply. That rule exists to stop two servers or
    bots bouncing error messages off each other forever, so every error
    path below is suppressed for NOTICE.
    """
    limits = server.config.limits

    if not msg.params or not msg.param(0):
        if not quiet:
            client.send_numeric(numerics.ERR_NORECIPIENT, f":No recipient given ({command_name})")
        return
    if len(msg.params) < 2:
        if not quiet:
            client.send_numeric(numerics.ERR_NOTEXTTOSEND, ":No text to send")
        return

    text = clean_text(msg.param(1), 400)
    if not text and command_name != "TAGMSG":
        if not quiet:
            client.send_numeric(numerics.ERR_NOTEXTTOSEND, ":No text to send")
        return

    targets = msg.param(0).split(",")
    if len(targets) > limits.max_targets_per_message:
        if not quiet:
            client.send_numeric(
                numerics.ERR_TOOMANYTARGETS,
                msg.param(0),
                f":Too many targets (max {limits.max_targets_per_message})",
            )
        return

    # Only forward tags the client was allowed to set. A client without
    # message-tags should not be able to inject them, and no client may
    # forge the ones the server owns.
    tags = {}
    if client.has_cap("message-tags"):
        tags = {k: v for k, v in msg.tags.items() if k not in ("time", "account")}

    seen = set()
    for target_name in targets:
        if target_name in seen:
            continue
        seen.add(target_name)

        if target_name[:1] in "#&":
            channel = server.find_channel(target_name)
            if channel is None:
                if not quiet:
                    client.send_numeric(
                        numerics.ERR_NOSUCHCHANNEL, target_name, ":No such channel"
                    )
                continue
            error = _deliver_to_channel(server, client, channel, command_name, text, tags)
            if error and not quiet:
                client.send_numeric(numerics.ERR_CANNOTSENDTOCHAN, channel.name, error)
            continue

        target = server.find_client(target_name)
        if target is None:
            if not quiet:
                client.send_numeric(numerics.ERR_NOSUCHNICK, target_name, ":No such nick/channel")
            continue

        _deliver_to_user(server, client, target, command_name, text, tags)

        # Away replies go only to PRIVMSG: an automatic reply to a NOTICE
        # is the loop this distinction exists to prevent.
        if target.away and command_name == "PRIVMSG":
            client.send_numeric(numerics.RPL_AWAY, target.nick, target.away)


@command("PRIVMSG", min_params=0)
def handle_privmsg(server, client, msg):
    _route(server, client, msg, "PRIVMSG", quiet=False)


@command("NOTICE", min_params=0)
def handle_notice(server, client, msg):
    _route(server, client, msg, "NOTICE", quiet=True)


@command("TAGMSG", min_params=1)
def handle_tagmsg(server, client, msg):
    """A message that is only tags -- typing indicators, reactions.

    Delivered only to recipients that negotiated message-tags: to anyone
    else it would arrive as a command they have no way to interpret.
    """
    if not client.has_cap("message-tags"):
        return
    tags = {k: v for k, v in msg.tags.items() if k not in ("time", "account")}
    if not tags:
        return

    for target_name in msg.param(0).split(",")[: server.config.limits.max_targets_per_message]:
        if target_name[:1] in "#&":
            channel = server.find_channel(target_name)
            if channel is None or not channel.has_member(client):
                continue
            outgoing = Message(
                command="TAGMSG", params=[channel.name], source=client.hostmask, tags=tags
            )
            for member in channel.members:
                if member is client and not member.has_cap("echo-message"):
                    continue
                if member.has_cap("message-tags"):
                    member.send(outgoing)
        else:
            target = server.find_client(target_name)
            if target is not None and target.has_cap("message-tags"):
                target.send(
                    Message(
                        command="TAGMSG", params=[target.nick], source=client.hostmask, tags=tags
                    )
                )


@command("AWAY", min_params=0)
def handle_away(server, client, msg):
    text = clean_text(msg.param(0), server.config.limits.max_away_length)
    if text:
        client.away = text
        client.send_numeric(numerics.RPL_NOWAWAY, ":You have been marked as being away")
    else:
        client.away = None
        client.send_numeric(numerics.RPL_UNAWAY, ":You are no longer marked as being away")

    # away-notify: everyone sharing a channel learns immediately, instead
    # of only finding out when they message the user.
    server.broadcast(
        server.common_peers(client, include_self=False),
        Message(
            command="AWAY",
            params=[client.away] if client.away else [],
            source=client.hostmask,
            force_trailing=bool(client.away),
        ),
        require_cap="away-notify",
    )
