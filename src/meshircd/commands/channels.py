"""Channel membership: JOIN, PART, TOPIC, NAMES, LIST, INVITE, KICK."""

from __future__ import annotations

import time

from .. import numerics
from ..channel import Channel
from ..protocol import Message, casefold
from ..validation import clean_text, is_valid_channel, is_valid_key
from . import command


def names_items(server, channel: Channel, viewer) -> list[str]:
    """Render the NAMES list as the viewer's capabilities require."""
    multi = viewer.has_cap("multi-prefix")
    with_host = viewer.has_cap("userhost-in-names")
    items = []
    for member in sorted(channel.members, key=lambda m: (m.nick or "").lower()):
        if member.is_invisible and not channel.has_member(viewer) and member is not viewer:
            continue
        prefix = channel.all_prefixes_for(member) if multi else channel.prefix_for(member)
        items.append(prefix + (member.hostmask if with_host else member.nick))
    return items


def send_names(server, client, channel: Channel):
    symbol = "@" if channel.is_secret else ("*" if channel.is_private else "=")
    items = names_items(server, channel, client)

    # One 353 per line, chunked so the rendered line stays inside the
    # 512-byte limit rather than being silently truncated on the way out.
    line: list[str] = []
    budget = 400 - len(channel.name)
    used = 0
    for item in items:
        if used + len(item) + 1 > budget and line:
            client.send_numeric(numerics.RPL_NAMREPLY, symbol, channel.name, " ".join(line))
            line, used = [], 0
        line.append(item)
        used += len(item) + 1
    if line:
        client.send_numeric(numerics.RPL_NAMREPLY, symbol, channel.name, " ".join(line))
    client.send_numeric(numerics.RPL_ENDOFNAMES, channel.name, ":End of /NAMES list")


def send_topic(server, client, channel: Channel):
    if channel.topic:
        client.send_numeric(numerics.RPL_TOPIC, channel.name, channel.topic)
        if channel.topic_setter:
            client.send_numeric(
                numerics.RPL_TOPICWHOTIME,
                channel.name,
                channel.topic_setter,
                str(channel.topic_time),
            )
    else:
        client.send_numeric(numerics.RPL_NOTOPIC, channel.name, ":No topic is set")


def _apply_persistent_access(server, client, channel: Channel):
    """Restore an op/voice grant recorded against this client's account.

    Channel operator status is stored per *account*, not per nick, because
    a nick is transient. This is what makes op survive both a reconnect and
    a server restart, instead of every restart leaving channels ownerless.
    """
    if not client.account:
        return ""
    return channel.access.get(casefold(client.account), "")


@command("JOIN", min_params=1)
def handle_join(server, client, msg):
    limits = server.config.limits
    # Bounded by how many channels a client may be in, NOT by the
    # per-message target limit: clients reconnecting send their whole
    # channel list as one comma-separated JOIN, and silently dropping the
    # tail would leave them missing channels with no error to explain it.
    requested = msg.param(0).split(",")
    targets = requested[: limits.max_channels_per_client]
    if len(requested) > len(targets):
        client.send_numeric(
            numerics.ERR_TOOMANYCHANNELS, msg.param(0), ":You have joined too many channels"
        )
    keys = msg.param(1).split(",") if len(msg.params) > 1 else []

    # "JOIN 0" is the RFC's "part every channel" shorthand.
    if msg.param(0) == "0":
        for key in list(client.channels):
            channel = server.channels.get(key)
            if channel:
                _do_part(server, client, channel, "Leaving all channels")
        return

    for index, name in enumerate(targets):
        if not is_valid_channel(name, limits.max_channel_length):
            client.send_numeric(numerics.ERR_NOSUCHCHANNEL, name, ":No such channel")
            continue

        channel = server.find_channel(name)
        if channel is not None and channel.has_member(client):
            continue
        if len(client.channels) >= limits.max_channels_per_client:
            client.send_numeric(
                numerics.ERR_TOOMANYCHANNELS, name, ":You have joined too many channels"
            )
            continue

        supplied_key = keys[index] if index < len(keys) else None
        existing = channel is not None and bool(channel.members)

        if channel is None:
            channel, _ = server.get_or_create_channel(name)

        if existing or channel.worth_persisting():
            # An empty-but-configured channel still enforces its modes:
            # otherwise +k and +b would evaporate whenever the last member
            # left, which is exactly what persistence exists to prevent.
            if not _check_join_permitted(server, client, channel, supplied_key):
                if not channel.members:
                    server.maybe_drop_channel(channel)
                continue

        first = not channel.members
        granted = _apply_persistent_access(server, client, channel)
        if first and not granted and not channel.access:
            # Whoever creates a channel that nobody owns becomes its
            # operator, or the channel would have no one able to configure
            # it. A channel with recorded access does NOT hand out op this
            # way -- that would let anyone seize a configured channel by
            # joining it while empty.
            granted = "o"
            if client.account:
                # Record the founder against their account so that they
                # keep op across a reconnect and across a server restart.
                # This only reaches the database if the channel becomes
                # worth persisting for some other reason -- see
                # Channel.worth_persisting.
                channel.access[casefold(client.account)] = "o"

        channel.add_member(client, granted)
        client.channels.add(channel.key_lower)
        channel.invited.discard(client.nick_lower)

        _announce_join(server, client, channel)

        if granted:
            server.broadcast(
                channel.members,
                Message(
                    command="MODE",
                    params=[channel.name, "+" + granted, client.nick],
                    source=server.config.server.name,
                ),
            )

        if channel.topic:
            send_topic(server, client, channel)
        send_names(server, client, channel)


def _announce_join(server, client, channel: Channel):
    """Send JOIN to the channel, in the form each member negotiated.

    extended-join adds the joiner's account and realname to the line, so a
    client can display who someone is without a WHOIS round trip. Clients
    without the capability must receive the plain two-token form, or they
    will parse the account as part of the channel name.
    """
    plain = Message(command="JOIN", params=[channel.name], source=client.hostmask)
    extended = Message(
        command="JOIN",
        params=[channel.name, client.account or "*", client.realname or ""],
        source=client.hostmask,
        force_trailing=True,
    )
    account_tag = {"account": client.account} if client.account else {}
    for member in channel.members:
        member.send(extended if member.has_cap("extended-join") else plain, **account_tag)

    if client.away:
        # away-notify recipients expect the current state of anyone who
        # becomes visible to them.
        server.broadcast(
            channel.members,
            Message(
                command="AWAY", params=[client.away], source=client.hostmask, force_trailing=True
            ),
            skip=client,
            require_cap="away-notify",
        )


def _check_join_permitted(server, client, channel: Channel, supplied_key) -> bool:
    limits = server.config.limits
    if channel.key is not None and supplied_key != channel.key:
        client.send_numeric(
            numerics.ERR_BADCHANNELKEY, channel.name, ":Cannot join channel (+k)"
        )
        return False
    if channel.limit is not None and len(channel.members) >= channel.limit:
        client.send_numeric(numerics.ERR_CHANNELISFULL, channel.name, ":Cannot join channel (+l)")
        return False
    if channel.is_banned(client.hostmask) and not channel.matches_list("I", client.hostmask):
        client.send_numeric(
            numerics.ERR_BANNEDFROMCHAN, channel.name, ":Cannot join channel (+b)"
        )
        return False
    if "i" in channel.modes:
        invited = client.nick_lower in channel.invited
        if not invited and not channel.matches_list("I", client.hostmask):
            client.send_numeric(
                numerics.ERR_INVITEONLYCHAN, channel.name, ":Cannot join channel (+i)"
            )
            return False
    del limits
    return True


def _do_part(server, client, channel: Channel, reason: str):
    server.broadcast(
        channel.members,
        Message(
            command="PART", params=[channel.name, reason], source=client.hostmask,
            force_trailing=True,
        ),
    )
    channel.remove_member(client)
    client.channels.discard(channel.key_lower)
    server.maybe_drop_channel(channel)


@command("PART", min_params=1)
def handle_part(server, client, msg):
    reason = clean_text(msg.param(1) or (client.nick or ""), 300)
    for name in msg.param(0).split(",")[: server.config.limits.max_channels_per_client]:
        channel = server.find_channel(name)
        if channel is None:
            client.send_numeric(numerics.ERR_NOSUCHCHANNEL, name, ":No such channel")
            continue
        if not channel.has_member(client):
            client.send_numeric(numerics.ERR_NOTONCHANNEL, name, ":You're not on that channel")
            continue
        _do_part(server, client, channel, reason)


@command("TOPIC", min_params=1)
def handle_topic(server, client, msg):
    name = msg.param(0)
    channel = server.find_channel(name)
    if channel is None:
        client.send_numeric(numerics.ERR_NOSUCHCHANNEL, name, ":No such channel")
        return

    if len(msg.params) == 1:
        if not channel.has_member(client) and not channel.visible_to(client):
            client.send_numeric(numerics.ERR_NOTONCHANNEL, name, ":You're not on that channel")
            return
        send_topic(server, client, channel)
        return

    if not channel.has_member(client):
        client.send_numeric(numerics.ERR_NOTONCHANNEL, name, ":You're not on that channel")
        return
    if "t" in channel.modes and not channel.is_op(client) and not client.is_oper:
        client.send_numeric(
            numerics.ERR_CHANOPRIVSNEEDED, channel.name, ":You're not channel operator"
        )
        return

    channel.topic = clean_text(msg.param(1), server.config.limits.max_topic_length) or None
    channel.topic_setter = client.nick or ""
    channel.topic_time = int(time.time())
    channel.dirty = True
    server.persist_channel(channel)
    server.broadcast(
        channel.members,
        Message(
            command="TOPIC", params=[channel.name, channel.topic or ""],
            source=client.hostmask, force_trailing=True,
        ),
    )


@command("NAMES", min_params=0, cost=2.0)
def handle_names(server, client, msg):
    if not msg.params:
        # Bare NAMES would mean "every channel on the network", which is
        # both expensive and a disclosure of secret channels. LIST is the
        # command for browsing.
        client.send_numeric(numerics.RPL_ENDOFNAMES, "*", ":End of /NAMES list")
        return
    for name in msg.param(0).split(",")[: server.config.limits.max_targets_per_message]:
        channel = server.find_channel(name)
        if channel is None or not channel.visible_to(client):
            client.send_numeric(numerics.RPL_ENDOFNAMES, name, ":End of /NAMES list")
            continue
        send_names(server, client, channel)


@command("LIST", min_params=0, cost=5.0)
def handle_list(server, client, msg):
    """Browse channels.

    Costs several flood tokens: it is one short command for the client and
    a walk of every channel for us, which is exactly the asymmetry a flood
    limiter exists to price.
    """
    client.send_numeric(numerics.RPL_LISTSTART, "Channel", ":Users  Name")

    wanted = set()
    min_users = max_users = None
    if msg.params:
        for item in msg.param(0).split(","):
            if item.startswith(">"):
                min_users = int(item[1:]) if item[1:].isdigit() else None
            elif item.startswith("<"):
                max_users = int(item[1:]) if item[1:].isdigit() else None
            elif item:
                wanted.add(casefold(item))

    for channel in sorted(server.channels.values(), key=lambda c: -len(c.members)):
        if wanted and channel.key_lower not in wanted:
            continue
        if not channel.visible_to(client) and not client.is_oper:
            continue
        count = len(channel.members)
        if min_users is not None and count <= min_users:
            continue
        if max_users is not None and count >= max_users:
            continue
        client.send_numeric(
            numerics.RPL_LIST, channel.name, str(count), channel.topic or ""
        )
    client.send_numeric(numerics.RPL_LISTEND, ":End of /LIST")


@command("INVITE", min_params=2)
def handle_invite(server, client, msg):
    target_nick, name = msg.param(0), msg.param(1)
    target = server.find_client(target_nick)
    if target is None:
        client.send_numeric(numerics.ERR_NOSUCHNICK, target_nick, ":No such nick/channel")
        return

    channel = server.find_channel(name)
    if channel is None:
        client.send_numeric(numerics.ERR_NOSUCHCHANNEL, name, ":No such channel")
        return
    if not channel.has_member(client):
        client.send_numeric(numerics.ERR_NOTONCHANNEL, name, ":You're not on that channel")
        return
    if channel.has_member(target):
        client.send_numeric(
            numerics.ERR_USERONCHANNEL, target.nick, channel.name, ":is already on channel"
        )
        return
    # Only ops may invite past +i; otherwise any member could quietly
    # defeat the mode the operators set.
    if "i" in channel.modes and not channel.is_op(client):
        client.send_numeric(
            numerics.ERR_CHANOPRIVSNEEDED, channel.name, ":You're not channel operator"
        )
        return
    if len(channel.invited) >= server.config.limits.max_invites_per_channel:
        client.send_numeric(numerics.ERR_LISTFULL, channel.name, "*", ":Invite list is full")
        return

    channel.invited.add(casefold(target.nick))
    client.send_numeric(numerics.RPL_INVITING, target.nick, channel.name)
    target.send(
        Message(command="INVITE", params=[target.nick, channel.name], source=client.hostmask)
    )
    if target.away:
        client.send_numeric(numerics.RPL_AWAY, target.nick, target.away)

    # invite-notify: tell the channel's operators, so an invite into a
    # restricted channel is not invisible to the people running it.
    notice = Message(
        command="INVITE", params=[target.nick, channel.name], source=client.hostmask
    )
    for member in channel.members:
        if member is not client and channel.is_op(member) and member.has_cap("invite-notify"):
            member.send(notice)


@command("KICK", min_params=2)
def handle_kick(server, client, msg):
    name = msg.param(0)
    channel = server.find_channel(name)
    if channel is None:
        client.send_numeric(numerics.ERR_NOSUCHCHANNEL, name, ":No such channel")
        return
    if not channel.has_member(client):
        client.send_numeric(numerics.ERR_NOTONCHANNEL, name, ":You're not on that channel")
        return
    if not channel.is_op(client) and not client.is_oper:
        client.send_numeric(
            numerics.ERR_CHANOPRIVSNEEDED, channel.name, ":You're not channel operator"
        )
        return

    reason = clean_text(msg.param(2) or client.nick or "", server.config.limits.max_kick_length)

    for target_nick in msg.param(1).split(",")[: server.config.limits.max_targets_per_message]:
        target = server.find_client(target_nick)
        if target is None or not channel.has_member(target):
            client.send_numeric(
                numerics.ERR_USERNOTINCHANNEL,
                target_nick,
                channel.name,
                ":They aren't on that channel",
            )
            continue

        # Everyone still in the channel sees the kick, the target included,
        # so it goes out before the removal.
        server.broadcast(
            channel.members,
            Message(
                command="KICK",
                params=[channel.name, target.nick, reason],
                source=client.hostmask,
                force_trailing=True,
            ),
        )
        channel.remove_member(target)
        target.channels.discard(channel.key_lower)
        server.maybe_drop_channel(channel)
