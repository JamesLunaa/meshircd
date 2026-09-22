"""MODE, for both users and channels.

Mode parsing is where most ircd bugs of the "wrong person got op" variety
live, because the parameter rules differ per mode letter and a
miscounted argument list silently shifts every later parameter onto the
wrong mode. The four classes, as advertised in ISUPPORT CHANMODES:

    A (beI)   list modes    -- take a mask; with no argument they are a
                               *query* of the list, not a change
    B (k)     always take a parameter, setting and clearing
    C (l)     take a parameter only when set
    D (imnpst) never take a parameter

Membership prefixes (o, v) always take a nickname.
"""

from __future__ import annotations

from .. import numerics
from ..channel import BOOL_MODES, LIST_MODES, PREFIX_BY_MODE
from ..protocol import Message, casefold
from ..validation import is_valid_key, is_valid_mask, normalise_mask
from . import command

# Modes a user may set on themselves. 'o' is deliberately absent: operator
# status is granted only by OPER, never by a client asking for it.
USER_SETTABLE = frozenset("iws")
USER_ALL = frozenset("iwso")

# Cap on changes per MODE command, matching the advertised MODES= token.
# Without it, one command could apply hundreds of changes and emit a
# broadcast far past the line limit.
MAX_CHANGES_PER_COMMAND = 6


@command("MODE", min_params=1)
def handle_mode(server, client, msg):
    target = msg.param(0)
    if target[:1] in "#&":
        _channel_mode(server, client, msg, target)
    else:
        _user_mode(server, client, msg, target)


# --- user modes ---------------------------------------------------------


def _user_mode(server, client, msg, target):
    if casefold(target) != client.nick_lower:
        # We do not track or expose other users' modes.
        client.send_numeric(numerics.ERR_USERSDONTMATCH, ":Can't change mode for other users")
        return

    if len(msg.params) == 1:
        flags = "".join(sorted(client.modes))
        client.send_numeric(numerics.RPL_UMODEIS, f"+{flags}" if flags else "+")
        return

    adding = True
    applied = []
    for char in msg.param(1):
        if char in "+-":
            adding = char == "+"
            continue
        if char == "o":
            # Deopering yourself is allowed; opering yourself is not.
            if not adding and "o" in client.modes:
                client.modes.discard("o")
                client.oper_name = None
                applied.append(("-", "o"))
            continue
        if char not in USER_SETTABLE:
            client.send_numeric(numerics.ERR_UMODEUNKNOWNFLAG, char, ":is unknown mode char to me")
            continue
        if adding and char not in client.modes:
            client.modes.add(char)
            applied.append(("+", char))
        elif not adding and char in client.modes:
            client.modes.discard(char)
            applied.append(("-", char))

    if applied:
        client.send(
            Message(command="MODE", params=[client.nick, _render(applied)[0]], source=client.hostmask)
        )


# --- channel modes -------------------------------------------------------


def _render(changes) -> tuple[str, list[str]]:
    """Collapse a change list into '+ov-b nick nick mask' form."""
    out, args, sign = "", [], None
    for change in changes:
        if len(change) == 3:
            this_sign, char, arg = change
        else:
            this_sign, char = change
            arg = None
        if this_sign != sign:
            out += this_sign
            sign = this_sign
        out += char
        if arg is not None:
            args.append(arg)
    return out, args


def _send_list(client, channel, kind: str):
    replies = {
        "b": (numerics.RPL_BANLIST, numerics.RPL_ENDOFBANLIST, "ban list"),
        "e": (numerics.RPL_EXCEPTLIST, numerics.RPL_ENDOFEXCEPTLIST, "exception list"),
        "I": (numerics.RPL_INVITELIST, numerics.RPL_ENDOFINVITELIST, "invite list"),
    }
    item_numeric, end_numeric, label = replies[kind]
    for mask, setter, set_at in channel.lists[kind]:
        client.send_numeric(item_numeric, channel.name, mask, setter or "*", str(set_at))
    client.send_numeric(end_numeric, channel.name, f":End of channel {label}")


def _channel_mode(server, client, msg, target):
    channel = server.find_channel(target)
    if channel is None:
        client.send_numeric(numerics.ERR_NOSUCHCHANNEL, target, ":No such channel")
        return

    is_member = channel.has_member(client)

    if len(msg.params) == 1:
        # A bare query. Clients send this straight after every JOIN, so it
        # must answer rather than being mistaken for an attempted change.
        flags, args = channel.mode_string(for_member=is_member)
        client.send_numeric(
            numerics.RPL_CHANNELMODEIS, channel.name, f"+{flags}" if flags else "+", *args
        )
        client.send_numeric(numerics.RPL_CREATIONTIME, channel.name, str(channel.created_at))
        return

    changestr = msg.param(1)
    arguments = list(msg.params[2:])
    arg_index = 0

    def next_arg():
        nonlocal arg_index
        if arg_index < len(arguments):
            arg_index += 1
            return arguments[arg_index - 1]
        return None

    # A pure list query ("MODE #chan b") is readable by any member and
    # requires no privileges, so handle it before the op check.
    if all(c in LIST_MODES for c in changestr.lstrip("+")) and not arguments:
        if changestr.startswith("-"):
            pass
        else:
            for kind in changestr.lstrip("+"):
                _send_list(client, channel, kind)
            return

    has_op = channel.is_op(client) or client.is_oper
    limits = server.config.limits
    changes = []
    denied = False
    adding = True

    def require_op() -> bool:
        nonlocal denied
        if not has_op and not denied:
            denied = True
            client.send_numeric(
                numerics.ERR_CHANOPRIVSNEEDED, channel.name, ":You're not channel operator"
            )
        return has_op

    for char in changestr:
        if char in "+-":
            adding = char == "+"
            continue
        if len(changes) >= MAX_CHANGES_PER_COMMAND:
            break

        # --- membership prefixes (always a nickname) ------------------
        if char in PREFIX_BY_MODE:
            nick = next_arg()
            if nick is None:
                client.send_numeric(numerics.ERR_NEEDMOREPARAMS, "MODE", ":Not enough parameters")
                continue
            if not require_op():
                continue
            member = server.find_client(nick)
            if member is None or not channel.has_member(member):
                client.send_numeric(
                    numerics.ERR_USERNOTINCHANNEL, nick, channel.name, ":They aren't on that channel"
                )
                continue
            held = channel.members[member]
            if adding and char in held:
                continue
            if not adding and char not in held:
                continue
            (channel.give if adding else channel.take)(member, char)
            changes.append(("+" if adding else "-", char, member.nick))
            # Mirror into persistent access so the grant survives both a
            # reconnect and a restart, but only for an authenticated user
            # -- there is nothing durable to attach it to otherwise.
            if member.account:
                key = casefold(member.account)
                if adding:
                    channel.access[key] = char
                    server.storage.set_channel_access(channel.key_lower, key, char)
                else:
                    channel.access.pop(key, None)
                    server.storage.clear_channel_access(channel.key_lower, key)
                channel.dirty = True

        # --- list modes ------------------------------------------------
        elif char in LIST_MODES:
            mask = next_arg()
            if mask is None:
                if is_member or client.is_oper:
                    _send_list(client, channel, char)
                continue
            if not require_op():
                continue
            if not is_valid_mask(mask):
                client.send_numeric(
                    numerics.ERR_INVALIDMODEPARAM, channel.name, char, mask, ":Invalid mask"
                )
                continue
            mask = normalise_mask(mask)
            if adding:
                if len(channel.lists[char]) >= limits.max_bans_per_channel:
                    client.send_numeric(
                        numerics.ERR_LISTFULL, channel.name, mask, ":Channel list is full"
                    )
                    continue
                if channel.add_list_entry(char, mask, client.nick or "*"):
                    server.storage.add_channel_list_entry(
                        channel.key_lower, char, mask, client.nick or "*"
                    )
                    changes.append(("+", char, mask))
            else:
                if channel.remove_list_entry(char, mask):
                    server.storage.remove_channel_list_entry(channel.key_lower, char, mask)
                    changes.append(("-", char, mask))

        # --- key (parameter both ways) ----------------------------------
        elif char == "k":
            value = next_arg()
            if not require_op():
                continue
            if adding:
                if value is None or not is_valid_key(value):
                    client.send_numeric(
                        numerics.ERR_INVALIDMODEPARAM,
                        channel.name, "k", value or "*", ":Invalid channel key",
                    )
                    continue
                channel.key = value
                changes.append(("+", "k", value))
            else:
                if channel.key is None:
                    continue
                # The old key is echoed when clearing, which is how clients
                # know which key was removed.
                cleared, channel.key = channel.key, None
                changes.append(("-", "k", cleared))
            channel.dirty = True

        # --- limit (parameter on set only) -------------------------------
        elif char == "l":
            if adding:
                value = next_arg()
                if value is None or not value.isdigit() or not 0 < int(value) <= 100000:
                    client.send_numeric(
                        numerics.ERR_INVALIDMODEPARAM,
                        channel.name, "l", value or "*", ":Invalid channel limit",
                    )
                    continue
                if not require_op():
                    continue
                channel.limit = int(value)
                changes.append(("+", "l", value))
            else:
                if not require_op():
                    continue
                if channel.limit is None:
                    continue
                channel.limit = None
                changes.append(("-", "l", None))
            channel.dirty = True

        # --- boolean flags --------------------------------------------
        elif char in BOOL_MODES:
            if not require_op():
                continue
            if adding and char not in channel.modes:
                channel.modes.add(char)
                changes.append(("+", char, None))
            elif not adding and char in channel.modes:
                channel.modes.discard(char)
                changes.append(("-", char, None))
            channel.dirty = True

        else:
            client.send_numeric(numerics.ERR_UNKNOWNMODE, char, ":is unknown mode char to me")

    if not changes:
        return

    server.persist_channel(channel)
    modestr, args = _render(changes)
    server.broadcast(
        channel.members,
        Message(command="MODE", params=[channel.name, modestr, *args], source=client.hostmask),
    )
