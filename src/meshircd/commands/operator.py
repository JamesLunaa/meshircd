"""Server operator commands: OPER, KILL, K-lines, D-lines, REHASH, WALLOPS.

Everything here can disconnect people or change who may connect at all, so
each command is logged and announced to other operators. An action that
can be taken silently by one person with a password is an action nobody
can audit afterwards.
"""

from __future__ import annotations

import time

from .. import numerics
from ..accounts import verify_config_password
from ..protocol import Message
from ..validation import clean_text, is_valid_mask, mask_matches, normalise_mask
from . import command

# Durations accepted by KLINE/DLINE: "30m", "2h", "7d", or bare minutes.
_UNITS = {"m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(value: str) -> int | None:
    """Return seconds, or None for a permanent ban."""
    if not value:
        return None
    if value.isdigit():
        return int(value) * 60  # bare number means minutes, as on most ircds
    if value[-1].lower() in _UNITS and value[:-1].isdigit():
        return int(value[:-1]) * _UNITS[value[-1].lower()]
    return None


@command("OPER", min_params=2, cost=3.0)
async def handle_oper(server, client, msg):
    """OPER <name> <password> -- become a server operator."""
    name, password = msg.param(0), msg.param(1)

    block = next((o for o in server.config.opers if o.name == name), None)

    # Every failure path below reports the same numeric and burns the same
    # work, so a wrong name and a wrong password are indistinguishable.
    if block is not None:
        if block.tls_only and not client.tls:
            block = None
        elif not mask_matches(block.host_mask, client.real_hostmask):
            block = None
        elif block.fingerprint and (client.certfp or "").lower() != block.fingerprint.lower():
            block = None

    # Hash against *some* block even when the name was wrong, so that an
    # unknown oper name costs the same time as a known one.
    reference = block or (server.config.opers[0] if server.config.opers else None)
    ok = False
    if reference is not None:
        ok = await server.storage.run(
            verify_config_password, password, reference.salt, reference.password_hash
        )
    else:
        # No oper blocks at all: still pay the hashing cost so that
        # "this server has no opers" is not detectable by timing.
        await server.storage.run(verify_config_password, password, "00" * 16, "00" * 64)

    if block is None or not ok:
        client.send_numeric(numerics.ERR_NOOPERHOST, ":Invalid oper credentials")
        server.log.warning(
            "failed OPER attempt as %r from %s", name, client.real_hostmask
        )
        server.notify_opers(f"Failed OPER attempt by {client.hostmask} as {name}")
        return

    client.modes.add("o")
    client.modes.add("w")
    client.oper_name = block.name
    client.send_numeric(numerics.RPL_YOUREOPER, ":You are now an IRC operator")
    client.send(
        Message(command="MODE", params=[client.nick, "+ow"], source=client.hostmask)
    )
    server.log.warning("%s opered up as %s", client.real_hostmask, block.name)
    server.notify_opers(f"{client.hostmask} is now an IRC operator ({block.name})")


@command("KILL", min_params=1, needs_oper=True)
def handle_kill(server, client, msg):
    """KILL <nick> [reason] -- disconnect a user immediately."""
    target = server.find_client(msg.param(0))
    if target is None:
        client.send_numeric(numerics.ERR_NOSUCHNICK, msg.param(0), ":No such nick/channel")
        return

    reason = clean_text(msg.param(1) or "No reason given", 300)
    banner = f"Killed by {client.nick} ({reason})"

    target.send_raw(f"ERROR :Closing Link: {banner}")
    server.remove_client(target, banner)
    target.disconnect(banner)
    target.abort()

    client.send_notice(f"Killed {target.nick}")
    server.log.warning("%s killed %s: %s", client.real_hostmask, target.real_hostmask, reason)
    server.notify_opers(f"{client.nick} killed {target.nick} ({reason})")


def _add_ban(server, client, msg, kind: str, label: str):
    args = list(msg.params)
    duration = None
    if args and (parsed := parse_duration(args[0])) is not None:
        duration = parsed
        args = args[1:]
    if not args:
        client.send_numeric(numerics.ERR_NEEDMOREPARAMS, label, ":Not enough parameters")
        return

    mask = args[0]
    reason = clean_text(" ".join(args[1:]) or "No reason given", 300)
    if not is_valid_mask(mask):
        client.send_notice(f"Invalid mask: {mask}")
        return
    if kind == "K":
        mask = normalise_mask(mask)

    # A mask that matches everything would lock the operator out along
    # with everyone else, which is almost never what someone meant to
    # type and is very hard to undo without shell access.
    if mask in ("*", "*!*@*", "*@*", "0.0.0.0/0", "::/0"):
        client.send_notice(f"Refusing to {label} a mask that matches every connection")
        return

    server.add_server_ban(kind, mask, reason, client.nick or "*", duration)
    expiry = f"for {duration}s" if duration else "permanently"
    client.send_notice(f"Added {label} for {mask} {expiry}: {reason}")
    server.log.warning("%s added %s %s (%s): %s", client.real_hostmask, label, mask, expiry, reason)
    server.notify_opers(f"{client.nick} added {label} for {mask} {expiry}: {reason}")

    # Apply it to anyone already connected -- a ban that only affects
    # future connections leaves the person you just banned still talking.
    removed = 0
    for existing in list(server.clients):
        if not existing.registered:
            continue
        if existing.is_oper:
            # Operators are exempt from retroactive enforcement. Without
            # this, an operator banning the network they are connected
            # from disconnects themselves with the same command -- and if
            # the ban also covers their address, they cannot get back in
            # to undo it. A lockout that needs shell access to repair is
            # not an acceptable outcome for a typo.
            continue
        hit = (
            mask_matches(mask, existing.ip)
            if kind == "D"
            else mask_matches(mask, existing.real_hostmask)
        )
        if hit:
            existing.send_raw(f"ERROR :Closing Link: Banned ({reason})")
            server.remove_client(existing, f"Banned: {reason}")
            existing.disconnect("Banned")
            existing.abort()
            removed += 1
    if removed:
        client.send_notice(f"Disconnected {removed} matching client(s)")


@command("KLINE", min_params=1, needs_oper=True)
def handle_kline(server, client, msg):
    """KLINE [duration] <user@host> [reason] -- ban a user@host mask."""
    _add_ban(server, client, msg, "K", "K-line")


@command("DLINE", min_params=1, needs_oper=True)
def handle_dline(server, client, msg):
    """DLINE [duration] <ip|cidr> [reason] -- ban an address before registration."""
    _add_ban(server, client, msg, "D", "D-line")


@command("UNKLINE", min_params=1, needs_oper=True)
def handle_unkline(server, client, msg):
    """UNKLINE <mask> -- remove a K-line."""
    mask = msg.param(0)
    if server.remove_server_ban("K", mask):
        client.send_notice(f"K-line for {normalise_mask(mask)} removed")
        server.notify_opers(f"{client.nick} removed K-line for {normalise_mask(mask)}")
    else:
        client.send_notice(f"No K-line matching {mask}")


@command("UNDLINE", min_params=1, needs_oper=True)
def handle_undline(server, client, msg):
    """UNDLINE <mask> -- remove a D-line."""
    mask = msg.param(0)
    if server.remove_server_ban("D", mask):
        client.send_notice(f"D-line for {mask} removed")
        server.notify_opers(f"{client.nick} removed D-line for {mask}")
    else:
        client.send_notice(f"No D-line matching {mask}")


@command("REHASH", min_params=0, needs_oper=True)
def handle_rehash(server, client, msg):
    """REHASH -- reload the MOTD and TLS certificate."""
    client.send_numeric(numerics.RPL_REHASHING, "ircd.toml", ":Rehashing")
    server.rehash()


@command("WALLOPS", min_params=1, needs_oper=True)
def handle_wallops(server, client, msg):
    """WALLOPS <text> -- broadcast to every user with mode +w."""
    text = clean_text(msg.param(0), 400)
    outgoing = Message(
        command="WALLOPS", params=[text], source=client.hostmask, force_trailing=True
    )
    for target in server.clients:
        if target.registered and "w" in target.modes:
            target.send(outgoing)
    server.log.info("WALLOPS from %s: %s", client.nick, text)


@command("SAMODE", min_params=2, needs_oper=True)
def handle_samode(server, client, msg):
    """SAMODE <channel> <modes> -- change modes regardless of channel status.

    Needed because a channel can end up with no operator at all (everyone
    with op left), and without a server-level override nobody could ever
    configure it again.
    """
    from .modes import _channel_mode

    channel = server.find_channel(msg.param(0))
    if channel is None:
        client.send_numeric(numerics.ERR_NOSUCHCHANNEL, msg.param(0), ":No such channel")
        return
    server.log.warning("%s used SAMODE on %s: %s", client.real_hostmask, channel.name, msg.params[1:])
    server.notify_opers(f"{client.nick} used SAMODE {channel.name} {' '.join(msg.params[1:])}")
    _channel_mode(server, client, msg, msg.param(0))


@command("CONNECTINFO", min_params=0, needs_oper=True)
def handle_connectinfo(server, client, msg):
    """CONNECTINFO [nick] -- show connection details an operator needs."""
    if msg.params:
        targets = [t for t in [server.find_client(msg.param(0))] if t]
        if not targets:
            client.send_numeric(numerics.ERR_NOSUCHNICK, msg.param(0), ":No such nick/channel")
            return
    else:
        targets = sorted(
            (c for c in server.clients if c.registered), key=lambda c: c.connected_at
        )[:50]

    for target in targets:
        client.send_notice(
            f"{target.nick}: ip={target.ip} cloak={target.host} "
            f"account={target.account or '-'} tls={target.tls_version or 'no'} "
            f"certfp={(target.certfp or '-')[:16]} idle={target.idle_seconds}s "
            f"conn={int(time.time() - target.connected_at)}s "
            f"sent={target.sent_bytes} recv={target.recv_bytes}"
        )
    client.send_notice(f"End of CONNECTINFO ({len(targets)} shown)")
