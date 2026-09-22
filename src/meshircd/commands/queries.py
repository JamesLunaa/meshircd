"""Informational commands: WHO, WHOIS, ISON, USERHOST, MOTD, LUSERS,
VERSION, TIME, ADMIN, INFO, STATS, HELP."""

from __future__ import annotations

import time

from .. import caps, numerics
from ..protocol import casefold
from . import REGISTRY, command


def send_motd(server, client):
    name = server.config.server.name
    if not server.motd:
        client.send_numeric(numerics.ERR_NOMOTD, ":MOTD File is missing")
        return
    client.send_numeric(numerics.RPL_MOTDSTART, f":- {name} Message of the Day -")
    for line in server.motd:
        client.send_numeric(numerics.RPL_MOTD, f":- {line}")
    client.send_numeric(numerics.RPL_ENDOFMOTD, ":End of /MOTD command")


def send_lusers(server, client):
    stats = server.stats()
    client.send_numeric(
        numerics.RPL_LUSERCLIENT,
        f":There are {stats['registered'] - stats['invisible']} users and "
        f"{stats['invisible']} invisible on 1 server",
    )
    if stats["opers"]:
        client.send_numeric(numerics.RPL_LUSEROP, str(stats["opers"]), ":IRC Operators online")
    if stats["unknown"]:
        client.send_numeric(
            numerics.RPL_LUSERUNKNOWN, str(stats["unknown"]), ":unknown connection(s)"
        )
    client.send_numeric(
        numerics.RPL_LUSERCHANNELS, str(stats["channels"]), ":channels formed"
    )
    client.send_numeric(
        numerics.RPL_LUSERME, f":I have {stats['registered']} clients and 0 servers"
    )
    client.send_numeric(
        numerics.RPL_LOCALUSERS,
        str(stats["registered"]), str(stats["peak"]),
        f":Current local users {stats['registered']}, max {stats['peak']}",
    )
    client.send_numeric(
        numerics.RPL_GLOBALUSERS,
        str(stats["registered"]), str(stats["peak"]),
        f":Current global users {stats['registered']}, max {stats['peak']}",
    )


@command("MOTD", min_params=0, cost=2.0)
def handle_motd(server, client, msg):
    send_motd(server, client)


@command("LUSERS", min_params=0)
def handle_lusers(server, client, msg):
    send_lusers(server, client)


@command("VERSION", min_params=0)
def handle_version(server, client, msg):
    from ..server import VERSION

    client.send_numeric(
        "351", f"meshircd-{VERSION}", server.config.server.name, f":{server.config.server.description}"
    )
    for chunk in server.isupport_lines():
        client.send_numeric(numerics.RPL_ISUPPORT, *chunk, ":are supported by this server")


@command("TIME", min_params=0)
def handle_time(server, client, msg):
    client.send_numeric(
        numerics.RPL_TIME,
        server.config.server.name,
        ":" + time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    )


@command("ADMIN", min_params=0)
def handle_admin(server, client, msg):
    info = server.config.server
    client.send_numeric(numerics.RPL_ADMINME, info.name, ":Administrative info")
    client.send_numeric(numerics.RPL_ADMINLOC1, f":{info.admin_name}")
    client.send_numeric(numerics.RPL_ADMINLOC2, f":{info.admin_location}")
    client.send_numeric(numerics.RPL_ADMINEMAIL, f":{info.admin_email}")


@command("INFO", min_params=0)
def handle_info(server, client, msg):
    from ..server import VERSION

    for line in (
        f"meshircd {VERSION}",
        "A small IRC server written from scratch in Python, standard library only.",
        "https://github.com/ (see README)",
        "",
        f"Running on {server.config.server.name} ({server.config.server.network})",
        f"Uptime: {server.stats()['uptime_seconds']} seconds",
    ):
        client.send_numeric(numerics.RPL_INFO, f":{line}")
    client.send_numeric(numerics.RPL_ENDOFINFO, ":End of /INFO list")


@command("ISON", min_params=1)
def handle_ison(server, client, msg):
    # ISON takes nicks as separate parameters, but clients often send them
    # space-separated in a trailing parameter; accept both.
    candidates = []
    for param in msg.params:
        candidates.extend(param.split())
    online = [c.nick for c in (server.find_client(n) for n in candidates[:32]) if c]
    client.send_numeric(numerics.RPL_ISON, ":" + " ".join(online))


@command("USERHOST", min_params=1)
def handle_userhost(server, client, msg):
    candidates = []
    for param in msg.params:
        candidates.extend(param.split())
    parts = []
    for nick in candidates[:5]:
        target = server.find_client(nick)
        if target is None:
            continue
        oper_flag = "*" if target.is_oper else ""
        away_flag = "-" if target.away else "+"
        parts.append(f"{target.nick}{oper_flag}={away_flag}{target.user}@{target.host}")
    client.send_numeric(numerics.RPL_USERHOST, ":" + " ".join(parts))


@command("WHO", min_params=0, cost=3.0)
def handle_who(server, client, msg):
    """WHO <channel|nick|mask>.

    Clients issue this right after joining to populate their user list.
    Visibility rules matter here: a +i user must not be listed to someone
    who shares no channel with them, or WHO becomes a way to enumerate
    everyone on the server.
    """
    if not msg.params:
        client.send_numeric(numerics.RPL_ENDOFWHO, "*", ":End of /WHO list")
        return

    mask = msg.param(0)
    name = server.config.server.name
    results = []

    channel = server.find_channel(mask)
    if channel is not None:
        if channel.visible_to(client) or client.is_oper:
            viewer_is_member = channel.has_member(client)
            for member in sorted(channel.members, key=lambda m: (m.nick or "").lower()):
                if member.is_invisible and not viewer_is_member and member is not client:
                    continue
                results.append((member, channel))
    else:
        target = server.find_client(mask)
        candidates = [target] if target else []
        for candidate in candidates:
            shares = bool(client.channels & candidate.channels)
            if candidate.is_invisible and not shares and candidate is not client and not client.is_oper:
                continue
            shared = next(
                (server.channels[k] for k in (client.channels & candidate.channels)), None
            )
            results.append((candidate, shared))

    for member, in_channel in results[:200]:
        flags = "G" if member.away else "H"
        if member.is_oper:
            flags += "*"
        if in_channel is not None:
            if client.has_cap("multi-prefix"):
                flags += in_channel.all_prefixes_for(member)
            else:
                flags += in_channel.prefix_for(member)
        client.send_numeric(
            numerics.RPL_WHOREPLY,
            in_channel.name if in_channel else "*",
            member.user or "*",
            member.host,
            name,
            member.nick,
            flags,
            f":0 {member.realname or ''}",
        )
    client.send_numeric(numerics.RPL_ENDOFWHO, mask, ":End of /WHO list")


@command("WHOIS", min_params=1, cost=2.0)
def handle_whois(server, client, msg):
    # "WHOIS <server> <nick>" is the remote form; with one server the
    # target is always the last parameter.
    target_nick = msg.params[-1].split(",")[0]
    target = server.find_client(target_nick)

    if target is None:
        # A connection that sent NICK but not USER is present in the nick
        # registry with user/realname still unset. It is not a visible user
        # yet, and formatting those into a numeric would raise.
        client.send_numeric(numerics.ERR_NOSUCHNICK, target_nick, ":No such nick/channel")
        client.send_numeric(numerics.RPL_ENDOFWHOIS, target_nick, ":End of /WHOIS list")
        return

    name = server.config.server.name
    client.send_numeric(
        numerics.RPL_WHOISUSER,
        target.nick, target.user or "*", target.host, "*", f":{target.realname or ''}",
    )

    # Secret channels are listed only to people already in them.
    visible = []
    for key in sorted(target.channels):
        channel = server.channels.get(key)
        if channel is None:
            continue
        if not channel.visible_to(client) and not client.is_oper:
            continue
        visible.append(channel.prefix_for(target) + channel.name)
    if visible:
        client.send_numeric(numerics.RPL_WHOISCHANNELS, target.nick, ":" + " ".join(visible))

    client.send_numeric(
        numerics.RPL_WHOISSERVER, target.nick, name, f":{server.config.server.description}"
    )
    if target.is_oper:
        client.send_numeric(
            numerics.RPL_WHOISOPERATOR, target.nick, ":is an IRC operator on this server"
        )
    if target.account:
        client.send_numeric(
            numerics.RPL_WHOISACCOUNT, target.nick, target.account, ":is logged in as"
        )
    if target.tls:
        client.send_numeric(
            numerics.RPL_WHOISSECURE, target.nick, ":is using a secure connection"
        )
    if target.away:
        client.send_numeric(numerics.RPL_AWAY, target.nick, target.away)

    # Operators, and a user asking about themselves, see the real address.
    if client.is_oper or target is client:
        client.send_numeric(
            numerics.RPL_WHOISACTUALLY,
            target.nick, f"{target.user}@{target.real_host}", target.ip, ":Actual user@host, actual IP",
        )
    client.send_numeric(
        numerics.RPL_WHOISIDLE,
        target.nick, str(target.idle_seconds), str(int(target.connected_at)),
        ":seconds idle, signon time",
    )
    client.send_numeric(numerics.RPL_ENDOFWHOIS, target.nick, ":End of /WHOIS list")


@command("STATS", min_params=0, cost=2.0)
def handle_stats(server, client, msg):
    """Server statistics. Most letters are operator-only, because they
    describe the server's configuration and its connected users."""
    letter = (msg.param(0) or "u")[:1]

    if letter == "u":  # uptime is harmless to disclose
        uptime = server.stats()["uptime_seconds"]
        days, rest = divmod(uptime, 86400)
        hours, rest = divmod(rest, 3600)
        minutes, seconds = divmod(rest, 60)
        client.send_numeric(
            "242", f":Server Up {days} days {hours:02d}:{minutes:02d}:{seconds:02d}"
        )
        client.send_numeric(
            "250",
            f":Highest connection count: {server.peak_connections} "
            f"({server.total_connections} connections received)",
        )
        client.send_numeric("219", letter, ":End of /STATS report")
        return

    if not client.is_oper:
        client.send_numeric(numerics.ERR_NOPRIVILEGES, ":Permission denied")
        client.send_numeric("219", letter, ":End of /STATS report")
        return

    if letter in "kK":
        for ban in server.server_bans:
            if ban["kind"] != "K":
                continue
            client.send_numeric("216", "K", ban["mask"], "*", f":{ban['reason']}")
    elif letter in "dD":
        for ban in server.server_bans:
            if ban["kind"] != "D":
                continue
            client.send_numeric("225", "D", ban["mask"], f":{ban['reason']}")
    elif letter == "o":
        for block in server.config.opers:
            client.send_numeric("243", "O", block.host_mask, "*", block.name, ":0")
    elif letter == "c":
        for listener in server.config.resolved_listeners():
            client.send_numeric("213", "C", listener.host, str(listener.port), ":listener")
    elif letter == "m":
        for name, spec in sorted(REGISTRY.items()):
            client.send_numeric("212", name, "0", "0", str(spec.cost))
    client.send_numeric("219", letter, ":End of /STATS report")


@command("HELP", min_params=0)
def handle_help(server, client, msg):
    topic = (msg.param(0) or "").upper()

    if not topic:
        names = " ".join(sorted(REGISTRY))
        client.send_numeric("704", "*", ":meshircd commands:")
        for start in range(0, len(names), 350):
            client.send_numeric("705", "*", f":{names[start:start + 350]}")
        client.send_numeric("705", "*", ":Capabilities: " + " ".join(sorted(caps.CAPABILITIES)))
        client.send_numeric("706", "*", ":End of /HELP")
        return

    spec = REGISTRY.get(topic)
    if spec is None:
        client.send_numeric(numerics.ERR_HELPNOTFOUND, topic, ":No help available on this topic")
        return

    doc = (spec.handler.__doc__ or "No description available.").strip().splitlines()
    client.send_numeric("704", topic, f":{topic}")
    for line in doc[:20]:
        client.send_numeric("705", topic, f":{line.strip()}")
    requirements = []
    if spec.needs_oper:
        requirements.append("operator only")
    if spec.min_params:
        requirements.append(f"at least {spec.min_params} parameter(s)")
    if requirements:
        client.send_numeric("705", topic, ":Requires: " + ", ".join(requirements))
    client.send_numeric("706", topic, ":End of /HELP")
