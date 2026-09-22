"""Connection registration, capability negotiation and SASL."""

from __future__ import annotations

import base64
import binascii

from .. import caps, numerics
from ..accounts import MAX_PASSWORD_LENGTH
from ..protocol import Message, casefold
from ..validation import (
    clean_text,
    is_valid_nick,
    sanitise_username,
)
from . import command

# A SASL payload arrives in 400-byte chunks; a chunk shorter than 400 ends
# the message. Cap the reassembled total so a client cannot stream an
# unbounded base64 blob into memory before we ever try to decode it.
SASL_CHUNK = 400
MAX_SASL_PAYLOAD = 8192
MAX_SASL_FAILURES = 5


@command("PASS", min_params=1, needs_registration=False)
def handle_pass(server, client, msg):
    if client.registered:
        client.send_numeric(numerics.ERR_ALREADYREGISTERED, ":You may not reregister")
        return
    # Stored, not checked: the comparison happens at registration, when we
    # also know whether SASL already authenticated this connection.
    client.password_sent = msg.param(0)[:MAX_PASSWORD_LENGTH]


@command("NICK", min_params=0, needs_registration=False)
def handle_nick(server, client, msg):
    if not msg.params or not msg.params[0]:
        client.send_numeric(numerics.ERR_NONICKNAMEGIVEN, ":No nickname given")
        return

    new_nick = msg.params[0]
    if not is_valid_nick(new_nick, server.config.limits.max_nick_length):
        client.send_numeric(numerics.ERR_ERRONEUSNICKNAME, new_nick, ":Erroneous nickname")
        return

    existing = server.find_any_client(new_nick)
    if existing is not None and existing is not client:
        client.send_numeric(numerics.ERR_NICKNAMEINUSE, new_nick, ":Nickname is already in use")
        return

    old_nick = client.nick
    if existing is client and old_nick == new_nick:
        return  # no-op, but a case-only change still goes through below

    renaming = client.registered and old_nick is not None
    old_hostmask = client.hostmask if renaming else None

    server.set_nick(client, new_nick)

    if renaming:
        # Everyone who can see this user needs to learn the new name, and
        # the user needs to see it too -- with the OLD mask as the source,
        # which is how clients match it to the person they knew.
        message = Message(command="NICK", params=[new_nick], source=old_hostmask)
        server.broadcast(server.common_peers(client, include_self=True), message)
    else:
        server.try_complete_registration(client)


@command("USER", min_params=4, needs_registration=False)
def handle_user(server, client, msg):
    if client.registered:
        client.send_numeric(numerics.ERR_ALREADYREGISTERED, ":You may not reregister")
        return
    # The '~' prefix marks the username as unverified -- we have no ident
    # lookup, so nothing the client claims here has been checked.
    client.user = sanitise_username(msg.param(0))
    client.realname = clean_text(msg.param(3), 200) or client.user
    server.try_complete_registration(client)


@command("PING", min_params=0, needs_registration=False)
def handle_ping(server, client, msg):
    token = msg.param(0) or server.config.server.name
    client.send(
        Message(
            command="PONG",
            params=[server.config.server.name, token],
            source=server.config.server.name,
        )
    )


@command("PONG", min_params=0, needs_registration=False)
def handle_pong(server, client, msg):
    # Answering our idle probe. The read loop already cleared ping_pending
    # on receipt of any byte; this exists so that a well-behaved client's
    # PONG is not answered with "Unknown command".
    client.ping_pending = None


@command("QUIT", min_params=0, needs_registration=False)
def handle_quit(server, client, msg):
    reason = clean_text(msg.param(0) or "Client quit", 300)
    client.send_raw(f"ERROR :Closing Link: {client.nick or '*'} (Quit: {reason})")
    server.remove_client(client, f"Quit: {reason}")
    client.disconnect(f"Quit: {reason}")


# --- capability negotiation ---------------------------------------------


@command("CAP", min_params=1, needs_registration=False)
def handle_cap(server, client, msg):
    sub = msg.param(0).upper()
    nick = client.nick or "*"
    name = server.config.server.name
    offered = caps.available_for(client)

    def reply(*params):
        client.send(Message(command="CAP", params=[nick, *params], source=name))

    if sub == "LS":
        # "CAP LS 302" signals a client that understands cap values and
        # cap-notify. Registration must now wait for CAP END.
        if len(msg.params) > 1 and msg.params[1].isdigit():
            client.cap_version = int(msg.params[1])
        client.cap_negotiating = True
        reply("LS", caps.render_ls(client))

    elif sub == "LIST":
        reply("LIST", " ".join(sorted(client.caps)))

    elif sub == "REQ":
        client.cap_negotiating = True
        requested = msg.param(1).split()
        # All-or-nothing: the spec requires that a REQ is applied in full
        # or not at all, so a client is never left guessing which half of
        # its request took effect.
        additions, removals = [], []
        for item in requested:
            if item.startswith("-"):
                removals.append(item[1:])
            else:
                additions.append(item)
        if all(c in offered for c in additions) and requested:
            client.caps.update(additions)
            client.caps.difference_update(removals)
            reply("ACK", " ".join(requested))
        else:
            reply("NAK", " ".join(requested))

    elif sub == "END":
        client.cap_negotiating = False
        server.try_complete_registration(client)

    else:
        client.send_numeric(numerics.ERR_INVALIDCAPCMD, msg.param(0), ":Invalid CAP command")


# --- SASL -----------------------------------------------------------------


def _sasl_fail(client, message: str = ":SASL authentication failed"):
    client.sasl_mechanism = None
    client.sasl_buffer = ""
    client.sasl_failures += 1
    client.send_numeric(numerics.ERR_SASLFAIL, message)
    if client.sasl_failures >= MAX_SASL_FAILURES:
        client.send_raw("ERROR :Closing Link: Too many authentication failures")
        client.disconnect("Too many authentication failures")


def _login_success(server, client, account: str):
    client.account = account
    client.sasl_mechanism = None
    client.sasl_buffer = ""
    client.send_numeric(
        numerics.RPL_LOGGEDIN,
        client.hostmask,
        account,
        f":You are now logged in as {account}",
    )
    client.send_numeric(numerics.RPL_SASLSUCCESS, ":SASL authentication successful")
    server.log.info("%s authenticated as account %s", client, account)


@command("AUTHENTICATE", min_params=1, needs_registration=False, cost=2.0)
async def handle_authenticate(server, client, msg):
    arg = msg.param(0)

    if "sasl" not in client.caps:
        # The client never negotiated SASL, so it should not be sending
        # this at all.
        client.send_numeric(numerics.ERR_SASLFAIL, ":SASL authentication failed")
        return

    if not client.tls:
        # Enforced independently of CAP LS hiding 'sasl' over plaintext: a
        # client that ignores the capability list and tries anyway must
        # still be refused, or the TLS requirement is decorative.
        client.send_numeric(
            numerics.ERR_SASLFAIL, ":SASL requires a TLS-encrypted connection"
        )
        return

    if client.account is not None:
        client.send_numeric(numerics.ERR_SASLALREADY, ":You have already authenticated")
        return

    # --- mechanism selection ---------------------------------------
    if client.sasl_mechanism is None:
        if arg == "*":
            client.send_numeric(numerics.ERR_SASLABORTED, ":SASL authentication aborted")
            return
        mechanism = arg.upper()
        if mechanism == "PLAIN":
            client.sasl_mechanism = "PLAIN"
            client.send_raw("AUTHENTICATE +")
        elif mechanism == "EXTERNAL":
            # CertFP: the client already proved possession of a private key
            # during the TLS handshake, so there is no password exchange.
            if not client.certfp:
                _sasl_fail(client, ":No TLS client certificate was presented")
                return
            client.sasl_mechanism = "EXTERNAL"
            client.send_raw("AUTHENTICATE +")
        else:
            client.send_numeric(
                numerics.RPL_SASLMECHS, "PLAIN,EXTERNAL", ":are available SASL mechanisms"
            )
            client.send_numeric(numerics.ERR_SASLFAIL, ":SASL authentication failed")
        return

    # --- payload ----------------------------------------------------
    if arg == "*":
        client.sasl_mechanism = None
        client.sasl_buffer = ""
        client.send_numeric(numerics.ERR_SASLABORTED, ":SASL authentication aborted")
        return

    if len(client.sasl_buffer) + len(arg) > MAX_SASL_PAYLOAD:
        client.sasl_buffer = ""
        client.sasl_mechanism = None
        client.send_numeric(numerics.ERR_SASLTOOLONG, ":SASL message too long")
        return

    if arg != "+":
        client.sasl_buffer += arg
    if len(arg) == SASL_CHUNK:
        return  # a full-length chunk means more is coming

    payload = client.sasl_buffer
    client.sasl_buffer = ""
    mechanism = client.sasl_mechanism

    if mechanism == "EXTERNAL":
        account = await server.storage.run(server.accounts.verify_fingerprint, client.certfp)
        if account is None:
            _sasl_fail(client, ":Your certificate fingerprint is not registered")
            return
        _login_success(server, client, account)
        return

    try:
        raw = base64.b64decode(payload, validate=True)
        authzid, authcid, password = raw.split(b"\0", 2)
    except (binascii.Error, ValueError):
        _sasl_fail(client)
        return

    if len(password) > MAX_PASSWORD_LENGTH:
        _sasl_fail(client)
        return

    if authzid and authzid != authcid:
        # Authenticating as one identity while acting as another is not
        # supported; authzid must be empty or identical.
        _sasl_fail(client)
        return

    authcid_str = authcid.decode("utf-8", errors="replace")
    password_str = password.decode("utf-8", errors="replace")

    # scrypt is deliberately expensive and blocking. Running it inline
    # would freeze every other client for the duration of one login.
    account = await server.storage.run(server.accounts.verify, authcid_str, password_str)
    if account is None:
        server.log.info("failed SASL login for %r from %s", casefold(authcid_str), client.ip)
        _sasl_fail(client)
        return

    _login_success(server, client, account)
