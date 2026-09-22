"""Command registry and dispatch.

Every handler is registered with the constraints it needs rather than
re-checking them itself. That is not only less repetitive: it means the
"have you registered?", "did you send enough parameters?" and "are you an
operator?" checks cannot be forgotten on a new command, which is exactly
the kind of omission that turns into an authentication bypass.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Callable

from .. import numerics
from ..protocol import Message

# Commands a connection may use before it has registered. Everything else
# gets 451 until NICK and USER have been accepted.
PRE_REGISTRATION = {"NICK", "USER", "PASS", "CAP", "AUTHENTICATE", "PING", "PONG", "QUIT", "ERROR"}


@dataclass
class CommandSpec:
    name: str
    handler: Callable
    min_params: int = 0
    needs_registration: bool = True
    needs_oper: bool = False
    # Flood cost. Commands that are cheap for the client to send but
    # expensive for us to answer cost more than one token.
    cost: float = 1.0


REGISTRY: dict[str, CommandSpec] = {}


def command(
    name: str,
    *,
    min_params: int = 0,
    needs_registration: bool = True,
    needs_oper: bool = False,
    cost: float = 1.0,
):
    def decorate(func):
        REGISTRY[name.upper()] = CommandSpec(
            name=name.upper(),
            handler=func,
            min_params=min_params,
            needs_registration=needs_registration,
            needs_oper=needs_oper,
            cost=cost,
        )
        return func

    return decorate


async def dispatch(server, client, message: Message):
    spec = REGISTRY.get(message.command)

    if spec is None:
        if client.registered:
            client.send_numeric(numerics.ERR_UNKNOWNCOMMAND, message.command, ":Unknown command")
        return

    if spec.needs_registration and not client.registered:
        client.send_numeric(numerics.ERR_NOTREGISTERED, ":You have not registered")
        return

    if spec.needs_oper and not client.is_oper:
        client.send_numeric(numerics.ERR_NOPRIVILEGES, ":Permission denied")
        return

    if len(message.params) < spec.min_params:
        client.send_numeric(numerics.ERR_NEEDMOREPARAMS, spec.name, ":Not enough parameters")
        return

    # Extra cost beyond the single token already spent by the read loop.
    if spec.cost > 1.0 and not client.consume_flood_token(spec.cost - 1.0):
        client.send_numeric(
            numerics.ERR_UNKNOWNERROR, spec.name, ":Rate limited, please slow down"
        )
        return

    try:
        result = spec.handler(server, client, message)
        if inspect.isawaitable(result):
            await result
    except Exception:
        # One buggy handler must not take the connection down with it. Log
        # the traceback locally and tell the client something deliberately
        # generic -- internals never go over the wire.
        server.log.exception("handler error: %s from %s", spec.name, client)
        client.send_numeric(
            numerics.ERR_UNKNOWNERROR, spec.name, ":Server error handling command"
        )


def load_all():
    """Import every handler module so their decorators run."""
    from . import channels, messaging, modes, operator, queries, registration  # noqa: F401


load_all()
