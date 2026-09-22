"""Channel state.

A channel is server-managed state, not something a client owns. It comes
into existence when the first member JOINs and -- unless it has state worth
keeping -- disappears when the last member PARTs.

"State worth keeping" is the one place this differs from the in-memory
version: a channel that somebody has deliberately configured (a topic, a
mode, a ban, an op grant) is written to the database and restored at
startup, so a server restart no longer silently resets every channel on
the network. A channel nobody configured is still purely ephemeral, which
keeps the table from growing without bound.
"""

from __future__ import annotations

import fnmatch
import time

from .protocol import casefold

# Modes taking no parameter.
#   i  invite only          n  no messages from outside the channel
#   m  moderated            p  private (hidden from LIST)
#   s  secret (hidden from LIST and from WHOIS/NAMES of non-members)
#   t  only ops may set the topic
BOOL_MODES = frozenset("imnpst")

# List modes: a mask list rather than a flag.
#   b  ban        e  ban exception     I  invite exception
LIST_MODES = frozenset("beI")

# Membership prefixes, most privileged first. The order matters: it is the
# order advertised in ISUPPORT PREFIX and the order NAMES uses.
PREFIX_MODES = (("o", "@"), ("v", "+"))
PREFIX_BY_MODE = dict(PREFIX_MODES)
MODE_BY_PREFIX = {p: m for m, p in PREFIX_MODES}


class Channel:
    def __init__(self, name: str, created_at: int | None = None):
        self.name = name  # display form, as first used
        self.key_lower = casefold(name)
        self.created_at = created_at or int(time.time())

        # Client -> set of membership modes held ({"o"}, {"v"}, or empty).
        self.members: dict = {}

        self.topic: str | None = None
        self.topic_setter: str = ""
        self.topic_time: int = 0

        self.modes: set[str] = set()
        self.key: str | None = None
        self.limit: int | None = None

        # kind -> list of (mask, setter, set_at)
        self.lists: dict[str, list[tuple[str, str, int]]] = {k: [] for k in LIST_MODES}

        # Nicks invited past +i. Cleared for a nick once it joins.
        self.invited: set[str] = set()

        # account name -> "o" | "v". Survives restarts and reconnects, and
        # re-applies when that account next joins.
        self.access: dict[str, str] = {}

        self.dirty = False  # has state that should be written to storage

    # --- membership ----------------------------------------------------

    def add_member(self, client, modes: str = ""):
        self.members[client] = set(modes)

    def remove_member(self, client):
        self.members.pop(client, None)

    def has_member(self, client) -> bool:
        return client in self.members

    def is_op(self, client) -> bool:
        return "o" in self.members.get(client, ())

    def is_voiced(self, client) -> bool:
        return bool(self.members.get(client, set()) & {"o", "v"})

    def give(self, client, mode: str):
        if client in self.members:
            self.members[client].add(mode)

    def take(self, client, mode: str):
        if client in self.members:
            self.members[client].discard(mode)

    def prefix_for(self, client) -> str:
        """The single highest prefix, for clients without multi-prefix."""
        held = self.members.get(client, set())
        for mode, prefix in PREFIX_MODES:
            if mode in held:
                return prefix
        return ""

    def all_prefixes_for(self, client) -> str:
        """Every prefix held, for clients that negotiated multi-prefix."""
        held = self.members.get(client, set())
        return "".join(p for m, p in PREFIX_MODES if m in held)

    # --- masks ---------------------------------------------------------

    def matches_list(self, kind: str, hostmask: str) -> bool:
        target = hostmask.lower()
        return any(fnmatch.fnmatch(target, mask.lower()) for mask, _, _ in self.lists.get(kind, ()))

    def is_banned(self, hostmask: str) -> bool:
        """Banned unless an explicit exception covers the same mask."""
        if not self.matches_list("b", hostmask):
            return False
        return not self.matches_list("e", hostmask)

    def add_list_entry(self, kind: str, mask: str, setter: str) -> bool:
        if any(existing == mask for existing, _, _ in self.lists[kind]):
            return False
        self.lists[kind].append((mask, setter, int(time.time())))
        self.dirty = True
        return True

    def remove_list_entry(self, kind: str, mask: str) -> bool:
        before = len(self.lists[kind])
        self.lists[kind] = [e for e in self.lists[kind] if e[0] != mask]
        changed = len(self.lists[kind]) != before
        self.dirty = self.dirty or changed
        return changed

    # --- modes ---------------------------------------------------------

    def mode_string(self, for_member: bool = True) -> tuple[str, list[str]]:
        """Render the current modes as (flags, args).

        Key and limit are only disclosed to members: a non-member learning
        the key from a MODE query would walk straight through +k.
        """
        flags = "".join(sorted(m for m in self.modes if m in BOOL_MODES))
        args: list[str] = []
        if self.key:
            flags += "k"
            if for_member:
                args.append(self.key)
            else:
                args.append("*")
        if self.limit:
            flags += "l"
            args.append(str(self.limit))
        return flags, args

    @property
    def is_secret(self) -> bool:
        return "s" in self.modes

    @property
    def is_private(self) -> bool:
        return "p" in self.modes

    def visible_to(self, client) -> bool:
        """Whether the channel should appear in LIST/WHOIS/NAMES output."""
        if not (self.is_secret or self.is_private):
            return True
        return self.has_member(client)

    # --- persistence ----------------------------------------------------

    def worth_persisting(self) -> bool:
        """Only channels somebody deliberately configured are stored.

        Without this test the channels table becomes an unbounded log of
        every throwaway channel any unauthenticated user ever created.

        Note what is deliberately NOT in this list: ``access``. The
        creator of a channel is auto-opped, so if a recorded op grant on
        its own were enough, every channel any logged-in user ever
        created would be stored forever. Access is persisted *alongside*
        a channel that earns storage some other way -- somebody set a
        topic, a mode, or a ban.
        """
        return bool(
            self.topic
            or self.modes
            or self.key
            or self.limit
            or any(self.lists[k] for k in LIST_MODES)
        )

    def to_state(self) -> dict:
        return {
            "name_lower": self.key_lower,
            "name": self.name,
            "topic": self.topic,
            "topic_setter": self.topic_setter,
            "topic_time": self.topic_time,
            "modes": "".join(sorted(self.modes)),
            "key": self.key,
            "user_limit": self.limit,
            "created_at": self.created_at,
        }

    @classmethod
    def from_state(cls, state: dict) -> "Channel":
        channel = cls(state["name"], created_at=state.get("created_at"))
        channel.topic = state.get("topic")
        channel.topic_setter = state.get("topic_setter") or ""
        channel.topic_time = state.get("topic_time") or 0
        channel.modes = set(state.get("modes") or "")
        channel.key = state.get("key")
        channel.limit = state.get("user_limit")
        for kind, entries in (state.get("lists") or {}).items():
            if kind in LIST_MODES:
                channel.lists[kind] = [(e["mask"], e["setter"], e["set_at"]) for e in entries]
        channel.access = dict(state.get("access") or {})
        return channel

    def __repr__(self):
        return f"<Channel {self.name} members={len(self.members)} modes={''.join(sorted(self.modes))}>"
