"""Host cloaking.

Every JOIN, PART, QUIT, KICK and PRIVMSG the server relays carries the
sender's hostmask, and in the uncloaked version of this server that mask
contained the client's real IP address. Anyone idling in a channel could
therefore harvest the address of everyone who spoke in it. For a server
whose expected deployment is a small private mesh, that is a straight
privacy leak.

A cloak replaces the address with a stable pseudonym:

    203.0.113.45   ->  7f3a91c2.b41e07.9d22ac.ip

Three properties matter, and they pull against each other:

1. **Stable.** The same address must always produce the same cloak, or
   channel bans against a cloaked mask would stop working the moment a
   user reconnects.
2. **Irreversible.** Given a cloak, recovering the address must be
   infeasible. HMAC with a secret key does this; a plain hash does not,
   because the IPv4 space is small enough to enumerate exhaustively in
   seconds.
3. **Structure-preserving.** Bans are written as globs, so operators need
   to be able to ban a whole network. The segments are hashes of
   progressively broader prefixes, so `*.9d22ac.ip` bans the entire /16
   that `7f3a91c2.b41e07.9d22ac.ip` belongs to, without revealing which
   /16 that is.

The secret must be stable across restarts. If it is not, every cloak
changes on restart and every cloak-based ban silently stops matching --
which is why `config.load()` warns loudly when it has to invent one.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress


class Cloaker:
    def __init__(self, secret: str, suffix: str = "ip", enabled: bool = True):
        self.enabled = enabled
        self.suffix = suffix.strip(".") or "ip"
        self._key = secret.encode("utf-8")

    def _digest(self, label: str, data: str, length: int) -> str:
        mac = hmac.new(self._key, f"{label}\0{data}".encode("utf-8"), hashlib.sha256)
        return mac.hexdigest()[:length]

    def cloak(self, address: str) -> str:
        """Return the cloaked host for a client address."""
        if not self.enabled:
            return address
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            # Not an address at all (a unix socket peer, or a hostname a
            # proxy handed us). Hash it whole rather than leaking it.
            return f"{self._digest('host', address.lower(), 12)}.{self.suffix}"

        if parsed.version == 4:
            octets = address.split(".")
            return ".".join((
                self._digest("v4-full", address, 8),
                self._digest("v4-24", ".".join(octets[:3]), 6),
                self._digest("v4-16", ".".join(octets[:2]), 6),
                self.suffix,
            ))

        full = parsed.compressed
        net64 = str(ipaddress.ip_network(f"{full}/64", strict=False).network_address)
        net48 = str(ipaddress.ip_network(f"{full}/48", strict=False).network_address)
        return ".".join((
            self._digest("v6-full", full, 8),
            self._digest("v6-64", net64, 6),
            self._digest("v6-48", net48, 6),
            f"{self.suffix}6",
        ))

    def matches_any_prefix(self, address: str) -> list[str]:
        """The cloak plus the broader masks that would also match it.

        Useful for operator tooling ("what would I have to ban to cover
        this user's /24?") without exposing the address itself.
        """
        cloaked = self.cloak(address)
        parts = cloaked.split(".")
        if len(parts) != 4:
            return [cloaked]
        return [
            cloaked,
            "*." + ".".join(parts[1:]),
            "*." + ".".join(parts[2:]),
        ]
