"""Resolving a network interface name to an address.

Binding a listener to ``tailscale0`` or ``wg0`` by name is materially safer
than binding it to an address. Overlay-network addresses are assigned by the
overlay, can change when a node is re-authenticated or a key is rotated, and
are not known when the config file is written. An operator who wants "listen
only on the tailnet" should be able to say exactly that; making them
hardcode 100.x.y.z means the server either fails to start or, worse, falls
back to a wider bind after the address changes.

Only Linux is supported here, via SIOCGIFADDR for IPv4 and /proc/net/if_inet6
for IPv6 -- both are stdlib-reachable (``fcntl``/``struct`` and a plain file
read). On other platforms an interface: spec raises, and the operator can
still bind by address.
"""

from __future__ import annotations

import socket
import sys

IFACE_PREFIX = "interface:"


class InterfaceError(Exception):
    """An interface was named in the config but could not be resolved."""


def _ipv4_for(name: str) -> str | None:
    if not sys.platform.startswith("linux"):
        return None
    import fcntl
    import struct

    SIOCGIFADDR = 0x8915
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", name.encode("utf-8")[:15])
        info = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, packed)
        return socket.inet_ntoa(info[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def _ipv6_for(name: str) -> str | None:
    if not sys.platform.startswith("linux"):
        return None
    try:
        with open("/proc/net/if_inet6", "r") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None
    for line in lines:
        fields = line.split()
        if len(fields) < 6 or fields[5] != name:
            continue
        raw = fields[0]
        grouped = ":".join(raw[i : i + 4] for i in range(0, 32, 4))
        try:
            # Normalise (compress zero runs) so logs show a canonical form.
            return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, grouped))
        except OSError:
            continue
    return None


def resolve_interface(name: str, prefer_ipv6: bool = False) -> str:
    """Return an address currently assigned to `name`.

    Raises InterfaceError if the interface has no usable address -- which is
    the correct outcome at startup. Silently widening the bind because an
    overlay interface is not up yet is exactly the accident this indirection
    exists to prevent.
    """
    order = (_ipv6_for, _ipv4_for) if prefer_ipv6 else (_ipv4_for, _ipv6_for)
    for lookup in order:
        address = lookup(name)
        if address:
            return address
    raise InterfaceError(
        f"interface {name!r} has no address assigned "
        f"(is the interface up? for Tailscale/WireGuard, start it before the server)"
    )


def resolve_host(host: str) -> str:
    """Expand an ``interface:<name>`` host spec; pass anything else through."""
    if not host.startswith(IFACE_PREFIX):
        return host
    spec = host[len(IFACE_PREFIX) :]
    name, _, family = spec.partition("/")
    if family not in ("", "4", "6"):
        raise InterfaceError(f"bad interface spec {host!r}: family must be 4 or 6")
    return resolve_interface(name, prefer_ipv6=(family == "6"))
