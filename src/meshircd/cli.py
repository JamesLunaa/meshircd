"""Command-line entry points: the daemon and the admin tool."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import os
import ssl
import sys

from . import config as config_module
from .accounts import AccountError, AccountStore, new_hash
from .logsetup import configure
from .server import VERSION, Server
from .storage import Storage


# --- the daemon ---------------------------------------------------------


async def _run(cfg) -> int:
    log = configure(cfg.logging.level, cfg.logging.format)
    log.info("meshircd %s starting (config: %s)", VERSION, cfg.source_path or "built-in defaults")

    server = Server(cfg, log)
    server.load_state()
    try:
        await server.start()
    except RuntimeError as exc:
        log.error("%s", exc)
        server.storage.close()
        return 1

    server.install_signal_handlers(asyncio.get_running_loop())
    log.info("ready: %d listener(s)", len(cfg.listeners))
    await server.serve_forever()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="meshircd", description="A small IRC server, standard library only."
    )
    parser.add_argument("-c", "--config", help="path to ircd.toml")
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate the configuration and exit without binding anything",
    )
    parser.add_argument("--version", action="version", version=f"meshircd {VERSION}")
    args = parser.parse_args(argv)

    try:
        cfg = config_module.load(args.config)
    except config_module.ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    if args.check_config:
        print(f"config OK: {cfg.source_path or 'built-in defaults'}")
        print(f"  server name : {cfg.server.name}  (network {cfg.server.network})")
        try:
            for listener in cfg.resolved_listeners():
                print(f"  listener    : {listener.label}")
        except Exception as exc:
            print(f"  listener    : UNRESOLVABLE -- {exc}", file=sys.stderr)
            return 2
        print(f"  storage     : {cfg.storage_path}")
        print(f"  cloaking    : {'on' if cfg.cloak.enabled else 'OFF'}"
              + ("  (WARNING: no secret set, cloaks change on restart)"
                 if cfg.cloak.enabled and cfg.cloak_secret_ephemeral else ""))
        print(f"  oper blocks : {len(cfg.opers)}")
        return 0

    try:
        return asyncio.run(_run(cfg))
    except KeyboardInterrupt:
        return 0


# --- the admin tool ------------------------------------------------------


def fingerprint_of_pem(path: str) -> str:
    """SHA-256 fingerprint of a PEM certificate -- the same value the
    server computes from the certificate a client presents."""
    try:
        with open(path, "r") as handle:
            pem = handle.read()
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"could not read certificate {path}: {exc}")
    return hashlib.sha256(der).hexdigest()


def _read_password(prompt: str, use_stdin: bool, confirm: bool = True) -> str:
    if use_stdin:
        return sys.stdin.readline().rstrip("\n")
    password = getpass.getpass(f"{prompt}: ")
    if confirm and password != getpass.getpass("Confirm: "):
        raise SystemExit("passwords did not match")
    return password


def _store(args) -> AccountStore:
    try:
        cfg = config_module.load(args.config)
    except config_module.ConfigError as exc:
        raise SystemExit(f"configuration error: {exc}")
    return AccountStore(Storage(cfg.storage_path))


def ctl(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="meshircdctl", description="Manage meshircd accounts and configuration."
    )
    parser.add_argument("-c", "--config", help="path to ircd.toml")
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name, help_text):
        return sub.add_parser(name, help=help_text)

    create = add("create", "create an account")
    create.add_argument("name")
    create.add_argument("--stdin", action="store_true",
                        help="read the password from stdin (for scripted provisioning)")

    add("list", "list accounts")

    delete = add("delete", "delete an account")
    delete.add_argument("name")

    passwd = add("passwd", "change an account password")
    passwd.add_argument("name")
    passwd.add_argument("--stdin", action="store_true")

    lock = add("lock", "prevent an account from authenticating")
    lock.add_argument("name")
    unlock = add("unlock", "allow an account to authenticate again")
    unlock.add_argument("name")

    certfp = add("certfp", "manage TLS client-certificate fingerprints")
    certfp.add_argument("action", choices=["add", "list", "remove"])
    certfp.add_argument("name", nargs="?")
    certfp.add_argument("fingerprint", nargs="?")

    oper = add("oper-hash", "generate an [[oper]] password hash for the config file")
    oper.add_argument("name")
    oper.add_argument("--stdin", action="store_true")

    add("server-pass", "generate a server password hash for the config file")
    add("stats", "show database statistics")
    add("genconfig", "print a starter ircd.toml to stdout")

    args = parser.parse_args(argv)

    if args.command == "genconfig":
        print(EXAMPLE_CONFIG)
        return 0

    if args.command == "oper-hash":
        password = _read_password(f"Password for oper {args.name}", args.stdin)
        if len(password) < 8:
            raise SystemExit("oper passwords must be at least 8 characters")
        salt, digest = new_hash(password)
        print("# Add this to your ircd.toml:\n")
        print("[[oper]]")
        print(f'name = "{args.name}"')
        print(f'salt = "{salt}"')
        print(f'password_hash = "{digest}"')
        print('host_mask = "*!*@*"      # tighten this to the address you oper from')
        print("tls_only = true")
        return 0

    if args.command == "server-pass":
        password = _read_password("Server password", False)
        salt, digest = new_hash(password)
        print("# Add this to the [server] section of your ircd.toml:\n")
        print(f'password_salt = "{salt}"')
        print(f'password_hash = "{digest}"')
        return 0

    store = _store(args)

    try:
        if args.command == "create":
            password = _read_password(f"Password for {args.name}", args.stdin)
            store.create(args.name, password)
            print(f"account {args.name!r} created")

        elif args.command == "list":
            rows = store.list()
            if not rows:
                print("no accounts")
            for row in rows:
                flags = " [LOCKED]" if row["locked"] else ""
                fingerprints = store.fingerprints(row["name"])
                extra = f"  certfp={len(fingerprints)}" if fingerprints else ""
                print(f"{row['name']}{flags}{extra}")

        elif args.command == "delete":
            store.delete(args.name)
            print(f"account {args.name!r} deleted")

        elif args.command == "passwd":
            store.set_password(args.name, _read_password(f"New password for {args.name}", args.stdin))
            print(f"password for {args.name!r} changed")

        elif args.command in ("lock", "unlock"):
            store.set_locked(args.name, args.command == "lock")
            print(f"account {args.name!r} {args.command}ed")

        elif args.command == "certfp":
            if args.action == "list":
                if not args.name:
                    raise SystemExit("certfp list requires an account name")
                for item in store.fingerprints(args.name):
                    print(item)
            elif args.action == "add":
                if not (args.name and args.fingerprint):
                    raise SystemExit(
                        "certfp add requires <name> <fingerprint|certificate.pem>"
                    )
                value = args.fingerprint
                if os.path.exists(value):
                    value = fingerprint_of_pem(value)
                    print(f"certificate fingerprint: {value}")
                store.add_fingerprint(args.name, value)
                print(f"fingerprint added to {args.name!r}")
            else:
                if not args.fingerprint and not args.name:
                    raise SystemExit("certfp remove requires a fingerprint")
                store.remove_fingerprint(args.fingerprint or args.name)
                print("fingerprint removed")

        elif args.command == "stats":
            for key, value in store.storage.stats().items():
                print(f"{key:16} {value}")

    except AccountError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        store.storage.close()

    return 0


EXAMPLE_CONFIG = '''# meshircd configuration.
# Every setting shown here is the default unless noted.

[server]
name        = "irc.example.org"   # must look like a hostname
network     = "ExampleNet"
description = "an meshircd instance"
# motd_file = "/etc/meshircd/motd.txt"
admin_name     = "unconfigured"
admin_location = "unconfigured"
admin_email    = "unconfigured"
# Require a password to connect at all (meshircdctl server-pass):
# password_salt = ""
# password_hash = ""

[storage]
path = "/var/lib/meshircd/meshircd.db"
# Peers allowed to send a PROXY header on a proxy_protocol listener.
trusted_proxies = ["127.0.0.1/32", "::1/128"]

# --- listeners ---------------------------------------------------------
# Bind by interface name for overlay networks: the address a tailnet or
# WireGuard peer gets is assigned by the overlay and can change, but the
# interface name does not.

[[listen]]
host = "127.0.0.1"
port = 6667

# [[listen]]
# host = "interface:tailscale0"    # or "interface:wg0"
# port = 6667

# [[listen]]
# host = "::"
# port = 6697
# tls  = true

# Behind a TLS terminator or load balancer. Only enable proxy_protocol on
# a listener the proxy alone can reach: the header lets the sender choose
# the client's apparent address.
# [[listen]]
# host = "127.0.0.1"
# port = 6668
# proxy_protocol = true

[tls]
# cert = "/etc/meshircd/tls/fullchain.pem"
# key  = "/etc/meshircd/tls/privkey.pem"
min_version = "TLSv1_2"

# CertFP / SASL EXTERNAL. Off by default: Python's ssl module cannot accept
# a client certificate it is unable to verify, so switching this on without
# a matching client_ca would stop anyone holding an unrelated client
# certificate from connecting at all. Point client_ca at the CA that signs
# your users' certificates, or at a bundle of the self-signed client
# certificates you accept.
# request_client_cert = true
# client_ca = "/etc/meshircd/tls/client-ca.pem"

[cloak]
enabled = true
# Generate once and keep it: changing it changes every user's visible host
# and silently breaks every cloak-based ban.
#   python3 -c "import secrets; print(secrets.token_hex(32))"
secret = ""
suffix = "ip"

[limits]
max_connections         = 1024
max_connections_per_ip  = 8
max_channels_per_client = 40
# flood_burst must absorb a client's reconnect: registration plus one JOIN
# per remembered channel. The server refuses to start if it is too small
# for max_channels_per_client, because the failure it causes -- ordinary
# clients disconnected for flooding the moment they reconnect -- is very
# hard to diagnose from the client side.
flood_burst             = 120
flood_refill_per_sec    = 2
ping_interval           = 120
ping_timeout            = 30
registration_timeout    = 30

[logging]
level  = "INFO"
format = "text"          # or "json"
log_raw_lines = false    # debugging only: records who said what

# --- operators ----------------------------------------------------------
# Generate a block with: meshircdctl oper-hash <name>
# [[oper]]
# name = "admin"
# salt = "..."
# password_hash = "..."
# host_mask = "*!*@10.0.0.5"
# tls_only = true
'''


if __name__ == "__main__":
    raise SystemExit(main())
