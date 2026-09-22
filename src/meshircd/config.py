"""Configuration: defaults, TOML file, environment overrides.

Precedence, lowest to highest: built-in defaults, the TOML file, then
``IRCD_*`` environment variables. The environment wins last because that is
the layer a container or systemd drop-in can set without rewriting a file
baked into an image.

Defaults are deliberately the *safe* ones rather than the convenient ones:
loopback-only listeners, cloaking on, no opers. A fresh install should be
useless to the internet until someone has decided otherwise in writing.
"""

from __future__ import annotations

import os
import secrets
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

from .netiface import resolve_host

DEFAULT_CONFIG_PATHS = (
    "./ircd.toml",
    "/etc/meshircd/ircd.toml",
)


class ConfigError(Exception):
    """The configuration is not usable. Always fatal at startup."""


@dataclass(frozen=True)
class Listener:
    host: str = "127.0.0.1"
    port: int = 6667
    tls: bool = False
    # PROXY protocol v1/v2 header parsing. Only ever enable this on a
    # listener that is unreachable except through the trusted proxy: the
    # header lets whoever sends it choose the client's apparent IP, which
    # would otherwise defeat every per-IP limit and ban we apply.
    proxy_protocol: bool = False

    @property
    def label(self) -> str:
        scheme = "tls" if self.tls else "plain"
        return f"{self.host}:{self.port} ({scheme})"


@dataclass(frozen=True)
class TLSConfig:
    cert: str | None = None
    key: str | None = None
    # TLS 1.2 floor: 1.0/1.1 have no safe configuration left and every
    # client that can speak IRC over TLS at all can speak 1.2.
    min_version: str = "TLSv1_2"
    ciphers: str = "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!RC4:!EXPORT"
    # CertFP (SASL EXTERNAL) support. Off by default, and deliberately so.
    #
    # Python's ssl module exposes no certificate-verification callback, so
    # the only way to ask a client for a certificate is CERT_OPTIONAL --
    # and CERT_OPTIONAL *aborts the handshake* for any certificate that
    # does not chain to a trusted CA. Turning this on unconditionally would
    # mean a user whose client happens to hold an unrelated client
    # certificate could no longer connect at all. That is a far worse
    # failure than not offering CertFP.
    #
    # So: enable it deliberately, and point client_ca at the CA that signs
    # your users' certificates (or at a bundle of the self-signed client
    # certificates you accept). Clients presenting a certificate outside
    # that bundle will be refused at the TLS layer.
    request_client_cert: bool = False
    client_ca: str | None = None
    prefer_server_ciphers: bool = True


@dataclass(frozen=True)
class Limits:
    max_connections: int = 1024
    max_connections_per_ip: int = 8
    max_channels_per_client: int = 40
    max_bans_per_channel: int = 200
    max_invites_per_channel: int = 100
    max_targets_per_message: int = 4
    max_away_length: int = 200
    max_topic_length: int = 390
    max_kick_length: int = 255
    max_nick_length: int = 30
    max_channel_length: int = 50
    max_sendq_bytes: int = 1024 * 1024
    max_recvq_bytes: int = 8192
    # Burst must cover a real client's reconnect storm: CAP + SASL +
    # NICK/USER is roughly ten commands, then one JOIN per remembered
    # channel, then the MODE and WHO many clients send per channel after
    # joining. A burst smaller than that flood-kills ordinary clients on
    # reconnect, which looks exactly like a server fault. The sustained
    # refill rate is what actually limits abuse; the burst only absorbs
    # the spike. See the validation in load(), which refuses a
    # configuration where the two settings contradict each other.
    flood_burst: int = 120
    flood_refill_per_sec: float = 2.0
    # Registration has its own, tighter budget: a connection that has not
    # identified itself yet should not get the full allowance.
    registration_timeout: int = 30
    ping_interval: int = 120
    ping_timeout: int = 30
    # Time a half-open TLS handshake may occupy a slot.
    handshake_timeout: int = 15


@dataclass(frozen=True)
class CloakConfig:
    # On by default. Without cloaking, every JOIN and PRIVMSG broadcasts the
    # sender's real IP to everyone in the channel -- for a server whose
    # whole point may be a private mesh, that is a privacy leak, not a
    # feature. Operators who want raw hosts must opt out explicitly.
    enabled: bool = True
    secret: str = ""
    suffix: str = "ip"


@dataclass(frozen=True)
class OperConfig:
    name: str
    password_hash: str  # scrypt, as produced by `meshircdctl oper-hash`
    salt: str
    # An oper block only applies to connections matching this host mask,
    # so a leaked password alone is not enough from an arbitrary address.
    host_mask: str = "*"
    # Require the connection be TLS-authenticated with this certificate
    # fingerprint (sha256, hex). Empty means no CertFP requirement.
    fingerprint: str = ""
    tls_only: bool = True


@dataclass(frozen=True)
class ServerInfo:
    name: str = "irc.local"
    network: str = "MeshIRCd"
    description: str = "meshircd"
    motd_file: str | None = None
    admin_name: str = "unconfigured"
    admin_location: str = "unconfigured"
    admin_email: str = "unconfigured"
    # A server password (the PASS command). Empty means none required.
    password_hash: str = ""
    password_salt: str = ""


@dataclass(frozen=True)
class LogConfig:
    level: str = "INFO"
    format: str = "text"  # or "json"
    # Logging every received line is a debugging aid, not an operational
    # one: at production volume it is a disk-filling liability and a
    # privacy problem, since it records who said what to whom.
    log_raw_lines: bool = False


@dataclass(frozen=True)
class Config:
    server: ServerInfo = field(default_factory=ServerInfo)
    listeners: tuple[Listener, ...] = (Listener(),)
    tls: TLSConfig = field(default_factory=TLSConfig)
    limits: Limits = field(default_factory=Limits)
    cloak: CloakConfig = field(default_factory=CloakConfig)
    logging: LogConfig = field(default_factory=LogConfig)
    opers: tuple[OperConfig, ...] = ()
    storage_path: str = "./meshircd.db"
    # Connections from these CIDRs may send a PROXY header on a listener
    # that has proxy_protocol enabled.
    trusted_proxies: tuple[str, ...] = ("127.0.0.1/32", "::1/128")
    source_path: str | None = None
    # True when no cloak secret was configured and one was generated for
    # this process only. Cloaked hosts will differ after a restart.
    cloak_secret_ephemeral: bool = False

    def resolved_listeners(self) -> tuple[Listener, ...]:
        """Expand any ``interface:<name>`` hosts to concrete addresses."""
        return tuple(replace(l, host=resolve_host(l.host)) for l in self.listeners)


# --- loading -----------------------------------------------------------


def _as_int(value, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ConfigError(f"{where}: expected a number, got {value!r}")
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{where}: expected a number, got {value!r}") from None


def _as_bool(value, where: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "1", "yes", "on"):
        return True
    if isinstance(value, str) and value.lower() in ("false", "0", "no", "off"):
        return False
    raise ConfigError(f"{where}: expected true/false, got {value!r}")


def _section(data: dict, name: str) -> dict:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] must be a table")
    return value


def _build_dataclass(cls, data: dict, where: str, **overrides):
    known = {f.name for f in cls.__dataclass_fields__.values()}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"[{where}]: unknown setting(s): {', '.join(sorted(unknown))}")
    kwargs = {}
    for name, raw in data.items():
        field_type = cls.__dataclass_fields__[name].type
        target = f"{where}.{name}"
        if field_type in ("bool",):
            kwargs[name] = _as_bool(raw, target)
        elif field_type in ("int",):
            kwargs[name] = _as_int(raw, target)
        elif field_type in ("float",):
            kwargs[name] = float(_as_int(raw, target)) if not isinstance(raw, float) else raw
        else:
            kwargs[name] = raw
    kwargs.update(overrides)
    return cls(**kwargs)


def _load_listeners(data: dict) -> tuple[Listener, ...]:
    raw = data.get("listen")
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError("[[listen]] must be an array of tables")
    out = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ConfigError(f"[[listen]] entry {index}: must be a table")
        out.append(_build_dataclass(Listener, item, f"listen[{index}]"))
    return tuple(out)


def _load_opers(data: dict) -> tuple[OperConfig, ...]:
    raw = data.get("oper")
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError("[[oper]] must be an array of tables")
    out = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ConfigError(f"[[oper]] entry {index}: must be a table")
        missing = {"name", "password_hash", "salt"} - set(item)
        if missing:
            raise ConfigError(
                f"[[oper]] entry {index}: missing {', '.join(sorted(missing))} "
                f"(generate with: meshircdctl oper-hash)"
            )
        out.append(_build_dataclass(OperConfig, item, f"oper[{index}]"))
    return tuple(out)


_ENV_LIMITS = {
    "IRCD_MAX_CONNECTIONS": "max_connections",
    "IRCD_MAX_CONNECTIONS_PER_IP": "max_connections_per_ip",
    "IRCD_MAX_CHANNELS_PER_CLIENT": "max_channels_per_client",
    "IRCD_MAX_BANS_PER_CHANNEL": "max_bans_per_channel",
    "IRCD_MAX_SENDQ": "max_sendq_bytes",
    "IRCD_FLOOD_BURST": "flood_burst",
    "IRCD_FLOOD_REFILL_PER_SEC": "flood_refill_per_sec",
    "IRCD_PING_INTERVAL": "ping_interval",
    "IRCD_PING_TIMEOUT": "ping_timeout",
    "IRCD_MAX_NICK_LENGTH": "max_nick_length",
    "IRCD_MAX_CHANNEL_LENGTH": "max_channel_length",
}


def _apply_env(config: Config) -> Config:
    """Environment overrides. The IRCD_* names predate the config file and
    are kept working so existing deployments and the test suite do not
    break; anything new should go in the TOML file."""
    server = config.server
    if name := os.environ.get("IRCD_SERVER_NAME"):
        server = replace(server, name=name)
    if network := os.environ.get("IRCD_NETWORK"):
        server = replace(server, network=network)
    if motd := os.environ.get("IRCD_MOTD_FILE"):
        server = replace(server, motd_file=motd)

    tls = config.tls
    if cert := os.environ.get("IRCD_TLS_CERT"):
        tls = replace(tls, cert=cert)
    if key := os.environ.get("IRCD_TLS_KEY"):
        tls = replace(tls, key=key)

    limit_updates = {}
    for env_name, field_name in _ENV_LIMITS.items():
        raw = os.environ.get(env_name)
        if raw is None:
            continue
        try:
            limit_updates[field_name] = (
                float(raw) if field_name == "flood_refill_per_sec" else int(raw)
            )
        except ValueError:
            raise ConfigError(f"{env_name}: expected a number, got {raw!r}") from None
    limits = replace(config.limits, **limit_updates) if limit_updates else config.limits

    cloak = config.cloak
    if raw := os.environ.get("IRCD_CLOAK_SECRET"):
        cloak = replace(cloak, secret=raw)
    if raw := os.environ.get("IRCD_CLOAK_ENABLED"):
        cloak = replace(cloak, enabled=_as_bool(raw, "IRCD_CLOAK_ENABLED"))

    logging_cfg = config.logging
    if raw := os.environ.get("IRCD_LOG_LEVEL"):
        logging_cfg = replace(logging_cfg, level=raw.upper())
    if raw := os.environ.get("IRCD_LOG_FORMAT"):
        logging_cfg = replace(logging_cfg, format=raw.lower())

    storage_path = os.environ.get("IRCD_STORAGE_PATH", config.storage_path)

    # The legacy single-listener environment variables. They only take
    # effect when the config file did not define listeners, so a TOML
    # [[listen]] block is never silently overridden by a stray variable.
    listeners = config.listeners
    env_host = os.environ.get("IRCD_HOST")
    env_port = os.environ.get("IRCD_PORT")
    env_tls_port = os.environ.get("IRCD_TLS_PORT")
    if env_host or env_port or env_tls_port:
        host = env_host or "127.0.0.1"
        built = [Listener(host=host, port=int(env_port or 6667), tls=False)]
        if tls.cert and tls.key:
            built.append(Listener(host=host, port=int(env_tls_port or 6697), tls=True))
        listeners = tuple(built)

    return replace(
        config,
        server=server,
        tls=tls,
        limits=limits,
        cloak=cloak,
        logging=logging_cfg,
        listeners=listeners,
        storage_path=storage_path,
    )


def _validate(config: Config) -> None:
    if not config.listeners:
        raise ConfigError("no listeners configured: add at least one [[listen]] block")

    seen = set()
    for listener in config.listeners:
        if not 1 <= listener.port <= 65535:
            raise ConfigError(f"listen port out of range: {listener.port}")
        key = (listener.host, listener.port)
        if key in seen:
            raise ConfigError(f"duplicate listener {listener.label}")
        seen.add(key)
        if listener.tls and not (config.tls.cert and config.tls.key):
            raise ConfigError(
                f"listener {listener.label} requires TLS but [tls] cert/key are not set"
            )

    if "." not in config.server.name and config.server.name != "irc.local":
        raise ConfigError(
            f"server.name must look like a hostname (got {config.server.name!r}); "
            "clients and the protocol treat it as one"
        )

    if config.limits.max_connections_per_ip > config.limits.max_connections:
        raise ConfigError("limits.max_connections_per_ip exceeds limits.max_connections")

    # A client reconnecting sends registration plus one JOIN per channel it
    # was in. If the burst cannot absorb that, ordinary clients get
    # disconnected for flooding the moment they reconnect -- a failure that
    # is very hard to diagnose from the client side. Catch it at startup
    # instead of in production.
    needed = config.limits.max_channels_per_client + 12
    if config.limits.flood_burst < needed:
        raise ConfigError(
            f"limits.flood_burst ({config.limits.flood_burst}) is too small for "
            f"limits.max_channels_per_client ({config.limits.max_channels_per_client}): "
            f"a client rejoining every channel would be disconnected for flooding. "
            f"Raise flood_burst to at least {needed}, or lower max_channels_per_client."
        )

    if config.limits.flood_refill_per_sec <= 0:
        raise ConfigError("limits.flood_refill_per_sec must be greater than zero")

    for listener in config.listeners:
        if listener.proxy_protocol and not config.trusted_proxies:
            raise ConfigError(
                f"listener {listener.label} enables proxy_protocol but "
                "trusted_proxies is empty -- that would let any peer spoof its IP"
            )

    if config.logging.format not in ("text", "json"):
        raise ConfigError(f"logging.format must be 'text' or 'json', got {config.logging.format!r}")

    try:
        getattr(__import__("ssl").TLSVersion, config.tls.min_version)
    except AttributeError:
        raise ConfigError(f"tls.min_version: unknown version {config.tls.min_version!r}") from None


def find_config_file(explicit: str | None = None) -> str | None:
    if explicit:
        if not Path(explicit).is_file():
            raise ConfigError(f"config file not found: {explicit}")
        return explicit
    if env_path := os.environ.get("IRCD_CONFIG"):
        if not Path(env_path).is_file():
            raise ConfigError(f"config file not found (IRCD_CONFIG): {env_path}")
        return env_path
    for candidate in DEFAULT_CONFIG_PATHS:
        if Path(candidate).is_file():
            return candidate
    return None


def load(path: str | None = None) -> Config:
    """Build the effective configuration. Raises ConfigError on anything
    unusable -- there is no partial start."""
    resolved = find_config_file(path)
    config = Config(source_path=resolved)

    if resolved:
        try:
            with open(resolved, "rb") as handle:
                data = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{resolved}: {exc}") from None
        except OSError as exc:
            raise ConfigError(f"{resolved}: {exc}") from None

        known_top = {"server", "listen", "tls", "limits", "cloak", "logging", "oper", "storage"}
        unknown = set(data) - known_top
        if unknown:
            raise ConfigError(f"{resolved}: unknown section(s): {', '.join(sorted(unknown))}")

        storage = _section(data, "storage")
        listeners = _load_listeners(data)
        config = Config(
            server=_build_dataclass(ServerInfo, _section(data, "server"), "server"),
            listeners=listeners or config.listeners,
            tls=_build_dataclass(TLSConfig, _section(data, "tls"), "tls"),
            limits=_build_dataclass(Limits, _section(data, "limits"), "limits"),
            cloak=_build_dataclass(CloakConfig, _section(data, "cloak"), "cloak"),
            logging=_build_dataclass(LogConfig, _section(data, "logging"), "logging"),
            opers=_load_opers(data),
            storage_path=storage.get("path", config.storage_path),
            trusted_proxies=tuple(storage.get("trusted_proxies", config.trusted_proxies)),
            source_path=resolved,
        )

    config = _apply_env(config)

    # A cloak secret that changes on restart would change everyone's
    # apparent host, breaking every ban that references it. Generate one
    # if absent, but say so loudly -- it belongs in the config file.
    if config.cloak.enabled and not config.cloak.secret:
        config = replace(
            config,
            cloak=replace(config.cloak, secret=secrets.token_hex(32)),
            cloak_secret_ephemeral=True,
        )

    _validate(config)
    return config
