# meshircd

A small, self-contained IRC server written with the Python standard
library. No framework, no runtime dependencies, no virtualenv needed to
run it — just `asyncio`, `ssl`, `sqlite3` and `hashlib`.

It speaks enough of RFC 1459/2812 that real clients (irssi, HexChat,
WeeChat, Halloy) connect and behave normally, and enough IRCv3 that
modern clients get message tags, SASL, and the capabilities they expect.

Designed to be deployed two ways: on a private mesh (Tailscale,
WireGuard) with nothing exposed to the internet, or on a public address
with the hardening that requires. The defaults assume the first.

```bash
pip install .
meshircdctl genconfig > ircd.toml
meshircd --config ircd.toml
```

---

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Deployment](#deployment)
- [Configuration](#configuration)
- [Accounts and authentication](#accounts-and-authentication)
- [Operators](#operators)
- [Persistence](#persistence)
- [Privacy and cloaking](#privacy-and-cloaking)
- [Operations](#operations)
- [Testing](#testing)
- [Architecture](#architecture)
- [Limitations](#limitations)
- [Security](#security)
- [Contributing](#contributing)

---

## Features

**Protocol**

`NICK` `USER` `PASS` `QUIT` `PING` `PONG` `JOIN` `PART` `TOPIC` `NAMES`
`LIST` `INVITE` `KICK` `PRIVMSG` `NOTICE` `TAGMSG` `AWAY` `MODE` `WHO`
`WHOIS` `ISON` `USERHOST` `MOTD` `LUSERS` `VERSION` `TIME` `ADMIN`
`INFO` `STATS` `HELP` `CAP` `AUTHENTICATE`

Operator: `OPER` `KILL` `KLINE` `UNKLINE` `DLINE` `UNDLINE` `REHASH`
`WALLOPS` `SAMODE` `CONNECTINFO`

**Channels**

- Modes `+b` ban, `+e` ban exception, `+I` invite exception (list modes);
  `+k` key; `+l` limit; `+i` invite-only, `+m` moderated, `+n` no
  external messages, `+p` private, `+s` secret, `+t` topic lock
- Membership prefixes `+o` (op, `@`) and `+v` (voice, `+`)
- RFC 1459 casemapping — `Foo[` and `foo{` are correctly the same name
- `005 ISUPPORT` generated from the same constants the server enforces,
  so the advertisement cannot drift from the behaviour

**IRCv3**

`multi-prefix` · `userhost-in-names` · `server-time` · `message-tags` ·
`account-tag` · `account-notify` · `away-notify` · `extended-join` ·
`chghost` · `echo-message` · `invite-notify` · `cap-notify` · `sasl`

Only capabilities that are actually implemented are advertised.

**Authentication**

- SASL `PLAIN` (password) and `EXTERNAL` (TLS client certificate)
- Offered only over TLS, and independently refused over plaintext even
  if a client ignores the capability list and tries anyway
- Passwords stored as salted `scrypt` hashes, never plaintext
- Accounts are independent of nicknames: logging in as `alice` neither
  requires nor reserves the nick `alice`
- Optional server-wide connection password

**Hardening**

- Host cloaking on by default — real IP addresses are never broadcast
- TLS 1.2 floor, compression off, weak ciphers excluded, certificate
  reload without a restart
- Per-client token-bucket flood control, with a startup check that the
  burst is large enough for a legitimate reconnect
- Total and per-IP connection limits; a registration deadline that reaps
  connections which never identify themselves
- Bounded send queue — a client that stops reading is disconnected
  rather than allowed to consume memory without limit
- 512-byte line limit enforced without breaking legitimate pipelining;
  outbound lines truncated on UTF-8 boundaries
- K-lines (user@host) and D-lines (address, enforced before registration)
- Credentials redacted from logs; account lookups are timing-safe
- Password hashing and database writes run off the event loop
- PROXY protocol v1/v2 for deployment behind a terminator

---

## Quick start

Requires **Python 3.11+** (for `tomllib`). Nothing else.

```bash
git clone <your-repo-url> meshircd
cd meshircd
pip install .

meshircdctl genconfig > ircd.toml
$EDITOR ircd.toml                  # set server.name and cloak.secret
meshircd --check-config -c ircd.toml
meshircd -c ircd.toml
```

The default configuration listens on **127.0.0.1:6667** only. A fresh
install is not reachable from anywhere else until you say so.

Connect:

```bash
irssi -c localhost -p 6667 -n yournick
```

Or drive the protocol directly, which is often the fastest way to see
what is really happening:

```bash
nc localhost 6667
NICK alice
USER alice 0 * :Alice Example
JOIN #test
PRIVMSG #test :hello
```

Running from a checkout without installing:

```bash
PYTHONPATH=src python3 -m meshircd --config ircd.toml
```

---

## Deployment

### Private mesh — Tailscale or WireGuard

The recommended deployment. Bind to the overlay interface **by name**:

```toml
[[listen]]
host = "interface:tailscale0"    # or "interface:wg0"
port = 6667
```

Not by address — overlay addresses are assigned by the overlay and
change. If the interface has no address the server refuses to start,
rather than quietly falling back to a wider bind.

On Tailscale you also get real Let's Encrypt certificates for your
`*.ts.net` name, so TLS works with no self-signed warnings at all.

**→ [deploy/mesh-networking.md](deploy/mesh-networking.md)** covers
Tailscale ACLs, certificate renewal without dropping clients, WireGuard
setup, firewall rules, systemd ordering, and running mesh-private and
internet-public listeners side by side.

### systemd

```bash
sudo cp deploy/meshircd.service /etc/systemd/system/
sudo mkdir -p /etc/meshircd && sudo cp ircd.toml /etc/meshircd/
sudo systemctl daemon-reload && sudo systemctl enable --now meshircd
```

The unit runs under `DynamicUser` with `ProtectSystem=strict`,
`NoNewPrivileges`, an empty capability set, and a syscall filter.
`systemctl reload` sends SIGHUP, which reloads the TLS certificate and
MOTD in place. `deploy/meshircd-reload.path` does that automatically
when an ACME client renews.

### Container

```bash
export IRCD_CLOAK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
docker compose up -d
```

Non-root, read-only root filesystem, all capabilities dropped, with a
healthcheck that validates the config and resolves every listener.

---

## Configuration

A TOML file, found at `--config`, then `$IRCD_CONFIG`, then `./ircd.toml`,
then `/etc/meshircd/ircd.toml`. Environment variables override the file.

```bash
meshircdctl genconfig       # a fully commented starter config
meshircd --check-config     # validate without binding anything
```

Configuration errors are fatal at startup and name the setting involved.
There is no partial start: a server running with a config you thought
said something else is worse than one that did not come up.

| Section | Purpose |
|---|---|
| `[server]` | name, network, MOTD, admin contact, optional server password |
| `[[listen]]` | one block per listener: host, port, `tls`, `proxy_protocol` |
| `[tls]` | certificate, key, minimum version, ciphers, CertFP CA |
| `[limits]` | every resource bound (see below) |
| `[cloak]` | host cloaking on/off, secret, suffix |
| `[logging]` | level, `text` or `json`, raw-line logging |
| `[[oper]]` | one block per operator |
| `[storage]` | database path, trusted proxy CIDRs |

Key limits and their defaults:

| Setting | Default | Purpose |
|---|---|---|
| `max_connections` | 1024 | total simultaneous connections |
| `max_connections_per_ip` | 8 | connections from one address |
| `max_channels_per_client` | 40 | channels one client may join |
| `max_bans_per_channel` | 200 | entries per channel list |
| `max_targets_per_message` | 4 | recipients per PRIVMSG/NOTICE |
| `flood_burst` | 120 | messages allowed in a burst |
| `flood_refill_per_sec` | 2 | sustained messages per second |
| `max_sendq_bytes` | 1048576 | unflushed output before a client is dropped |
| `ping_interval` / `ping_timeout` | 120 / 30 | idle probe and its deadline |
| `registration_timeout` | 30 | seconds to complete registration |

`flood_burst` must be large enough to absorb a client reconnecting and
rejoining every channel it was in. The server refuses to start if it is
not, because the resulting failure — ordinary clients disconnected for
flooding the instant they reconnect — is very hard to diagnose from the
client side.

The 512-byte line limit is fixed. It is the protocol's, not ours.

Environment overrides: `IRCD_CONFIG`, `IRCD_SERVER_NAME`, `IRCD_NETWORK`,
`IRCD_MOTD_FILE`, `IRCD_TLS_CERT`, `IRCD_TLS_KEY`, `IRCD_STORAGE_PATH`,
`IRCD_CLOAK_SECRET`, `IRCD_CLOAK_ENABLED`, `IRCD_LOG_LEVEL`,
`IRCD_LOG_FORMAT`, `IRCD_HOST`, `IRCD_PORT`, `IRCD_TLS_PORT`, and
`IRCD_MAX_*` / `IRCD_FLOOD_*` / `IRCD_PING_*` for the limits.

---

## Accounts and authentication

Accounts are created out of band. SASL authenticates against existing
accounts; there is no wire command that creates one.

```bash
meshircdctl create alice          # prompts for a password
meshircdctl list
meshircdctl passwd alice
meshircdctl lock alice            # keep the account, refuse logins
meshircdctl unlock alice
meshircdctl delete alice
```

`--stdin` reads the password from standard input for scripted
provisioning. Avoid it on a shared shell.

### SASL PLAIN

```
/network add -sasl_mechanism PLAIN -sasl_username alice -sasl_password '<pw>' MyNet
/connect -tls -network MyNet irc.example.org 6697
```

### SASL EXTERNAL (CertFP)

Authenticate with a TLS client certificate instead of a password.

```bash
openssl req -x509 -newkey rsa:2048 -keyout alice.key -out alice.crt \
    -days 3650 -nodes -subj "/CN=alice"
meshircdctl certfp add alice alice.crt      # a PEM path or a hex digest
```

```toml
[tls]
request_client_cert = true
client_ca = "/etc/meshircd/tls/client-ca.pem"
```

> **This requires `client_ca`, and the server refuses to start without
> it.** Python's `ssl` module exposes no certificate-verification
> callback, so the only way to request a client certificate is
> `CERT_OPTIONAL` — which aborts the handshake for any certificate that
> does not chain to a trusted CA. Enabling it without a matching CA
> bundle would stop anyone who happens to hold an unrelated client
> certificate from connecting at all. Point `client_ca` at the CA that
> signs your users' certificates, or concatenate the self-signed client
> certificates you accept into one PEM file. Clients presenting a
> certificate outside that bundle will be refused at the TLS layer.
>
> This is why `request_client_cert` is **off by default**.

---

## Operators

```bash
meshircdctl oper-hash admin        # prints a ready-to-paste [[oper]] block
```

```toml
[[oper]]
name = "admin"
salt = "..."
password_hash = "..."
host_mask = "*!*@100.64.0.5"     # tighten this
tls_only = true
fingerprint = ""                  # optionally require a specific CertFP
```

A wrong name and a wrong password are indistinguishable — both pay the
same hashing cost and return the same numeric. Every operator action is
logged and announced to other operators; an action one person can take
silently is one nobody can audit.

```
/OPER admin <password>
/KILL baduser :reason
/KLINE 24h *@198.51.100.0/24 :spam
/DLINE 1w 203.0.113.7 :scanning
/STATS k
/UNKLINE *@198.51.100.0/24
/REHASH
```

Durations: `30m`, `2h`, `7d`, `1w`, or a bare number meaning minutes.
Omit for permanent.

Two guard rails: a mask matching every connection (`*!*@*`) is refused,
and live operators are exempt from retroactive ban enforcement — so
banning the network you are connected from does not disconnect you with
the same command and lock you out of undoing it.

---

## Persistence

State an operator deliberately set survives a restart, in SQLite:

- Accounts, password hashes, CertFP fingerprints, lock status
- Channel topics, modes, keys, limits, and ban/exception/invite lists
- Channel operator and voice grants, recorded **against accounts** — a
  nick is transient, an account is not, so op survives both a reconnect
  and a restart
- K-lines and D-lines, with expiry honoured on load

What is *not* persisted: who is connected, which nick is in use, and
channel membership. Those describe live connections, which do not
survive a restart no matter what is written down.

A channel is only stored once somebody configures it — a topic, a mode,
a ban. Throwaway channels stay purely in memory, so the table cannot
grow without bound from unauthenticated users creating channels.
Channels untouched for 90 days are pruned.

A channel with recorded access does **not** auto-op whoever joins it
while empty, which would otherwise let anyone seize a configured channel
by waiting for it to empty out.

---

## Privacy and cloaking

Without cloaking, every `JOIN`, `PART`, `QUIT` and `PRIVMSG` broadcasts
the sender's real IP address to everyone in the channel. Cloaking is on
by default:

```
203.0.113.45   ->   7f3a91c2.b41e07.9d22ac.ip
```

HMAC-SHA256 with a secret key, so the mapping is stable (bans keep
working), irreversible (the IPv4 space is small enough to enumerate
against a plain hash in seconds), and structure-preserving — the
segments are hashes of progressively broader prefixes, so
`*.9d22ac.ip` bans the whole /16 without revealing which /16 it is.

> **Set `cloak.secret` and never change it.** If it is absent the server
> generates one per process and warns loudly. Every user's visible host
> would then change on restart, and every cloak-based ban would silently
> stop matching.

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Operators see real addresses via `WHOIS` (numeric 338) and
`CONNECTINFO`. Ordinary users never do.

---

## Operations

**Signals.** `SIGTERM`/`SIGINT` shut down gracefully: listeners close,
every client gets a real `ERROR` line explaining why rather than a silent
reset, and channel state is flushed. `SIGHUP` reloads the MOTD and the
TLS certificate in place — no restart, no disconnections. A failed
certificate reload is logged and the old certificate keeps serving, so a
half-written file during renewal cannot take the server down.

**Logging.** `text` for a terminal or journald, `json` for an
aggregator. Credentials are redacted from every raw protocol line before
it is logged — `AUTHENTICATE` carries the SASL password base64-encoded,
which is encoding, not encryption. `log_raw_lines` is off by default: at
production volume it is both a disk-filling liability and a record of
who said what to whom.

**Health.** `meshircd --check-config` validates the configuration and
resolves every listener without binding, which makes it a real readiness
check rather than a liveness placeholder.

**Visibility.** `/STATS u` (uptime, peak connections) is public;
`/STATS k`, `/STATS d`, `/STATS o`, `/STATS c`, `/STATS m` are operator
only. `/CONNECTINFO` shows addresses, accounts, TLS details, idle times
and byte counts.

---

## Testing

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

130 tests, no test framework required — the suite uses stdlib `unittest`
(including `IsolatedAsyncioTestCase`), held to the same standard-library
rule as the server. It is also collectable by `pytest` if you have it.

Each test starts a real server in-process on throwaway ports with a
temporary certificate and database, so nothing touches a server you are
already running. Coverage includes the wire format, validation and
CRLF-injection resistance, cloaking properties, channel modes and
visibility, every IRCv3 capability, SASL PLAIN and EXTERNAL, the
operator layer, flood and connection limits, PROXY protocol, and
restart persistence.

---

## Architecture

```
src/meshircd/
├── server.py        registries, connection lifecycle, dispatch
├── client.py        one connection: identity, capabilities, output
├── channel.py       channel state: members, modes, lists, access
├── protocol.py      wire format: parsing, tags, casefolding
├── connection.py    framing, idle detection, PROXY protocol
├── commands/        one module per command group
│   ├── registration.py   NICK USER PASS CAP AUTHENTICATE QUIT PING PONG
│   ├── channels.py       JOIN PART TOPIC NAMES LIST INVITE KICK
│   ├── messaging.py      PRIVMSG NOTICE TAGMSG AWAY
│   ├── modes.py          MODE, user and channel
│   ├── queries.py        WHO WHOIS ISON MOTD LUSERS STATS HELP ...
│   └── operator.py       OPER KILL KLINE DLINE REHASH WALLOPS ...
├── accounts.py      password hashing and the authentication decision
├── storage.py       SQLite schema and access
├── cloak.py         host cloaking
├── caps.py          IRCv3 capability registry
├── config.py        TOML + environment, with validation
├── tlsctx.py        TLS context and certificate reloading
├── validation.py    identifier validation (allow-list)
├── netiface.py      interface-name to address resolution
├── numerics.py      named numeric reply codes
└── cli.py           meshircd and meshircdctl
```

One asyncio task per connection, single-threaded, **no locks**: the event
loop is the mutual exclusion, so the shared registries cannot be observed
half-updated. The corollary is that nothing blocking may run on the loop.
The two things that genuinely block — `scrypt` hashing (~30 ms) and
SQLite writes — are pushed to threads, and there is a test asserting that
a login does not stall other clients.

Commands are registered with a decorator carrying their constraints
(minimum parameters, registration required, operator required, flood
cost) so those checks cannot be forgotten on a new command — the kind of
omission that turns into an authentication bypass.

---

## Limitations

Known and deliberate:

- **No server-to-server linking.** Single node. S2S is the hardest part
  of IRC and is out of scope.
- **No services.** No NickServ or ChanServ, no nick registration
  enforcement, no channel registration commands. Op grants persist
  against accounts, but there is no ACL system beyond `+o` and `+v`.
- **No `WHOWAS`, no `SILENCE`, no `MONITOR`,** no `+q`/`+a` (owner and
  admin prefixes), no channel forwarding.
- **CertFP needs a CA bundle** — see [above](#sasl-external-certfp) for
  why the stdlib leaves no alternative.
- **Slow clients are dropped, not queued.** Exceeding the send-queue
  bound disconnects the client, which is what real servers do, but a
  long network stall on a busy channel can cost a client its connection.
- **No brute-force lockout** beyond the general flood limiter and the
  per-connection SASL failure cap. Accounts can be locked manually.
- **No metrics endpoint.** Operational visibility is logs and `/STATS`.
- **Linux-only interface binding.** `interface:` specs use SIOCGIFADDR
  and `/proc/net/if_inet6`. Bind by address on other platforms.

---

## Security

Never commit `meshircd.db`, `server.key`, `server.crt`, or any file
containing `cloak.secret` or an oper hash. The shipped `.gitignore`
covers the defaults.

The database is created `0600`. Passwords are salted and hashed with
`scrypt` (N=2¹⁴). Account lookups pay the same cost whether or not the
account exists, so timing does not reveal which names are valid — there
is a test for that. Credential lines are redacted before logging.

Defaults are chosen to be safe rather than convenient: loopback-only
listeners, cloaking on, no operators, no server password, SASL over TLS
only. A fresh install is useless to the internet until someone decides
otherwise in writing.

This server has not been through an external audit or a public
deployment at scale. If you need a battle-tested network daemon, use
[Ergo](https://github.com/ergochat/ergo),
[Solanum](https://github.com/solanum-ircd/solanum), or
[InspIRCd](https://github.com/inspircd/inspircd). If you want something
small enough to read end to end and run on a tailnet for your friends,
that is what this is for.

Please report security issues by describing the class of problem rather
than posting a working exploit.

---

## Contributing

Two rules shape everything:

1. **Standard library only.** This applies to the test suite too. If a
   dependency seems necessary, open an issue explaining what problem it
   solves and what implementing it by hand would involve.
2. **Don't hide the networking.** This code exists to be read. Prefer an
   explicit implementation over a clever one, and explain protocol
   decisions in comments where the reasoning is not obvious from the
   code.

Run the suite before opening a pull request, and add a case for anything
new:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

## License

[MIT](LICENSE).
