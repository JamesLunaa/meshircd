# Running meshircd on a public VPS

This guide covers the other deployment: a server on the open internet that
anyone with a plain IRC client can reach at `irc.example.org:6697`, with
no VPN, tunnel, or extra software on the user's side.

It was written from a real deployment on a DigitalOcean droplet running
Ubuntu, with DNS on Cloudflare. Every step below is one that was
actually needed, and every error in [Troubleshooting](#troubleshooting) is
one that was actually hit.

If everyone who will use the server can install Tailscale or WireGuard,
read [mesh-networking.md](mesh-networking.md) instead — a private
deployment is simpler and has a much smaller attack surface. Use this
guide when you want friends to connect with nothing but an IRC client.

---

## Contents

- [Choosing where to run it](#choosing-where-to-run-it)
- [Why not Cloudflare Tunnel](#why-not-cloudflare-tunnel)
- [Overview](#overview)
- [1. Install](#1-install)
- [2. DNS record](#2-dns-record)
- [3. TLS certificate](#3-tls-certificate)
- [4. Configuration](#4-configuration)
- [5. Certificate permissions](#5-certificate-permissions)
- [6. systemd](#6-systemd)
- [7. Firewall](#7-firewall)
- [8. Certificate renewal](#8-certificate-renewal)
- [9. Verify](#9-verify)
- [10. Accounts, operators and finishing touches](#10-accounts-operators-and-finishing-touches)
- [Connecting](#connecting)
- [Troubleshooting](#troubleshooting)
- [Hardening a public server](#hardening-a-public-server)
- [Checklist](#checklist)

---

## Choosing where to run it

A public IRC server needs **a public IP address that accepts inbound TCP
connections**. That rules out most home machines:

| Host | Works? | Why |
|---|---|---|
| VPS (DigitalOcean, Hetzner, Vultr, Linode…) | Yes | Real public IP, always on, no NAT |
| Home machine, router you control, real WAN IP | Yes, with a port-forward | You must forward 6697 to the machine and keep it awake |
| Home machine behind CGNAT | **No** | Your ISP shares one IP among many customers; a port-forward on your router does nothing |
| Home machine where you cannot port-forward | **No** | Same result — nothing can reach it from outside |

To tell whether you are behind CGNAT, compare the WAN address shown in
your router's admin page with what `curl -4 ifconfig.me` prints. If they
differ, or the router shows an address in `100.64.0.0/10`, you are behind
CGNAT.

The smallest VPS size is plenty. meshircd idles at about 13 MB of memory
and the systemd unit caps it at 512 MB. It happily shares a droplet with a
website or anything else.

---

## Why not Cloudflare Tunnel

If you already serve a website through `cloudflared`, it is tempting to
put IRC through the same tunnel. It does not work the way you want:

- **Cloudflare's edge only proxies HTTP(S) to ordinary visitors.** A
  browser can reach a tunnelled website because Cloudflare understands
  HTTP. IRC is a raw TCP protocol, which Cloudflare's free proxy does not
  forward to arbitrary clients.
- **Raw TCP through a tunnel needs `cloudflared` on the client too.** Each
  user would have to run
  `cloudflared access tcp --hostname irc.example.org --url localhost:6667`
  and point their IRC client at `localhost`. That defeats the point.
- **Public raw TCP on Cloudflare is Spectrum**, which is a paid product.
- **Putting nginx in front changes nothing.** The limitation is at
  Cloudflare's edge, not on your server; nginx would just forward the same
  TCP stream one hop earlier.

The fix is simple: a VPS already has a public IP, so IRC does not need a
tunnel. Let clients connect to the droplet directly on port 6697. The
website keeps using its tunnel on its own hostname; the two never touch.

> A tunnel only makes sense for IRC if you put a **web** IRC client
> (TheLounge, Kiwi IRC) in front of meshircd and tunnel that web UI. Users
> then chat in a browser, not in their own IRC client. This guide does not
> cover that.

---

## Overview

```
IRC client ──TLS:6697──▶ irc.example.org (DNS-only A record)
                               │
                               ▼
                         VPS public IP
                         ufw + cloud firewall allow 6697/tcp
                               │
                               ▼
                         meshircd (systemd, DynamicUser)
                         reads /etc/letsencrypt via group cert-readers
                         state in /var/lib/meshircd/meshircd.db
```

Throughout, replace:

| Placeholder | Meaning |
|---|---|
| `irc.example.org` | the hostname users will connect to |
| `example.org` | the Cloudflare zone that hostname belongs to |
| `203.0.113.10` | your VPS's public IPv4 address |

Commands are for Ubuntu/Debian and are run on the VPS unless stated
otherwise.

---

## 1. Install

meshircd needs Python 3.11 or later and nothing else.

```bash
sudo apt update
sudo apt install -y python3 python3-venv git
python3 --version           # must print 3.11 or later
```

Install into its own virtual environment. Recent Ubuntu, Debian and Arch
releases mark the system Python as *externally managed* (PEP 668), so a
bare `sudo pip install .` is refused — and mixing packages into the system
Python is a bad idea anyway.

```bash
sudo git clone https://github.com/JamesLunaa/meshircd.git /opt/meshircd-src
sudo python3 -m venv /opt/meshircd-venv
sudo /opt/meshircd-venv/bin/pip install /opt/meshircd-src
```

This gives you two commands:

- `/opt/meshircd-venv/bin/meshircd` — the server
- `/opt/meshircd-venv/bin/meshircdctl` — accounts, operators, config

Upgrading later:

```bash
sudo git -C /opt/meshircd-src pull
sudo /opt/meshircd-venv/bin/pip install --upgrade /opt/meshircd-src
sudo systemctl restart meshircd
```

---

## 2. DNS record

In the Cloudflare dashboard, open the zone for `example.org` → **DNS** →
**Add record**:

| Field | Value |
|---|---|
| Type | `A` |
| Name | `irc` (gives `irc.example.org`) |
| IPv4 address | your VPS's public IP (`curl -4 ifconfig.me` on the VPS) |
| Proxy status | **DNS only** — grey cloud, not orange |
| TTL | Auto |

**The record must be DNS only.** With the orange cloud on, the hostname
resolves to Cloudflare's edge instead of your server, and Cloudflare does
not forward IRC on port 6697. Clients will time out or get refused. With
the grey cloud, Cloudflare only answers the DNS query and the traffic goes
straight to your VPS.

If the VPS has a public IPv6 address, add an `AAAA` record the same way
(also DNS only). meshircd listens on IPv6 if you add a `[[listen]]` block
with `host = "::"`.

If the same Cloudflare account holds several zones, make sure you add the
record to the zone for the hostname you chose. It is fine — and tidy — to
use a different domain for IRC than for a website on the same VPS.

Check it from any machine:

```bash
dig +short irc.example.org
# must print your VPS IP, not a Cloudflare address (104.x / 172.64-71.x)
```

---

## 3. TLS certificate

Use Let's Encrypt with the **DNS-01** challenge through the Cloudflare
API. DNS-01 proves you own the domain by creating a TXT record, so it
needs no web server and no open port 80 — which matters when a website or
tunnel already owns port 80/443 on this machine.

### Create a Cloudflare API token

Cloudflare dashboard → **My Profile** → **API Tokens** → **Create Token** →
use the **Edit zone DNS** template:

- Permissions: `Zone` · `DNS` · `Edit`
- Zone Resources: `Include` · `Specific zone` · `example.org`

Scope it to the one zone. Do not use the Global API Key.

### Install certbot and request the certificate

```bash
sudo apt install -y certbot python3-certbot-dns-cloudflare

sudo mkdir -p /etc/certbot
sudo tee /etc/certbot/cloudflare.ini > /dev/null <<'EOF'
dns_cloudflare_api_token = PASTE_YOUR_TOKEN_HERE
EOF
sudo chmod 600 /etc/certbot/cloudflare.ini

sudo certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /etc/certbot/cloudflare.ini \
  --dns-cloudflare-propagation-seconds 30 \
  -d irc.example.org
```

Check what was created:

```bash
sudo ls -la /etc/letsencrypt/live/
sudo ls -la /etc/letsencrypt/live/irc.example.org/
```

Use the directory name that actually appears. If a certificate for that
name existed before, certbot may have created `irc.example.org-0001`.

The files you need:

- `/etc/letsencrypt/live/irc.example.org/fullchain.pem`
- `/etc/letsencrypt/live/irc.example.org/privkey.pem`

Both are symlinks into `/etc/letsencrypt/archive/irc.example.org/`. That
detail matters in [step 5](#5-certificate-permissions).

---

## 4. Configuration

Generate a fully commented starting config:

```bash
sudo mkdir -p /etc/meshircd /var/lib/meshircd
sudo /opt/meshircd-venv/bin/meshircdctl genconfig \
  | sudo tee /etc/meshircd/ircd.toml > /dev/null
sudo nano /etc/meshircd/ircd.toml
```

Generate a cloak secret:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

The settings that must change from the defaults:

```toml
[server]
name        = "irc.example.org"     # must look like a hostname
network     = "ExampleNet"          # shown to users; no spaces
description = "Example IRC server"
admin_name     = "Your Name"
admin_location = "Somewhere"
admin_email    = "you@example.org"

[storage]
path = "/var/lib/meshircd/meshircd.db"

# The public TLS listener.
[[listen]]
host = "0.0.0.0"
port = 6697
tls  = true

[tls]
cert = "/etc/letsencrypt/live/irc.example.org/fullchain.pem"
key  = "/etc/letsencrypt/live/irc.example.org/privkey.pem"
min_version = "TLSv1_2"

[cloak]
enabled = true
secret  = "PASTE_THE_64_HEX_CHARACTERS_HERE"
suffix  = "ip"
```

Things to get right:

- **Replace the default listener, don't just add a new one next to a
  commented-out example.** The generated config listens on
  `127.0.0.1:6667`, which is unreachable from outside. The server will
  start happily and log `listening on ('127.0.0.1', 6667)` — it is doing
  exactly what it was told. Look for an active (uncommented) `[[listen]]`
  block with `host = "0.0.0.0"`, `port = 6697`, `tls = true`.
- **`[tls]` must point at real files.** The generated config points at
  `/etc/meshircd/tls/…`, which does not exist unless you create it.
- **Set `cloak.secret` once and never change it.** Without it, a new
  secret is generated on every start, so everyone's visible host changes
  on restart and every cloak-based ban silently stops matching.
- **Don't offer plaintext 6667 publicly.** SASL is refused over plaintext
  anyway, and every message would cross the internet unencrypted. If you
  want a plaintext listener for local debugging, bind it to `127.0.0.1`.

Validate before starting anything:

```bash
sudo /opt/meshircd-venv/bin/meshircd --check-config -c /etc/meshircd/ircd.toml
```

This reads the config, checks every setting, and resolves every listener
without binding. A problem is reported with the setting that caused it,
for example:

```
configuration error: listener 0.0.0.0:6697 (tls) requires TLS but [tls] cert/key are not set
```

Note that `--check-config` runs as root when you use `sudo`, so it can
read the certificate even when the service cannot. Passing it does not
prove the service has permission — that is the next step.

---

## 5. Certificate permissions

The shipped systemd unit runs meshircd as a `DynamicUser`: a throwaway,
unprivileged UID that exists only while the service runs. That is good
for security, but it means the service **cannot read `/etc/letsencrypt`**,
which certbot creates as `0700 root:root`. The server would exit on start
and systemd would restart it every 5 seconds.

Give a dedicated group read access to the certificates, then put the
service in that group.

```bash
sudo groupadd --system cert-readers

sudo chgrp cert-readers /etc/letsencrypt
sudo chmod 750 /etc/letsencrypt

sudo chgrp -R cert-readers /etc/letsencrypt/live /etc/letsencrypt/archive
sudo chmod -R g+rX /etc/letsencrypt/live /etc/letsencrypt/archive
```

`g+rX` gives the group read on files and traverse (execute) on
directories only. Nothing becomes world-readable.

Why every level: to open
`/etc/letsencrypt/live/irc.example.org/privkey.pem` a process needs
execute permission on `/etc/letsencrypt`, `/etc/letsencrypt/live` and
`/etc/letsencrypt/live/irc.example.org`, and then — because `privkey.pem`
is a symlink — on every directory along
`/etc/letsencrypt/archive/irc.example.org/`, plus read permission on
`privkey1.pem` itself. Missing any one of those produces a permission
error.

The alternative is a certbot deploy hook that copies the certificate into
`/etc/meshircd/tls/` with suitable ownership. That avoids touching
`/etc/letsencrypt` permissions at all, at the cost of one more moving
part. Either works; this guide uses the group.

---

## 6. systemd

Install the unit:

```bash
sudo cp /opt/meshircd-src/deploy/meshircd.service /etc/systemd/system/
sudo nano /etc/systemd/system/meshircd.service
```

Make three changes.

**Point `ExecStart` at the venv:**

```ini
ExecStart=/opt/meshircd-venv/bin/meshircd -c /etc/meshircd/ircd.toml
```

**Uncomment the certificate lines** (they are already in the file,
commented out, under `# --- filesystem ---`):

```ini
ReadOnlyPaths=/etc/letsencrypt
SupplementaryGroups=cert-readers
```

- `ProtectSystem=strict` makes the whole filesystem read-only and
  `ReadOnlyPaths` explicitly exposes `/etc/letsencrypt` to the service.
- `SupplementaryGroups` adds the dynamic user to `cert-readers`, which is
  what actually grants read access.

Leave the rest of the hardening alone. Ports 6667 and 6697 are above 1024,
so no capabilities are needed.

Start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now meshircd
sudo systemctl status meshircd
sudo journalctl -u meshircd -n 30 --no-pager
```

A healthy start looks like:

```
INFO  ircd  meshircd 1.0.0 starting (config: /etc/meshircd/ircd.toml)
INFO  ircd  restored 0 channel(s), 0 server ban(s) from /var/lib/meshircd/meshircd.db
INFO  ircd  listening on ('0.0.0.0', 6697) [TLS]
INFO  ircd  ready: 1 listener(s)
```

The `[TLS]` marker is the thing to look for. If it says
`('127.0.0.1', 6667)`, the config still has the default listener.

If the status shows `activating (auto-restart)` and `status=1/FAILURE`,
the server is crashing on start. The journal will say why — almost always
a certificate path or permission problem.

---

## 7. Firewall

There are usually **two** firewalls, and both must allow 6697.

### On the VPS (ufw)

```bash
sudo ufw allow 6697/tcp comment 'meshircd TLS'
sudo ufw status
```

If ufw is not enabled yet, **allow SSH before enabling it** or you will
lock yourself out:

```bash
sudo ufw allow OpenSSH
sudo ufw enable
```

### At the provider (DigitalOcean Cloud Firewall)

DigitalOcean Cloud Firewalls are applied outside the droplet and are
independent of ufw. If one is attached to your droplet:

**Networking → Firewalls → your firewall → Inbound Rules → New rule**
`Custom` · `TCP` · `6697` · Sources `All IPv4`, `All IPv6`.

Other providers have the same concept under different names (Hetzner
Firewall, AWS Security Group, Vultr Firewall Group).

### Confirm it's listening

```bash
sudo ss -tlnp | grep 6697
# LISTEN 0  100  0.0.0.0:6697  0.0.0.0:*  users:(("meshircd",pid=...))
```

---

## 8. Certificate renewal

Let's Encrypt certificates last 90 days; certbot's systemd timer renews
them automatically at around 60. Two things must happen after a renewal:

1. The new files in `/etc/letsencrypt/archive/` must be readable by
   `cert-readers`. Renewal creates new files (`privkey2.pem`, …) and they
   are not guaranteed to inherit the group.
2. meshircd must reload the certificate. `SIGHUP` does this in place with
   no dropped clients; `systemctl reload meshircd` sends it.

A certbot **deploy hook** handles both, and only runs when a certificate
was actually renewed:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/meshircd.sh > /dev/null <<'EOF'
#!/bin/sh
set -e
chgrp -R cert-readers /etc/letsencrypt/live /etc/letsencrypt/archive
chmod -R g+rX /etc/letsencrypt/live /etc/letsencrypt/archive
systemctl reload meshircd.service
EOF
sudo chmod 755 /etc/letsencrypt/renewal-hooks/deploy/meshircd.sh
```

Test the whole renewal path without issuing a real certificate:

```bash
sudo certbot renew --dry-run
```

A failed reload never takes the server down: a half-written or unreadable
certificate is refused, logged, and the old one keeps serving.

The repo also ships `meshircd-reload.path` / `meshircd-reload.service`,
which watch the certificate file and reload on change. With the deploy
hook above you don't need them. If you use them instead, edit
`PathChanged=` in `meshircd-reload.path` to your real hostname first — it
defaults to `irc.example.org` — and you will still need to fix the
permissions some other way.

Check when renewal will next run:

```bash
systemctl list-timers | grep certbot
```

---

## 9. Verify

### From the VPS

```bash
openssl s_client -connect 127.0.0.1:6697 -servername irc.example.org </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

This should show your hostname, a Let's Encrypt issuer, and valid dates.

### From another machine

```bash
openssl s_client -connect irc.example.org:6697 -servername irc.example.org </dev/null
```

Look for `Verify return code: 0 (ok)`. Then connect with a real client
(see [Connecting](#connecting)). A successful registration looks like:

```
Welcome to the ExampleNet IRC Network, you!~you@335789c8.f917b1.793efa.ip
Your host is irc.example.org, running version meshircd-1.0.0
```

The host part being a cloak (`….ip`) rather than your real address
confirms cloaking works.

---

## 10. Accounts, operators and finishing touches

`meshircdctl` finds the database through the config file, so always pass
`-c`. There is no `--db` flag.

### Accounts

Accounts are needed for SASL login, and channel op/voice grants are
recorded against accounts — so they survive reconnects and restarts. Users
without an account can still connect and chat with just a nickname.

```bash
sudo /opt/meshircd-venv/bin/meshircdctl -c /etc/meshircd/ircd.toml create alice
sudo /opt/meshircd-venv/bin/meshircdctl -c /etc/meshircd/ircd.toml list
sudo /opt/meshircd-venv/bin/meshircdctl -c /etc/meshircd/ircd.toml passwd alice
sudo /opt/meshircd-venv/bin/meshircdctl -c /etc/meshircd/ircd.toml lock alice
sudo /opt/meshircd-venv/bin/meshircdctl -c /etc/meshircd/ircd.toml delete alice
```

Accounts are created only out of band — there is no command a user can
send to register themselves. On a public server that is a feature: nobody
can fill your database with junk accounts.

A shell alias saves typing:

```bash
echo "alias ircctl='sudo /opt/meshircd-venv/bin/meshircdctl -c /etc/meshircd/ircd.toml'" >> ~/.bashrc
```

### Operators

Without an `[[oper]]` block the server logs
`no [[oper]] blocks configured: no one can use OPER`, and nobody can
`KILL`, `KLINE` or `DLINE`. On a public server you want this before you
need it.

```bash
sudo /opt/meshircd-venv/bin/meshircdctl -c /etc/meshircd/ircd.toml oper-hash admin
```

Paste the printed block into `ircd.toml` and tighten it:

```toml
[[oper]]
name = "admin"
salt = "..."
password_hash = "..."
host_mask = "*!*@*"        # see below
tls_only = true
```

Operators' `host_mask` is matched against the **real** host, not the
cloak. If you connect from a stable IP, put it here. If your IP changes
(home broadband, mobile), you will need a wider mask — keep `tls_only =
true` and use a strong password, or better, require a client certificate
with `fingerprint`.

Then `sudo systemctl restart meshircd` and, in your client, `/OPER admin
<password>`.

### MOTD

```bash
sudo tee /etc/meshircd/motd.txt > /dev/null <<'EOF'
Welcome to ExampleNet.
Be nice. Admin: you@example.org
EOF
```

```toml
[server]
motd_file = "/etc/meshircd/motd.txt"
```

`sudo systemctl reload meshircd` picks up MOTD changes without a restart.
`/etc/meshircd` is the unit's `ConfigurationDirectory`, so the service can
read it.

### Backups

All persistent state is one SQLite file. Back it up with SQLite's online
backup so you never copy a half-written database:

```bash
sudo apt install -y sqlite3
sudo sqlite3 /var/lib/meshircd/meshircd.db ".backup '/root/meshircd-$(date +%F).db'"
```

Also keep a copy of `/etc/meshircd/ircd.toml` — it holds the cloak secret
and operator hashes.

---

## Connecting

Give users the hostname, the port, and the fact that it is TLS:

> **Server:** `irc.example.org` · **Port:** `6697` · **TLS:** on

### irssi

irssi has **no `--tls` command-line flag** — `irssi -c host -p 6697 --tls`
fails with `Unknown option --tls`. Start irssi, then:

```
/connect -tls irc.example.org 6697
```

To save it as a network with SASL:

```
/network add -sasl_mechanism PLAIN -sasl_username alice -sasl_password 'secret' ExampleNet
/server add -tls -network ExampleNet irc.example.org 6697
/save
/connect ExampleNet
```

### WeeChat

```
/server add examplenet irc.example.org/6697 -tls
/set irc.server.examplenet.sasl_mechanism plain
/set irc.server.examplenet.sasl_username alice
/set irc.server.examplenet.sasl_password secret
/connect examplenet
```

### HexChat

**HexChat → Network List → Add**, name it, **Edit**:

- Servers: `irc.example.org/6697`
- Tick **Use SSL for all the servers on this network**
- Login method: **SASL (username + password)**, fill in user and password

### Halloy (`config.toml`)

```toml
[servers.examplenet]
nickname = "alice"
server = "irc.example.org"
port = 6697
use_tls = true
channels = ["#general"]

[servers.examplenet.sasl.plain]
username = "alice"
password = "secret"
```

### Mobile

Any IRC app with TLS support works the same way: host, port 6697, TLS on,
optionally SASL PLAIN. (Goguma, Palaver, and Revolution IRC are common
choices.)

---

## Troubleshooting

Work from the server outward: is it running, is it listening on the right
address, is TLS configured, is the firewall open, does DNS point here.

```bash
sudo systemctl status meshircd
sudo journalctl -u meshircd -n 50 --no-pager
sudo ss -tlnp | grep 6697
sudo /opt/meshircd-venv/bin/meshircd --check-config -c /etc/meshircd/ircd.toml
curl -4 ifconfig.me; echo      # compare with: dig +short irc.example.org
```

| Symptom | Cause | Fix |
|---|---|---|
| Client: `SSL handshake failed: Connection refused`; log says `listening on ('127.0.0.1', 6667)` | Still using the default listener from `genconfig` | Add/uncomment a `[[listen]]` with `host = "0.0.0.0"`, `port = 6697`, `tls = true`; restart |
| Client: `SSL handshake failed: Connection refused`; `ss` shows nothing on 6697 | Service is not running — usually crashing on start | `systemctl status`; if `activating (auto-restart)`, read the journal |
| `status=1/FAILURE`, restarting every 5 s | Service cannot read the certificate (`DynamicUser` vs `/etc/letsencrypt` `0700`) | [Step 5](#5-certificate-permissions) and the two lines in [step 6](#6-systemd) |
| `configuration error: listener 0.0.0.0:6697 (tls) requires TLS but [tls] cert/key are not set` | `[tls]` section missing or commented out | Set `cert` and `key` under `[tls]` |
| `[tls]` paths look right but the file isn't found | Certbot used a suffixed directory (`irc.example.org-0001`) | `sudo ls /etc/letsencrypt/live/` and use the real name |
| Client: `SSL handshake failed: unexpected eof while reading` | The port accepted TCP but did not speak TLS — a plaintext listener, or an old process still bound after a config change | Confirm `tls = true` on that listener and `[TLS]` in the startup log; `systemctl restart` |
| Connection hangs, then times out | A firewall is dropping packets | Check both ufw **and** the provider's cloud firewall |
| Works from the VPS, not from outside | Provider firewall, or DNS pointing elsewhere | Compare `dig +short` with `curl ifconfig.me`; check cloud firewall |
| `dig` returns a `104.x` / `172.6x.x` address | Cloudflare record is proxied (orange cloud) | Switch the record to **DNS only** |
| Certificate name mismatch warning | Connecting by IP, or `-d` in certbot differs from the hostname used | Connect by hostname; reissue the cert for the right name |
| `meshircdctl: error: argument command: invalid choice` | Used `--db` | Use `-c /etc/meshircd/ircd.toml` |
| `irssi: Unknown option --tls` | irssi has no such CLI flag | `/connect -tls host 6697` from inside irssi |
| Works for 60–90 days, then fails after a renewal | New archive files not readable by `cert-readers` | Install the [deploy hook](#8-certificate-renewal); run it once by hand |
| `MOTD File is missing` | No `motd_file` set | Harmless; see [MOTD](#motd) |
| `no [[oper]] blocks configured` | No operator defined | Harmless until you need one; see [Operators](#operators) |
| Users disconnected with `Excess Flood` | Real flooding, or bots | Working as intended; tune `[limits]` only if legitimate users hit it |

For deeper protocol debugging, set `log_raw_lines = true` under
`[logging]` temporarily. Credentials are redacted, but it records every
message — turn it back off afterwards.

---

## Hardening a public server

Once the port is open, the server will be found by scanners within hours.
The defaults are already reasonable; these are the knobs worth knowing.

- **Server password for a friends-only server.** If you don't want
  strangers at all, require a connection password:
  `meshircdctl -c /etc/meshircd/ircd.toml server-pass`, paste the output
  into `[server]`, and give the password to your friends. Clients send it
  with `/connect -tls irc.example.org 6697 <password>` (irssi) or the
  "Server password" field.
- **Connection limits.** `max_connections_per_ip = 8` is generous for a
  small group; `3` is enough for most people. Lower `max_connections` to
  something proportionate on a small VPS.
- **Flood control.** `flood_burst` and `flood_refill_per_sec` are safe
  defaults. The server refuses to start if `flood_burst` is too small for
  a legitimate reconnect, so you can't tune it into a broken state.
- **Ban tools.** `/DLINE 1d 198.51.100.7 :scanning` drops an address before
  it can even register; `/KLINE 24h *@198.51.100.0/24 :spam` bans a range.
  Both persist across restarts.
- **Keep TLS-only.** Don't add a public plaintext listener.
- **SSH.** The IRC port is not the most attractive target on the box. Use
  key-only SSH login and consider `fail2ban`.
- **Updates.** `unattended-upgrades` for the OS; upgrade meshircd as in
  [step 1](#1-install).

---

## Checklist

- [ ] Python 3.11+, meshircd installed in `/opt/meshircd-venv`
- [ ] `A` record `irc.example.org` → VPS IP, **DNS only**
- [ ] Cloudflare API token scoped to one zone, stored `0600`
- [ ] Certificate issued; real directory name confirmed in `/etc/letsencrypt/live/`
- [ ] `ircd.toml`: `server.name`, `network`, admin fields
- [ ] `ircd.toml`: active `[[listen]]` on `0.0.0.0:6697` with `tls = true`
- [ ] `ircd.toml`: `[tls]` `cert`/`key` → `/etc/letsencrypt/live/…`
- [ ] `ircd.toml`: `cloak.secret` set, and backed up
- [ ] `meshircd --check-config` passes
- [ ] `cert-readers` group created; `/etc/letsencrypt` permissions granted
- [ ] Unit: `ExecStart` → venv; `ReadOnlyPaths` and `SupplementaryGroups` uncommented
- [ ] `systemctl status meshircd` is `active (running)`; log shows `('0.0.0.0', 6697) [TLS]`
- [ ] ufw allows 6697/tcp (and SSH)
- [ ] Provider cloud firewall allows 6697/tcp
- [ ] Certbot deploy hook installed; `certbot renew --dry-run` succeeds
- [ ] Connected from an outside machine; host shows as a cloak
- [ ] Operator block configured
- [ ] Accounts created for users who want SASL
- [ ] Database backup scheduled
