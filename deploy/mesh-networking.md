# Running meshircd on Tailscale or WireGuard

This is the deployment this server is tuned for: a private IRC network
reachable only by machines you have explicitly enrolled, with no port open
to the internet at all.

The security argument is simple. An IRC server exposed to the internet has
to survive scanning, credential stuffing, spam floods and whatever else
arrives unsolicited. Behind an overlay network, the only peers that can
open a TCP connection are ones holding a key you issued. Everything the
server does — flood limits, K-lines, cloaking — is still there, but it
becomes defence in depth rather than the only thing standing between your
users and the internet.

---

## The one thing to get right: bind by interface, not by address

```toml
[[listen]]
host = "interface:tailscale0"
port = 6667
```

Not `host = "100.101.102.103"`.

Overlay addresses are assigned by the overlay. A Tailscale address can
change when a node is re-authenticated, removed and re-added, or moved
between tailnets; a WireGuard address changes whenever you edit the peer
config. If the address in `ircd.toml` stops matching reality, the server
fails to bind and will not start — and the tempting fix ("just bind
`0.0.0.0`") silently exposes it to every network the host is on.

`interface:<name>` resolves the interface's current address at startup.
If the interface has no address, the server refuses to start rather than
falling back to something wider. That is deliberate: a loud failure is
correct, and a silent widening of the bind is not.

Force a family with a suffix when an interface has both:

```toml
host = "interface:tailscale0/4"   # IPv4
host = "interface:tailscale0/6"   # IPv6
```

Check what will be resolved before starting:

```bash
meshircd --check-config --config /etc/meshircd/ircd.toml
```

---

## Tailscale

### Install and bring the node up

```bash
sudo pacman -S tailscale                  # Arch
sudo systemctl enable --now tailscaled
sudo tailscale up
tailscale ip -4                           # the address in the 100.64.0.0/10 range
ip -br addr show tailscale0
```

### Configure the server

```toml
[server]
name    = "irc.your-tailnet.ts.net"
network = "YourNet"

[[listen]]
host = "interface:tailscale0"
port = 6667

[[listen]]
host = "interface:tailscale0"
port = 6697
tls  = true

[tls]
cert = "/var/lib/meshircd/tls/irc.your-tailnet.ts.net.crt"
key  = "/var/lib/meshircd/tls/irc.your-tailnet.ts.net.key"

[cloak]
secret = "<generate once, see below>"
```

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Real TLS certificates, no CA warnings

Tailscale issues genuine Let's Encrypt certificates for `*.ts.net` names.
This is the best reason to run TLS on a tailnet: clients verify the
certificate normally, with no `-tls_verify off` and no self-signed
warnings.

Enable HTTPS in the Tailscale admin console (DNS → HTTPS Certificates),
then:

```bash
sudo mkdir -p /var/lib/meshircd/tls
cd /var/lib/meshircd/tls
sudo tailscale cert "$(tailscale status --json | jq -r .Self.DNSName | sed 's/\.$//')"
```

Renew on a timer and reload in place — no restart, no disconnections:

```bash
sudo systemctl edit --force --full meshircd-cert-renew.timer
```

```ini
# meshircd-cert-renew.service
[Service]
Type=oneshot
WorkingDirectory=/var/lib/meshircd/tls
ExecStart=/usr/bin/tailscale cert irc.your-tailnet.ts.net
ExecStartPost=/bin/systemctl reload meshircd.service
```

```ini
# meshircd-cert-renew.timer
[Timer]
OnCalendar=weekly
Persistent=true
[Install]
WantedBy=timers.target
```

`systemctl reload` sends SIGHUP, which re-reads the certificate and the
MOTD without dropping a single connection. If the new certificate is
unreadable or half-written, the reload is refused and logged and the old
one keeps serving.

### Restrict who can reach it

Binding to `tailscale0` means every node on the tailnet can connect. To
narrow it further, use a tailnet ACL (admin console → Access Controls):

```jsonc
{
  "tagOwners": { "tag:irc": ["autogroup:admin"] },
  "acls": [
    // Only devices owned by members of the "irc" group may reach the
    // server, and only on the IRC ports.
    {
      "action": "accept",
      "src":    ["group:irc"],
      "dst":    ["tag:irc:6667,6697"]
    }
  ],
  "groups": { "group:irc": ["you@example.com", "friend@example.com"] }
}
```

Tag the server so the ACL applies to it:

```bash
sudo tailscale up --advertise-tags=tag:irc
```

### systemd ordering

The interface must exist before the server binds to it. Uncomment these
lines in `meshircd.service`:

```ini
After=tailscaled.service
Requires=tailscaled.service
```

Without them, a reboot races: systemd may start `meshircd` before
`tailscale0` has an address, the bind fails, and `Restart=on-failure`
papers over it with a retry loop.

---

## WireGuard

### Server side

`/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address    = 10.100.0.1/24
ListenPort = 51820
PrivateKey = <server private key>

[Peer]
PublicKey  = <client public key>
AllowedIPs = 10.100.0.2/32
```

```bash
sudo systemctl enable --now wg-quick@wg0
ip -br addr show wg0
```

### Configure the server

```toml
[[listen]]
host = "interface:wg0"
port = 6667
```

WireGuard has no certificate authority of its own, so for TLS you either
accept a self-signed certificate (clients need `-tls_verify off`) or use
a name you can obtain a real certificate for via DNS-01:

```bash
certbot certonly --dns-cloudflare -d irc.example.org
```

The A record can point at the WireGuard address — DNS-01 never needs the
name to be reachable from the internet, which is exactly what makes it
work for a private address.

### systemd ordering

```ini
After=wg-quick@wg0.service
Requires=wg-quick@wg0.service
```

---

## Firewalling

Binding to an interface is not a firewall. It stops the server from
*listening* elsewhere, which is most of the value, but defence in depth
is cheap here:

```bash
# nftables: accept IRC only from the overlay interfaces
sudo nft add rule inet filter input iifname { "tailscale0", "wg0" } \
    tcp dport { 6667, 6697 } accept
sudo nft add rule inet filter input tcp dport { 6667, 6697 } drop
```

Verify what is actually listening — this is the check that matters, and
the one people skip:

```bash
ss -tlnp | grep -E '6667|6697'
```

You want to see the overlay address, never `0.0.0.0` or `*`.

---

## Mesh-private and internet-public at the same time

Nothing stops you doing both; just be deliberate about which listener is
which.

```toml
# Trusted: plaintext is acceptable here because the overlay encrypts the
# transport already, and it keeps `nc` debugging usable.
[[listen]]
host = "interface:tailscale0"
port = 6667

# Untrusted: TLS only, no plaintext port at all.
[[listen]]
host = "::"
port = 6697
tls  = true
```

With a public listener, revisit these before opening the port:

- `limits.max_connections_per_ip` — the default of 8 is sized for a
  private network. A public server behind CGNAT needs more; a public
  server without it should probably have less.
- `[[oper]]` blocks — set `host_mask` to the address you actually oper
  from, and keep `tls_only = true`.
- `cloak.secret` — must be set, and must not change. Read the warning in
  the README.
- `server.password_hash` — a server password is a crude but effective
  filter if the network is meant to be invite-only.

---

## Behind a TLS terminator or load balancer

If something else terminates TLS, every connection appears to come from
the proxy, which defeats per-IP limits and D-lines. PROXY protocol fixes
that:

```toml
[[listen]]
host = "127.0.0.1"
port = 6668
proxy_protocol = true

[storage]
trusted_proxies = ["127.0.0.1/32"]
```

Two rules, and both matter:

1. Only enable `proxy_protocol` on a listener the proxy alone can reach.
   The header lets whoever sends it choose the client's apparent address,
   so a reachable proxy-protocol port hands every attacker a way to forge
   their IP and walk past bans.
2. Keep `trusted_proxies` tight. Connections from outside it are dropped
   on a proxy-protocol listener without being read.

HAProxy:

```
backend irc
    mode tcp
    server ircd 127.0.0.1:6668 send-proxy-v2
```

nginx stream:

```nginx
stream {
    server {
        listen 6697 ssl;
        proxy_pass 127.0.0.1:6668;
        proxy_protocol on;
    }
}
```

---

## Connecting

irssi, over a tailnet with a real Tailscale certificate:

```
/network add -sasl_mechanism PLAIN -sasl_username alice -sasl_password '<password>' MyNet
/connect -tls -network MyNet irc.your-tailnet.ts.net 6697
```

With a self-signed certificate, add `-tls_verify off`. That is the correct
behaviour from the client, not a bug — it is telling you it cannot verify
who it is talking to.

Raw protocol check, which is often the fastest way to see what is actually
happening:

```bash
nc 100.101.102.103 6667
NICK alice
USER alice 0 * :Alice
JOIN #test

openssl s_client -connect irc.your-tailnet.ts.net:6697 -verify_return_error
```
