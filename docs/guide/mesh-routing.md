# Mesh subnet routing (Tailscale-like)

ShadowVPN can share subnet routes between clients the way a Tailscale subnet
router does — without any external control plane. A client **advertises** the
subnets it can reach (IPv4 and/or IPv6 CIDRs), the server **approves** them
against an operator policy, and any client that opts in **accepts** the
approved set: the routes are pushed down the tunnel and installed onto its TUN
interface automatically, then removed when withdrawn and on exit.

The server also acts as a **hub relay**: packets from one client to another
client (or to another client's advertised subnet) are relayed UDP→UDP by
longest-prefix match, without touching the server's TUN device — so
spoke↔spoke traffic needs no IP forwarding or NAT on the server at all.

```text
 accept-routes client                hub (server)              subnet router client
 10.77.0.3 / fd07:7::3         10.77.0.1 / fd07:7::1         10.77.0.2 / fd07:7::2
        │                             │                             │  advertises
        │        encrypted UDP        │        encrypted UDP        │  192.168.200.0/24
        ├────────────────────────────►├────────────────────────────►│  fd42:cafe::/64
        │                             │  (relayed, never on TUN)    │
   routes installed             longest-prefix                 subnet behind
   automatically                match + relay                  this client
```

## Why IPv6 routes?

Overlapping private IPv4 ranges are the classic multi-site problem: two sites
that both use `10.0.0.0/16` cannot be distinguished by a route. Advertising
**globally unique IPv6 prefixes** (each site's ULA or GUA prefix) sidesteps
the ambiguity — each destination selects exactly one route. Give every tunnel
node an address in one shared ULA prefix with `tun_ip6` so IPv6 traffic has an
in-tunnel source and return address.

## Server: approval policy

Route approval is the stand-in for Tailscale's admin-console checkbox. Either
approve everything:

```bash
sudo shadowvpn-server -l 0.0.0.0:8388 -k <password> \
  --tun-ip 10.77.0.1 --peer-ip 10.77.0.2 \
  --tun-ip6 fd07:7::1/64 \
  --auto-approve-routes
```

or allowlist the prefixes that clients may announce (an advertised route is
approved when it equals, or is a subnet of, an allowlist entry):

```bash
sudo shadowvpn-server ... --approve-routes 192.168.200.0/24,fd42:cafe::/64
```

Advertised routes outside the allowlist are held and logged as *awaiting
approval*; they are never routed and never pushed to peers. Add the prefix to
`approve_routes` and restart to approve it. Routes whose advertiser goes
quiet expire after `lease_ttl_secs` (default 120 s) and are withdrawn from
accepting clients on their next push.

Mesh routing requires the default learning mode — it identifies clients by
their distinct tunnel IPs, which `--nat` mode deliberately erases, so the two
cannot be combined. [Automatic assignment](./auto-assign) works on top:
clients may omit `tun_ip` / `peer_ip` and still advertise, accept, and
hub-relay subnets. Assignment is the node-IP piece; this page is the
subnet-router piece.

## Subnet router client: advertise

```bash
sudo shadowvpn-client -s <server>:8388 -k <password> \
  --tun-ip 10.77.0.2 --peer-ip 10.77.0.1 \
  --tun-ip6 fd07:7::2/64 \
  --advertise-routes 192.168.200.0/24,fd42:cafe::/64
```

Adverts ride the keepalive tick (default every 15 s), so the server's table
stays fresh with no extra traffic. When the advertised subnet is a real LAN
behind this machine (not one of its own addresses), also enable forwarding and
masquerade, exactly like the guide's SNAT model — the target then sees the
router's own address as the source and needs no route back into the tunnel:

```bash
sudo sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
sudo iptables  -t nat -A POSTROUTING -o <lan-if> -j MASQUERADE
sudo ip6tables -t nat -A POSTROUTING -o <lan-if> -j MASQUERADE
```

## Accepting client: accept

```bash
sudo shadowvpn-client -s <server>:8388 -k <password> \
  --tun-ip 10.77.0.3 --peer-ip 10.77.0.1 \
  --tun-ip6 fd07:7::3/64 \
  --accept-routes
```

The server answers each of this client's keepalives with the current approved
route set (split horizon: a client is never sent the routes it advertised
itself). The client diffs the push against what it has installed, adds and
removes kernel routes on its TUN accordingly (rtnetlink on Linux, `PF_ROUTE`
on macOS, IP Helper on Windows), and removes everything on exit. A pushed
route that would cover the VPN server's own address is refused — it would loop
the tunnel into itself.

All of the JSON equivalents exist too: `advertise_routes`, `accept_routes`,
`approve_routes`, `auto_approve_routes`, and `tun_ip6`.

## Validating end to end

The validation ladder runs from most foundational to application level, from
the accepting client:

```bash
# 1. spoke↔spoke through the hub relay
ping  -c3 10.77.0.2
ping -6 -c3 fd07:7::2

# 2. the advertised subnets
ping  -c3 192.168.200.1
ping -6 -c3 fd42:cafe::1

# 3. TCP services (IPv6 literals use bracket notation)
curl "http://[fd42:cafe::1]:8000/"
ssh admin@fd07:7::2
```

On the accepting client, `ip route` / `ip -6 route` show the pushed routes as
`proto static` entries on the tun device; the server logs every
approval, hold, move, withdrawal, and expiry.

This flow is exercised end to end in CI on every PR
(`docker/run-e2e-mesh.sh`, run in both `auto` and `allowlist` approval
modes): a hub, a subnet router advertising a local `192.168.200.0/24` +
`fd42:cafe::/64`, and an accepting client — covering advert/approve/accept,
hub relay for IPv4 + IPv6, allowlist gating (an unlisted route is held as
awaiting approval and never pushed), and route withdrawal after the
advertiser goes away.

## Wire format

Control messages share the tunnel's plaintext channel with IP packets. Every
control payload starts with a `0x00` byte — an IP packet's first nibble is its
version (4 or 6), so the two can never collide, and peers that predate the
feature simply drop what they don't understand (the extension is
wire-compatible in both directions). See the
[wire protocol reference](/reference/wire-protocol) for the envelope itself.

```text
keepalive   : 00                      (legacy, 1 byte)
keepalive   : 00 ip4[4]               (legacy, 5 bytes)
route advert: 00 01 flags ip4[4] ip6[16] count { family plen addr[4|16] }*
route push  : 00 02 00    count { family plen addr[4|16] }*
assign req  : 00 03 flags node[16] hint4[4] hint6[16]     (39 bytes)
assign      : 00 04 status ip4[4] mask[4] peer[4] ip6[16] plen6 flags ttl[4]
                                                              (37 bytes)
name advert : 00 05 flags ip4[4] ip6[16] nlen name[nlen]
peer push   : 00 06 flags count { eflags ip4[4] ip6[16] nlen name[nlen] }*
```

Auto clients replace the 5-byte keepalive with `AssignRequest` and, when
mesh is active, send a `RouteAdvert` immediately on `Assign` Ok and again
on every tick. See [automatic assignment](./auto-assign) and the
[wire protocol](/reference/wire-protocol#control-channel).

Like every ShadowVPN datagram, control messages are AEAD-authenticated with
the pre-shared key — a route advert is exactly as trustworthy as the header
of a data packet from the same client.
