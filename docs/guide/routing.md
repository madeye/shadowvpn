# Routing & IP forwarding

ShadowVPN brings the TUN interface up (address, netmask, peer, MTU) but
**deliberately does not touch the system routing table or `sysctl`**. Doing so
silently is dangerous and platform-specific. The steps below are what you run
**outside** the process. The binaries also print these hints at startup.

::: tip Prefer a split tunnel?
If you only want *some* destinations tunneled, skip the manual routes below
and use the client's built-in [policy routing](./policy-routing) — it programs
per-destination routes automatically and removes them on exit.
:::

## Server: enable IP forwarding + NAT

So that tunneled clients can reach the wider network through the server, the
server host must forward packets and NAT (masquerade) them out its WAN
interface. Replace `<wan-if>` with the server's real outbound interface (e.g.
`eth0`).

**Linux:**

```sh
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o <wan-if> -j MASQUERADE
```

**macOS:**

```sh
sudo sysctl -w net.inet.ip.forwarding=1
# Configure pf NAT, e.g. add to /etc/pf.conf:
#   nat on <wan-if> from 10.9.0.0/24 to any -> (<wan-if>)
# then: sudo pfctl -f /etc/pf.conf -e
```

## Client: route traffic through the tunnel (full tunnel)

The client must keep a **host route to the server's IP via the real gateway**
(otherwise the encrypted UDP would loop back into the tunnel), then route the
desired destinations via the tunnel peer. The two `/1` routes below override
the default route without deleting it.

**Linux:**

```sh
# Keep the server reachable over your real link (replace GW/DEV):
sudo ip route add <SERVER_IP>/32 via <YOUR_DEFAULT_GW> dev <YOUR_WAN_DEV>
# Route everything through the tunnel peer:
sudo ip route add 0.0.0.0/1 via 10.9.0.1
sudo ip route add 128.0.0.0/1 via 10.9.0.1
```

**macOS:**

```sh
# Keep the server reachable over your real link (replace GW):
sudo route -n add -host <SERVER_IP> <YOUR_DEFAULT_GW>
# Route everything through the tunnel peer:
sudo route -n add -net 0.0.0.0/1 10.9.0.1
sudo route -n add -net 128.0.0.0/1 10.9.0.1
```

**Windows** (elevated prompt):

```bat
:: Keep the server reachable over your real link (replace GW):
route add <SERVER_IP> mask 255.255.255.255 <YOUR_DEFAULT_GW>
:: Route everything through the tunnel peer:
route add 0.0.0.0 mask 128.0.0.0 10.9.0.1
route add 128.0.0.0 mask 128.0.0.0 10.9.0.1
```

To stop using the tunnel, delete the routes you added. If the server is given
as a hostname rather than a literal IP, resolve it first and add the host
route for that resolved IP.

## MTU

The TUN MTU defaults to `1400`, leaving headroom for the salt + AEAD tag + UDP
+ IP overhead on the outer datagram. If you enable `base64` obfuscation
(~33% payload growth on the wire), size the `mtu` down to compensate — see
[carrier obfuscation](/reference/obfuscation).
