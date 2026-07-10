# Carrier obfuscation

By default the UDP payload on the wire is the bare `salt ++ AEAD` envelope.
The optional `obfs` field shapes that payload so it doesn't read as an opaque
random-looking UDP blob, to evade naive protocol classification. It is
selected with the `obfs` config field and **both ends must agree** — a
mismatched peer just sees its traffic dropped.

::: warning Cosmetic framing only
This adds **no security**. The AEAD envelope underneath is unchanged, and a
wrong/absent obfuscation simply fails to decode (the packet is dropped before
decryption).
:::

## Modes

| `obfs`   | On the wire                                                                              | Note                                            |
|----------|-------------------------------------------------------------------------------------------|-------------------------------------------------|
| `none`   | the plain `salt ++ AEAD` datagram (default)                                               | —                                               |
| `quic`   | each datagram is wrapped as a **QUIC 1-RTT short-header** packet, so it reads as HTTP/3   | adds a few header bytes; self-describing decode |
| `base64` | each datagram is **standard base64**, so the UDP payload is printable ASCII               | ~33% larger — size the `mtu` down to compensate |

## Configuration

Set it in **both** config files (it has no CLI flag):

```json
{
  "server": "vpn.example.com:8388",
  "password": "correct horse battery staple",
  "obfs": "quic"
}
```

The server logs the active mode in its startup banner. The wire formats are
documented in
[`src/obfs.rs`](https://github.com/madeye/shadowvpn/blob/main/src/obfs.rs).

## Impact on throughput

Negligible for `quic` framing at broadband rates — see the
[benchmarks](./benchmarks), which include a `chacha20-poly1305 / quic` row
within noise of the unobfuscated run. `base64` grows the payload ~33%, so
lower the tunnel `mtu` to keep the outer datagram under the path MTU.
