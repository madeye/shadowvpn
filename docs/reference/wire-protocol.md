# Wire protocol

Each UDP datagram on the wire is:

```text
[ salt (salt_len bytes) ] ++ [ AEAD ciphertext ++ tag (16 bytes) ]
```

![ShadowVPN on-wire datagram format](../wire.svg)

- **`salt_len == key_len`** of the cipher: 16 bytes for `aes-128-gcm`,
  32 bytes for `aes-256-gcm` and `chacha20-poly1305`. A fresh random salt is
  generated for **every** datagram.
- **Subkey:** `subkey = HKDF-SHA1(ikm = master_key, salt = salt,
  info = "ss-subkey", L = key_len)`.
- **Nonce:** the all-zero 12-byte nonce for every UDP packet. This is safe
  because each datagram has a unique random salt and therefore a unique
  subkey, so the `(subkey, nonce)` pair is never reused.
- **Master key:** derived from the password string with shadowsocks'
  `EVP_BytesToKey` (the OpenSSL legacy MD5-based KDF): repeatedly compute
  `d_0 = MD5(password)`, `d_i = MD5(d_{i-1} ++ password)`, and concatenate
  until `key_len` bytes are available. (Implemented in-tree; no external
  crate.)
- **Plaintext:** the raw IP packet read from the TUN device. UDP datagram
  boundaries are the frame boundaries — there is no length prefix, no
  multiplexing, and no reassembly. One IP packet maps to exactly one datagram.

The scheme is the **shadowsocks.org AEAD UDP scheme**, matched byte-for-byte,
with one deliberate deviation below.

## Deviation from ss-proxy

Standard shadowsocks UDP relays prepend a SOCKS-style target address to the
plaintext. **ShadowVPN does not.** This is a fixed point-to-point tunnel, not
a SOCKS proxy: the plaintext is exactly the raw IP packet, with no address
header. Everything else (salt, HKDF-SHA1 `"ss-subkey"` subkey, zero nonce,
AEAD tag) matches the shadowsocks UDP AEAD scheme byte-for-byte. This
deviation is also documented in
[`src/crypto.rs`](https://github.com/madeye/shadowvpn/blob/main/src/crypto.rs)
and
[`src/protocol.rs`](https://github.com/madeye/shadowvpn/blob/main/src/protocol.rs).

## Keepalive

*A ShadowVPN convention, not part of the ss spec.*

The client periodically sends a tiny encrypted datagram — a 5-byte plaintext:
a `0x00` marker followed by the client's 4-byte tunnel IP — so that stateful
NAT/firewall mappings stay open and the server learns the client's current
source address before any real traffic flows.

- In the default **learning mode**, the announced tunnel IP lets the server
  map (and re-map, after a NAT rebind) the client's UDP address from the
  keepalive alone.
- In [`--nat` mode](/guide/multi-client), the keepalive refreshes an existing
  lease, and the mapping itself is allocated by the first real packet.

The server drops any decrypted payload smaller than a 20-byte IPv4 header, so
the keepalive never reaches the TUN write path (older 1-byte `0x00`
keepalives are still accepted and treated as refresh-only).

The interval is 15 seconds by default (`keepalive_secs` /
`--keepalive-secs`) — keep it below the path's UDP NAT timeout.

## Optional carrier obfuscation

The `salt ++ AEAD` envelope can optionally be wrapped in a cosmetic carrier —
a QUIC 1-RTT short-header framing or base64 encoding — before hitting the
wire. This changes nothing above: the envelope is unwrapped before decryption.
See [carrier obfuscation](./obfuscation).
