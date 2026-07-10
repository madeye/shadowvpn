# Ciphers

All ciphers are AEAD, from the RustCrypto project. Nonce length is 12 bytes
and tag length is 16 bytes for all three.

| Cipher name (config) | Key / salt length | Crate              |
|----------------------|-------------------|--------------------|
| `aes-128-gcm`        | 16 bytes          | `aes-gcm`          |
| `aes-256-gcm`        | 32 bytes          | `aes-gcm`          |
| `chacha20-poly1305`  | 32 bytes          | `chacha20poly1305` |

The alias `chacha20-ietf-poly1305` is accepted and treated as
`chacha20-poly1305`. The default cipher (when none is specified) is
`chacha20-poly1305`.

Selected with the `cipher` config field / `-m, --cipher` flag; **both ends
must use the same cipher** (there is no negotiation — a mismatch just means
packets fail to decrypt and are dropped).

## Hardware acceleration (especially on ARM)

`chacha20-poly1305` uses runtime SIMD feature detection, so it is fast out of
the box on every target. AES-GCM uses AES-NI automatically on x86-64, **but on
aarch64 (Raspberry Pi, Apple Silicon, Windows-on-ARM) the ARMv8 AES backend is
gated behind compile-time target features** — a plain `cargo build` for ARM
runs AES-GCM in slow constant-time software. So:

- On ARM hardware that lacks (or isn't built for) AES acceleration, prefer
  `chacha20-poly1305` — it is both faster and simpler there.
- To use AES-GCM at full speed on ARM, build with the crypto features
  enabled:

  ```sh
  RUSTFLAGS="-C target-feature=+aes,+neon" cargo build --release
  # or, when building on the device itself:
  RUSTFLAGS="-C target-cpu=native" cargo build --release
  ```

## Does the cipher matter for throughput?

At broadband rates (≤ 100 Mbit/s) the link, not the AEAD, is the bottleneck —
cipher choice barely moves the numbers. On CPU-bound links (or ARM without AES
acceleration) it matters more. See the [benchmarks](./benchmarks).
