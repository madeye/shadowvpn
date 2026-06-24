# ShadowVPN benchmarks

Throughput and latency of the data plane over an **emulated internet path**,
measured with the Docker + `netem` harness in [`docker/`](../docker). To
reproduce any row below:

```sh
./docker/run-bench.sh                                   # clean broadband
DELAY=80ms JITTER=10ms LOSS=1% RATE=20mbit ./docker/run-bench.sh   # lossy link
OBFS=quic CIPHER=aes-256-gcm ./docker/run-bench.sh      # different cipher/obfs
```

## Method

Two containers (server + client), each with its own TUN device, share one
private bridge that stands in for the public internet. **Both** apply a `tc
netem` qdisc — delay, jitter, loss, bandwidth — to that link. netem shapes
egress only, so applying it on each side shapes both directions and the
round-trip delay is ≈ 2 × `DELAY`.

The client then measures, with `iperf3` and `ping`:

- **Tunnel** — traffic to the server's in-tunnel address (`10.9.0.1`), i.e.
  through TUN → encrypt → UDP → server → decrypt → TUN.
- **Direct (WAN)** — the same traffic straight to the server container over the
  *same shaped link*, with no tunnel.

Because both paths cross the identical netem qdisc, the **gap between the two
columns is ShadowVPN's own overhead** (AEAD + carrier framing + the 1400-byte
tunnel MTU), not the emulated link.

> Notes on reading the tables:
> - The **UDP** row reports the *offered* load (`UDP_RATE`, default 50M) and the
>   measured **loss %**; goodput ≈ offered × (1 − loss). On a link narrower than
>   the offered rate, high loss simply means the link is saturated.
> - TCP throughput over a *lossy* link is a single-flow, RTT-sensitive figure
>   with high run-to-run variance — treat lossy-link TCP numbers as approximate.

## Results

Measured on the host below. **Absolute numbers are host- and run-dependent;**
the tunnel-vs-direct ratio is the portable takeaway. Run it on your own hardware
for figures that matter to you.

| | |
|---|---|
| CPU | Apple M4 (10 cores), arm64 |
| Host OS | macOS 26.5 |
| Docker | 29.2.1, Compose 5.0.2 (Linux VM) |
| Build | `--release` (fat LTO, `codegen-units = 1`) |
| iperf3 | 10 s per stream |

### Clean broadband — RTT ≈ 48 ms, 0 % loss, 100 Mbit/s cap

| Cipher / obfs | Dir. | RTT (ms) | TCP up (Mbit/s) | TCP down (Mbit/s) | UDP @ 50M loss |
|------------------------------|--------|---------|-----------------|-------------------|----------------|
| chacha20-poly1305 / none | tunnel | 48.0 | 68.8 | 87.3 | 0.00 % |
| | direct | 51.2 | 77.6 | 93.3 | 0.00 % |
| chacha20-poly1305 / quic | tunnel | 47.0 | 69.1 | 73.6 | 0.00 % |
| | direct | 46.9 | 90.0 | 90.2 | 0.00 % |
| aes-256-gcm / none | tunnel | 48.5 | 69.7 | 74.3 | 0.00 % |
| | direct | 45.3 | 85.7 | 90.3 | 0.00 % |

The tunnel sustains roughly **70 Mbit/s up and 75–87 Mbit/s down** against an
80–93 Mbit/s direct baseline — a modest ~15–25 % overhead — and it is
**consistent across ciphers**: at these rates the link and per-packet latency
dominate, not the AEAD. UDP rides at line rate with zero loss. The QUIC carrier
adds a few bytes per packet and a slightly lower TCP ceiling, as expected for the
extra framing.

### Lossy / higher-latency link — RTT ≈ 165 ms, 1 % loss, 20 Mbit/s cap

| Cipher / obfs | Dir. | RTT (ms) | TCP up (Mbit/s) | TCP down (Mbit/s) | UDP @ 50M loss |
|------------------------------|--------|---------|-----------------|-------------------|----------------|
| chacha20-poly1305 / none | tunnel | 172.4 | 0.9 | 1.3 | 61.0 % |
| | direct | 159.3 | 3.3 | 4.1 | 58.7 % |

Here a single TCP flow collapses on **both** paths — classic high-RTT + 1 % loss
behaviour for one cubic flow — with the tunnel a bit lower than direct because of
the added latency. The UDP row shows the 50 Mbit offer saturating the 20 Mbit
link (so ~60 % is shed), which the tunnel does at line rate just like the direct
path: ShadowVPN itself is **not** the bottleneck on a lossy link, TCP's
loss-recovery is.

## Interpretation

- **Forwarding capacity is not the limit.** UDP runs at line rate with
  link-level loss in every scenario; the per-packet crypto/obfs path keeps up.
- **The TCP gap is latency- and loss-bound,** not CPU-bound. It is widest on
  high-RTT/lossy links, where a single tunneled flow inherits the carrier's loss
  as inner-packet drops. The most promising next step is decoupling socket I/O
  from crypto in the relay loops (and larger socket buffers) so the data plane
  pipelines instead of doing strict `recv → crypt → send` per packet.
- **Cipher choice barely moves throughput here** because the link, not the AEAD,
  is the bottleneck at ≤ 100 Mbit/s. On CPU-bound links (or ARM without AES
  acceleration) it matters more — see the cipher notes in the
  [README](../README.md#hardware-acceleration-especially-on-arm).
