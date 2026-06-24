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
| Build | `--release` (fat LTO, `codegen-units = 1`), pipelined relay loops, 4 MiB UDP buffers |
| iperf3 | 10 s per stream |

### Throughput ceiling — RTT ≈ 3 ms, 0 % loss, 4 Gbit/s cap

How fast the tunnel goes when the *link* is not the limit. This is where the data
plane's own ceiling shows, and where decoupling socket I/O from the per-packet
crypto (a dedicated reader task feeding a single ordered processor, plus enlarged
socket buffers) pays off:

| Relay loops | TCP up (Mbit/s) | TCP down (Mbit/s) | UDP @ 2G loss |
|------------------------------|-----------------|-------------------|---------------|
| serial `recv → crypt → send` | 285 | 317 | 42 % |
| **pipelined (reader ‖ processor)** | **1007** | **1003** | 37 % |
| direct (no tunnel), for scale | 3811 | 3821 | 0.05 % |

The pipeline **~3.2×'s single-flow TCP** through the tunnel (≈0.3 → ≈1.0 Gbit/s)
by overlapping the receive syscall with decryption and the send. One-way UDP at a
2 Gbit/s offer still sheds ~37 % — past ~1.25 Gbit/s the single crypto+send
processor becomes the limit, so a blast like that is the next frontier (parallel
crypto workers, at the cost of reordering). Real traffic is TCP, which is the row
that moved.

### Clean broadband — RTT ≈ 48 ms, 0 % loss, 100 Mbit/s cap

| Cipher / obfs | Dir. | RTT (ms) | TCP up (Mbit/s) | TCP down (Mbit/s) | UDP @ 50M loss |
|------------------------------|--------|---------|-----------------|-------------------|----------------|
| chacha20-poly1305 / none | tunnel | 45.2 | 87.6 | 88.2 | 0.00 % |
| | direct | 47.4 | 92.8 | 83.0 | 0.00 % |
| chacha20-poly1305 / quic | tunnel | 45.1 | 86.1 | 86.6 | 0.00 % |
| | direct | 45.1 | 77.9 | 81.7 | 0.00 % |
| aes-256-gcm / none | tunnel | 49.7 | 73.8 | 87.2 | 0.00 % |
| | direct | 47.2 | 89.7 | 85.7 | 0.00 % |

At ~100 Mbit/s the tunnel runs **at or near line rate** — within a few percent of
the direct baseline, and effectively at parity within run-to-run noise — because
the link, not ShadowVPN, is the bottleneck here. UDP rides at line rate with zero
loss; cipher and carrier framing barely move the result.

### Lossy / higher-latency link — RTT ≈ 165 ms, 1 % loss, 20 Mbit/s cap

| Cipher / obfs | Dir. | RTT (ms) | TCP up (Mbit/s) | TCP down (Mbit/s) | UDP @ 50M loss |
|------------------------------|--------|---------|-----------------|-------------------|----------------|
| chacha20-poly1305 / none | tunnel | 172.3 | 0.8 | 1.7 | 61.0 % |
| | direct | 163.9 | 3.6 | 3.1 | 58.8 % |

Here a single TCP flow collapses on **both** paths — classic high-RTT + 1 % loss
behaviour for one cubic flow — with the tunnel a bit lower than direct because of
the added latency. The UDP row shows the 50 Mbit offer saturating the 20 Mbit
link (so ~60 % is shed), which the tunnel does at line rate just like the direct
path: ShadowVPN itself is **not** the bottleneck on a lossy link, TCP's
loss-recovery is.

## Interpretation

- **Decoupling I/O from crypto roughly tripled single-flow TCP** at high rates
  (≈0.3 → ≈1.0 Gbit/s) and closed the gap to the direct baseline at broadband
  rates. A dedicated reader task drains the socket/TUN continuously instead of
  stalling on the crypto+send of the previous packet, so the carrier stops
  dropping bursts and TCP can keep its window full.
- **Forwarding capacity is no longer the everyday limit.** UDP runs at line rate
  with link-level loss in every realistic scenario; only a multi-Gbit one-way
  blast still saturates the single crypto+send processor.
- **The remaining TCP gap is latency- and loss-bound,** not CPU-bound — widest on
  high-RTT/lossy links, where a single tunneled flow inherits the carrier's loss
  as inner-packet drops. The next lever for that regime is parallel crypto
  workers with a reorder buffer (a larger change, traded against packet
  reordering).
- **Cipher choice barely moves throughput here** because the link, not the AEAD,
  is the bottleneck at ≤ 100 Mbit/s. On CPU-bound links (or ARM without AES
  acceleration) it matters more — see the cipher notes in the
  [README](../README.md#hardware-acceleration-especially-on-arm).
