# Testing (Docker e2e)

Beyond the unit tests (`cargo test --lib`, covering crypto + config), a suite
of Docker-based end-to-end tests lives under
[`docker/`](https://github.com/madeye/shadowvpn/tree/main/docker). CI runs
`fmt` + `clippy` + unit tests, plus the e2e and policy tests, on every push
(see
[`.github/workflows/ci.yml`](https://github.com/madeye/shadowvpn/blob/main/.github/workflows/ci.yml)).

All the containers need `NET_ADMIN` and `/dev/net/tun`; the compose files
request both.

## End-to-end ping test

Builds both binaries, starts a **server** and a **client** container — each
with its own TUN device — on a private bridge network, and then pings the
server's in-tunnel address from the client. A successful, lossless ping
exercises the entire path: TUN → encrypt → UDP → server → decrypt → TUN, and
the reply all the way back.

```sh
./docker/run-e2e.sh                 # default cipher (chacha20-poly1305)
./docker/run-e2e.sh aes-256-gcm     # any supported cipher
```

The script exits non-zero if connectivity through the tunnel fails, so it
doubles as the CI gate — CI runs it across all three ciphers.

## HTTP/3-over-tunnel test

A more demanding test proves ShadowVPN carries arbitrary UDP traffic by
running **real HTTP/3 (QUIC)** through the tunnel. The server enables IP
forwarding and masquerades the tunnel subnet to the internet; the client
routes **all** egress through the tunnel (its default route is deleted, so the
only way out is via ShadowVPN) and fetches a QUIC site with an HTTP/3-only
`curl`:

```sh
./docker/run-e2e-http3.sh                       # default: https://www.cloudflare-quic.com/
TARGET_URL=https://www.cloudflare-quic.com/ ./docker/run-e2e-http3.sh aes-256-gcm
```

The test passes when the response is delivered over **HTTP/3**
(`http_version=3`); the application status code is irrelevant (Cloudflare may
bot-block with `403` — the point is that the QUIC handshake and HTTP/3
exchange completed over the tunnel). It runs on a private bridge network with
any host proxy neutralized, so QUIC must travel through ShadowVPN rather than
around it. In CI this job runs on pushes to `main` and on manual dispatch (it
depends on external connectivity).

## Policy-routing test

Exercises [policy routing](/guide/policy-routing) end to end. The topology
puts a source-IP echo server behind the tunnel and another on the LAN: a
tunneled request shows up as the *server's* address, a direct one as the
*client's*, so the two paths are unambiguous. It verifies that both modes
tunnel the selected domain and leave the other direct:

```sh
./docker/run-e2e-policy.sh             # both gfwlist and chinadns
./docker/run-e2e-policy.sh gfwlist     # one mode
```

Fully self-contained (no external network), so CI runs it on every PR.

## Magic DNS test

Exercises [Magic DNS](/guide/magic-dns) end to end: a learning-mode hub
named `vpn` and two auto clients named `laptop` and `pi`. Each client's
stub at `127.0.0.1:53` must answer the other peer (A and AAAA), NXDOMAIN
an unknown `*.svpn`, and resolve the server name to the hub's tunnel IP.

```sh
./docker/run-e2e-magicdns.sh
```

Self-contained; CI runs it on every PR.

## Throughput / latency benchmark

`docker/run-bench.sh` measures the data plane over an emulated internet path
(delay, jitter, loss, bandwidth via `tc netem`) — both through the tunnel and
directly over the same shaped link, so the gap is ShadowVPN's own overhead.
Full methodology and results: [Benchmarks](./benchmarks).

```sh
./docker/run-bench.sh                                 # ~100 Mbit broadband-ish
OBFS=quic CIPHER=aes-256-gcm ./docker/run-bench.sh    # with QUIC carrier shaping
DELAY=80ms LOSS=1% RATE=20mbit ./docker/run-bench.sh  # lossy mobile-ish link
```
