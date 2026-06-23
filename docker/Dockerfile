# syntax=docker/dockerfile:1
#
# Image used by the Docker-based end-to-end test. It contains both ShadowVPN
# binaries plus the userspace tools (iproute2, ping) needed to bring the tunnel
# up and probe connectivity across it. The same image runs as both the server
# and the client; the compose file selects the role via the command.

# --- Build stage ------------------------------------------------------------
FROM rust:1-bookworm AS builder
WORKDIR /src

# Copy the manifest first so the dependency build layer is cached as long as the
# manifests are unchanged.
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build both binaries against the pinned lockfile.
RUN cargo build --release --locked --bins

# --- Runtime stage ----------------------------------------------------------
FROM debian:bookworm-slim

# iproute2: interface/route inspection. iputils-ping: the cross-tunnel probe.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/shadowvpn-server /usr/local/bin/shadowvpn-server
COPY --from=builder /src/target/release/shadowvpn-client /usr/local/bin/shadowvpn-client

COPY docker/server.json docker/client.json docker/client-auto.json /etc/shadowvpn/
COPY docker/run-server.sh docker/test-client.sh \
     docker/run-server-auto.sh docker/run-client-auto.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/run-server.sh /usr/local/bin/test-client.sh \
    /usr/local/bin/run-server-auto.sh /usr/local/bin/run-client-auto.sh

ENV RUST_LOG=info
