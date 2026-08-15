# Config URIs & QR codes

A client config can be exported as a single `shadowvpn://` URI (the config
JSON, URL-safe Base64) and imported back — handy for moving a config to
another device by copy-paste or by scanning a QR code.

This lives in a **separate `shadowvpn-uri` binary** so the server/client
builds stay lean; build it with the `uri` feature (off by default):

```sh
cargo build --release --features uri --bin shadowvpn-uri
```

## Usage

```sh
# Print the shadowvpn:// URI for a config…
shadowvpn-uri export -c client.json

# …or also render a scannable QR code to the terminal:
shadowvpn-uri export -c client.json --qr

# Import a URI back into a JSON config (omit -o to print to stdout):
shadowvpn-uri import 'shadowvpn://…' -o client.json

# Import by decoding a QR-code image instead of pasting the URI:
shadowvpn-uri import --image config-qr.png -o client.json

# Render an existing shadowvpn:// URI as a terminal QR code (also reads stdin):
shadowvpn-uri qr 'shadowvpn://…'
```

## Caveats

- The URI carries **every** config field — including the password. Treat a
  `shadowvpn://` URI (or its QR code) as a secret.
- File-path fields (`gfwlist`, `chnroute`, `geoip`, `cache_file`) are only
  meaningful on the host that has those files — re-point them after importing.
- When several clients share one server, [omit `tun_ip` and `peer_ip`](./auto-assign).
  [Magic DNS](./magic-dns) `hostname` is **not** in the URI (same as `node_id`).
  so one URI/QR works on every device and each still gets a unique tunnel
  IP. The persisted `node_id` lives in `<config>.state` next to the imported
  JSON — it is **not** in the URI. Alternatively give each client a distinct
  static `tun_ip`, or run the server with [`--nat`](./multi-client) (no
  client↔client) so every device can share one identical placeholder config.

The [desktop app](./desktop) supports `shadowvpn://` URI import/export in its
profile manager, so a QR/URI produced here drops straight into the GUI.
