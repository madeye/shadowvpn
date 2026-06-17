# Running ShadowVPN as a service

Example service definitions. Adjust the binary path (`/usr/local/bin`), config
path (`/etc/shadowvpn`), and—on the server—the WAN interface / tunnel subnet to
match your setup.

| File | Platform | Role |
|------|----------|------|
| [`systemd/shadowvpn-server.service`](systemd/shadowvpn-server.service) | Linux (systemd) | server (incl. forwarding + NAT) |
| [`systemd/shadowvpn-client.service`](systemd/shadowvpn-client.service) | Linux (systemd) | client |
| [`launchd/io.github.madeye.shadowvpn-client.plist`](launchd/io.github.madeye.shadowvpn-client.plist) | macOS (launchd) | client |

Both binaries need root (TUN creation, and on the client routing/DNS changes).

## Linux (systemd)

```sh
# server
sudo install -Dm755 target/release/shadowvpn-server /usr/local/bin/shadowvpn-server
sudo install -Dm600 server.json /etc/shadowvpn/server.json
sudo cp dist/systemd/shadowvpn-server.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now shadowvpn-server

# client
sudo install -Dm755 target/release/shadowvpn-client /usr/local/bin/shadowvpn-client
sudo install -Dm600 client.json /etc/shadowvpn/client.json
sudo cp dist/systemd/shadowvpn-client.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now shadowvpn-client

# logs / control
journalctl -u shadowvpn-client -f
sudo systemctl stop shadowvpn-client     # graceful: restores DNS + routes, saves cache
```

## macOS (launchd, client)

```sh
sudo install -Dm755 target/release/shadowvpn-client /usr/local/bin/shadowvpn-client
sudo mkdir -p /etc/shadowvpn && sudo cp client.json /etc/shadowvpn/client.json
sudo cp dist/launchd/io.github.madeye.shadowvpn-client.plist /Library/LaunchDaemons/
sudo launchctl load -w /Library/LaunchDaemons/io.github.madeye.shadowvpn-client.plist

# logs / stop
tail -f /var/log/shadowvpn-client.log
sudo launchctl unload -w /Library/LaunchDaemons/io.github.madeye.shadowvpn-client.plist  # graceful
```

Stopping either client service sends `SIGTERM`, which the client handles
gracefully — it restores the system resolver, removes the per-destination
routes, and saves the DNS cache before exiting.
