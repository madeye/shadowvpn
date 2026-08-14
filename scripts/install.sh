#!/usr/bin/env bash
# ShadowVPN one-line installer / uninstaller (Linux + macOS).
#
#   install server:   curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- server
#   setup server:     curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- server --setup
#   install client:   curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- client
#   uninstall server: curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- uninstall server
#   uninstall client: curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- uninstall client
#
# Options (after the role):
#   --service    also install the service definition (systemd unit / launchd
#                plist) from the release package — installed, not enabled
#   --setup      server on Linux only: full working setup — write a real config
#                (random password, learning mode + auto-assign), install the
#                systemd unit with the detected WAN interface, enable + start
#                the service, open the UDP port in ufw/firewalld, and print
#                the matching client config (no tun_ip/peer_ip)
#   --port N     with --setup: UDP port to listen on (default 8388)
#   --obfs MODE  with --setup: obfs mode none|quic|base64 (default none;
#                both ends must match)
#   --purge      uninstall only: also remove /etc/shadowvpn configs
#
# Environment overrides:
#   SHADOWVPN_VERSION  release tag to install (e.g. v0.4.0; default: latest)
#   PREFIX             install prefix (default /usr/local). With a non-root
#                      PREFIX no sudo is needed; configs/services are skipped.
#
# Windows has no curl|bash flow — use the release .zip (client + wintun.dll
# bundled): https://github.com/madeye/shadowvpn/releases
set -euo pipefail

REPO="madeye/shadowvpn"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"
ETC_DIR="/etc/shadowvpn"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
usage: install.sh <server|client> [--service]
       install.sh server --setup [--port N] [--obfs none|quic|base64]
       install.sh uninstall <server|client|all> [--purge]

  --service    also install the service definition (systemd unit / launchd
               plist) from the release package — installed, not enabled
  --setup      server on Linux only: full working setup — write a real config
               (random password, learning mode + auto-assign), install the
               systemd unit with the detected WAN interface, enable + start
               the service, open the UDP port in ufw/firewalld, and print
               the matching client config (no tun_ip/peer_ip)
  --port N     with --setup: UDP port to listen on (default 8388)
  --obfs MODE  with --setup: obfs mode none|quic|base64 (default none;
               both ends must match)
  --purge      uninstall only: also remove /etc/shadowvpn configs

environment:
  SHADOWVPN_VERSION  release tag to install (e.g. v0.4.0; default: latest)
  PREFIX             install prefix (default /usr/local); a user-writable
                     PREFIX needs no sudo (configs/services are skipped)
EOF
  exit 1
}

# ---------- argument parsing ----------------------------------------------

ACTION=install ROLE="" SERVICE=0 SETUP=0 PURGE=0 PORT=8388 OBFS=none
while [ $# -gt 0 ]; do
  case "$1" in
    server|client) ROLE="$1" ;;
    uninstall)     ACTION=uninstall ;;
    all)           ROLE=all ;;
    --service)     SERVICE=1 ;;
    --setup)       SETUP=1 ;;
    --port)        [ $# -ge 2 ] || die "--port needs a value"; shift; PORT="$1" ;;
    --obfs)        [ $# -ge 2 ] || die "--obfs needs a value"; shift; OBFS="$1" ;;
    --purge)       PURGE=1 ;;
    -h|--help)     usage ;;
    *)             die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done
[ -n "$ROLE" ] || usage
[ "$ROLE" = all ] && [ "$ACTION" = install ] && die "'all' is only valid with uninstall"
if [ "$SETUP" = 1 ]; then
  [ "$ACTION" = install ] && [ "$ROLE" = server ] || die "--setup only applies to 'server' install"
fi
case "$PORT" in (*[!0-9]*|'') die "--port needs a number (got: '$PORT')" ;; esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port out of range: $PORT"
case "$OBFS" in (none|quic|base64) ;; (*) die "--obfs must be none, quic, or base64 (got: '$OBFS')" ;; esac

# ---------- platform detection --------------------------------------------

OS=$(uname -s)
case "$OS" in
  Linux)  SYS=linux;  TARGET_OS=unknown-linux-gnu ;;
  Darwin) SYS=darwin; TARGET_OS=apple-darwin ;;
  *) die "unsupported OS: $OS (Windows: use the release .zip — https://github.com/$REPO/releases)" ;;
esac

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) die "unsupported CPU architecture: $ARCH" ;;
esac
TARGET="$ARCH-$TARGET_OS"

# Root is needed for the default prefix and for configs/services; a custom
# user-writable PREFIX works without sudo (configs/services are skipped).
IS_ROOT=0; [ "$(id -u)" = 0 ] && IS_ROOT=1
if [ "$IS_ROOT" = 0 ] && [ ! -w "$BIN_DIR" ] && ! mkdir -p "$BIN_DIR" 2>/dev/null; then
  die "cannot write $BIN_DIR — re-run with sudo, or set PREFIX to a writable directory"
fi

if [ "$SETUP" = 1 ]; then
  [ "$SYS" = linux ] || die "--setup is Linux-only (it configures systemd + iptables)"
  command -v systemctl >/dev/null 2>&1 || die "--setup needs systemd"
  [ "$IS_ROOT" = 1 ] || die "--setup needs root — re-run with sudo"
fi

# ---------- uninstall -------------------------------------------------------

remove_service() { # role
  local role="$1"
  if [ "$SYS" = linux ] && command -v systemctl >/dev/null 2>&1; then
    local unit="shadowvpn-$role.service"
    if [ -f "/etc/systemd/system/$unit" ]; then
      say "removing systemd unit $unit"
      systemctl disable --now "$unit" 2>/dev/null || true
      rm -f "/etc/systemd/system/$unit"
      systemctl daemon-reload 2>/dev/null || true
    fi
  elif [ "$SYS" = darwin ] && [ "$role" = client ]; then
    local plist="/Library/LaunchDaemons/io.github.madeye.shadowvpn-client.plist"
    if [ -f "$plist" ]; then
      say "removing launchd daemon"
      launchctl unload -w "$plist" 2>/dev/null || true
      rm -f "$plist"
    fi
  fi
}

uninstall_role() { # role
  local role="$1"
  [ "$IS_ROOT" = 1 ] && remove_service "$role"
  say "removing $BIN_DIR/shadowvpn-$role"
  rm -f "$BIN_DIR/shadowvpn-$role"
  if [ "$role" = client ]; then
    # bundled policy data + DNS cache live next to the binary
    rm -f "$BIN_DIR/gfwlist.txt" "$BIN_DIR/GeoLite2-Country.mmdb" "$BIN_DIR/dns-cache.json"
  fi
  if [ "$PURGE" = 1 ] && [ -f "$ETC_DIR/$role.json" ]; then
    say "purging $ETC_DIR/$role.json"
    rm -f "$ETC_DIR/$role.json"
    rmdir "$ETC_DIR" 2>/dev/null || true
  fi
}

if [ "$ACTION" = uninstall ]; then
  if [ "$ROLE" = all ]; then uninstall_role server; uninstall_role client
  else uninstall_role "$ROLE"; fi
  if [ "$PURGE" = 1 ]; then say "done."
  else say "done (configs in $ETC_DIR were kept; add --purge to remove them)."
  fi
  exit 0
fi

# ---------- resolve version & download -------------------------------------

VERSION="${SHADOWVPN_VERSION:-}"
if [ -z "$VERSION" ]; then
  say "resolving latest release"
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
    sed -n 's/^ *"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VERSION" ] || die "could not determine the latest release tag"
fi
VER="${VERSION#v}"

NAME="shadowvpn-$VER-$TARGET"
URL="https://github.com/$REPO/releases/download/$VERSION/$NAME.tar.gz"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

say "downloading $NAME.tar.gz"
curl -fsSL "$URL" -o "$TMP/pkg.tar.gz" ||
  die "download failed: $URL (does release $VERSION have a $TARGET build?)"
tar -xzf "$TMP/pkg.tar.gz" -C "$TMP"
PKG="$TMP/$NAME"
[ -x "$PKG/shadowvpn-$ROLE" ] || die "shadowvpn-$ROLE not found in the release package"

# ---------- install ---------------------------------------------------------

say "installing shadowvpn-$ROLE $VERSION to $BIN_DIR"
install -m 755 "$PKG/shadowvpn-$ROLE" "$BIN_DIR/shadowvpn-$ROLE"

if [ "$ROLE" = client ] && [ -f "$PKG/gfwlist.txt" ]; then
  # next to the binary, where policy routing auto-discovers it
  install -m 644 "$PKG/gfwlist.txt" "$BIN_DIR/gfwlist.txt"
fi

# Example config (root only; never overwrites an existing one).
# With --setup the server config is generated further down instead.
if [ "$SETUP" = 0 ] && [ "$IS_ROOT" = 1 ] && [ ! -f "$ETC_DIR/$ROLE.json" ]; then
  say "writing example config $ETC_DIR/$ROLE.json (edit it before starting!)"
  mkdir -p "$ETC_DIR"
  if [ "$ROLE" = server ]; then
    cat > "$ETC_DIR/server.json" <<'EOF'
{
  "server": "0.0.0.0:8388",
  "password": "CHANGE-ME",
  "cipher": "chacha20-poly1305",
  "tun_ip": "10.9.0.1",
  "tun_netmask": "255.255.255.0",
  "peer_ip": "10.9.0.2",
  "mtu": 1400
}
EOF
  else
    # learning-mode example: omit tun_ip/peer_ip so the server auto-assigns.
    cat > "$ETC_DIR/client.json" <<'EOF'
{
  "server": "vpn.example.com:8388",
  "password": "CHANGE-ME",
  "cipher": "chacha20-poly1305",
  "tun_netmask": "255.255.255.0",
  "mtu": 1400
}
EOF
  fi
  chmod 600 "$ETC_DIR/$ROLE.json"
fi

# ---------- --setup: full server setup (Linux + systemd, root) --------------

json_str() { # file key -> first string value (best-effort, flat configs)
  sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -n1
}
json_num() { # file key -> first numeric value (best-effort, flat configs)
  sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$1" | head -n1
}

if [ "$SETUP" = 1 ]; then
  CFG="$ETC_DIR/server.json"

  # Config: generate one with a random password; never overwrite an existing one.
  if [ -f "$CFG" ]; then
    say "keeping existing config $CFG"
  else
    if command -v openssl >/dev/null 2>&1; then
      PASSWORD=$(openssl rand -base64 24)
    else
      PASSWORD=$(head -c 24 /dev/urandom | base64 | tr -d '\n')
    fi
    say "writing $CFG (port $PORT/udp, obfs $OBFS, learning mode, random password)"
    mkdir -p "$ETC_DIR"
    {
      echo '{'
      echo "  \"server\": \"0.0.0.0:$PORT\","
      echo "  \"password\": \"$PASSWORD\","
      echo '  "cipher": "chacha20-poly1305",'
      echo '  "tun_ip": "10.9.0.1",'
      echo '  "tun_netmask": "255.255.255.0",'
      # peer_ip .2 is reserved (legacy static slot) so the assigner never
      # hands it to an auto client.
      echo '  "peer_ip": "10.9.0.2",'
      if [ "$OBFS" != none ]; then
        echo '  "mtu": 1400,'
        echo "  \"obfs\": \"$OBFS\""
      else
        echo '  "mtu": 1400'
      fi
      echo '}'
    } > "$CFG"
    chmod 600 "$CFG"
  fi

  # Effective values — a pre-existing config wins over the flags.
  PASSWORD=$(json_str "$CFG" password)
  BIND=$(json_str "$CFG" server)
  case "${BIND##*:}" in (''|*[!0-9]*) ;; (*) PORT="${BIND##*:}" ;; esac
  CIPHER=$(json_str "$CFG" cipher);   CIPHER="${CIPHER:-chacha20-poly1305}"
  OBFS=$(json_str "$CFG" obfs);       OBFS="${OBFS:-none}"
  TUN_IP=$(json_str "$CFG" tun_ip);   TUN_IP="${TUN_IP:-10.9.0.1}"
  MTU=$(json_num "$CFG" mtu);         MTU="${MTU:-1400}"
  SUBNET="${TUN_IP%.*}.0/24"
  [ "$PASSWORD" = CHANGE-ME ] && warn "$CFG still has the CHANGE-ME password — edit it before real use"

  # Previous --setup wrote "nat": true and we never overwrite. json_str only
  # reads quoted strings, so grep the boolean.
  NAT_ON=0
  if grep -Eq '"nat"[[:space:]]*:[[:space:]]*true' "$CFG"; then
    NAT_ON=1
    PEER_IP=$(json_str "$CFG" peer_ip); PEER_IP="${PEER_IP:-10.9.0.2}"
    warn "$CFG has \"nat\": true — auto-assign clients get NatMode (fatal); drop \"nat\" for learning + auto-assign, or use the static snippet below"
  fi

  # systemd unit: patch the WAN interface / tunnel subnet / binary path, enable.
  UNIT_SRC="$PKG/systemd/shadowvpn-server.service"
  [ -f "$UNIT_SRC" ] || die "release package has no systemd unit — use a newer SHADOWVPN_VERSION"
  WAN=$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
  if [ -z "$WAN" ]; then
    warn "could not detect the WAN interface; keeping 'eth0' — edit /etc/systemd/system/shadowvpn-server.service if that's wrong"
    WAN=eth0
  fi
  say "installing systemd unit (WAN interface: $WAN, tunnel subnet: $SUBNET)"
  sed -e "s/eth0/$WAN/g" \
      -e "s|10\.9\.0\.0/24|$SUBNET|g" \
      -e "s|/usr/local/bin/shadowvpn-server|$BIN_DIR/shadowvpn-server|" \
      "$UNIT_SRC" > /etc/systemd/system/shadowvpn-server.service
  chmod 644 /etc/systemd/system/shadowvpn-server.service
  systemctl daemon-reload
  say "enabling + starting shadowvpn-server"
  systemctl enable --now shadowvpn-server ||
    die "could not start the service — check: journalctl -u shadowvpn-server -e"
  sleep 1
  if systemctl is-active --quiet shadowvpn-server; then
    say "shadowvpn-server is running"
  else
    warn "shadowvpn-server is not active — check: journalctl -u shadowvpn-server -e"
  fi

  # Host firewall (best effort). Cloud firewalls must be opened separately.
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    say "allowing $PORT/udp in ufw"
    ufw allow "$PORT/udp" >/dev/null 2>&1 || warn "ufw allow $PORT/udp failed — open it manually"
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    say "allowing $PORT/udp in firewalld"
    { firewall-cmd --permanent --add-port="$PORT/udp" >/dev/null 2>&1 &&
      firewall-cmd --reload >/dev/null 2>&1; } || warn "firewall-cmd failed — open $PORT/udp manually"
  fi

  PUB_IP=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)
  [ -n "$PUB_IP" ] || PUB_IP="<server-public-ip>"

  say "installed: $BIN_DIR/shadowvpn-server ($VERSION, $TARGET) — service enabled + started"
  echo
  echo "check the server:"
  echo "  systemctl status shadowvpn-server"
  echo "  journalctl -u shadowvpn-server -f"
  echo
  echo "IMPORTANT: also open UDP $PORT in your cloud firewall / security group"
  echo "(DigitalOcean, AWS, GCP, ...) — the host firewall alone is not enough."
  echo
  if [ "$NAT_ON" = 1 ]; then
    echo "matching client config (NAT is on: static tun_ip/peer_ip; drop \"nat\" from $CFG for auto-assign):"
  else
    echo "matching client config (no tun_ip/peer_ip: the server auto-assigns):"
  fi
  echo '  {'
  echo "    \"server\": \"$PUB_IP:$PORT\","
  echo "    \"password\": \"$PASSWORD\","
  echo "    \"cipher\": \"$CIPHER\","
  if [ "$NAT_ON" = 1 ]; then
    echo "    \"tun_ip\": \"$PEER_IP\","
  fi
  echo '    "tun_netmask": "255.255.255.0",'
  if [ "$NAT_ON" = 1 ]; then
    echo "    \"peer_ip\": \"$TUN_IP\","
  fi
  if [ "$OBFS" != none ]; then
    echo "    \"mtu\": $MTU,"
    echo "    \"obfs\": \"$OBFS\""
  else
    echo "    \"mtu\": $MTU"
  fi
  echo '  }'
  echo
  echo "install a client:"
  echo "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install.sh | sudo bash -s -- client"
  echo
  echo "docs: https://madeye.github.io/shadowvpn/"
  exit 0
fi

# Optional service definition — installed, not enabled.
if [ "$SERVICE" = 1 ]; then
  if [ "$IS_ROOT" != 1 ]; then
    warn "--service needs root; skipped"
  elif [ "$SYS" = linux ] && [ -f "$PKG/systemd/shadowvpn-$ROLE.service" ]; then
    say "installing systemd unit (not enabled)"
    install -m 644 "$PKG/systemd/shadowvpn-$ROLE.service" /etc/systemd/system/
    systemctl daemon-reload 2>/dev/null || true
    SERVICE_HINT="sudo systemctl enable --now shadowvpn-$ROLE"
  elif [ "$SYS" = darwin ] && [ "$ROLE" = client ] && [ -f "$PKG/launchd/io.github.madeye.shadowvpn-client.plist" ]; then
    say "installing launchd daemon (not loaded)"
    install -m 644 "$PKG/launchd/io.github.madeye.shadowvpn-client.plist" /Library/LaunchDaemons/
    SERVICE_HINT="sudo launchctl load -w /Library/LaunchDaemons/io.github.madeye.shadowvpn-client.plist"
  else
    warn "no service definition for $ROLE on $SYS; skipped"
  fi
fi

say "installed: $BIN_DIR/shadowvpn-$ROLE ($VERSION, $TARGET)"
echo
echo "next steps:"
if [ "$IS_ROOT" = 1 ]; then
  echo "  1. edit $ETC_DIR/$ROLE.json (set the password on BOTH ends)"
  echo "  2. run:  sudo $BIN_DIR/shadowvpn-$ROLE -c $ETC_DIR/$ROLE.json"
else
  echo "  1. create a $ROLE.json config (set the password on BOTH ends)"
  echo "  2. run:  sudo $BIN_DIR/shadowvpn-$ROLE -c $ROLE.json"
fi
[ -n "${SERVICE_HINT:-}" ] && echo "  3. or as a service:  $SERVICE_HINT"
echo
echo "docs: https://madeye.github.io/shadowvpn/"
