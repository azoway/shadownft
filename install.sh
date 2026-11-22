#!/bin/bash
# Install shadowsocks-rust behind an nftables knock whitelist.
# Run this on the Linux server, as root.

set -euo pipefail

CONFIG_DIR=/etc/shadownft
CONFIG_ENV=$CONFIG_DIR/config.env
CLIENT_TXT=$CONFIG_DIR/client.txt
NFT_FILE=$CONFIG_DIR/shadownft.nft
NFT_RULES=$CONFIG_DIR/shadownft.rules.nft
STATE_DIR=/var/lib/shadownft
BASE_URL=${BASE_URL:-https://raw.githubusercontent.com/azoway/shadownft/main}
CONFIRMED=$STATE_DIR/confirmed
SS_DIR=/etc/shadowsocks-rust
SS_CONFIG=$SS_DIR/config.json
LIB_DIR=/usr/local/lib/shadownft
PY_INSTALLED=$LIB_DIR/shadownft-watch.py
BIN=/usr/local/sbin/shadownft
SSSERVER=/usr/local/bin/ssserver
SSSERVICE=/usr/local/bin/ssservice

usage() {
  cat <<'EOF'
用法:
  curl -fsSL https://raw.githubusercontent.com/azoway/shadownft/main/install.sh | bash
  confirm=yes bash /usr/local/sbin/shadownft
  ALLOW_PORTS=22,80,443,8443 bash /usr/local/sbin/shadownft
  /usr/local/sbin/shadownft rollback
  /usr/local/sbin/shadownft uninstall

已写入 /etc/shadownft/config.env 的端口、密码和额外放行端口会保留。
这次命令里显式传入的同名变量覆盖它们。
confirm=yes 或运行时输入 y，才会关闭 ufw、firewalld 和系统 nftables 服务。
EOF
}

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "需要 root"
  fi
}

require_linux() {
  if [ "$(uname -s)" != "Linux" ]; then
    die "需要在 Linux 服务器上运行"
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    die "需要 systemd"
  fi
}

maybe_reexec() {
  if [ -f "$0" ]; then
    return 0
  fi
  require_root
  require_linux
  command -v curl >/dev/null 2>&1 || die "需要 curl"
  install -d -m 0755 /usr/local/sbin "$LIB_DIR"
  curl -fsSL --retry 3 --max-time 60 "$BASE_URL/install.sh" -o "$BIN"
  curl -fsSL --retry 3 --max-time 60 "$BASE_URL/shadownft-watch.py" -o "$PY_INSTALLED"
  chmod 755 "$BIN" "$PY_INSTALLED"
  exec "$BIN" "$@"
}

clean_requested() {
  if [ "${confirm:-}" = "yes" ] || [ "${CONFIRM:-}" = "yes" ] || [ "${REPLACE_FIREWALL:-}" = "1" ]; then
    return 0
  fi
  return 1
}

ask_clean() {
  if clean_requested; then
    return 0
  fi
  if [ -r /dev/tty ]; then
    printf '%s' "发现已有防火墙。输入 y 关闭 ufw、firewalld 和系统 nftables 服务，直接回车则保留: " >/dev/tty
    IFS= read -r answer </dev/tty || true
    if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
      return 0
    fi
  else
    printf '%s\n' "没有交互终端，也没有 confirm=yes，保留已有防火墙。" >&2
  fi
  return 1
}

script_path() {
  if readlink -f "$0" >/dev/null 2>&1; then
    readlink -f "$0"
  else
    die "需要 GNU readlink"
  fi
}

find_nft() {
  if [ -x /usr/sbin/nft ]; then
    printf '%s\n' /usr/sbin/nft
  elif [ -x /sbin/nft ]; then
    printf '%s\n' /sbin/nft
  elif command -v nft >/dev/null 2>&1; then
    command -v nft
  else
    die "没有找到 nft"
  fi
}

find_python() {
  if command -v python3 >/dev/null 2>&1; then
    command -v python3
  else
    die "没有找到 python3"
  fi
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y nftables python3 curl ca-certificates xz-utils
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y nftables python3 curl ca-certificates xz
  else
    die "需要 apt-get 或 dnf"
  fi
}

dump_ruleset() {
  local dest=$1
  if ! "$NFT" -j list ruleset >"$dest" 2>/dev/null; then
    printf '%s\n' '{"nftables":[]}' >"$dest"
  fi
}

firewall_conflict() {
  local json=$1
  local hit=0
  local state=""
  if command -v ufw >/dev/null 2>&1; then
    state=$(LC_ALL=C ufw status 2>/dev/null | awk '/^Status:/ {print $2; exit}' || true)
    if [ "$state" = "active" ]; then
      hit=1
    fi
  fi
  if systemctl is-active --quiet firewalld; then
    hit=1
  fi
  if systemctl is-enabled --quiet nftables; then
    hit=1
  fi
  if [ -s "$json" ]; then
    if ! "$PYTHON" "$PY" --check-firewall "$json"; then
      hit=1
    fi
  fi
  [ "$hit" -eq 1 ]
}

disable_other_firewalls() {
  if command -v ufw >/dev/null 2>&1; then
    ufw --force disable >/dev/null 2>&1 || true
  fi
  systemctl disable --now ufw >/dev/null 2>&1 || true
  systemctl disable --now firewalld >/dev/null 2>&1 || true
  systemctl disable --now nftables >/dev/null 2>&1 || true
}

detect_ssh_port() {
  local sshd_bin=""
  if [ -n "${SSH_PORT:-}" ]; then
    return 0
  fi
  if command -v sshd >/dev/null 2>&1; then
    sshd_bin=$(command -v sshd)
  elif [ -x /usr/sbin/sshd ]; then
    sshd_bin=/usr/sbin/sshd
  fi
  if [ -n "$sshd_bin" ]; then
    SSH_PORT=$(LC_ALL=C "$sshd_bin" -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)
  fi
  if [ -z "${SSH_PORT:-}" ]; then
    SSH_PORT=22
  fi
}

detect_public_ip() {
  local body=""
  if [ -n "${PUBLIC_IP:-}" ]; then
    return 0
  fi
  body=$(curl -4 -fsS --max-time 8 "http://ip-api.com/json/?fields=query" || true)
  if [ -n "$body" ]; then
    PUBLIC_IP=$(printf '%s' "$body" | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin).get("query",""))')
  fi
  if [ -z "${PUBLIC_IP:-}" ]; then
    die "没有探测到公网 IPv4，请传入 PUBLIC_IP=x.x.x.x"
  fi
}

normalize_version() {
  local version=$1
  case "$version" in
    v*) printf '%s\n' "$version" ;;
    *) printf 'v%s\n' "$version" ;;
  esac
}

download_shadowsocks() {
  local version=$1
  local target=""
  local asset=""
  local url=""
  case "$(uname -m)" in
    x86_64) target=x86_64-unknown-linux-gnu ;;
    aarch64|arm64) target=aarch64-unknown-linux-gnu ;;
    *) die "只支持 x86_64 和 aarch64" ;;
  esac
  if [ -z "$version" ] || [ "$version" = "latest" ]; then
    version=$(curl -fsSL --retry 3 --max-time 30 \
      https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest \
      | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')
  fi
  version=$(normalize_version "$version")
  asset="shadowsocks-${version}.${target}.tar.xz"
  url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${version}/${asset}"
  curl -fsSL --retry 3 --retry-delay 2 --max-time 180 -o "$tmp/$asset" "$url"
  curl -fsSL --retry 3 --retry-delay 2 --max-time 60 -o "$tmp/${asset}.sha256" "${url}.sha256"
  (
    cd "$tmp"
    sha256sum -c "${asset}.sha256" >&2
  )
  tar -xJf "$tmp/$asset" -C /usr/local/bin ssserver ssservice
  chmod 755 "$SSSERVER" "$SSSERVICE"
  "$SSSERVER" --version >/dev/null
  printf '%s\n' "$version"
}

ensure_user() {
  local nologin=/usr/sbin/nologin
  if [ ! -x "$nologin" ]; then
    nologin=/sbin/nologin
  fi
  if ! getent group shadowsocks >/dev/null 2>&1; then
    groupadd --system shadowsocks
  fi
  if ! id -u shadowsocks >/dev/null 2>&1; then
    useradd --system --gid shadowsocks --no-create-home --shell "$nologin" shadowsocks
  elif ! id -nG shadowsocks | tr ' ' '\n' | grep -qx shadowsocks; then
    usermod -aG shadowsocks shadowsocks
  fi
}

cmd_load_nft() {
  local nft_bin size
  nft_bin=$(find_nft)
  if [ ! -f "$NFT_FILE" ]; then
    die "没有 $NFT_FILE"
  fi
  if ! "$nft_bin" list table inet shadownft >/dev/null 2>&1; then
    "$nft_bin" -f "$NFT_FILE"
    return 0
  fi
  if ! "$nft_bin" list set inet shadownft whitelist >/dev/null 2>&1; then
    size=$(awk '/^[[:space:]]*size / {print $2; exit}' "$NFT_FILE")
    if [ -z "$size" ]; then
      size=100
    fi
    "$nft_bin" add set inet shadownft whitelist "{ type ipv4_addr; size ${size}; }"
  fi
  "$nft_bin" add chain inet shadownft input '{ type filter hook input priority 0; policy drop; }' >/dev/null 2>&1 || true
  if [ ! -f "$NFT_RULES" ]; then
    die "没有 $NFT_RULES"
  fi
  "$nft_bin" -f "$NFT_RULES"
}

cmd_confirm() {
  systemctl stop shadownft-rollback.timer shadownft-rollback.service >/dev/null 2>&1 || true
  printf '%s\n' "已取消遗留的自动回滚。重复安装默认保留已有规则。"
}

cmd_rollback() {
  systemctl disable --now shadownft >/dev/null 2>&1 || true
  systemctl disable --now shadowsocks-rust >/dev/null 2>&1 || true
  if [ -x /usr/sbin/nft ]; then
    /usr/sbin/nft delete table inet shadownft >/dev/null 2>&1 || true
  elif command -v nft >/dev/null 2>&1; then
    nft delete table inet shadownft >/dev/null 2>&1 || true
  fi
  rm -f "$CONFIRMED"
  printf '%s\n' "已停止 shadowsocks-rust 和 shadownft，并删除 inet shadownft。"
  printf '%s\n' "白名单文件仍留在 $STATE_DIR/whitelist.order。"
  printf '%s\n' "若安装时用过 REPLACE_FIREWALL=1，ufw 和 firewalld 不会自动重新打开。"
}

cmd_uninstall() {
  systemctl stop shadownft-rollback.timer shadownft-rollback.service >/dev/null 2>&1 || true
  systemctl disable --now shadownft >/dev/null 2>&1 || true
  systemctl disable --now shadowsocks-rust >/dev/null 2>&1 || true
  if [ -x /usr/sbin/nft ]; then
    /usr/sbin/nft delete table inet shadownft >/dev/null 2>&1 || true
  elif command -v nft >/dev/null 2>&1; then
    nft delete table inet shadownft >/dev/null 2>&1 || true
  fi
  rm -f /etc/systemd/system/shadownft.service /etc/systemd/system/shadowsocks-rust.service
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -rf "$CONFIG_DIR" "$SS_DIR" "$STATE_DIR" "$LIB_DIR"
  rm -f "$BIN" "$SSSERVER" "$SSSERVICE"
  if id -u shadowsocks >/dev/null 2>&1; then
    if ! userdel shadowsocks; then
      printf '%s\n' "用户 shadowsocks 还在，进程退出后再执行 userdel shadowsocks" >&2
    fi
  fi
  if getent group shadowsocks >/dev/null 2>&1; then
    if ! groupdel shadowsocks; then
      printf '%s\n' "用户组 shadowsocks 还在，稍后执行 groupdel shadowsocks" >&2
    fi
  fi
  printf '%s\n' "已卸载 shadownft 和 shadowsocks-rust 的服务、规则、配置与程序。"
  printf '%s\n' "nftables、python3、curl 仍留在系统里。ufw 和 firewalld 不会自动重新打开。"
}

cmd_install() {
  local SCRIPT_PATH PY PYTHON NFT ruleset version ports
  local pybin clean_now=0
  umask 077
  set -a
  systemctl stop shadownft-rollback.timer shadownft-rollback.service >/dev/null 2>&1 || true
  if clean_requested; then
    clean_now=1
  fi
  SCRIPT_PATH=$(script_path)
  PY=$(dirname "$SCRIPT_PATH")/shadownft-watch.py
  if [ ! -f "$PY" ]; then
    PY=$PY_INSTALLED
  fi

  install_packages
  PYTHON=$(find_python)
  NFT=$(find_nft)

  install -d -m 0755 "$LIB_DIR" /usr/local/sbin /usr/local/bin /etc/systemd/system
  install -d -m 0700 "$CONFIG_DIR" "$STATE_DIR"
  install -d "$SS_DIR"
  if [ -f "$PY" ] && [ "$PY" != "$PY_INSTALLED" ]; then
    install -m 0755 "$PY" "$PY_INSTALLED"
  elif [ ! -f "$PY_INSTALLED" ]; then
    curl -fsSL --retry 3 --max-time 60 "$BASE_URL/shadownft-watch.py" -o "$PY_INSTALLED"
    chmod 755 "$PY_INSTALLED"
  fi
  if [ -f "$SCRIPT_PATH" ] && [ "$SCRIPT_PATH" != "$BIN" ]; then
    install -m 0755 "$SCRIPT_PATH" "$BIN"
  fi
  PY=$PY_INSTALLED
  if [ ! -f "$PY" ]; then
    die "找不到 shadownft-watch.py"
  fi

  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  ruleset=$tmp/ruleset.json
  dump_ruleset "$ruleset"
  if firewall_conflict "$ruleset"; then
    if [ "$clean_now" -eq 1 ] || ask_clean; then
      clean_now=1
      printf '%s\n' "将在加载规则前停用现有防火墙。"
    else
      clean_now=0
      printf '%s\n' "保留已有防火墙，只更新 shadownft 自己的规则。"
    fi
  fi

  "$PYTHON" "$PY" --resolve-settings >"$tmp/resolved.json"
  "$PYTHON" - "$tmp/resolved.json" "$tmp/resolved.env" <<'PY'
import json, shlex, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    for key, value in data.items():
        handle.write("%s=%s\n" % (key, shlex.quote(str(value))))
PY
  # shellcheck disable=SC1090
  . "$tmp/resolved.env"

  detect_ssh_port
  if [ -z "${ALLOW_PORTS:-}" ]; then
    ALLOW_PORTS="${SSH_PORT},80,443"
  fi
  ALLOW_PORTS=$("$PYTHON" "$PY" --normalize-allow-ports | tr -d '[:space:]')
  ports=$("$PYTHON" "$PY" --choose-ports)
  SS_PORT=$(printf '%s\n' "$ports" | awk 'NR==1 {print; exit}')
  PORT_A=$(printf '%s\n' "$ports" | awk 'NR==2 {print; exit}')
  if [ -z "$SS_PORT" ] || [ -z "$PORT_A" ]; then
    die "没有得到端口 A 或端口 B"
  fi

  version=$(download_shadowsocks "${SS_VERSION:-}")
  SS_VERSION=$version
  if [ -z "${SS_PASSWORD:-}" ] || [ "$SS_PASSWORD" = "generate" ]; then
    SS_PASSWORD=$("$SSSERVICE" genkey -m "$SS_METHOD" | tr -d '[:space:]')
  fi
  "$PYTHON" "$PY" --check-password
  detect_public_ip

  if command -v timedatectl >/dev/null 2>&1; then
    if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)" != "yes" ]; then
      systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || true
      printf '%s\n' "时钟尚未显示已同步。2022 加密要求两端误差在 30 秒以内。"
    fi
  fi

  ensure_user
  chown root:shadowsocks "$SS_DIR"
  chmod 750 "$SS_DIR"
  "$PYTHON" "$PY" --write-env "$CONFIG_ENV"
  "$PYTHON" "$PY" --render-nft >"$NFT_FILE"
  "$PYTHON" "$PY" --render-rules >"$NFT_RULES"
  chmod 644 "$NFT_FILE" "$NFT_RULES"
  "$PYTHON" "$PY" --write-ss-config "$SS_CONFIG"
  chown root:shadowsocks "$SS_CONFIG"
  chmod 640 "$SS_CONFIG"
  if command -v su >/dev/null 2>&1; then
    if ! su -s /bin/sh shadowsocks -c "test -r '$SS_CONFIG'"; then
      die "shadowsocks 用户读不到 $SS_CONFIG"
    fi
  fi
  "$PYTHON" "$PY" --write-client "$CLIENT_TXT" >"$tmp/client.txt"
  chmod 600 "$CONFIG_ENV" "$CLIENT_TXT"

  pybin=$PYTHON
  if readlink -f "$PYTHON" >/dev/null 2>&1; then
    pybin=$(readlink -f "$PYTHON")
  fi
  cat > /etc/systemd/system/shadowsocks-rust.service <<'EOF'
[Unit]
Description=Shadowsocks-rust server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=shadowsocks
Group=shadowsocks
ExecStart=/usr/local/bin/ssserver -c /etc/shadowsocks-rust/config.json
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF
  cat > /etc/systemd/system/shadownft.service <<EOF
[Unit]
Description=shadownft knock watcher
After=network-online.target shadowsocks-rust.service
Wants=network-online.target shadowsocks-rust.service

[Service]
Type=simple
EnvironmentFile=$CONFIG_ENV
Environment=PYTHONUTF8=1
ExecStartPre=$BIN load-nft
ExecStart=$pybin $PY_INSTALLED
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 /etc/systemd/system/shadowsocks-rust.service /etc/systemd/system/shadownft.service

  systemctl daemon-reload
  systemctl enable shadowsocks-rust
  systemctl enable shadownft

  dump_ruleset "$ruleset"
  if [ "$clean_now" -eq 1 ] && firewall_conflict "$ruleset"; then
    disable_other_firewalls
    dump_ruleset "$ruleset"
    if ! "$PYTHON" "$PY" --check-firewall "$ruleset"; then
      printf '%s\n' "停掉 ufw / firewalld / nftables 之后，仍有其他 input drop 链。shadownft 仍会加载自己的规则。" >&2
    fi
  fi

  systemctl restart shadowsocks-rust
  systemctl restart shadownft
  if ! systemctl is-active --quiet shadowsocks-rust; then
    journalctl -u shadowsocks-rust -n 40 --no-pager || true
    die "shadowsocks-rust 没有运行"
  fi
  if ! systemctl is-active --quiet shadownft; then
    journalctl -u shadownft -n 40 --no-pager || true
    die "shadownft 没有运行"
  fi
  if command -v ss >/dev/null 2>&1; then
    if ! ss -lntu | grep -E ":${SS_PORT}([^0-9]|\$)" >/dev/null; then
      die "ssserver 没有监听 ${SS_PORT}"
    fi
  fi

  printf '\n'
  cat "$CLIENT_TXT"
  printf '%s\n' "额外放行端口: ${ALLOW_PORTS}"
  if [ "$clean_now" -eq 1 ]; then
    printf '%s\n' "已按确认关闭 ufw、firewalld 和系统 nftables 服务。"
  else
    printf '%s\n' "没有清理已有防火墙。下次要清理时执行: confirm=yes $BIN"
  fi
}

main() {
  local cmd=${1:-install}
  maybe_reexec "$@"
  case "$cmd" in
    -h|--help|help)
      usage
      exit 0
      ;;
  esac
  require_root
  require_linux
  case "$cmd" in
    install) cmd_install ;;
    confirm) cmd_confirm ;;
    rollback) cmd_rollback ;;
    uninstall) cmd_uninstall ;;
    load-nft) cmd_load_nft ;;
    *)
      usage
      exit 2
      ;;
  esac
}

main "$@"
