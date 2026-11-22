#!/usr/bin/env python3
"""Knock watcher and install helpers for shadownft.

Knock ports are never bound. nftables logs packets to those ports and drops
packets to any other unexpected port into a blacklist. This process records
the whitelist and blacklist, and queries ip-api only when IP_API=yes.
"""

import base64
import ipaddress
import json
import logging
import os
import random
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

LOG = logging.getLogger("shadownft")

DEFAULTS = {
    "SS_METHOD": "2022-blake3-aes-128-gcm",
    "SS_PASSWORD": "",
    "SS_PORT": "",
    "PORT_B": "",
    "PORT_A": "",
    "INSTALL_PROXY": "yes",
    "KNOCK_PORTS": "",
    "KNOCK_COUNT": "1",
    "SS_BIND": "0.0.0.0",
    "SS_MODE": "tcp_and_udp",
    "SS_VERSION": "",
    "SSH_PORT": "",
    "ALLOW_PORTS": "",
    "INTRANET_V4": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8",
    "INTRANET_V6": "::1,fc00::/7,fe80::/10",
    "ALLOW_REGIONS": "CQ,重庆",
    "ALLOW_MOBILE": "true",
    "WHITELIST_MAX": "100",
    "WHITELIST_SCOPE": "dport_b",
    "IP_API": "no",
    "BLACKLIST_TIMEOUT": "86400",
    "BLACKLIST_MAX": "10000",
    "IP_API_URL": (
        "http://ip-api.com/json/{ip}"
        "?fields=status,message,query,region,regionName,city,mobile&lang={lang}"
    ),
    "IP_API_LANG": "zh-CN",
    "IP_API_RATE": "40",
    "KNOCK_COOLDOWN": "600",
    "NEGATIVE_TTL": "600",
    "PUBLIC_IP": "",
    "REPLACE_FIREWALL": "",
    "PORT_MIN": "10000",
    "PORT_MAX": "20000",
    "PORT_A_OFFSET_MAX": "1000",
    "QUEUE_MAX": "50",
}

KEY_LEN = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
    "2022-blake3-chacha8-poly1305": 32,
}

MODES = {"tcp_only", "udp_only", "tcp_and_udp"}
ENV_PATH = "/etc/shadownft/config.env"
ORDER_PATH = "/var/lib/shadownft/whitelist.order"
BLACKLIST_PATH = "/var/lib/shadownft/blacklist.txt"
BAN_PREFIX = "shadownft-ban "
NFT_FAMILY = "inet"
NFT_TABLE = "shadownft"
LOG_PREFIX = "shadownft "

SRC_RE = re.compile(r"\bSRC=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b")
DPT_RE = re.compile(r"\bDPT=([0-9]+)\b")
NAME_SUFFIXES = ("省", "市")
CGNAT = ipaddress.IPv4Network("100.64.0.0/10")
DOCS = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)


class CommandError(Exception):
    pass


def split_csv(value):
    return [part.strip() for part in str(value).split(",") if part.strip()]


def env_bool(value, name="布尔值"):
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    raise CommandError("%s 只能是 yes 或 no" % name)


def parse_env_text(text):
    found = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in DEFAULTS:
            found[key] = value.strip().strip("'").strip('"')
    return found


def require_int(value, name, low, high):
    text = str(value).strip()
    if not text.isdigit():
        raise CommandError("%s 不是整数" % name)
    number = int(text)
    if number < low or number > high:
        raise CommandError("%s 需要在 %s 到 %s 之间" % (name, low, high))
    return number


def resolve_settings(explicit, file_text):
    merged = dict(DEFAULTS)
    merged.update(parse_env_text(file_text or ""))
    for key, value in explicit.items():
        if key in DEFAULTS and str(value).strip() != "":
            merged[key] = str(value).strip()
    for key in (
        "WHITELIST_MAX",
        "IP_API_RATE",
        "KNOCK_COOLDOWN",
        "NEGATIVE_TTL",
        "PORT_MIN",
        "PORT_MAX",
        "PORT_A_OFFSET_MAX",
        "QUEUE_MAX",
        "KNOCK_COUNT",
        "BLACKLIST_TIMEOUT",
        "BLACKLIST_MAX",
    ):
        require_int(merged[key], key, 1, 1000000)
    port_min = require_int(merged["PORT_MIN"], "PORT_MIN", 1, 65535)
    port_max = require_int(merged["PORT_MAX"], "PORT_MAX", 1, 65535)
    if port_min > port_max:
        raise CommandError("PORT_MIN 不能大于 PORT_MAX")
    require_int(merged["PORT_A_OFFSET_MAX"], "PORT_A_OFFSET_MAX", 1, 65535)
    require_int(merged["WHITELIST_MAX"], "WHITELIST_MAX", 1, 65535)
    require_int(merged["QUEUE_MAX"], "QUEUE_MAX", 1, 10000)
    require_int(merged["KNOCK_COUNT"], "KNOCK_COUNT", 1, 100)
    require_int(merged["BLACKLIST_TIMEOUT"], "BLACKLIST_TIMEOUT", 1, 31536000)
    require_int(merged["BLACKLIST_MAX"], "BLACKLIST_MAX", 1, 65535)
    merged["IP_API"] = "yes" if env_bool(merged["IP_API"], "IP_API") else "no"
    merged["INSTALL_PROXY"] = "yes" if env_bool(merged["INSTALL_PROXY"], "INSTALL_PROXY") else "no"
    port_b = merged.get("PORT_B", "").strip()
    ss_port = merged.get("SS_PORT", "").strip()
    if port_b and ss_port and port_b != ss_port:
        raise CommandError("PORT_B 和 SS_PORT 不一致")
    if port_b:
        merged["SS_PORT"] = port_b
        merged["PORT_B"] = port_b
    elif ss_port:
        merged["PORT_B"] = ss_port
    if merged["KNOCK_PORTS"] and merged["KNOCK_PORTS"] != "generate":
        parse_port_list(merged["KNOCK_PORTS"], "KNOCK_PORTS")
    for key in ("SSH_PORT", "SS_PORT", "PORT_A", "PORT_B"):
        if merged[key] != "":
            require_int(merged[key], key, 1, 65535)
    if merged["WHITELIST_SCOPE"] != "dport_b":
        raise CommandError("WHITELIST_SCOPE 只支持 dport_b")
    if merged["SS_MODE"] not in MODES:
        raise CommandError("SS_MODE 只能是 tcp_only、udp_only 或 tcp_and_udp")
    env_bool(merged["ALLOW_MOBILE"])
    if "{ip}" not in merged["IP_API_URL"]:
        raise CommandError("IP_API_URL 需要包含 {ip}")
    if not merged["IP_API_URL"].startswith(("http://", "https://")):
        raise CommandError("IP_API_URL 需要以 http:// 或 https:// 开头")
    try:
        ipaddress.IPv4Address(merged["SS_BIND"])
    except ipaddress.AddressValueError:
        raise CommandError("SS_BIND 需要是 IPv4 地址")
    if merged["PUBLIC_IP"]:
        try:
            ipaddress.IPv4Address(merged["PUBLIC_IP"])
        except ipaddress.AddressValueError:
            raise CommandError("PUBLIC_IP 需要是 IPv4 地址")
    version = merged["SS_VERSION"]
    if version and version != "latest" and not re.match(r"^v?\d+\.\d+\.\d+$", version):
        raise CommandError("SS_VERSION 需要是 latest 或 v1.2.3 这种版本号")
    return merged


def parse_port_list(value, name):
    ports = []
    seen = set()
    for part in split_csv(value):
        port = require_int(part, name, 1, 65535)
        if port in seen:
            continue
        seen.add(port)
        ports.append(port)
    return ports


def parse_allow_ports(value, ssh_port):
    raw = str(value or "").strip()
    if raw:
        parts = split_csv(raw)
    else:
        parts = [str(ssh_port), "80", "443"]
    ports = []
    seen = set()
    for part in parts:
        port = require_int(part, "ALLOW_PORTS", 1, 65535)
        if port in seen:
            continue
        seen.add(port)
        ports.append(port)
    if not ports:
        raise CommandError("ALLOW_PORTS 是空的")
    return ports


def choose_service_ports(ss_port, knock_spec, legacy_port, knock_count, ssh_port, allow_ports, port_min, port_max, rng):
    port_min = int(port_min)
    port_max = int(port_max)
    open_ports = set(parse_allow_ports(allow_ports, ssh_port))
    if ss_port in ("", None):
        pool = [port for port in range(port_min, port_max + 1) if port not in open_ports]
        if not pool:
            raise CommandError("随机范围内没有可用的 Shadowsocks 端口")
        ss_port = rng.choice(pool)
    else:
        ss_port = require_int(ss_port, "SS_PORT", 1, 65535)
        if ss_port in open_ports:
            raise CommandError("Shadowsocks 端口与额外放行端口相同")
    spec = str(knock_spec or "").strip()
    legacy = str(legacy_port or "").strip()
    if spec == "generate":
        spec = ""
        legacy = ""
    if spec:
        knocks = parse_port_list(spec, "KNOCK_PORTS")
    elif legacy:
        knocks = [require_int(legacy, "PORT_A", 1, 65535)]
    else:
        count = require_int(knock_count, "KNOCK_COUNT", 1, 100)
        pool = [port for port in range(port_min, port_max + 1) if port != ss_port and port not in open_ports]
        if len(pool) < count:
            raise CommandError("随机范围内没有足够的敲门端口")
        knocks = rng.sample(pool, count)
    for port in knocks:
        if port == ss_port or port in open_ports:
            raise CommandError("敲门端口 %s 与放行端口或 Shadowsocks 端口相同" % port)
    return ss_port, knocks


def check_password(method, password):
    if not password:
        raise CommandError("密码是空的")
    if method not in KEY_LEN:
        return
    try:
        raw = base64.b64decode(password, validate=True)
    except Exception:
        raise CommandError("%s 的密码需要是 Base64 密钥" % method)
    need = KEY_LEN[method]
    if len(raw) != need:
        raise CommandError("%s 的密钥必须是 %s 字节，当前是 %s 字节" % (method, need, len(raw)))


def normalize_name(value):
    text = str(value or "").strip()
    for suffix in NAME_SUFFIXES:
        if text.endswith(suffix) and len(text) > len(suffix):
            text = text[: -len(suffix)]
    return text.casefold()


def is_allowed(payload, regions, allow_mobile):
    if allow_mobile and payload.get("mobile") is True:
        return True
    tokens = set()
    for region in regions:
        tokens.add(region.casefold())
        tokens.add(normalize_name(region))
    for key in ("region", "regionName", "city"):
        raw = str(payload.get(key) or "")
        if raw.casefold() in tokens or normalize_name(raw) in tokens:
            return True
    return False


def is_public_ipv4(value):
    try:
        addr = ipaddress.IPv4Address(str(value))
    except ipaddress.AddressValueError:
        return False
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or addr in CGNAT
    ):
        return False
    for network in DOCS:
        if addr in network:
            return False
    return True


def bump_order(order, ip, limit):
    if ip in order:
        order.remove(ip)
        order.append(ip)
        return None
    evicted = order.pop(0) if len(order) >= limit else None
    order.append(ip)
    return evicted


def parse_v4_list(value):
    nets = []
    for part in split_csv(value):
        try:
            nets.append(str(ipaddress.IPv4Network(part, strict=True)))
        except ValueError:
            raise CommandError("INTRANET_V4 里有无法识别的网段: %s" % part)
    if not nets:
        raise CommandError("INTRANET_V4 是空的")
    return nets


def parse_v6_list(value):
    nets = []
    for part in split_csv(value):
        try:
            nets.append(str(ipaddress.IPv6Network(part, strict=False)))
        except ValueError:
            raise CommandError("INTRANET_V6 里有无法识别的网段: %s" % part)
    if not nets:
        raise CommandError("INTRANET_V6 是空的")
    return nets


def knock_ports_from_settings(settings):
    spec = str(settings.get("KNOCK_PORTS") or "").strip()
    if spec and spec != "generate":
        return parse_port_list(spec, "KNOCK_PORTS")
    if str(settings.get("PORT_A") or "").strip():
        return [require_int(settings["PORT_A"], "PORT_A", 1, 65535)]
    raise CommandError("没有敲门端口")


def nft_port_set(ports):
    return "{ %s }" % ", ".join(str(port) for port in ports)


def rule_statements(settings):
    if settings["WHITELIST_SCOPE"] != "dport_b":
        raise CommandError("WHITELIST_SCOPE 只支持 dport_b")
    ssh_port = require_int(settings["SSH_PORT"] or "22", "SSH_PORT", 1, 65535)
    ss_port = require_int(settings["SS_PORT"], "SS_PORT", 1, 65535)
    knock_ports = knock_ports_from_settings(settings)
    open_ports = parse_allow_ports(settings.get("ALLOW_PORTS", ""), ssh_port)
    for port in list(open_ports) + knock_ports:
        if port == ss_port:
            raise CommandError("端口 %s 与 Shadowsocks 端口相同" % port)
    for port in knock_ports:
        if port in open_ports:
            raise CommandError("敲门端口 %s 与默认放行端口相同" % port)
    safe = []
    for port in list(open_ports) + knock_ports + [ss_port]:
        if port not in safe:
            safe.append(port)
    safe_set = nft_port_set(safe)
    knock_set = nft_port_set(knock_ports)
    ban_timeout = require_int(settings.get("BLACKLIST_TIMEOUT", "86400"), "BLACKLIST_TIMEOUT", 1, 31536000)
    statements = [
        "ct state established,related accept",
        'iif "lo" accept',
    ]
    for net in parse_v4_list(settings["INTRANET_V4"]):
        statements.append("ip saddr %s accept" % net)
    for net in parse_v6_list(settings["INTRANET_V6"]):
        statements.append("ip6 saddr %s accept" % net)
    for port in open_ports:
        statements.append("tcp dport %s accept" % port)
        statements.append("udp dport %s accept" % port)
    for proto, match in (("tcp", "tcp dport"), ("udp", "udp dport")):
        guard = "ip protocol %s %s != %s" % (proto, match, safe_set)
        statements.append("%s add @blacklist { ip saddr timeout %ss }" % (guard, ban_timeout))
        statements.append("%s delete @whitelist { ip saddr }" % guard)
        statements.append(
            '%s limit rate 20/second burst 40 packets log prefix "%s"' % (guard, BAN_PREFIX)
        )
        statements.append("%s drop" % guard)
    statements.append("ip saddr @blacklist drop")
    for proto, match in (("tcp", "tcp dport"), ("udp", "udp dport")):
        statements.append(
            'ip protocol %s %s %s limit rate 10/second burst 20 packets log prefix "%s" drop'
            % (proto, match, knock_set, LOG_PREFIX)
        )
    statements.append("ip saddr @whitelist tcp dport %s accept" % ss_port)
    statements.append("ip saddr @whitelist udp dport %s accept" % ss_port)
    return statements


def render_nft(settings):
    size = require_int(settings["WHITELIST_MAX"], "WHITELIST_MAX", 1, 65535)
    ban_size = require_int(settings.get("BLACKLIST_MAX", "10000"), "BLACKLIST_MAX", 1, 65535)
    ban_timeout = require_int(settings.get("BLACKLIST_TIMEOUT", "86400"), "BLACKLIST_TIMEOUT", 1, 31536000)
    lines = [
        "table inet %s {" % NFT_TABLE,
        "    set whitelist {",
        "        type ipv4_addr",
        "        size %s" % size,
        "        flags dynamic",
        "    }",
        "",
        "    set blacklist {",
        "        type ipv4_addr",
        "        size %s" % ban_size,
        "        flags dynamic,timeout",
        "        timeout %ss" % ban_timeout,
        "    }",
        "",
        "    chain input {",
        "        type filter hook input priority 0; policy drop;",
        "",
    ]
    for statement in rule_statements(settings):
        lines.append("        %s" % statement)
    lines.extend(["    }", "}", ""])
    return "\n".join(lines)


def set_flags(set_obj):
    flags = set_obj.get("flags") or []
    if isinstance(flags, str):
        return {flags}
    return set(flags)


def set_elements(set_obj):
    found = []
    for item in set_obj.get("elem") or []:
        if isinstance(item, str):
            found.append((item, None))
            continue
        if isinstance(item, dict) and isinstance(item.get("elem"), dict):
            item = item["elem"]
        if not isinstance(item, dict):
            continue
        value = item.get("val") or item.get("elem")
        if value:
            found.append((str(value), item.get("expires")))
    return found


def needs_set_rebuild(set_obj, timeout):
    if set_obj is None:
        return True
    flags = set_flags(set_obj)
    if "dynamic" not in flags:
        return True
    if timeout and "timeout" not in flags:
        return True
    return False


def build_apply_script(settings, whitelist_set, blacklist_set):
    lines = ["flush chain inet %s input" % NFT_TABLE]
    white_size = require_int(settings["WHITELIST_MAX"], "WHITELIST_MAX", 1, 65535)
    black_size = require_int(settings.get("BLACKLIST_MAX", "10000"), "BLACKLIST_MAX", 1, 65535)
    ban_timeout = require_int(settings.get("BLACKLIST_TIMEOUT", "86400"), "BLACKLIST_TIMEOUT", 1, 31536000)
    if needs_set_rebuild(whitelist_set, False):
        if whitelist_set is not None:
            lines.append("delete set inet %s whitelist" % NFT_TABLE)
        lines.append(
            "add set inet %s whitelist { type ipv4_addr; size %s; flags dynamic; }" % (NFT_TABLE, white_size)
        )
        elements = [ip for ip, _expires in set_elements(whitelist_set or {}) if is_public_ipv4(ip)]
        if elements:
            lines.append("add element inet %s whitelist { %s }" % (NFT_TABLE, ", ".join(elements)))
    if needs_set_rebuild(blacklist_set, True):
        if blacklist_set is not None:
            lines.append("delete set inet %s blacklist" % NFT_TABLE)
        lines.append(
            "add set inet %s blacklist { type ipv4_addr; size %s; flags dynamic,timeout; timeout %ss; }"
            % (NFT_TABLE, black_size, ban_timeout)
        )
        for ip, expires in set_elements(blacklist_set or {}):
            if not is_public_ipv4(ip):
                continue
            seconds = ban_timeout if not expires else max(1, int(expires))
            lines.append("add element inet %s blacklist { %s timeout %ss }" % (NFT_TABLE, ip, seconds))
    for statement in rule_statements(settings):
        lines.append("add rule inet %s input %s" % (NFT_TABLE, statement))
    lines.append("")
    return "\n".join(lines)


def nft_json_set(name):
    result = subprocess.run(
        [nft_bin(), "-j", "list", "set", NFT_FAMILY, NFT_TABLE, name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=10,
    )
    if result.returncode != 0:
        return None
    try:
        data = json.loads(result.stdout or "{}")
    except ValueError:
        return None
    for item in data.get("nftables", []):
        if "set" in item:
            return item["set"]
    return None


def apply_rules(settings):
    script = build_apply_script(settings, nft_json_set("whitelist"), nft_json_set("blacklist"))
    fd, path = tempfile.mkstemp(prefix="shadownft-", suffix=".nft")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(script)
        nft_run(["-f", path])
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def render_refresh(settings):
    lines = ["flush chain inet %s input" % NFT_TABLE]
    for statement in rule_statements(settings):
        lines.append("add rule inet %s input %s" % (NFT_TABLE, statement))
    lines.append("")
    return "\n".join(lines)


def foreign_drop_chains(data):
    found = []
    for item in data.get("nftables", []):
        chain = item.get("chain") or {}
        if chain.get("hook") != "input" or chain.get("policy") != "drop":
            continue
        if chain.get("family") == NFT_FAMILY and chain.get("table") == NFT_TABLE:
            continue
        found.append(
            "%s %s %s" % (chain.get("family", "?"), chain.get("table", "?"), chain.get("name", "?"))
        )
    return found


def ss_uri(method, password, host, port):
    token = base64.urlsafe_b64encode(("%s:%s" % (method, password)).encode()).decode().rstrip("=")
    return "ss://%s@%s:%s" % (token, host, port)


def proxy_enabled(settings):
    return env_bool(settings.get("INSTALL_PROXY", "yes"), "INSTALL_PROXY")


def client_text(settings):
    knocks = knock_ports_from_settings(settings)
    lines = [
        "server: %s" % settings["PUBLIC_IP"],
        "port_b: %s" % settings["SS_PORT"],
        "knock_ports: %s" % ",".join(str(port) for port in knocks),
        "port_a: %s" % knocks[0],
    ]
    if proxy_enabled(settings):
        lines.extend(
            [
                "method: %s" % settings["SS_METHOD"],
                "password: %s" % settings["SS_PASSWORD"],
                ss_uri(settings["SS_METHOD"], settings["SS_PASSWORD"], settings["PUBLIC_IP"], settings["SS_PORT"]),
                "clients: sing-box, Clash Meta, Shadowrocket, v2rayN, shadowsocks-rust, or any client that supports this method",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def ss_config(settings):
    return json.dumps(
        {
            "server": settings["SS_BIND"],
            "server_port": require_int(settings["SS_PORT"], "SS_PORT", 1, 65535),
            "method": settings["SS_METHOD"],
            "password": settings["SS_PASSWORD"],
            "mode": settings["SS_MODE"],
        },
        indent=4,
    ) + "\n"


def format_env_value(value):
    text = str(value)
    if any(char in text for char in "\n\r\x00$`"):
        raise CommandError("配置值不能包含换行、$ 或反引号")
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return '"%s"' % escaped


def shell_assignments(settings):
    lines = []
    for key in DEFAULTS:
        lines.append("%s=%s" % (key, format_env_value(settings[key])))
    lines.append("")
    return "\n".join(lines)


def atomic_write(path, text, mode):
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(path, mode)


def build_api_url(template, ip, lang):
    return template.replace("{ip}", urllib.parse.quote(ip)).replace("{lang}", urllib.parse.quote(lang))


def explicit_from_environ():
    found = {}
    for key in DEFAULTS:
        if key in os.environ and os.environ[key].strip() != "":
            found[key] = os.environ[key].strip()
    return found


def settings_from_environ():
    file_text = ""
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r", encoding="utf-8") as handle:
            file_text = handle.read()
    return resolve_settings(explicit_from_environ(), file_text)


def load_order(path, limit):
    if not os.path.exists(path):
        return []
    order = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            ip = raw.strip()
            if not is_public_ipv4(ip):
                continue
            if ip in order:
                order.remove(ip)
            order.append(ip)
    if len(order) > limit:
        order = order[-limit:]
    return order


def parse_blacklist_text(text, now):
    found = {}
    for raw in str(text).splitlines():
        parts = raw.split()
        if len(parts) != 2 or not is_public_ipv4(parts[0]):
            continue
        try:
            expiry = float(parts[1])
        except ValueError:
            continue
        if expiry > now:
            found[parts[0]] = expiry
    return found


def load_blacklist(path, now):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        return parse_blacklist_text(handle.read(), now)


def blacklist_text(entries):
    lines = ["%s %d" % (ip, int(expiry)) for ip, expiry in sorted(entries.items(), key=lambda item: item[1])]
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


class Watcher(object):
    def __init__(self, settings):
        self.knock_ports = set(knock_ports_from_settings(settings))
        self.use_api = env_bool(settings.get("IP_API", "no"), "IP_API")
        self.regions = split_csv(settings["ALLOW_REGIONS"])
        self.allow_mobile = env_bool(settings["ALLOW_MOBILE"], "ALLOW_MOBILE")
        self.limit = require_int(settings["WHITELIST_MAX"], "WHITELIST_MAX", 1, 65535)
        self.cooldown = require_int(settings["KNOCK_COOLDOWN"], "KNOCK_COOLDOWN", 1, 1000000)
        self.negative_ttl = require_int(settings["NEGATIVE_TTL"], "NEGATIVE_TTL", 1, 1000000)
        self.rate = require_int(settings["IP_API_RATE"], "IP_API_RATE", 1, 1000000)
        self.queue_max = require_int(settings["QUEUE_MAX"], "QUEUE_MAX", 1, 10000)
        self.blacklist_timeout = require_int(settings.get("BLACKLIST_TIMEOUT", "86400"), "BLACKLIST_TIMEOUT", 1, 31536000)
        self.api_url = settings["IP_API_URL"]
        self.api_lang = settings["IP_API_LANG"]
        self.order = load_order(ORDER_PATH, self.limit)
        self.blacklist = load_blacklist(BLACKLIST_PATH, time.time())
        self.lock = threading.Lock()
        self.skip_until = {}
        self.inflight = set()
        self.queue = []
        self.queue_cond = threading.Condition(self.lock)
        self.stop = False
        self.tokens = float(self.rate)
        self.updated = time.monotonic()

    def save(self):
        os.makedirs(os.path.dirname(ORDER_PATH), 0o700, exist_ok=True)
        atomic_write(ORDER_PATH, "".join("%s\n" % ip for ip in self.order), 0o600)

    def save_blacklist(self):
        os.makedirs(os.path.dirname(BLACKLIST_PATH), 0o700, exist_ok=True)
        now = time.time()
        self.blacklist = {ip: expiry for ip, expiry in self.blacklist.items() if expiry > now}
        atomic_write(BLACKLIST_PATH, blacklist_text(self.blacklist), 0o600)

    def blacklisted(self, ip):
        expiry = self.blacklist.get(ip, 0)
        if expiry <= time.time():
            self.blacklist.pop(ip, None)
            return False
        return True

    def restore_set(self):
        for ip in list(self.order):
            if self.blacklisted(ip):
                self.order.remove(ip)
                continue
            try:
                nft_add(ip)
            except Exception as exc:
                LOG.error("恢复白名单 %s 失败: %s", ip, exc)
        self.save()

    def restore_blacklist(self):
        now = time.time()
        for ip, expiry in list(self.blacklist.items()):
            remaining = int(expiry - now)
            if remaining <= 0:
                continue
            try:
                nft_add_blacklist(ip, remaining)
            except Exception as exc:
                LOG.error("恢复黑名单 %s 失败: %s", ip, exc)

    def remember_skip(self, ip, seconds):
        with self.lock:
            self.skip_until[ip] = time.time() + seconds
            if len(self.skip_until) > 10000:
                now = time.time()
                self.skip_until = {key: until for key, until in self.skip_until.items() if until > now}

    def handle_ban(self, line):
        src = SRC_RE.search(line)
        if not src:
            return
        ip = src.group(1)
        if not is_public_ipv4(ip):
            return
        with self.lock:
            self.blacklist[ip] = time.time() + self.blacklist_timeout
            if ip in self.order:
                self.order.remove(ip)
            self.save()
            self.save_blacklist()
        try:
            nft_delete(ip)
        except Exception as exc:
            LOG.error("移出白名单 %s 失败: %s", ip, exc)
        LOG.info("拉黑 %s", ip)

    def handle_line(self, line):
        if BAN_PREFIX in line:
            self.handle_ban(line)
            return
        if LOG_PREFIX not in line:
            return
        src = SRC_RE.search(line)
        dpt = DPT_RE.search(line)
        if not src or not dpt or int(dpt.group(1)) not in self.knock_ports:
            return
        ip = src.group(1)
        if not is_public_ipv4(ip):
            return
        if self.blacklisted(ip):
            LOG.info("黑名单中，忽略敲门: %s", ip)
            return
        if not self.use_api:
            self.admit(ip)
            LOG.info("加白 %s", ip)
            return
        with self.queue_cond:
            if ip in self.order:
                bump_order(self.order, ip, self.limit)
                self.save()
                LOG.info("已在白名单，移到最新: %s", ip)
                return
            now = time.time()
            if self.skip_until.get(ip, 0) > now or ip in self.inflight:
                return
            if len(self.queue) >= self.queue_max:
                LOG.info("查询队列已满，忽略 %s", ip)
                return
            self.inflight.add(ip)
            self.queue.append(ip)
            self.queue_cond.notify()

    def acquire_token(self):
        while not self.stop:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.updated
                self.updated = now
                self.tokens = min(float(self.rate), self.tokens + elapsed * (self.rate / 60.0))
                if self.tokens >= 1:
                    self.tokens -= 1
                    return True
                wait = (1 - self.tokens) * (60.0 / self.rate)
            time.sleep(min(wait, 1))
        return False

    def query(self, ip):
        url = build_api_url(self.api_url, ip, self.api_lang)
        request = urllib.request.Request(url, headers={"User-Agent": "shadownft"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                code = response.getcode()
                body = response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, None
        except Exception as exc:
            LOG.info("查询 %s 失败: %s", ip, exc)
            return 0, None
        if code != 200:
            return code, None
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            LOG.info("查询 %s 的响应不是 JSON", ip)
            return 0, None
        return 200, payload

    def admit(self, ip):
        if self.blacklisted(ip):
            LOG.info("黑名单中，不加白: %s", ip)
            return
        with self.lock:
            if ip in self.order:
                bump_order(self.order, ip, self.limit)
                self.save()
                return
            evicted = self.order[0] if len(self.order) >= self.limit else None
        if evicted:
            nft_delete(evicted)
        try:
            nft_add(ip)
        except Exception:
            if evicted:
                try:
                    nft_add(evicted)
                except Exception as exc:
                    LOG.error("加白失败后无法放回 %s: %s", evicted, exc)
            raise
        extras = []
        with self.lock:
            if evicted and evicted in self.order:
                self.order.remove(evicted)
            bump_order(self.order, ip, self.limit)
            while len(self.order) > self.limit:
                extras.append(self.order.pop(0))
            self.save()
        for extra in extras:
            try:
                nft_delete(extra)
            except Exception as exc:
                LOG.error("删除多余白名单 %s 失败: %s", extra, exc)

    def process(self, ip, pause_until):
        if self.blacklisted(ip):
            LOG.info("黑名单中，不加白: %s", ip)
            return
        now = time.time()
        if pause_until[0] > now:
            time.sleep(min(pause_until[0] - now, 60))
        if not self.acquire_token():
            return
        code, payload = self.query(ip)
        if code == 429:
            pause_until[0] = time.time() + 60
            self.remember_skip(ip, 60)
            LOG.info("ip-api 返回 429，暂停查询 60 秒")
            return
        if code != 200 or not payload or payload.get("status") != "success" or payload.get("query") != ip:
            self.remember_skip(ip, self.negative_ttl)
            LOG.info("没有得到可用的归属地，不加白: %s", ip)
            return
        if not is_allowed(payload, self.regions, self.allow_mobile):
            self.remember_skip(ip, max(self.cooldown, self.negative_ttl))
            LOG.info(
                "不匹配，不加白: %s region=%s city=%s mobile=%s",
                ip,
                payload.get("region"),
                payload.get("city"),
                payload.get("mobile"),
            )
            return
        self.admit(ip)
        LOG.info(
            "加白 %s region=%s city=%s mobile=%s",
            ip,
            payload.get("region"),
            payload.get("city"),
            payload.get("mobile"),
        )

    def worker(self):
        pause_until = [0.0]
        while not self.stop:
            with self.queue_cond:
                while not self.queue and not self.stop:
                    self.queue_cond.wait(timeout=1)
                if self.stop:
                    return
                ip = self.queue.pop(0)
            try:
                self.process(ip, pause_until)
            except Exception as exc:
                LOG.error("处理 %s 失败: %s", ip, exc)
                self.remember_skip(ip, self.negative_ttl)
            finally:
                with self.lock:
                    self.inflight.discard(ip)

    def run(self):
        os.makedirs(os.path.dirname(ORDER_PATH), 0o700, exist_ok=True)
        self.restore_blacklist()
        self.restore_set()
        LOG.info("监听敲门端口 %s，白名单上限 %s，ip-api=%s", ",".join(str(port) for port in sorted(self.knock_ports)), self.limit, "yes" if self.use_api else "no")
        thread = threading.Thread(target=self.worker, name="shadownft-query")
        thread.start()
        try:
            for line in iter_kmsg():
                if not thread.is_alive():
                    raise CommandError("查询线程退出了")
                self.handle_line(line)
        finally:
            self.stop = True
            with self.queue_cond:
                self.queue_cond.notify_all()
            thread.join(timeout=2)


def nft_bin():
    for path in ("/usr/sbin/nft", "/sbin/nft"):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return "nft"


def nft_run(args):
    result = subprocess.run(
        [nft_bin()] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=10,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise CommandError(detail or "nft 命令失败")
    return result


def nft_add(ip):
    if not is_public_ipv4(ip):
        raise CommandError("拒绝把非公网地址写入白名单")
    result = subprocess.run(
        [nft_bin(), "add", "element", NFT_FAMILY, NFT_TABLE, "whitelist", "{ %s }" % ip],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=10,
    )
    if result.returncode == 0:
        return
    detail = ((result.stderr or "") + (result.stdout or "")).lower()
    if "exist" in detail:
        return
    raise CommandError((result.stderr or result.stdout or "nft add 失败").strip())


def nft_add_blacklist(ip, seconds):
    if not is_public_ipv4(ip):
        raise CommandError("拒绝把非公网地址写入黑名单")
    seconds = max(1, int(seconds))
    result = subprocess.run(
        [nft_bin(), "add", "element", NFT_FAMILY, NFT_TABLE, "blacklist", "{ %s timeout %ss }" % (ip, seconds)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=10,
    )
    if result.returncode == 0:
        return
    detail = ((result.stderr or "") + (result.stdout or "")).lower()
    if "exist" in detail:
        return
    raise CommandError((result.stderr or result.stdout or "nft add blacklist 失败").strip())


def nft_delete(ip):
    result = subprocess.run(
        [nft_bin(), "delete", "element", NFT_FAMILY, NFT_TABLE, "whitelist", "{ %s }" % ip],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=10,
    )
    if result.returncode != 0:
        detail = ((result.stderr or "") + (result.stdout or "")).lower()
        if "no such" in detail or "not found" in detail or "does not exist" in detail:
            return
        raise CommandError((result.stderr or result.stdout or "nft delete 失败").strip())


def iter_kmsg():
    fd = os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK)
    try:
        os.lseek(fd, 0, os.SEEK_END)
    except OSError as exc:
        LOG.warning("无法把内核日志定位到末尾: %s", exc)
    import fcntl

    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
    while True:
        try:
            data = os.read(fd, 8192)
        except InterruptedError:
            continue
        except OSError as exc:
            if exc.errno == 11:
                time.sleep(0.2)
                continue
            raise
        if not data:
            time.sleep(0.2)
            continue
        yield data.decode("utf-8", "replace")


def read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read().strip()
    if not text:
        return {"nftables": []}
    try:
        return json.loads(text)
    except ValueError:
        raise CommandError("无法解析 nft 规则 JSON")


def cmd_resolve():
    settings = settings_from_environ()
    json.dump(settings, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")


def cmd_write_shell(path):
    atomic_write(path, shell_assignments(settings_from_environ()), 0o600)


def require_ready(settings):
    for key in ("SS_PORT", "SSH_PORT", "PUBLIC_IP"):
        if not str(settings.get(key, "")).strip():
            raise CommandError("%s 还是空的" % key)
    knock_ports_from_settings(settings)
    if proxy_enabled(settings):
        if not str(settings.get("SS_PASSWORD", "")).strip():
            raise CommandError("SS_PASSWORD 还是空的")
        check_password(settings["SS_METHOD"], settings["SS_PASSWORD"])


def fail(exc):
    LOG.error("%s", exc)
    return 1


def run_self_test():
    regions = ["CQ", "重庆"]
    assert is_allowed(
        {"region": "CQ", "regionName": "重庆市", "city": "重庆", "mobile": False},
        regions,
        True,
    )
    assert is_allowed({"region": "CQ", "regionName": "", "city": "", "mobile": False}, regions, False)
    assert is_allowed(
        {"region": "BJ", "regionName": "北京", "city": "北京市", "mobile": True},
        regions,
        True,
    )
    assert not is_allowed(
        {"region": "BJ", "regionName": "北京", "city": "北京市", "mobile": False},
        regions,
        True,
    )
    assert not is_public_ipv4("10.1.1.1")
    assert not is_public_ipv4("100.64.1.1")
    assert not is_public_ipv4("127.0.0.1")
    assert is_public_ipv4("8.8.8.8")
    assert not is_public_ipv4("2001:db8::1")

    order = []
    assert bump_order(order, "1.1.1.1", 3) is None
    bump_order(order, "1.1.1.2", 3)
    bump_order(order, "1.1.1.3", 3)
    assert bump_order(order, "1.1.1.4", 3) == "1.1.1.1"
    assert order == ["1.1.1.2", "1.1.1.3", "1.1.1.4"]
    assert bump_order(order, "1.1.1.2", 3) is None
    assert order == ["1.1.1.3", "1.1.1.4", "1.1.1.2"]
    big = []
    for index in range(101):
        bump_order(big, "1.2.0.%s" % index, 100)
    assert len(big) == 100
    assert big[0] == "1.2.0.1"
    assert big[-1] == "1.2.0.100"

    merged = resolve_settings(
        {"ALLOW_REGIONS": "SH,上海", "SS_PORT": "18000"},
        "SS_PORT=100\nALLOW_REGIONS=SC,四川\nSS_METHOD=2022-blake3-aes-256-gcm\n",
    )
    assert merged["SS_PORT"] == "18000"
    assert merged["ALLOW_REGIONS"] == "SH,上海"
    assert merged["SS_METHOD"] == "2022-blake3-aes-256-gcm"
    fresh = resolve_settings({}, "")
    assert fresh["SS_METHOD"] == "2022-blake3-aes-128-gcm"
    assert fresh["ALLOW_REGIONS"] == "CQ,重庆"
    assert fresh["WHITELIST_MAX"] == "100"
    assert fresh["PORT_A_OFFSET_MAX"] == "1000"
    assert fresh["SS_PORT"] == ""
    try:
        resolve_settings({"WHITELIST_SCOPE": "all"}, "")
        raise AssertionError("scope should fail")
    except CommandError:
        pass

    assert fresh["INSTALL_PROXY"] == "yes"
    assert fresh["IP_API"] == "no"
    synced = resolve_settings({"PORT_B": "13511", "PORT_A": "14142"}, "")
    assert synced["SS_PORT"] == "13511" and synced["PORT_B"] == "13511"
    try:
        resolve_settings({"PORT_B": "13511", "SS_PORT": "13512"}, "")
        raise AssertionError("PORT_B and SS_PORT should match")
    except CommandError:
        pass
    no_proxy = dict(synced)
    no_proxy.update({"INSTALL_PROXY": "no", "SSH_PORT": "22", "PUBLIC_IP": "203.0.113.10", "SS_PASSWORD": ""})
    no_proxy_text = client_text(no_proxy)
    assert "ss://" not in no_proxy_text
    assert "port_b: 13511" in no_proxy_text
    assert "port_a: 14142" in no_proxy_text
    with_proxy = dict(no_proxy)
    with_proxy.update({"INSTALL_PROXY": "yes", "SS_PASSWORD": "x", "SS_METHOD": "2022-blake3-aes-128-gcm"})
    with_proxy_text = client_text(with_proxy)
    assert "ss://" in with_proxy_text
    assert "sing-box" in with_proxy_text
    assert fresh["KNOCK_COUNT"] == "1"
    assert fresh["BLACKLIST_TIMEOUT"] == "86400"
    port_b, knocks = choose_service_ports("", "", "", "2", 22, "22,80,443", 20000, 20010, random.Random(1))
    assert 20000 <= port_b <= 20010 and port_b not in (22, 80, 443)
    assert len(knocks) == 2 and port_b not in knocks
    assert all(20000 <= port <= 20010 and port not in (22, 80, 443) for port in knocks)
    assert choose_service_ports(15000, "", "16000", "3", 22, "", 10000, 20000, random.Random(0)) == (15000, [16000])
    try:
        choose_service_ports(15000, "15000", "", "1", 22, "", 10000, 20000, random.Random(0))
        raise AssertionError("knock port should not reuse shadowsocks")
    except CommandError:
        pass
    try:
        choose_service_ports(80, "", "", "1", 22, "", 10000, 20000, random.Random(0))
        raise AssertionError("port B should not reuse an open port")
    except CommandError:
        pass

    good = base64.b64encode(b"\x01" * 16).decode()
    check_password("2022-blake3-aes-128-gcm", good)
    try:
        check_password("2022-blake3-aes-128-gcm", base64.b64encode(b"\x01" * 32).decode())
        raise AssertionError("32-byte key should fail for aes-128")
    except CommandError:
        pass

    sample = dict(fresh)
    sample.update({"SSH_PORT": "22", "SS_PORT": "15000", "PORT_A": "16000"})
    rendered = render_nft(sample)
    assert "policy drop;" in rendered
    assert "tcp dport 22 accept" in rendered
    assert "tcp dport 80 accept" in rendered
    assert "tcp dport 443 accept" in rendered
    assert "ip saddr @whitelist tcp dport 15000 accept" in rendered
    assert "ip saddr @whitelist udp dport 15000 accept" in rendered
    assert 'tcp dport { 16000 } limit rate 10/second burst 20 packets log prefix "shadownft "' in rendered
    assert "tcp dport != { 22, 80, 443, 16000, 15000 }" in rendered
    assert "add @blacklist { ip saddr timeout 86400s }" in rendered
    assert "delete @whitelist { ip saddr }" in rendered
    assert 'log prefix "shadownft-ban "' in rendered
    assert "flags dynamic" in rendered
    assert "size 100" in rendered
    assert "ip saddr 10.0.0.0/8 accept" in rendered
    assert "ip6 saddr fe80::/10 accept" in rendered
    assert "dport 16000 accept" not in rendered
    custom = dict(sample)
    custom["ALLOW_PORTS"] = "8080,8080,8443"
    custom_rendered = render_nft(custom)
    assert "tcp dport 8080 accept" in custom_rendered
    assert "tcp dport 8443 accept" in custom_rendered
    assert "tcp dport 80 accept" not in custom_rendered
    custom["ALLOW_PORTS"] = "15000"
    try:
        render_nft(custom)
        raise AssertionError("allow port should not overlap port B")
    except CommandError:
        pass
    kept = parse_blacklist_text("1.2.3.4 200\n10.0.0.1 999\nbad line\n8.8.8.8 50\n", 100)
    assert kept == {"1.2.3.4": 200.0}
    rebuilt = build_apply_script(sample, {"flags": ["interval"], "elem": ["8.8.8.8"]}, None)
    assert "delete set inet shadownft whitelist" in rebuilt
    assert "add element inet shadownft whitelist { 8.8.8.8 }" in rebuilt
    assert "add set inet shadownft blacklist" in rebuilt
    steady = build_apply_script(
        sample,
        {"flags": ["dynamic"], "elem": ["1.2.3.4"]},
        {"flags": ["dynamic", "timeout"], "elem": []},
    )
    assert "delete set" not in steady
    refresh = render_refresh(sample)
    assert refresh.startswith("flush chain inet shadownft input\n")
    assert "add rule inet shadownft input tcp dport 443 accept" in refresh

    drops = foreign_drop_chains(
        {
            "nftables": [
                {"chain": {"family": "inet", "table": "shadownft", "hook": "input", "policy": "drop"}},
                {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "hook": "input", "policy": "drop"}},
                {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "hook": "forward", "policy": "drop"}},
            ]
        }
    )
    assert drops == ["ip filter INPUT"]

    url = build_api_url(fresh["IP_API_URL"], "1.2.3.4", "zh-CN")
    assert url.startswith("http://ip-api.com/json/1.2.3.4?")
    assert "lang=zh-CN" in url
    assert "city" in url
    parsed = parse_env_text(shell_assignments(fresh))
    assert parsed["SS_METHOD"] == "2022-blake3-aes-128-gcm"
    assert parsed["ALLOW_REGIONS"] == "CQ,重庆"
    assert parsed["WHITELIST_MAX"] == "100"
    assert parsed["PORT_A_OFFSET_MAX"] == "1000"
    assert "{ip}" in parsed["IP_API_URL"]
    assert "&lang=" in parsed["IP_API_URL"]
    print("self-test ok")


def main(argv):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    command = argv[1] if len(argv) > 1 else "watch"
    try:
        if command == "--self-test":
            run_self_test()
            return 0
        if command == "--resolve-settings":
            cmd_resolve()
            return 0
        if command == "--write-shell":
            cmd_write_shell(argv[2])
            return 0
        if command == "--choose-ports":
            settings = settings_from_environ()
            ssh_port = settings["SSH_PORT"] or "22"
            port_b, knocks = choose_service_ports(
                settings["SS_PORT"],
                settings.get("KNOCK_PORTS", ""),
                settings.get("PORT_A", ""),
                settings.get("KNOCK_COUNT", "1"),
                ssh_port,
                settings.get("ALLOW_PORTS", ""),
                settings["PORT_MIN"],
                settings["PORT_MAX"],
                random.SystemRandom(),
            )
            sys.stdout.write("%s\n%s\n" % (port_b, ",".join(str(port) for port in knocks)))
            return 0
        if command == "--apply-rules":
            apply_rules(settings_from_environ())
            return 0
        if command == "--check-password":
            settings = settings_from_environ()
            check_password(settings["SS_METHOD"], settings["SS_PASSWORD"])
            return 0
        if command == "--normalize-allow-ports":
            settings = settings_from_environ()
            ssh_port = settings["SSH_PORT"] or "22"
            ports = parse_allow_ports(settings.get("ALLOW_PORTS", ""), ssh_port)
            sys.stdout.write(",".join(str(port) for port in ports) + "\n")
            return 0
        if command == "--render-nft":
            settings = settings_from_environ()
            sys.stdout.write(render_nft(settings))
            return 0
        if command == "--render-rules":
            settings = settings_from_environ()
            sys.stdout.write(render_refresh(settings))
            return 0
        if command == "--check-firewall":
            found = foreign_drop_chains(read_json(argv[2]))
            if found:
                sys.stderr.write("发现其他 input drop 链: %s\n" % ", ".join(found))
                return 1
            return 0
        if command == "--write-ss-config":
            settings = settings_from_environ()
            require_ready(settings)
            atomic_write(argv[2], ss_config(settings), 0o640)
            return 0
        if command == "--write-env":
            settings = settings_from_environ()
            require_ready(settings)
            atomic_write(argv[2], shell_assignments(settings), 0o600)
            return 0
        if command == "--write-client":
            settings = settings_from_environ()
            require_ready(settings)
            text = client_text(settings)
            atomic_write(argv[2], text, 0o600)
            sys.stdout.write(text)
            return 0
        if command == "watch":
            Watcher(settings_from_environ()).run()
            return 0
        sys.stderr.write("未知命令: %s\n" % command)
        return 2
    except CommandError as exc:
        return fail(exc)
    except IndexError:
        sys.stderr.write("参数不够\n")
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
