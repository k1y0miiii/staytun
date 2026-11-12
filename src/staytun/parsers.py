"""Разбор конфигов xray, sing-box и WireGuard: адреса серверов и direct-правила."""

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any

PROXY_URI = re.compile(
    r"\b(vless|vmess|trojan|ss|ssr|hy2|hysteria2?|tuic|socks5?|wireguard|wg|anytls|naive\+https|juicity)://([^\s\"'<>]+)",
    re.IGNORECASE,
)
XRAY_SKIP = {"freedom", "blackhole", "dns", "loopback"}
SINGBOX_SKIP = {"direct", "block", "dns", "selector", "urltest"}


@dataclass
class Direct:
    """Что клиент сам пускает мимо туннеля: страны из geoip и конкретные адреса/порты."""

    codes: set[str] = field(default_factory=set)
    targets: list[tuple[str, str | None]] = field(default_factory=list)  # (адрес, порты | None)

    def merge(self, other: Direct) -> None:
        self.codes |= other.codes
        self.targets += [t for t in other.targets if t not in self.targets]


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def ports(value: Any) -> str | None:
    """xray '53,443' / '1000-2000' / 53 и sing-box [53] / '1000:2000' → '53,443' / '1000-2000'."""
    items = []
    for item in _as_list(value):
        items += [p.strip().replace(":", "-") for p in str(item).split(",") if p.strip()]
    return ",".join(items) or None


def uri_hosts(text: str) -> list[str]:
    hosts = []
    for scheme, rest in PROXY_URI.findall(text):
        if scheme.lower() == "vmess" and "@" not in rest:
            try:
                blob = rest.split("#", 1)[0]
                data = json.loads(base64.b64decode(blob + "=" * (-len(blob) % 4)))
                hosts.append(str(data.get("add", "")))
            except ValueError, TypeError:
                pass
            continue
        authority = rest.split("@", 1)[-1]
        if authority.startswith("["):
            hosts.append(authority[1:].split("]", 1)[0])
        else:
            hosts.append(re.split(r"[:/?#]", authority, maxsplit=1)[0])
    return [h for h in hosts if h]


def xray_servers(conf: dict) -> list[str]:
    hosts = []
    for out in _as_list(conf.get("outbounds")):
        if not isinstance(out, dict) or str(out.get("protocol", "")).lower() in XRAY_SKIP:
            continue
        settings = out.get("settings") or {}
        for key in ("vnext", "servers", "peers"):
            for item in _as_list(settings.get(key)):
                if isinstance(item, dict):
                    host = item.get("address") or item.get("endpoint")
                    if host:
                        hosts.append(str(host))
        if settings.get("address"):
            hosts.append(str(settings["address"]))
    return hosts


def xray_direct(conf: dict) -> Direct:
    direct = Direct()
    direct_tags = {"direct"} | {
        o.get("tag")
        for o in _as_list(conf.get("outbounds"))
        if isinstance(o, dict) and str(o.get("protocol", "")).lower() == "freedom"
    }
    for rule in _as_list((conf.get("routing") or {}).get("rules")):
        if not isinstance(rule, dict) or rule.get("outboundTag") not in direct_tags:
            continue
        for ip in _as_list(rule.get("ip")):
            ip = str(ip)
            if ip.lower().startswith("geoip:"):
                code = ip[6:].upper()
                if code != "PRIVATE" and not code.startswith("!"):
                    direct.codes.add(code)
            elif not ip.startswith(("ext:", "!")):
                direct.targets.append((ip, ports(rule.get("port"))))
    return direct


def singbox_servers(conf: dict) -> list[str]:
    hosts = []
    for out in _as_list(conf.get("outbounds")) + _as_list(conf.get("endpoints")):
        if not isinstance(out, dict) or str(out.get("type", "")).lower() in SINGBOX_SKIP:
            continue
        if out.get("server"):
            hosts.append(str(out["server"]))
        for peer in _as_list(out.get("peers")):
            if isinstance(peer, dict) and peer.get("address"):
                hosts.append(str(peer["address"]))
    return hosts


def singbox_direct(conf: dict) -> Direct:
    direct = Direct()
    direct_tags = {"direct"} | {
        o.get("tag") for o in _as_list(conf.get("outbounds")) if isinstance(o, dict) and o.get("type") == "direct"
    }
    for rule in _as_list((conf.get("route") or {}).get("rules")):
        if not isinstance(rule, dict) or rule.get("outbound") not in direct_tags:
            continue
        port = ports(_as_list(rule.get("port")) + _as_list(rule.get("port_range")))
        for cidr in _as_list(rule.get("ip_cidr")):
            direct.targets.append((str(cidr), port))
        for code in _as_list(rule.get("geoip")):
            if str(code).lower() != "private":
                direct.codes.add(str(code).upper())
    return direct


def wg_endpoints(text: str) -> list[str]:
    return re.findall(r"^\s*Endpoint\s*=\s*(\S+)", text, re.MULTILINE | re.IGNORECASE)


def scan(obj: Any, depth: int = 0) -> list[str]:
    """Рекурсивно ищет серверы в чём угодно: xray/sing-box JSON, строки с URI, вложенный JSON."""
    if depth > 12:
        return []
    hosts: list[str] = []
    if isinstance(obj, dict):
        if isinstance(obj.get("outbounds"), list) or isinstance(obj.get("endpoints"), list):
            hosts += xray_servers(obj) + singbox_servers(obj)
        for value in obj.values():
            hosts += scan(value, depth + 1)
    elif isinstance(obj, list):
        for value in obj:
            hosts += scan(value, depth + 1)
    elif isinstance(obj, (bytes, bytearray)):
        hosts += scan(bytes(obj).decode("utf-8", "ignore"), depth + 1)
    elif isinstance(obj, str):
        hosts += uri_hosts(obj)
        text = obj.strip()
        if text[:1] in "{[" and len(text) > 20:
            try:
                hosts += scan(json.loads(text), depth + 1)
            except ValueError:
                pass
    return list(dict.fromkeys(h.strip() for h in hosts if h and h.strip()))
