from __future__ import annotations

import ipaddress
import os
import platform
import re
import shutil
import socket
import subprocess
from collections.abc import Iterable, Sequence
from typing import Union

Net = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

LAN4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"]
# link-local и multicast нужны всегда: без них ломается NDP и IPv6 в локалке
LINK6 = ["fe80::/10", "ff00::/8"]
LAN6 = ["fc00::/7"]

# Сеть шире этого префикса в исключения не пустим: так можно случайно открыть весь интернет
MIN_PREFIX = {4: 8, 6: 16}

TUNNEL_NAME = re.compile(r"^(utun|tun|tap|wg|awg|ipsec|ppp|tailscale|nekoray|sing|xray|hiddify|amn)[\w.-]*$")


def run(cmd: Sequence[str], sudo: bool = False, input: str | None = None) -> subprocess.CompletedProcess:
    argv = (["sudo"] if sudo else []) + list(cmd)
    try:
        return subprocess.run(argv, input=input, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(argv, 127, "", str(exc))


def sudo_cached() -> bool:
    return run(["sudo", "-n", "true"]).returncode == 0


def split_host(value: str) -> str:
    """'host:443', '[v6]:443', 'v6', 'host' → хост без порта."""
    value = value.strip()
    if value.startswith("["):
        return value[1:].split("]", 1)[0]
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    return value


def parse_net(value: str) -> Net | None:
    try:
        return ipaddress.ip_network(split_host(value) if "/" not in value else value.strip(), strict=False)
    except ValueError:
        return None


def resolve(host: str) -> list[Net]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return []
    return [ipaddress.ip_network(info[4][0]) for info in infos]


def to_nets(value: str) -> list[Net]:
    """IP, CIDR или хост → список сетей. ValueError, если сеть слишком широкая или хост не резолвится."""
    net = parse_net(value)
    if net is None:
        nets = resolve(split_host(value))
        if not nets:
            raise ValueError(f"не резолвится: {value}")
        return nets
    if net.prefixlen < MIN_PREFIX[net.version]:
        raise ValueError(f"слишком широкая сеть: {value}")
    return [net]


def is_public(value: str) -> bool:
    try:
        return ipaddress.ip_address(split_host(value)).is_global
    except ValueError:
        return False


def collapse(nets: Iterable[Net]) -> list[Net]:
    nets = list(nets)
    v4 = ipaddress.collapse_addresses(n for n in nets if n.version == 4)
    v6 = ipaddress.collapse_addresses(n for n in nets if n.version == 6)
    return list(v4) + list(v6)


def default_iface() -> str | None:
    """Интерфейс маршрута по умолчанию. Только чтение таблицы маршрутов, пакеты не уходят."""
    if IS_MAC:
        out = run(["route", "-n", "get", "default"]).stdout
        match = re.search(r"interface:\s*(\S+)", out)
    else:
        out = run(["ip", "-o", "route", "get", "1.1.1.1"]).stdout
        match = re.search(r"\bdev\s+(\S+)", out)
    return match.group(1) if match else None


def iface_exists(name: str) -> bool:
    if IS_LINUX:
        return os.path.exists(f"/sys/class/net/{name}")
    return run(["ifconfig", name]).returncode == 0


def is_tunnel(name: str) -> bool:
    if IS_LINUX:
        try:
            with open(f"/sys/class/net/{name}/type") as fh:
                if fh.read().strip() == "65534":  # ARPHRD_NONE: tun и wireguard
                    return True
        except OSError:
            pass
    return bool(TUNNEL_NAME.match(name))


def list_tunnels() -> list[str]:
    if IS_LINUX:
        names = sorted(os.listdir("/sys/class/net")) if os.path.isdir("/sys/class/net") else []
    else:
        names = run(["ifconfig", "-l"]).stdout.split()
    result = []
    for name in names:
        if not is_tunnel(name):
            continue
        if IS_MAC and "inet " not in run(["ifconfig", name]).stdout:
            continue  # системные utun без IPv4 — не VPN
        result.append(name)
    return result


def pids(pattern: str) -> list[str]:
    out = run(["pgrep", "-f", pattern]).stdout
    return [p for p in out.split() if p.isdigit() and int(p) != os.getpid()]


def process_remote_ips(pattern: str) -> list[str]:
    """Внешние IP, к которым сейчас подключены процессы по шаблону (lsof, без сетевых запросов)."""
    found = pids(pattern)
    if not found or not shutil.which("lsof"):
        return []
    cmd = ["lsof", "-nP", "-i", "-a", "-p", ",".join(found), "-Fn"]
    out = run(cmd).stdout
    if not out and sudo_cached():
        out = run(cmd, sudo=True).stdout
    seen: list[str] = []
    for line in out.splitlines():
        if line.startswith("n") and "->" in line:
            host = line.split("->", 1)[1].rsplit(":", 1)[0].strip("[]")
            if is_public(host) and host not in seen:
                seen.append(host)
    return seen
