"""Сборка плана: какой туннель и какие адреса пускать мимо него."""

import ipaddress
import os
import re
from dataclasses import dataclass, field

from staytun import clients as clients_mod
from staytun import config as config_mod
from staytun import geoip
from staytun.netutil import (
    LAN4,
    LAN6,
    LINK6,
    Net,
    collapse,
    connections,
    default_iface,
    iface_addrs,
    iface_exists,
    is_tunnel,
    parse_net,
    to_nets,
)
from staytun.ui import Fail


@dataclass
class ClientReport:
    title: str
    running: bool
    servers: list[str]
    direct: list[str]
    notes: list[str]


@dataclass
class Plan:
    iface: str
    allow: list[Net]  # VPN-серверы и пользовательские исключения
    direct: list[Net]  # direct-маршруты клиентов и geoip без портов
    ported: list[tuple[Net, str]]  # direct с портами: (сеть, "53,443")
    lan: list[Net]
    link6: list[Net]
    direct_desc: list[str] = field(default_factory=list)
    reports: list[ClientReport] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def pick_iface(cfg: config_mod.Config, override: str | None = None) -> str:
    wanted = override or cfg.get("interface")
    current = default_iface()
    if wanted and wanted != "auto":
        if not iface_exists(wanted):
            raise Fail(f"интерфейса {wanted} нет — VPN не подключён? Список: staytun interfaces")
        return wanted
    if not current:
        raise Fail("нет маршрута по умолчанию — нет сети")
    if not is_tunnel(current):
        raise Fail(
            f"интернет идёт через {current}, а не через VPN-туннель. Подключи VPN "
            "или укажи туннель явно: staytun set interface <имя>"
        )
    return current


def _resolve_all(entries: list[str], warnings: list[str], public_only: bool) -> list[Net]:
    nets: list[Net] = []
    for entry in dict.fromkeys(entries):
        try:
            for net in to_nets(entry):
                if public_only and not net.network_address.is_global:
                    continue
                nets.append(net)
        except ValueError as exc:
            warnings.append(f"пропущено: {exc}")
    return nets


def build(cfg: config_mod.Config, iface: str | None = None, strict: bool = True) -> Plan:
    """strict=False — для doctor: проблемы уходят в warnings, а не в исключение."""
    warnings: list[str] = []
    try:
        iface = pick_iface(cfg, iface)
    except Fail as exc:
        if strict:
            raise
        warnings.append(str(exc))
        iface = ""
    selected = cfg.items("clients")
    if selected in ([], ["none"]):
        chosen: list[clients_mod.Client] = []
    elif selected == ["auto"]:
        chosen = [c for c in clients_mod.available() if c.installed()]
    else:
        try:
            chosen = clients_mod.by_ids(selected)
        except KeyError as exc:
            known = ", ".join(c.id for c in clients_mod.available())
            raise Fail(f"неизвестные клиенты: {exc}. Доступны: {known}") from None

    servers: list[str] = []
    live: list[str] = []
    codes_by_file: dict[str, set] = {}
    targets: list[tuple[str, str | None]] = []
    any_geoip: str | None = cfg.get("geoip_file") or None
    reports: list[ClientReport] = []

    for client in chosen:
        found = client.collect()
        running = client.running()
        servers += found.servers
        live += found.live
        any_geoip = any_geoip or found.geoip_file
        direct_desc = []
        if cfg.flag("direct") and running:
            if found.direct.codes:
                if found.geoip_file:
                    codes_by_file.setdefault(found.geoip_file, set()).update(found.direct.codes)
                    direct_desc += [f"geoip:{c}" for c in sorted(found.direct.codes)]
                else:
                    warnings.append(f"{client.title}: direct по geoip без geoip.dat — пропущено")
            targets += found.direct.targets
            direct_desc += [f"{t}:{p}" if p else t for t, p in found.direct.targets]
        reports.append(
            ClientReport(
                client.title, running, list(dict.fromkeys(found.servers + found.live)), direct_desc, found.notes
            )
        )

    extra_codes = {c.upper() for c in cfg.items("geoip")}
    if extra_codes:
        if any_geoip:
            codes_by_file.setdefault(any_geoip, set()).update(extra_codes)
        else:
            warnings.append("geoip задан, но geoip.dat не найден — укажи staytun set geoip_file <путь>")

    if live:
        config_mod.remember_live(live)
    known_live = config_mod.read_lines(config_mod.LIVE_FILE)

    allow = _resolve_all(servers + known_live, warnings, public_only=True)
    allow += _resolve_all(cfg.allow, warnings, public_only=False)

    direct: list[Net] = []
    ported: list[tuple[Net, str]] = []
    desc = []
    for target, port in dict.fromkeys(targets):
        for net in _resolve_all([target], warnings, public_only=False):
            if port:
                ported.append((net, port))
            else:
                direct.append(net)
            desc.append(f"{net}:{port}" if port else str(net))
    for path, codes in codes_by_file.items():
        nets = geoip.load_cached(path, codes, config_mod.CACHE_DIR)
        direct += nets
        desc.insert(0, f"geoip:{','.join(sorted(codes))} ({len(nets)} подсетей)")

    if not allow:
        message = (
            "не нашёл ни одного VPN-сервера — без него туннель не переподключится. "
            "Добавь адрес сервера: staytun allow add <IP или домен>"
        )
        if strict:
            raise Fail(message)
        warnings.append(message)

    return Plan(
        iface=iface,
        allow=collapse(allow),
        direct=collapse(direct),
        ported=ported,
        lan=[ipaddress.ip_network(n) for n in (LAN4 + LAN6 if cfg.flag("lan") else ["255.255.255.255/32"])],
        link6=[ipaddress.ip_network(n) for n in LINK6],
        direct_desc=desc,
        reports=reports,
        warnings=warnings,
    )


VPN_PROCESS = re.compile(
    r"(?i)xray|v2ray|sing-?box|hysteria|tuic|wireguard|amnezia|openvpn|happ|v2box|v2raytun|streisand|hiddify"
    r"|nekoray|nekobox|clash|mihomo|outline|shadowsocks|PacketTunnel|network-?extension|\.appex/"
)


@dataclass
class Bypass:
    """Соединения VPN-процесса мимо туннеля: covered — разрешены планом, uncovered — будут отрезаны."""

    path: str
    covered: list[str] = field(default_factory=list)
    uncovered: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        match = re.search(r"([^/]+)\.app/", self.path)
        return match.group(1) if match else os.path.basename(self.path.split(" ")[0]) or self.path


def bypass_report(plan: Plan) -> list[Bypass]:
    """Кто из VPN-процессов ходит в сеть мимо туннеля и что из этого план пропустит.

    Если у процесса ни одно такое соединение не разрешено, это почти наверняка его
    сервер, которого нет в исключениях: после включения туннель умрёт вместе с сетью.
    """
    tunnel_addrs = iface_addrs(plan.iface)
    allowed = plan.allow + plan.lan + [n for n, _ in plan.ported]
    report: dict[str, Bypass] = {}
    for conn in connections():
        if conn.local in tunnel_addrs or not VPN_PROCESS.search(conn.path):
            continue
        addr = ipaddress.ip_address(conn.remote)
        entry = report.setdefault(conn.path, Bypass(conn.path))
        ok = any(addr in n for n in allowed if n.version == addr.version) or any(
            addr in n for n in plan.direct if n.version == addr.version
        )
        bucket = entry.covered if ok else entry.uncovered
        if conn.remote not in bucket:
            bucket.append(conn.remote)
    return list(report.values())


def parse_entry(value: str) -> bool:
    """Проверка строки для allow add: IP/CIDR или похоже на домен."""
    return parse_net(value) is not None or ("." in value and " " not in value)
