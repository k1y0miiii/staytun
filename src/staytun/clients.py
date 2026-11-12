"""Адаптеры VPN-клиентов: где лежат серверы и что клиент пускает мимо туннеля.

Серверы берём из конфигов всех установленных клиентов (это VPN-серверы — пускать
к ним напрямую безопасно, и так работает переключение серверов). Direct-правила —
только у запущенных клиентов. Живые соединения процесса читаем только там, где
процесс не ходит напрямую никуда, кроме своего сервера (WireGuard, Happ без direct).
"""

from __future__ import annotations

import glob
import json
import os
import plistlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from staytun import parsers
from staytun.netutil import IS_LINUX, IS_MAC, pids, process_remote_ips, run, sudo_cached
from staytun.parsers import Direct

HOME = os.path.expanduser("~")
GROUP = os.path.join(HOME, "Library", "Group Containers")


@dataclass
class Found:
    servers: list[str] = field(default_factory=list)
    live: list[str] = field(default_factory=list)  # серверы из живых соединений
    direct: Direct = field(default_factory=Direct)
    geoip_file: str | None = None
    notes: list[str] = field(default_factory=list)


def _first(patterns: Iterable[str]) -> str | None:
    for pattern in patterns:
        hits = sorted(glob.glob(os.path.expanduser(pattern)))
        if hits:
            return hits[0]
    return None


def _json(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


class Client:
    id = ""
    title = ""
    platforms = ("darwin", "linux")
    homes: tuple = ()  # где лежат данные клиента (glob)
    procs: tuple = ()  # шаблоны pgrep -f для «запущен»

    def home(self) -> str | None:
        return _first(self.homes)

    def installed(self) -> bool:
        return self.home() is not None

    def running(self) -> bool:
        return any(pids(p) for p in self.procs)

    def collect(self) -> Found:
        raise NotImplementedError


class XrayClient(Client):
    """Клиенты на xray-core: серверы — из всех конфигов, direct — из активного."""

    configs: tuple = ()  # относительно home: все профили/подписки (glob)
    active: tuple = ()  # относительно home: конфиг текущего подключения
    geoip: tuple = ("geoip.dat",)

    def collect(self) -> Found:
        home = self.home() or ""
        found = Found()
        for pattern in self.configs + self.active:
            for path in sorted(glob.glob(os.path.join(home, pattern))):
                found.servers += parsers.scan(self._read(path))
        if self.running():
            for pattern in self.active:
                for path in glob.glob(os.path.join(home, pattern)):
                    conf = self._read(path)
                    if isinstance(conf, dict):
                        found.direct.merge(parsers.xray_direct(conf))
                        found.direct.merge(parsers.singbox_direct(conf))
        found.geoip_file = _first(os.path.join(home, g) for g in self.geoip)
        found.servers = list(dict.fromkeys(found.servers))
        return found

    @staticmethod
    def _read(path: str):
        if path.endswith(".plist"):
            try:
                with open(path, "rb") as fh:
                    return plistlib.load(fh)
            except (OSError, plistlib.InvalidFileException, ValueError):
                return None
        return _json(path)


class V2Box(XrayClient):
    id, title, platforms = "v2box", "V2Box", ("darwin",)
    homes = (f"{GROUP}/group.hossin.asaadi.V2Box",)
    procs = ("V2Box.app/Contents/PlugIns/PacketTunnel", "hossin.asaadi.V2Box.PacketTunnel")
    active = ("config.json",)


class V2RayTun(XrayClient):
    id, title, platforms = "v2raytun", "v2RayTun", ("darwin",)
    homes = (f"{GROUP}/*.com.databridges.privacy.v2RayTun",)
    procs = ("v2RayTun.app/Contents/PlugIns", "com.databridges.privacy.v2RayTun.packet")
    configs = (
        "Library/Application Support/Xray/configs/*.json",
        "Library/Application Support/Xray/subscriptions/*.json",
    )
    active = ("Library/Application Support/Xray/current-config.json",)


class Streisand(XrayClient):
    id, title, platforms = "streisand", "Streisand", ("darwin",)
    homes = (f"{GROUP}/group.com.effect.streisand",)
    procs = ("Streisand.app/Contents/PlugIns", "com.effect.streisand.")
    configs = ("ProfileStore.plist",)
    geoip = ("geodat/geoip.dat", "geoip.dat")


class Hiddify(XrayClient):
    """sing-box внутри. Формат хранения меняется от версии к версии — адаптер экспериментальный."""

    id, title = "hiddify", "Hiddify"
    homes = ("~/Library/Application Support/app.hiddify.com", "~/.local/share/app.hiddify.com")
    procs = ("Hiddify", "hiddify")
    configs = ("*.json", "configs/*.json", "data/*.json")
    active = ("data/current-config.json", "current-config.json")
    geoip = ("geoip.dat", "data/geoip.dat")


class Happ(Client):
    """Конфиг сервера Happ зашифрован — сервер узнаём по живым соединениям его xray-ядра.

    Если в Happ включить direct-маршрутизацию, сюда попадут и прямые адреса —
    поэтому только когда маршрутизация Happ пустая (по умолчанию так и есть).
    """

    id, title = "happ", "Happ"
    homes = (
        "/Applications/Happ.app",
        "~/Library/Containers/su.ffg.happ.plus*",
        "~/Library/Preferences/Happ",
        "~/.config/Happ",
        "/opt/happ",
    )
    procs = ("Happ.app/Contents/MacOS", "su.ffg.happ", "happ/core/")
    # ядро и TUN (их запускает root-демон happd), App Store-версия — через PlugIns.
    # Сам GUI сюда не входит: он ходит за подписками и обновлениями.
    cores = (
        r"(?i)happ[^/]*\.app/Contents/(MacOS/(core|tun2?)/|MacOS/happd$|PlugIns/)"
        r"|su\.ffg\.happ|/happ[^/]*/(core|tun)/"
    )

    def collect(self) -> Found:
        found = Found()
        found.live = process_remote_ips(self.cores)
        if not found.live:
            hint = "сервер узнаем после подключения Happ: staytun sync"
            if not sudo_cached():
                hint += " (ядро Happ работает от root — без sudo его соединения не видны)"
            found.notes.append(hint)
        found.geoip_file = _first(["/Applications/Happ.app/Contents/Resources/geoip.dat"])
        return found


class WireGuard(Client):
    """WireGuard и AmneziaWG: процесс ходит только к endpoint'у, поэтому живые соединения безопасны."""

    id, title = "wireguard", "WireGuard / AmneziaWG"
    homes = (
        "/Applications/WireGuard.app",
        "/Applications/AmneziaWG.app",
        "/Applications/AmneziaVPN.app",
        "/etc/wireguard",
        "/etc/amnezia",
    )
    procs = (
        "com.wireguard.macos.network-extension",
        "WireGuardNetworkExtension",
        "org.amnezia.awg.network-extension",
        "AmneziaVPN",
    )

    def collect(self) -> Found:
        found = Found()
        if IS_LINUX:
            for tool in ("wg", "awg"):
                result = run([tool, "show", "all", "endpoints"], sudo=sudo_cached())
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] != "(none)":
                        found.live.append(parts[2])
            for path in glob.glob("/etc/wireguard/*.conf") + glob.glob("/etc/amnezia/amneziawg/*.conf"):
                try:
                    with open(path) as fh:
                        found.servers += parsers.wg_endpoints(fh.read())
                except OSError:
                    pass
        else:
            found.live = process_remote_ips("|".join(re.escape(p) for p in self.procs))
        if not found.live and not found.servers:
            found.notes.append("endpoint узнаем, когда туннель поднят: staytun sync")
        return found


ALL: list[Client] = [V2Box(), V2RayTun(), Streisand(), Hiddify(), Happ(), WireGuard()]


def available() -> list[Client]:
    platform = "darwin" if IS_MAC else "linux"
    return [c for c in ALL if platform in c.platforms]


def by_ids(ids: list[str]) -> list[Client]:
    known = {c.id: c for c in available()}
    unknown = [i for i in ids if i not in known]
    if unknown:
        raise KeyError(", ".join(unknown))
    return [known[i] for i in ids]
