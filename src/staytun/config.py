from __future__ import annotations

import configparser
import os
from dataclasses import dataclass

from staytun.netutil import IS_MAC

CONFIG_DIR = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "staytun")
CACHE_DIR = os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "staytun")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.ini")
ALLOW_FILE = os.path.join(CONFIG_DIR, "allow.txt")
LIVE_FILE = os.path.join(CACHE_DIR, "live-servers.txt")
STATE_FILE = "/var/run/staytun.state" if IS_MAC else "/run/staytun.state"

SETTINGS: dict[str, tuple] = {
    # ключ: (значение по умолчанию, подсказка)
    "interface": ("auto", "туннель: auto или имя (utun4, wg0, tun0)"),
    "clients": ("auto", "VPN-клиенты: auto, none или список через запятую (v2box,happ)"),
    "direct": ("yes", "пускать мимо туннеля то, что клиент сам маршрутизирует напрямую (geoip:ru и т.п.)"),
    "lan": ("yes", "доступ к локальной сети (роутер, принтер, NAS)"),
    "geoip": ("", "доп. страны мимо туннеля, через запятую (ru,by)"),
    "geoip_file": ("", "путь к geoip.dat, если ни один клиент его не дал"),
    "protect": ("claude cursor cursor-agent", "команды, которые staytun shell-init не пустит без защиты"),
}

ALLOW_HEADER = """\
# staytun: адреса, которым можно мимо VPN-туннеля.
# По одному на строку: IP, подсеть (CIDR) или домен. # — комментарий.
# Сюда стоит вписать ВСЕ серверы своего VPN, чтобы переключение между ними работало.
"""


@dataclass
class Config:
    values: dict[str, str]
    allow: list[str]

    def get(self, key: str) -> str:
        return self.values.get(key, SETTINGS[key][0]).strip()

    def flag(self, key: str) -> bool:
        return self.get(key).lower() in {"1", "yes", "true", "on", "да"}

    def items(self, key: str) -> list[str]:
        return [x for x in self.get(key).replace(",", " ").split() if x]


def _parser() -> configparser.ConfigParser:
    parser = configparser.ConfigParser(delimiters=("=",), interpolation=None)
    parser.read(CONFIG_FILE)
    if not parser.has_section("staytun"):
        parser.add_section("staytun")
    return parser


def read_lines(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        return [line.split("#", 1)[0].strip() for line in fh if line.split("#", 1)[0].strip()]


def load() -> Config:
    return Config(dict(_parser()["staytun"]), read_lines(ALLOW_FILE))


def set_value(key: str, value: str) -> None:
    if key not in SETTINGS:
        raise KeyError(key)
    parser = _parser()
    parser["staytun"][key] = value
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w") as fh:
        parser.write(fh)


def _write_allow(lines: list[str]) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(ALLOW_FILE, "w") as fh:
        fh.write(ALLOW_HEADER + "".join(f"{line}\n" for line in lines))


def allow_add(entries: list[str]) -> list[str]:
    current = read_lines(ALLOW_FILE)
    added = [e for e in entries if e not in current]
    _write_allow(current + added)
    return added


def allow_remove(entries: list[str]) -> list[str]:
    current = read_lines(ALLOW_FILE)
    removed = [e for e in entries if e in current]
    _write_allow([line for line in current if line not in removed])
    return removed


def remember_live(ips: list[str]) -> None:
    known = read_lines(LIVE_FILE)
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(LIVE_FILE, "w") as fh:
        fh.write("".join(f"{ip}\n" for ip in dict.fromkeys(known + ips)))
