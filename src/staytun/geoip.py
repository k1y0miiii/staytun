"""Чтение xray/v2ray geoip.dat (protobuf) без сторонних зависимостей.

GeoIPList { repeated GeoIP entry = 1; }
GeoIP     { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3; }
CIDR      { bytes ip = 1; uint32 prefix = 2; }
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
from collections.abc import Iterable, Iterator

from staytun.netutil import Net


def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return result, pos


def _fields(buf: bytes) -> Iterator[tuple[int, object]]:
    pos = 0
    while pos < len(buf):
        key, pos = _varint(buf, pos)
        wire = key & 7
        if wire == 0:
            value, pos = _varint(buf, pos)
        elif wire == 2:
            size, pos = _varint(buf, pos)
            value = buf[pos : pos + size]
            pos += size
        elif wire == 5:
            value, pos = buf[pos : pos + 4], pos + 4
        elif wire == 1:
            value, pos = buf[pos : pos + 8], pos + 8
        else:
            raise ValueError(f"geoip.dat: неизвестный wire type {wire}")
        yield key >> 3, value


def _entries(data: bytes) -> Iterator[tuple[str, list[tuple[int, object]]]]:
    for field, entry in _fields(data):
        if field != 1:
            continue
        parts = list(_fields(entry))  # type: ignore[arg-type]
        code = next((bytes(v).decode() for f, v in parts if f == 1), "")  # type: ignore[arg-type]
        yield code.upper(), parts


def codes(path: str) -> list[str]:
    with open(path, "rb") as fh:
        return sorted(code for code, _ in _entries(fh.read()))


def load(path: str, wanted: Iterable[str]) -> dict[str, list[Net]]:
    wanted = {c.upper() for c in wanted}
    result: dict[str, list[Net]] = {}
    with open(path, "rb") as fh:
        data = fh.read()
    for code, parts in _entries(data):
        if code not in wanted:
            continue
        nets = []
        for field, cidr in parts:
            if field != 2:
                continue
            sub = dict(_fields(cidr))  # type: ignore[arg-type]
            addr = ipaddress.ip_address(bytes(sub.get(1, b"")))  # type: ignore[arg-type]
            nets.append(ipaddress.ip_network(f"{addr}/{sub.get(2, 0)}", strict=False))
        result[code] = nets
    return result


def load_cached(path: str, wanted: Iterable[str], cache_dir: str) -> list[Net]:
    """Как load(), но с кэшем: geoip.dat бывает 20+ МБ, а парсить его на каждый on незачем."""
    wanted = sorted({c.upper() for c in wanted})
    stat = os.stat(path)
    key = hashlib.sha1(f"{path}|{stat.st_mtime}|{stat.st_size}|{','.join(wanted)}".encode()).hexdigest()[:16]
    cache = os.path.join(cache_dir, f"geoip-{key}.txt")
    if os.path.exists(cache):
        with open(cache) as fh:
            return [ipaddress.ip_network(line.strip()) for line in fh if line.strip()]
    nets = [n for group in load(path, wanted).values() for n in group]
    os.makedirs(cache_dir, exist_ok=True)
    with open(cache, "w") as fh:
        fh.write("".join(f"{n}\n" for n in nets))
    return nets
