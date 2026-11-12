import ipaddress

from staytun import geoip


def _varint(n: int) -> bytes:
    out = b""
    while True:
        byte = n & 0x7F
        n >>= 7
        out += bytes([byte | (0x80 if n else 0)])
        if not n:
            return out


def _field(num: int, payload: bytes) -> bytes:
    return _varint(num << 3 | 2) + _varint(len(payload)) + payload


def _cidr(net: str) -> bytes:
    n = ipaddress.ip_network(net)
    return _field(1, n.network_address.packed) + _varint(2 << 3) + _varint(n.prefixlen)


def _country(code: str, nets) -> bytes:
    return _field(1, code.encode()) + b"".join(_field(2, _cidr(n)) for n in nets)


def _dat(tmp_path):
    data = _field(1, _country("RU", ["77.88.0.0/18", "2a02:6b8::/29"])) + _field(1, _country("US", ["8.8.8.0/24"]))
    path = tmp_path / "geoip.dat"
    path.write_bytes(data)
    return str(path)


def test_codes(tmp_path):
    assert geoip.codes(_dat(tmp_path)) == ["RU", "US"]


def test_load_and_cache(tmp_path):
    path = _dat(tmp_path)
    expected = [ipaddress.ip_network("77.88.0.0/18"), ipaddress.ip_network("2a02:6b8::/29")]
    assert geoip.load(path, ["ru"])["RU"] == expected
    cache = tmp_path / "cache"
    assert geoip.load_cached(path, ["RU"], str(cache)) == expected
    assert geoip.load_cached(path, ["RU"], str(cache)) == expected  # второй раз — из кэша
    assert len(list(cache.iterdir())) == 1
