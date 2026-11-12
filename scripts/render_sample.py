"""Рендер правил для тестового плана — CI проверяет их синтаксис настоящими pfctl / nft.

python scripts/render_sample.py <каталог> <интерфейс>
"""

import ipaddress
import os
import sys

from staytun.backends import write_tables
from staytun.backends.nft import Nft
from staytun.backends.pf import Pf
from staytun.netutil import LAN4, LAN6, LINK6
from staytun.plan import Plan


def main() -> None:
    out, iface = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    # большая таблица — как geoip:ru (~23 тыс. подсетей)
    geo = [ipaddress.ip_network(f"10.{i // 256}.{i % 256}.0/24") for i in range(20000)]
    geo += [ipaddress.ip_network(f"2a02:{i:x}::/32") for i in range(3000)]
    plan = Plan(
        iface=iface,
        allow=[ipaddress.ip_network("203.0.113.10/32"), ipaddress.ip_network("2001:db8::10/128")],
        direct=geo,
        ported=[(ipaddress.ip_network("8.8.8.8/32"), "53"), (ipaddress.ip_network("1.1.1.1/32"), "53,1000-2000")],
        lan=[ipaddress.ip_network(n) for n in LAN4 + LAN6],
        link6=[ipaddress.ip_network(n) for n in LINK6],
    )
    pf = Pf()
    with open(os.path.join(out, "pf.conf"), "w") as fh:
        fh.write(pf.render(plan, write_tables(pf.tables(plan), out)))
    with open(os.path.join(out, "staytun.nft"), "w") as fh:
        fh.write(Nft().render(plan, {}))


if __name__ == "__main__":
    main()
