import ipaddress
import re

import pytest

from staytun import cli, clients, config
from staytun import plan as plan_mod
from staytun.netutil import LAN4, LINK6, Conn
from staytun.plan import Plan
from staytun.ui import Fail

HAPP_XRAY = "/Applications/Happ.app/Contents/MacOS/core/xray"
V2BOX = "/Applications/V2Box.app/Contents/PlugIns/PacketTunnel.appex/Contents/MacOS/PacketTunnel"


def _plan(allow):
    return Plan(
        iface="utun7",
        allow=[ipaddress.ip_network(a) for a in allow],
        direct=[ipaddress.ip_network("77.88.0.0/18")],
        ported=[],
        lan=[ipaddress.ip_network(n) for n in LAN4],
        link6=[ipaddress.ip_network(n) for n in LINK6],
    )


@pytest.fixture
def conns(monkeypatch):
    items = [
        Conn("1", HAPP_XRAY, "192.168.1.5", "203.0.113.50"),  # Happ → свой сервер мимо туннеля
        Conn("2", V2BOX, "192.168.1.5", "198.51.100.7"),  # V2Box → сервер
        Conn("2", V2BOX, "192.168.1.5", "77.88.55.88"),  # V2Box direct → geoip
        Conn("2", V2BOX, "192.168.1.5", "104.16.1.1"),  # V2Box direct → не покрыто
        Conn("3", "/Applications/Safari.app/Contents/MacOS/Safari", "172.19.0.1", "1.1.1.1"),
        Conn("4", HAPP_XRAY, "172.19.0.1", "203.0.113.99"),  # через туннель — не обход
    ]
    monkeypatch.setattr(plan_mod, "connections", lambda: items)
    monkeypatch.setattr(plan_mod, "iface_addrs", lambda name: {"172.19.0.1"})
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/sbin/lsof")
    return items


def test_bypass_report_classifies(conns):
    report = {b.name: b for b in plan_mod.bypass_report(_plan(["198.51.100.7/32"]))}
    assert set(report) == {"Happ", "V2Box"}
    assert report["Happ"].covered == [] and report["Happ"].uncovered == ["203.0.113.50"]
    assert report["V2Box"].covered == ["198.51.100.7", "77.88.55.88"]
    assert report["V2Box"].uncovered == ["104.16.1.1"]


def test_preflight_refuses_when_vpn_server_unknown(conns):
    with pytest.raises(Fail, match="203.0.113.50"):
        cli._preflight(_plan(["198.51.100.7/32"]), auto=False)


def test_preflight_auto_remembers(conns, monkeypatch):
    saved = []
    monkeypatch.setattr(config, "remember_live", saved.extend)
    cli._preflight(_plan(["198.51.100.7/32"]), auto=True)
    assert saved == ["203.0.113.50"]


def test_preflight_passes_when_servers_known(conns):
    cli._preflight(_plan(["198.51.100.7/32", "203.0.113.50/32"]), auto=False)


@pytest.mark.parametrize(
    "path, expected",
    [
        (HAPP_XRAY, True),
        ("/Applications/Happ.app/Contents/MacOS/tun/sing-box", True),
        ("/Applications/Happ.app/Contents/MacOS/happd", True),
        ("/Applications/Happ.app/Contents/PlugIns/HappTunnel.appex/Contents/MacOS/HappTunnel", True),
        ("/Applications/Happ.app/Contents/MacOS/Happ", False),  # GUI ходит за подписками — не сервер
        (V2BOX, False),
    ],
)
def test_happ_core_regex(path, expected):
    assert bool(re.search(clients.Happ.cores, path)) is expected
