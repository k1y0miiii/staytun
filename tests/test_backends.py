import ipaddress

import pytest

from staytun.backends.nft import Nft
from staytun.backends.pf import Pf
from staytun.netutil import LAN4, LAN6, LINK6, collapse, split_host, to_nets
from staytun.plan import Plan


def net(value):
    return ipaddress.ip_network(value)


@pytest.fixture
def plan():
    return Plan(
        iface="utun7",
        allow=[net("5.231.119.226/32"), net("2001:db8::1/128")],
        direct=[net("77.88.0.0/18"), net("2a02:6b8::/29")],
        ported=[(net("8.8.8.8/32"), "53"), (net("1.1.1.1/32"), "53,1000-2000")],
        lan=[net(n) for n in LAN4 + LAN6],
        link6=[net(n) for n in LINK6],
    )


def test_pf_render(plan):
    pf = Pf()
    text = pf.render(plan, {"staytun_allow": "/tmp/a", "staytun_direct": "/tmp/d"})
    lines = text.splitlines()
    assert 'table <staytun_allow> persist file "/tmp/a"' in lines
    assert 'pass out quick on utun7 all flags any keep state label "staytun"' in lines
    assert "pass out quick proto { tcp udp } to 1.1.1.1/32 port { 53 1000:2000 } flags any keep state" in lines
    assert "set state-policy if-bound" in lines
    block = lines.index('block drop out quick all label "staytun"')
    assert block < lines.index('anchor "com.apple/*"')
    assert all(line.startswith("pass") for line in lines[lines.index('dummynet-anchor "com.apple/*"') + 1 : block])


def test_pf_tables_skip_empty_direct(plan):
    plan.direct = []
    assert list(Pf().tables(plan)) == ["staytun_allow"]


def test_nft_render(plan):
    text = Nft().render(plan, {})
    assert text.startswith("table inet staytun\ndelete table inet staytun\n")
    assert "elements = { 5.231.119.226/32 }" in text
    assert "elements = { 2a02:6b8::/29 }" in text
    assert 'oifname "utun7" accept' in text
    assert "ip daddr 1.1.1.1/32 meta l4proto { tcp, udp } th dport { 53, 1000-2000 } accept" in text
    assert text.count('counter drop comment "staytun"') == 2


def test_nft_empty_sets_have_no_elements(plan):
    plan.direct = []
    text = Nft().render(plan, {})
    direct4 = text.split("set direct4 {", 1)[1].split("}", 1)[0]
    assert "elements" not in direct4


def test_split_host_and_to_nets():
    assert split_host("1.2.3.4:443") == "1.2.3.4"
    assert split_host("[2001:db8::1]:443") == "2001:db8::1"
    assert split_host("2001:db8::1") == "2001:db8::1"
    assert to_nets("1.2.3.4") == [net("1.2.3.4/32")]
    with pytest.raises(ValueError):
        to_nets("0.0.0.0/0")
    with pytest.raises(ValueError):
        to_nets("::/0")


def test_collapse_merges_overlaps():
    assert collapse([net("10.0.0.0/24"), net("10.0.0.0/25"), net("10.0.1.0/24")]) == [net("10.0.0.0/23")]
