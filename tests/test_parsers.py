import base64
import json

from staytun import parsers


def test_xray_servers_all_shapes():
    conf = {
        "outbounds": [
            {"protocol": "vless", "settings": {"vnext": [{"address": "a.example.com", "port": 443}]}},
            {"protocol": "shadowsocks", "settings": {"servers": [{"address": "1.2.3.4"}]}},
            {"protocol": "vless", "settings": {"address": "5.6.7.8", "port": 443}},
            {"protocol": "wireguard", "settings": {"peers": [{"endpoint": "9.9.9.1:51820"}]}},
            {"protocol": "freedom", "settings": {"address": "should.not.appear"}},
        ]
    }
    assert parsers.xray_servers(conf) == ["a.example.com", "1.2.3.4", "5.6.7.8", "9.9.9.1:51820"]


def test_xray_direct_string_ip_and_ports():
    conf = {
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        "routing": {
            "rules": [
                {"outboundTag": "direct", "ip": "8.8.8.8", "port": "53"},
                {"outboundTag": "direct", "ip": ["geoip:ru", "geoip:private", "1.1.1.0/24"]},
                {"outboundTag": "proxy", "ip": ["geoip:us"]},
                {"outboundTag": "direct", "domain": ["geosite:category-ru"]},
            ]
        },
    }
    direct = parsers.xray_direct(conf)
    assert direct.codes == {"RU"}
    assert direct.targets == [("8.8.8.8", "53"), ("1.1.1.0/24", None)]


def test_singbox_servers_and_direct():
    conf = {
        "outbounds": [
            {"type": "vless", "tag": "proxy", "server": "s.example.com"},
            {"type": "direct", "tag": "direct"},
            {"type": "socks", "tag": "local", "server": "127.0.0.1"},
        ],
        "endpoints": [{"type": "wireguard", "peers": [{"address": "4.4.4.4"}]}],
        "route": {"rules": [{"outbound": "direct", "ip_cidr": ["77.88.0.0/16"], "port": [443]}]},
    }
    assert parsers.singbox_servers(conf) == ["s.example.com", "127.0.0.1", "4.4.4.4"]
    assert parsers.singbox_direct(conf).targets == [("77.88.0.0/16", "443")]


def test_uri_hosts():
    vmess = base64.b64encode(json.dumps({"add": "vm.example.com", "port": 443}).encode()).decode()
    text = (
        "vless://uuid@1.2.3.4:443?security=reality#name\n"
        "trojan://pass@[2001:db8::1]:443\n"
        "hy2://pw@hy.example.net:8443/?sni=x\n"
        f"vmess://{vmess}"
    )
    assert parsers.uri_hosts(text) == ["1.2.3.4", "2001:db8::1", "hy.example.net", "vm.example.com"]


def test_scan_nested_json_string_and_plist_like():
    inner = json.dumps({"outbounds": [{"protocol": "vless", "settings": {"address": "6.6.6.6"}}]})
    blob = {"vector": [{"wrapper": {"payload": {"xrayConfig": inner}}}, {"uri": "vless://u@7.7.7.7:443"}]}
    assert parsers.scan(blob) == ["6.6.6.6", "7.7.7.7"]


def test_ports_normalization():
    assert parsers.ports("53,443") == "53,443"
    assert parsers.ports("1000-2000") == "1000-2000"
    assert parsers.ports(["1000:2000", 53]) == "1000-2000,53"
    assert parsers.ports(None) is None


def test_wg_endpoints():
    conf = "[Interface]\nPrivateKey = x\n[Peer]\nEndpoint = vpn.example.com:51820\n"
    assert parsers.wg_endpoints(conf) == ["vpn.example.com:51820"]
