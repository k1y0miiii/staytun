"""Linux: nftables. Отдельная таблица inet staytun, замена атомарная (add+delete+create в одном файле).

Фильтруем output (сам хост) и forward (Docker, VM, раздача), по каждому пакету —
без conntrack-исключений, поэтому старые соединения после падения VPN тоже режутся.
"""

from __future__ import annotations

import tempfile

from staytun.backends import Backend, sudo_or_fail
from staytun.netutil import Net, run
from staytun.plan import Plan

TABLE = "inet staytun"
COMMENT = "staytun"


def _set(name: str, kind: str, nets: list[Net]) -> list[str]:
    body = [f"\tset {name} {{", f"\t\ttype {kind}; flags interval; auto-merge;"]
    if nets:
        body.append("\t\telements = { " + ", ".join(str(n) for n in nets) + " }")
    return body + ["\t}"]


def _ports(spec: str) -> str:
    return "{ " + ", ".join(spec.split(",")) + " }"


class Nft(Backend):
    name = "nftables"

    def tables(self, plan: Plan) -> dict:
        return {
            "allow4": [n for n in plan.allow if n.version == 4],
            "allow6": [n for n in plan.allow if n.version == 6],
            "direct4": [n for n in plan.direct if n.version == 4],
            "direct6": [n for n in plan.direct if n.version == 6],
        }

    def render(self, plan: Plan, tables: dict) -> str:
        sets = self.tables(plan)  # nft держит адреса прямо в файле правил, tables не нужен
        lan4 = ", ".join(str(n) for n in plan.lan if n.version == 4)
        lan6 = ", ".join(str(n) for n in plan.lan + plan.link6 if n.version == 6)
        accepts = [
            "\t\tip daddr @allow4 accept",
            "\t\tip6 daddr @allow6 accept",
            "\t\tip daddr @direct4 accept",
            "\t\tip6 daddr @direct6 accept",
        ]
        for net, spec in plan.ported:
            family = "ip" if net.version == 4 else "ip6"
            accepts.append(f"\t\t{family} daddr {net} meta l4proto {{ tcp, udp }} th dport {_ports(spec)} accept")
        if lan4:
            accepts.append(f"\t\tip daddr {{ {lan4} }} accept")
        accepts.append(f"\t\tip6 daddr {{ {lan6} }} accept")

        lines = [f"table {TABLE}", f"delete table {TABLE}", f"table {TABLE} {{"]
        for name, kind in (
            ("allow4", "ipv4_addr"),
            ("allow6", "ipv6_addr"),
            ("direct4", "ipv4_addr"),
            ("direct6", "ipv6_addr"),
        ):
            lines += _set(name, kind, sets[name])
        lines += [
            "\tchain out {",
            "\t\ttype filter hook output priority 0; policy accept;",
            '\t\toifname "lo" accept',
            f'\t\toifname "{plan.iface}" accept',
            *accepts,
            "\t\tudp sport 68 udp dport 67 accept",
            f'\t\tcounter drop comment "{COMMENT}"',
            "\t}",
            "\tchain fwd {",
            "\t\ttype filter hook forward priority 0; policy accept;",
            f'\t\toifname "{plan.iface}" accept',
            "\t\tip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 } accept",
            *accepts,
            f'\t\tcounter drop comment "{COMMENT}"',
            "\t}",
            "}",
        ]
        return "\n".join(lines) + "\n"

    def apply(self, plan: Plan, old_state: dict) -> dict:
        with tempfile.NamedTemporaryFile("w", prefix="staytun-", suffix=".nft", delete=False) as fh:
            fh.write(self.render(plan, {}))
            path = fh.name
        try:
            sudo_or_fail(["nft", "-c", "-f", path], "правила не прошли проверку nft, ничего не применено")
            sudo_or_fail(["nft", "-f", path], "nft не загрузил правила")
        finally:
            run(["rm", "-f", path])
        return {}

    def remove(self, state: dict) -> None:
        run(["nft", "delete", "table", *TABLE.split()], sudo=True)

    def active(self, sudo_args: list[str]) -> bool:
        out = run(sudo_args + ["nft", "list", "table", *TABLE.split()]).stdout
        return f'comment "{COMMENT}"' in out

    def add_allow(self, nets: list[Net]) -> None:
        for version, name in ((4, "allow4"), (6, "allow6")):
            items = [str(n) for n in nets if n.version == version]
            if items:
                sudo_or_fail(
                    ["nft", "add", "element", *TABLE.split(), name, "{ " + ", ".join(items) + " }"], "nft add element"
                )
