"""macOS: pf. Заменяем главный ruleset копией штатного /etc/pf.conf + своими правилами.

- block стоит quick и до com.apple/*, чтобы правила из якорей его не обошли;
- state-policy if-bound: состояние, созданное на туннеле, не выпустит пакет через Wi-Fi;
- flags any: уже открытые соединения переживают включение без обрыва;
- pf включаем через токен (-E/-X), а не -e/-d, чтобы не сломать другим их pf.
"""

import re
import tempfile

from staytun.backends import Backend, sudo_or_fail, write_tables
from staytun.netutil import Net, run
from staytun.plan import Plan
from staytun.ui import Fail

LABEL = "staytun"


def _ports(spec: str) -> str:
    items = [p.replace("-", ":") for p in spec.split(",")]
    return items[0] if len(items) == 1 else "{ " + " ".join(items) + " }"


class Pf(Backend):
    name = "pf"

    def tables(self, plan: Plan) -> dict:
        tables = {"staytun_allow": plan.allow}
        if plan.direct:
            tables["staytun_direct"] = plan.direct
        return tables

    def render(self, plan: Plan, tables: dict) -> str:
        lan4 = " ".join(str(n) for n in plan.lan if n.version == 4)
        lan6 = " ".join(str(n) for n in plan.lan + plan.link6 if n.version == 6)
        lines = [
            "set limit table-entries 400000",
            "set block-policy drop",
            "set state-policy if-bound",
            "set skip on lo0",
        ]
        lines += [f'table <{name}> persist file "{path}"' for name, path in tables.items()]
        lines += [
            'scrub-anchor "com.apple/*"',
            'nat-anchor "com.apple/*"',
            'rdr-anchor "com.apple/*"',
            'dummynet-anchor "com.apple/*"',
            f'pass out quick on {plan.iface} all flags any keep state label "{LABEL}"',
        ]
        lines += [f"pass out quick to <{name}> flags any keep state" for name in tables]
        lines += [
            f"pass out quick proto {{ tcp udp }} to {net} port {_ports(spec)} flags any keep state"
            for net, spec in plan.ported
        ]
        if lan4:
            lines.append(f"pass out quick inet to {{ {lan4} }} flags any keep state")
        lines += [
            "pass out quick inet proto udp from any port 68 to any port 67 keep state",
            f"pass out quick inet6 to {{ {lan6} }} flags any keep state",
            f'block drop out quick all label "{LABEL}"',
            'anchor "com.apple/*"',
            'load anchor "com.apple" from "/etc/pf.anchors/com.apple"',
        ]
        return "\n".join(lines) + "\n"

    def apply(self, plan: Plan, old_state: dict) -> dict:
        with tempfile.TemporaryDirectory(prefix="staytun-") as tmp:
            paths = write_tables(self.tables(plan), tmp)
            rules = f"{tmp}/pf.conf"
            with open(rules, "w") as fh:
                fh.write(self.render(plan, paths))
            sudo_or_fail(["pfctl", "-nf", rules], "правила не прошли проверку pfctl, ничего не применено")
            sudo_or_fail(["pfctl", "-f", rules], "pfctl не загрузил правила")
        out = sudo_or_fail(["pfctl", "-E"], "pf не включился")
        match = re.search(r"Token\s*:\s*(\d+)", out)
        if not match:
            raise Fail("pf включился без токена — проверь: staytun status")
        token = match.group(1)
        run(["pfctl", "-F", "states"], sudo=True)
        old = old_state.get("token")
        if old and old != token:
            run(["pfctl", "-X", old], sudo=True)
        return {"token": token}

    def remove(self, state: dict) -> None:
        sudo_or_fail(["pfctl", "-f", "/etc/pf.conf"], "не смог вернуть /etc/pf.conf")
        if state.get("token"):
            run(["pfctl", "-X", state["token"]], sudo=True)

    def active(self, sudo_args: list[str]) -> bool:
        info = run(sudo_args + ["pfctl", "-s", "info"]).stdout
        rules = run(sudo_args + ["pfctl", "-s", "rules"]).stdout
        return "Status: Enabled" in info and f'label "{LABEL}"' in rules

    def add_allow(self, nets: list[Net]) -> None:
        sudo_or_fail(["pfctl", "-t", "staytun_allow", "-T", "add"] + [str(n) for n in nets], "pfctl -T add")
