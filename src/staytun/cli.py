from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import time

from staytun import __version__, backends, clients, config
from staytun import plan as plan_mod
from staytun.netutil import IS_MAC, default_iface, is_tunnel, list_tunnels, sudo_cached, to_nets
from staytun.ui import Fail, error, green, info, red, row, warn, yellow

COMMANDS = (
    "on",
    "off",
    "status",
    "check",
    "doctor",
    "rules",
    "sync",
    "allow",
    "set",
    "config",
    "interfaces",
    "run",
    "shell-init",
    "version",
)


def _no_root() -> None:
    if os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        raise Fail("запускай без sudo — staytun сам спросит пароль, когда он нужен")


def _sudo_prompt() -> None:
    if sudo_cached():
        return
    info("нужен пароль администратора для фаервола")
    if subprocess.call(["sudo", "-v"]) != 0:
        raise Fail("sudo не получен")


def _short(items: list[str], limit: int = 6) -> str:
    return ", ".join(items[:limit]) + (f" и ещё {len(items) - limit}" if len(items) > limit else "")


def cmd_on(args) -> int:
    _no_root()
    cfg = config.load()
    plan_mod.pick_iface(cfg, args.interface)  # ранняя проверка до пароля
    _sudo_prompt()
    plan = plan_mod.build(cfg, args.interface)
    for message in plan.warnings:
        warn(message)
    backend = backends.get()
    old = backends.read_state()
    extra = backend.apply(plan, old)
    backends.write_state(
        {
            "iface": plan.iface,
            "backend": backend.name,
            "since": time.strftime("%Y-%m-%d %H:%M"),
            "servers": [str(n) for n in plan.allow],
            "direct": plan.direct_desc,
            **extra,
        }
    )
    info(green("ВКЛ") + f": интернет только через {plan.iface}")
    info(
        f"мимо туннеля: VPN-серверы ({_short([str(n) for n in plan.allow])})"
        + (f"; direct: {_short(plan.direct_desc, 4)}" if plan.direct_desc else "")
        + ("; локальная сеть" if cfg.flag("lan") else "")
    )
    info("если VPN переподключится на другой интерфейс — интернет встанет, повтори: staytun on")
    return 0


def cmd_off(args) -> int:
    _no_root()
    _sudo_prompt()
    backends.get().remove(backends.read_state())
    backends.clear_state()
    info(red("ВЫКЛ") + ": фаервол в штатном режиме, трафик идёт как обычно")
    return 0


def cmd_status(args) -> int:
    state = backends.read_state()
    backend = backends.get()
    active = backend.active(["sudo"])
    current = default_iface()
    code = 0
    if active:
        row("защита", green("ВКЛ") + f" с {state.get('since', '?')} ({backend.name})")
    else:
        row("защита", red("ВЫКЛ"))
        code = 1
        if state:
            print("              state-файл есть, а правил нет (перезагрузка?) — staytun on")
    if state:
        iface = state.get("iface", "")
        if current == iface:
            row("туннель", f"{iface} — интернет идёт через него")
        else:
            row("туннель", yellow(f"{iface} не активен (сейчас: {current or 'нет'}) — интернет заблокирован"))
            code = 1
        row("серверы", _short(state.get("servers", [])))
        if state.get("live"):
            row("найдены", _short(state["live"]))
        row("direct", _short(state.get("direct", []), 4) or "нет")
    else:
        row("интернет", f"через {current or 'нет'}")
    return code


def cmd_check(args) -> int:
    state = backends.read_state()
    if not state:
        args.quiet or error("защита выключена — сначала: staytun on")
        return 1
    if default_iface() != state.get("iface"):
        args.quiet or error(f"VPN ({state.get('iface')}) не активен — переподключи VPN и staytun on")
        return 1
    if sudo_cached() and not backends.get().active(["sudo", "-n"]):
        args.quiet or error("правила фаервола не загружены — staytun on")
        return 1
    return 0


def cmd_doctor(args) -> int:
    cfg = config.load()
    tool = "pfctl" if IS_MAC else "nft"
    row("система", f"{platform.system()} {platform.release()}, python {platform.python_version()}")
    row(
        "фаервол",
        f"{tool} "
        + (
            green("есть")
            if shutil.which(tool) or os.path.exists(f"/sbin/{tool}")
            else red("не найден — поставь nftables")
        ),
    )
    current = default_iface()
    tunnels = list_tunnels()
    mark = green("это VPN-туннель") if current and is_tunnel(current) else red("это НЕ туннель — VPN не подключён?")
    row("интернет", f"через {current or 'нет'} — {mark}")
    row("туннели", ", ".join(tunnels) or "нет")
    if cfg.get("interface") != "auto":
        row("интерфейс", f"задан вручную: {cfg.get('interface')}")

    plan = plan_mod.build(cfg, strict=False)
    print()
    for rep in plan.reports:
        status = green("запущен") if rep.running else "установлен"
        print(f"  {rep.title} — {status}")
        print(f"      серверы: {_short(rep.servers) or 'не найдены'}")
        if rep.direct:
            print(f"      direct : {_short(rep.direct, 4)}")
        for note in rep.notes:
            print(f"      {yellow(note)}")
    if not plan.reports:
        print("  поддерживаемых VPN-клиентов не найдено — работает ручной режим (staytun allow add)")
    print()
    row("allow.txt", f"{len(cfg.allow)} строк ({config.ALLOW_FILE})")
    row(
        "мимо VPN",
        f"{len(plan.allow)} адресов серверов"
        + (f"; direct: {_short(plan.direct_desc, 4)}" if plan.direct_desc else ""),
    )
    row("защита", green("ВКЛ") if backends.read_state() else red("ВЫКЛ"))
    for message in plan.warnings:
        warn(message)
    ready = bool(plan.iface and plan.allow)
    print()
    print(green("Готово к включению: staytun on") if ready else yellow("Пока включать рано — см. предупреждения выше"))
    return 0 if ready else 1


def cmd_rules(args) -> int:
    cfg = config.load()
    plan = plan_mod.build(cfg, args.interface)
    backend = backends.get()
    tables = backend.tables(plan)
    preview = os.path.join(config.CACHE_DIR, "preview")
    os.makedirs(preview, exist_ok=True)
    paths = backends.write_tables(tables, preview)
    for line in backend.render(plan, paths).splitlines():
        print(line if args.full or len(line) < 200 else line[:160] + " … (обрезано, --full покажет всё)")
    print("\n# таблицы: " + ", ".join(f"{name}={len(nets)}" for name, nets in tables.items()), file=sys.stderr)
    return 0


def cmd_sync(args) -> int:
    _no_root()
    config.load()
    live: list[str] = []
    for client in clients.available():
        if client.installed() and client.id in ("happ", "wireguard"):
            live += client.collect().live
    if not live:
        warn("живых VPN-соединений не найдено (Happ / WireGuard не подключены?)")
        return 1
    config.remember_live(live)
    info(f"запомнил серверы: {_short(live)}")
    state = backends.read_state()
    if state:
        nets = [n for ip in live for n in to_nets(ip)]
        backends.get().add_allow(nets)
        state["live"] = sorted(set(state.get("live", []) + live))
        backends.write_state(state)
        info("добавил их в работающую защиту")
    return 0


def cmd_allow(args) -> int:
    if args.action == "list" or not args.action:
        entries = config.load().allow
        print("\n".join(entries) if entries else f"пусто ({config.ALLOW_FILE})")
        return 0
    if not args.entries:
        raise Fail("укажи хотя бы один адрес: staytun allow add 1.2.3.4 vpn.example.com 5.6.7.0/24")
    if args.action == "add":
        bad = [e for e in args.entries if not plan_mod.parse_entry(e)]
        if bad:
            raise Fail(f"не похоже на IP, подсеть или домен: {', '.join(bad)}")
        added = config.allow_add(args.entries)
        info(f"добавлено: {', '.join(added) or 'всё уже было'}")
        if added and backends.read_state():
            nets = []
            for entry in added:
                try:
                    nets += to_nets(entry)
                except ValueError as exc:
                    warn(str(exc))
            if nets:
                backends.get().add_allow(nets)
                info("и сразу применено к работающей защите")
    else:
        removed = config.allow_remove(args.entries)
        info(f"удалено: {', '.join(removed) or 'ничего не нашлось'}")
        if removed and backends.read_state():
            info("чтобы убрать из работающей защиты: staytun on")
    return 0


def cmd_set(args) -> int:
    try:
        config.set_value(args.key, " ".join(args.value))
    except KeyError:
        raise Fail(f"нет такой настройки: {args.key}. Список: staytun config") from None
    info(f"{args.key} = {' '.join(args.value)}" + (" (применится при staytun on)" if backends.read_state() else ""))
    return 0


def cmd_config(args) -> int:
    cfg = config.load()
    for key, (_, hint) in config.SETTINGS.items():
        print(f"{key:<11}= {cfg.get(key) or '—':<28} # {hint}")
    print(f"\nфайл настроек : {config.CONFIG_FILE}\nисключения    : {config.ALLOW_FILE}")
    print("изменить      : staytun set <ключ> <значение>")
    return 0


def cmd_interfaces(args) -> int:
    current = default_iface()
    for name in list_tunnels():
        print(name + (green("  ← интернет сейчас здесь") if name == current else ""))
    if current and not is_tunnel(current):
        print(yellow(f"интернет сейчас идёт через {current} — это не туннель"))
    return 0


def cmd_run(args) -> int:
    if not args.command:
        raise Fail("что запускать? staytun run claude")
    if cmd_check(argparse.Namespace(quiet=False)) != 0:
        return 1
    os.execvp(args.command[0], args.command)
    return 0


def cmd_shell_init(args) -> int:
    names = config.load().items("protect")
    print("# staytun: эти команды не стартуют без активной защиты (обход: command <имя>)")
    for name in names:
        print(f'{name}() {{ staytun check && command {name} "$@"; }}')
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="staytun",
        description="Kill switch для VPN: если туннель упал — интернет режется, реальный IP не утекает.",
    )
    p.add_argument("-V", "--version", action="version", version=f"staytun {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="команда")

    s = sub.add_parser("on", help="включить защиту")
    s.add_argument("-i", "--interface", help="туннель вручную (по умолчанию — куда идёт интернет)")
    s.set_defaults(func=cmd_on)
    sub.add_parser("off", help="выключить защиту").set_defaults(func=cmd_off)
    sub.add_parser("status", help="состояние (спросит sudo)").set_defaults(func=cmd_status)
    s = sub.add_parser("check", help="тихая проверка для скриптов: код 0 — защищено")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(func=cmd_check)
    sub.add_parser("doctor", help="диагностика: что найдено и готово ли к включению").set_defaults(func=cmd_doctor)
    s = sub.add_parser("rules", help="показать правила фаервола, ничего не применяя")
    s.add_argument("-i", "--interface")
    s.add_argument("--full", action="store_true", help="не обрезать длинные строки")
    s.set_defaults(func=cmd_rules)
    sub.add_parser("sync", help="подхватить серверы Happ / WireGuard из живых соединений").set_defaults(func=cmd_sync)
    s = sub.add_parser("allow", help="исключения: allow add|rm|list <IP, подсеть, домен>")
    s.add_argument("action", nargs="?", choices=("add", "rm", "list"))
    s.add_argument("entries", nargs="*")
    s.set_defaults(func=cmd_allow)
    s = sub.add_parser("set", help="изменить настройку: set <ключ> <значение>")
    s.add_argument("key")
    s.add_argument("value", nargs="+")
    s.set_defaults(func=cmd_set)
    sub.add_parser("config", help="показать настройки").set_defaults(func=cmd_config)
    sub.add_parser("interfaces", help="список VPN-туннелей").set_defaults(func=cmd_interfaces)
    s = sub.add_parser("run", help="запустить команду только под защитой: run claude")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(func=cmd_run)
    s = sub.add_parser("shell-init", help="функции-обёртки для .zshrc / .bashrc")
    s.set_defaults(func=cmd_shell_init)
    sub.add_parser("version", help="версия").set_defaults(func=lambda a: print(f"staytun {__version__}") or 0)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0].startswith("--") and argv[0][2:] in COMMANDS:
        argv[0] = argv[0][2:]  # staytun --on == staytun on
    p = parser()
    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        p.print_help()
        return 1
    try:
        return int(args.func(args) or 0)
    except Fail as exc:
        error(str(exc))
        return 1
    except KeyboardInterrupt:
        return 130
