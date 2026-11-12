import json
import os

from staytun.config import STATE_FILE
from staytun.netutil import IS_MAC, Net, run
from staytun.plan import Plan
from staytun.ui import Fail


class Backend:
    name = ""

    def render(self, plan: Plan, tables: dict) -> str:
        """Текст правил. tables: имя таблицы → путь к файлу с её адресами."""
        raise NotImplementedError

    def tables(self, plan: Plan) -> dict:
        """Имя таблицы → список сетей."""
        raise NotImplementedError

    def apply(self, plan: Plan, old_state: dict) -> dict:
        """Применяет правила. Возвращает поля для state-файла."""
        raise NotImplementedError

    def remove(self, state: dict) -> None:
        raise NotImplementedError

    def active(self, sudo_args: list[str]) -> bool:
        raise NotImplementedError

    def add_allow(self, nets: list[Net]) -> None:
        raise NotImplementedError


def get() -> Backend:
    if IS_MAC:
        from staytun.backends.pf import Pf

        return Pf()
    from staytun.backends.nft import Nft

    return Nft()


def write_tables(tables: dict, directory: str) -> dict:
    paths = {}
    for name, nets in tables.items():
        path = os.path.join(directory, f"{name}.txt")
        with open(path, "w") as fh:
            fh.write("".join(f"{n}\n" for n in nets))
        paths[name] = path
    return paths


def read_state() -> dict:
    try:
        with open(STATE_FILE) as fh:
            return json.load(fh)
    except OSError, ValueError:
        return {}


def write_state(state: dict) -> None:
    # state пишет root: процессы пользователя не подделают «защита включена»
    result = run(["tee", STATE_FILE], sudo=True, input=json.dumps(state, ensure_ascii=False, indent=1))
    if result.returncode != 0:
        raise Fail(f"не смог записать {STATE_FILE}: {result.stderr.strip()}")
    run(["chmod", "644", STATE_FILE], sudo=True)


def clear_state() -> None:
    run(["rm", "-f", STATE_FILE], sudo=True)


def sudo_or_fail(cmd: list[str], what: str) -> str:
    result = run(cmd, sudo=True)
    if result.returncode != 0:
        raise Fail(f"{what}:\n{(result.stderr or result.stdout).strip()}")
    return result.stdout + result.stderr


def state_iface(state: dict | None) -> str:
    return (state or {}).get("iface", "")
