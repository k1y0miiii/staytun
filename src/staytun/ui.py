import sys


class Fail(Exception):
    """Ошибка, которую показываем пользователю без traceback."""


def _paint(code: str, text: str, stream) -> str:
    return f"\033[{code}m{text}\033[0m" if stream.isatty() else text


def info(text: str) -> None:
    print(_paint("36", "[staytun]", sys.stderr), text, file=sys.stderr)


def warn(text: str) -> None:
    print(_paint("33", "[staytun]", sys.stderr), text, file=sys.stderr)


def error(text: str) -> None:
    print(_paint("31", "[staytun]", sys.stderr), text, file=sys.stderr)


def green(text: str) -> str:
    return _paint("32", text, sys.stdout)


def red(text: str) -> str:
    return _paint("31", text, sys.stdout)


def yellow(text: str) -> str:
    return _paint("33", text, sys.stdout)


def row(label: str, value: str) -> None:
    print(f"{label:<12}: {value}")
