import sys

if sys.version_info < (3, 14):  # noqa: UP036 — этот файл запускают и старым python3
    sys.exit(
        f"staytun нужен Python 3.14+, а запущен {sys.version.split()[0]}.\n"
        "Переустанови — установщик сам поставит нужный Python:\n"
        "  curl -fsSL https://raw.githubusercontent.com/k1y0miiii/staytun/main/install.sh | sh"
    )

from staytun.cli import main  # noqa: E402

raise SystemExit(main())
