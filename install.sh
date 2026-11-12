#!/bin/sh
# Установка staytun:
#   curl -fsSL https://raw.githubusercontent.com/k1y0miiii/staytun/main/install.sh | sh
# Удаление:
#   curl -fsSL https://raw.githubusercontent.com/k1y0miiii/staytun/main/install.sh | sh -s -- --uninstall
#
# Ставит через uv (https://docs.astral.sh/uv): он сам скачает Python 3.14 в свою папку,
# системный Python и Homebrew не трогаются, sudo не нужен.
set -eu

REPO="${STAYTUN_REPO:-k1y0miiii/staytun}"
PYTHON="3.14"

say() { printf '\033[36m[staytun]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[staytun]\033[0m %s\n' "$*" >&2; exit 1; }

# старые версии (до 0.2) ставились обёрткой в ~/.local/share/staytun
remove_legacy() {
    if [ -f "$HOME/.local/bin/staytun" ] && grep -q 'python3 -m staytun' "$HOME/.local/bin/staytun" 2>/dev/null; then
        rm -f "$HOME/.local/bin/staytun"
    fi
    rm -rf "$HOME/.local/share/staytun"
}

if [ "${1:-}" = "--uninstall" ]; then
    if command -v staytun >/dev/null 2>&1; then staytun off || true; fi
    if command -v uv >/dev/null 2>&1; then uv tool uninstall staytun 2>/dev/null || true; fi
    remove_legacy
    say "удалён. Настройки остались в ~/.config/staytun — удали вручную, если не нужны."
    exit 0
fi

case "$(uname -s)" in
    Darwin) [ -x /sbin/pfctl ] || command -v pfctl >/dev/null 2>&1 || die "pfctl не найден — странная macOS" ;;
    Linux)  command -v nft >/dev/null 2>&1 || say "nft не найден — поставь пакет nftables (apt/dnf/pacman install nftables)" ;;
    *)      die "поддерживаются только macOS и Linux" ;;
esac

if ! command -v uv >/dev/null 2>&1; then
    say "ставлю uv — менеджер Python, он принесёт Python $PYTHON"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    PATH="$HOME/.local/bin:$PATH"
    export PATH
    command -v uv >/dev/null 2>&1 || die "uv не установился — поставь вручную: https://docs.astral.sh/uv"
fi

remove_legacy

HERE="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
if [ -n "$HERE" ] && [ -f "$HERE/pyproject.toml" ] && [ -d "$HERE/src/staytun" ]; then
    say "ставлю из локальной копии $HERE"
    SOURCE="$HERE"
else
    SOURCE="staytun @ https://github.com/$REPO/archive/refs/heads/main.tar.gz"
fi
uv tool install --force --reinstall --python "$PYTHON" "$SOURCE"

BIN_DIR="$(uv tool dir --bin 2>/dev/null || echo "$HOME/.local/bin")"
say "готово: $BIN_DIR/staytun"
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) say "добавь в PATH: uv tool update-shell && exec \$SHELL" ;;
esac
say "дальше: подключи VPN → staytun doctor → staytun on"
