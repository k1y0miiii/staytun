#!/bin/sh
# Установка staytun:
#   curl -fsSL https://raw.githubusercontent.com/k1y0miiii/staytun/main/install.sh | sh
# Удаление:
#   curl -fsSL https://raw.githubusercontent.com/k1y0miiii/staytun/main/install.sh | sh -s -- --uninstall
set -eu

REPO="${STAYTUN_REPO:-k1y0miiii/staytun}"
PREFIX="${STAYTUN_PREFIX:-$HOME/.local}"
SHARE="$PREFIX/share/staytun"
BIN="$PREFIX/bin/staytun"

say() { printf '\033[36m[staytun]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[staytun]\033[0m %s\n' "$*" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
    if command -v staytun >/dev/null 2>&1; then staytun off || true; fi
    rm -rf "$SHARE" "$BIN"
    say "удалён. Настройки остались в ~/.config/staytun — удали вручную, если не нужны."
    exit 0
fi

case "$(uname -s)" in
    Darwin) command -v pfctl >/dev/null 2>&1 || [ -x /sbin/pfctl ] || die "pfctl не найден — странная macOS" ;;
    Linux)  command -v nft >/dev/null 2>&1 || say "nft не найден — поставь пакет nftables (apt/dnf/pacman install nftables)" ;;
    *)      die "поддерживаются только macOS и Linux" ;;
esac

command -v python3 >/dev/null 2>&1 || die "нужен python3. macOS: xcode-select --install; Linux: пакет python3"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || die "нужен python3 версии 3.9 или новее"

mkdir -p "$SHARE" "$PREFIX/bin"
HERE="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
if [ -n "$HERE" ] && [ -f "$HERE/src/staytun/cli.py" ]; then
    say "ставлю из локальной копии $HERE"
    rm -rf "$SHARE/src" && cp -R "$HERE/src" "$SHARE/src"
else
    say "скачиваю github.com/$REPO"
    TMP="$(mktemp -d)"
    curl -fsSL "https://github.com/$REPO/archive/refs/heads/main.tar.gz" | tar xz -C "$TMP" --strip-components=1
    rm -rf "$SHARE/src" && cp -R "$TMP/src" "$SHARE/src"
    rm -rf "$TMP"
fi

cat > "$BIN" <<EOF
#!/bin/sh
PYTHONPATH="$SHARE/src" exec python3 -m staytun "\$@"
EOF
chmod +x "$BIN"

say "готово: $BIN"
case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *) say "добавь в PATH: echo 'export PATH=\"$PREFIX/bin:\$PATH\"' >> ~/.zshrc && exec zsh" ;;
esac
say "дальше: подключи VPN → staytun doctor → staytun on"
