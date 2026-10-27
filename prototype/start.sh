#!/usr/bin/env bash
# Ariadne launcher for Linux.
#   ./start.sh              start the app and open it in the browser
#   ./start.sh --install    add Ariadne to the applications menu
#   ./start.sh --uninstall  remove it from the menu again
# Any other arguments go to app.py, e.g. ./start.sh --port 9000
set -euo pipefail

HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
DESKTOP_FILE="${XDG_DATA_HOME:-$HOME/.local/share}/applications/ariadne.desktop"

case "${1:-}" in
  --install)
    mkdir -p "$(dirname "$DESKTOP_FILE")"
    chmod +x "$HERE/start.sh"
    # Terminal=true: the window shows the server log, and closing it stops the app.
    cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=Ariadne
Comment=A friendly guide to Nmap
GenericName=Nmap scanner
Exec="$HERE/start.sh"
Icon=network-workgroup
Terminal=true
Categories=Network;Security;
EOF
    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$(dirname "$DESKTOP_FILE")" || true
    echo "Added Ariadne to the applications menu ($DESKTOP_FILE)."
    exit 0
    ;;
  --uninstall)
    rm -f "$DESKTOP_FILE"
    echo "Removed Ariadne from the applications menu."
    exit 0
    ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  echo "Ariadne needs Python 3. Install it with: sudo apt install python3"
  echo "(or your distribution's package manager)"
  exit 1
fi
if ! command -v nmap >/dev/null 2>&1; then
  echo "Nmap is not installed, so scans will only be simulated."
  echo "Install it with: sudo apt install nmap  (or your distribution's package manager)"
fi

cd "$HERE"
exec python3 app.py --open "$@"
