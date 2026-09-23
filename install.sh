#!/usr/bin/env bash
# Install PhishHawk for the current user, no root needed.
#
#   ./install.sh              install (pipx if you have it, otherwise a private virtualenv)
#   ./install.sh --uninstall  remove it again
#
# PHISHHAWK_HOME (default ~/.local/share/phishhawk) and PHISHHAWK_BIN (default
# ~/.local/bin) override where the virtualenv and the command go.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOME_DIR="${PHISHHAWK_HOME:-$HOME/.local/share/phishhawk}"
BIN_DIR="${PHISHHAWK_BIN:-$HOME/.local/bin}"

if [[ -t 1 ]]; then ARROW=$'\033[1;38;5;208m==>\033[0m'; else ARROW="==>"; fi
if [[ -t 2 ]]; then ERROR=$'\033[1;31merror:\033[0m'; else ERROR="error:"; fi
say() { printf '%s %s\n' "$ARROW" "$*"; }
die() { printf '%s %s\n' "$ERROR" "$*" >&2; exit 1; }

if [[ "${1:-}" == "--uninstall" ]]; then
  if command -v pipx >/dev/null 2>&1 && pipx list 2>/dev/null | grep -q "package phishhawk"; then
    pipx uninstall phishhawk
  fi
  rm -f "$BIN_DIR/phishhawk"
  rm -rf "$HOME_DIR"
  say "PhishHawk removed. The lookup cache is left in ~/.cache/phishhawk (delete it if you like)."
  exit 0
fi

command -v python3 >/dev/null 2>&1 || die "python3 not found"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' \
  || die "PhishHawk needs Python 3.10+, found $(python3 --version 2>&1)"

if command -v pipx >/dev/null 2>&1; then
  say "Installing with pipx"
  pipx install --force "$HERE"
  COMMAND="$(command -v phishhawk || echo "$BIN_DIR/phishhawk")"
else
  say "Creating a private virtualenv in $HOME_DIR"
  python3 -m venv "$HOME_DIR" || die "python3 -m venv failed (on Debian/Ubuntu: sudo apt install python3-venv)"
  "$HOME_DIR/bin/python" -m pip install --quiet --upgrade pip
  say "Installing PhishHawk"
  "$HOME_DIR/bin/python" -m pip install --quiet "$HERE"
  mkdir -p "$BIN_DIR"
  ln -sf "$HOME_DIR/bin/phishhawk" "$BIN_DIR/phishhawk"
  COMMAND="$BIN_DIR/phishhawk"
fi

say "Installed: $("$COMMAND" --version)"
case ":$PATH:" in
  *":$BIN_DIR:"*) say "Try it:  phishhawk doctor" ;;
  *) say "Add $BIN_DIR to your PATH, e.g.:  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc" ;;
esac
