#!/usr/bin/env sh
set -e
ROOT=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
cd "$ROOT"
[ -x build/sniffer_tui ] || { echo "Lancez: make all"; exit 1; }
if [ "$(id -u)" -ne 0 ]; then
  echo "Relance avec sudo pour capturer..."
  exec sudo "$ROOT/build/sniffer_tui"
fi
exec "$ROOT/build/sniffer_tui"
