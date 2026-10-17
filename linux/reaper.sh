#!/bin/bash
# reaper.sh — tear the daemon + firewall down when the tray it watches dies.
#
# Usage: reaper.sh <TRAY_PID>
#
# Spawned detached by start.sh once the tray is up. tray.py's own atexit/signal
# handlers cover a clean exit; this covers SIGKILL, an X/Wayland disconnect and
# a hard session teardown.
#
# It must NEVER fire during a tray-driven restart: start.sh kills the old tray
# on purpose in order to replace it. Two guards below make that safe even when
# start.sh failed to kill this reaper first.

set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
for _p in "$APP_DIR/lib/platform.sh" "$APP_DIR/platform.sh" \
          "$APP_DIR/../share/DPIGate/lib/platform.sh"; do
    [ -f "$_p" ] && { . "$_p"; break; }
done
if [ -z "${PLAT_SH_LOADED:-}" ]; then
    echo "FATAL: lib/platform.sh not found next to $0" >&2; exit 1
fi

WATCH_PID="${1:-}"
case "$WATCH_PID" in
    ''|*[!0-9]*) echo "usage: $0 <tray-pid>" >&2; exit 2 ;;
esac

# PLAT_STATE_DIR override keeps this testable without root (single state-dir
# namespace shared with the other scripts).
DATA_DIR="${PLAT_STATE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/DPIGate}"
RESTART_MARKER="$DATA_DIR/restart.pid"
REAPER_LOG="$DATA_DIR/reaper.log"
mkdir -p "$DATA_DIR" 2>/dev/null || true

_rlog() { echo "[reaper] $*" >> "$REAPER_LOG" 2>/dev/null || true; }

while kill -0 "$WATCH_PID" 2>/dev/null; do sleep 2; done

# Guard 1 — a start.sh restart is in flight. It owns the daemon and it killed
# the tray deliberately. Wait for it to finish instead of tearing down the
# daemon it is starting. 60s cap so a wedged start.sh cannot hang the reaper.
_waited=0
while [ "$_waited" -lt 60 ]; do
    _rp=""
    [ -f "$RESTART_MARKER" ] && _rp="$(cat "$RESTART_MARKER" 2>/dev/null || true)"
    case "$_rp" in ''|*[!0-9]*) _rp=0 ;; esac
    if [ "$_rp" -gt 0 ] && kill -0 "$_rp" 2>/dev/null; then
        [ "$_waited" -eq 0 ] && _rlog "restart in flight (start.sh PID $_rp) — waiting"
        sleep 1
        _waited=$((_waited + 1))
    else
        break
    fi
done

# Guard 2 — a replacement tray is already running; it owns the daemon now.
if [ -n "$(plat_pids_cmdline "$APP_DIR/tray.py")" ]; then
    _rlog "replacement tray alive — not tearing down"
    exit 0
fi

_rlog "tray $WATCH_PID gone - tearing down"
# The tray this watched is already dead, so there is no window to answer a
# password dialog and nobody asked for one: tear down what is reachable
# without root. Declared explicitly instead of relying on kill.sh guessing
# from the absence of a TTY.
exec env PLAT_NOPROMPT=1 "$APP_DIR/kill.sh"
