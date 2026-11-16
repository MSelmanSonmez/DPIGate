#!/bin/bash
# portable-root.sh — root helper of the AppImage's "run without installing" mode.
#
# Started by portable-bootstrap.sh, from the ROOT-OWNED copy of the payload
# (<run dir>/app), never from a file the user can write. It owns the engine and
# the firewall rules for as long as the tray lives, then removes everything,
# including its own directory.
#
# Usage (internal): portable-root.sh UID GID WATCH_PID ROLES USER_CFG_DIR RUN_DIR NONCE
#
# What it reuses instead of reimplementing:
#   lib/platform.sh   plat_deps_install, plat_fw_is_loaded/plat_fw_load
#   start.sh --no-tray   the same entry the root system service uses: DNS probe,
#                        firewall load, engine start as root (no setcap)
#   reaper.sh         waits for the tray to exit, then runs kill.sh
#   kill.sh           firewall unload, engine stop, DNS override revert
#
# There is NO channel from the user to this process. "Stop" is the death of the
# tray (the tray's PID is WATCH_PID), however it dies: Exit menu, crash, SIGKILL,
# logout. The only user data root reads are ProgramFilters and settings, each
# read as the USER (setpriv) and capped at 64 KiB.

exec 3>&2   # the caller's stderr, kept for error reports after the log redirect

uid="${1:?}"; gid="${2:?}"; watch="${3:?}"; roles="${4:-}"; usercfg="${5:?}"; RD="${6:?}"; nonce="${7:?}"
APP="$RD/app"; DATA="$RD/data"; CFG="$RD/cfg"
IS_ROOT=0
[ "$(id -u)" = "0" ] && IS_ROOT=1

umask 022
cd / || exit 1
echo "$$" > "$DATA/helper.pid"

write_state() {   # write_state "ready PID NONCE": AppRun polls $DATA/state
    printf '%s\n' "$1" > "$DATA/state.tmp" 2>/dev/null \
        && mv -f "$DATA/state.tmp" "$DATA/state" 2>/dev/null
    return 0
}

TD=0
REAPER_PID=0
STARTED=0     # 1 once start.sh was attempted: before that there is nothing of ours to undo
teardown() {
    [ "$TD" -eq 1 ] && return 0
    TD=1
    trap '' TERM INT HUP
    [ "$REAPER_PID" -gt 0 ] && kill "$REAPER_PID" 2>/dev/null
    # kill.sh stops EVERY goodbyedpi on our queue and removes the rules: only run
    # it when this session may have started something (an installed engine that
    # was never ours must survive a failed start of this one).
    if [ "$STARTED" -eq 1 ]; then
        PLAT_NOPROMPT=1 bash "$APP/kill.sh" >>"$DATA/helper.log" 2>&1
    fi
    cd / && rm -rf -- "$RD"
    return 0
}
trap 'teardown; exit 0' TERM INT HUP
trap 'teardown' EXIT

die() {   # die CODE MESSAGE: tell the caller (exit code + stderr), clean up
    echo "[portable-root] ERROR: $2" >&3
    # The run directory (and the log in it) is removed on exit: show the tail now.
    [ -s "$DATA/helper.log" ] && tail -n 20 -- "$DATA/helper.log" >&3 2>/dev/null
    exit "$1"
}

# ── environment: nothing of the user's, nothing under a home directory ──────
export HOME="$RD/home"
export XDG_DATA_HOME="$RD/home/.local/share" XDG_CONFIG_HOME="$RD/home/.config" XDG_CACHE_HOME="$RD/home/.cache"
mkdir -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"
export PLAT_LOG="$DATA/platform.log" PLAT_STATE_DIR="$DATA"
export GDPI_DATA_DIR="$DATA" GDPI_CONFIG_DIR="$CFG" GDPI_PROGRAMS="$CFG/ProgramFilters"
export PLAT_DEPS_RUNTIME_ONLY=1
unset SUDO_PASSWORD DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS

# ── packages: one escalation already happened, so no second prompt ──────────
nfq_missing() {
    local so cache
    cache="$(ldconfig -p 2>/dev/null || /sbin/ldconfig -p 2>/dev/null)"
    for so in libnetfilter_queue.so.1 libnfnetlink.so.0 libmnl.so.0; do
        printf '%s\n' "$cache" | awk -v s="$so" '$1 == s { f = 1 } END { exit !f }' || printf ' %s' "$so"
    done
}
tray_missing() {
    command -v python3 >/dev/null 2>&1 && python3 -I "$APP/lib/tray-probe.py" >/dev/null 2>&1 && return 1
    return 0
}

want_nfq=0; want_tray=0
for r in $roles; do
    case "$r" in nfq) want_nfq=1 ;; tray) want_tray=1 ;; esac
done
if [ "$want_nfq" -eq 1 ] || [ "$want_tray" -eq 1 ]; then
    # shellcheck disable=SC1091
    . "$APP/lib/platform.sh" || die 14 "cannot load lib/platform.sh"
    if [ "$want_nfq" -eq 1 ] && [ "$want_tray" -eq 1 ]; then role=appimage
    elif [ "$want_nfq" -eq 1 ]; then role=nfq
    else role=tray; fi
    plat_deps_install "$role" || echo "[portable-root] package installation reported a failure" >&2
fi
[ -z "$(nfq_missing)" ] || die 10 "runtime libraries missing:$(nfq_missing)"
if tray_missing; then
    die 11 "the tray needs python3 with PyGObject, GTK 3 and AyatanaAppIndicator3 or AppIndicator3"
fi
if [ "${PLAT_SH_LOADED:-}" = "" ]; then
    # shellcheck disable=SC1091
    . "$APP/lib/platform.sh" || die 14 "cannot load lib/platform.sh"
fi

exec >>"$DATA/helper.log" 2>&1

# ── settings: read AS THE USER, never as root ───────────────────────────────
snap() {   # snap SRC DST: copy at most 64 KiB of a user file, as the user
    local src="$1" dst="$2"
    if [ "$IS_ROOT" -eq 1 ] && command -v setpriv >/dev/null 2>&1; then
        setpriv --reuid="$uid" --regid="$gid" --init-groups -- head -c 65536 -- "$src" > "$dst.new" 2>/dev/null \
            || { rm -f "$dst.new"; return 1; }
    else
        # No setpriv (or a test run): only a regular file the user owns.
        [ -f "$src" ] && [ ! -L "$src" ] && [ "$(stat -c %u "$src" 2>/dev/null)" = "$uid" ] \
            || { rm -f "$dst.new"; return 1; }
        head -c 65536 -- "$src" > "$dst.new" 2>/dev/null || { rm -f "$dst.new"; return 1; }
    fi
    chmod 0644 "$dst.new" && mv -f "$dst.new" "$dst"
}
stamp() { stat -L -c '%Y %s' "$1" 2>/dev/null || echo none; }

snap "$usercfg/settings" "$CFG/settings" || rm -f "$CFG/settings"
snap "$usercfg/ProgramFilters" "$CFG/ProgramFilters" || : > "$CFG/ProgramFilters"
last_stamp="$(stamp "$usercfg/ProgramFilters")"

# ── engine ──────────────────────────────────────────────────────────────────
kill -0 "$watch" 2>/dev/null || die 14 "the tray (pid $watch) is already gone"

# --restart: take over a stale engine or rule set instead of "already running".
STARTED=1
bash "$APP/start.sh" --no-tray --restart || die 14 "start.sh failed (see $DATA/helper.log)"

gpid="$(cat "$DATA/goodbyedpi.pid" 2>/dev/null)"
case "$gpid" in ''|*[!0-9]*) die 14 "the engine left no PID file" ;; esac
[ -d "/proc/$gpid" ] || die 14 "the engine exited right away (see $DATA/goodbyedpi.log)"
write_state "ready $gpid $nonce"

# ── watch ───────────────────────────────────────────────────────────────────
# reaper.sh returns only after the tray is gone (and then runs kill.sh itself).
bash "$APP/reaper.sh" "$watch" &
REAPER_PID=$!

tick=0
while kill -0 "$REAPER_PID" 2>/dev/null; do
    sleep 1
    tick=$((tick + 1))
    # The engine died: the firewall rules must not outlive it.
    if [ ! -d "/proc/$gpid" ]; then
        echo "[portable-root] engine $gpid is gone; removing the firewall rules"
        break
    fi
    # ProgramFilters is edited by the user in the tray; the engine reloads the
    # root-owned snapshot when its mtime changes.
    cur="$(stamp "$usercfg/ProgramFilters")"
    if [ "$cur" != "$last_stamp" ]; then
        last_stamp="$cur"
        snap "$usercfg/ProgramFilters" "$CFG/ProgramFilters" || true
    fi
    # Another firewall manager may flush our rules: put them back.
    if [ $((tick % 30)) -eq 0 ]; then
        _rc=0; plat_fw_is_loaded || _rc=$?
        if [ "$_rc" -eq 1 ]; then plat_fw_load || true; fi
    fi
done
teardown
exit 0
