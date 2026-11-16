# portable-bootstrap.sh — the ONLY text that runs as root before DPIGate's own
# files are trusted. It is NOT executed from a file: AppRun reads it and passes
# it to `plat_run_root /bin/bash -c "$(cat portable-bootstrap.sh)" dpigate-boot ARGS`,
# so no file the user can write is ever run by root.
#
# Arguments (all validated below):
#   $1 uid      the desktop user (digits, not 0)
#   $2 watch    PID whose death means "stop" (the tray; AppRun execs into it)
#   $3 tarball  the payload as a tar file, prepared by the user
#   $4 sha256   hex SHA-256 AppRun computed over that tarball inside the
#               AppImage mount (read-only, so the user cannot alter it)
#   $5 roles    "", "nfq", "tray" or "nfq tray": packages to install
#   $6 usercfg  absolute path of the user's settings directory
#   $7 nonce    letters/digits/dots; echoed in the "ready" state so AppRun never
#               mistakes a dead session's leftovers for this one
#
# What it does: make a fresh root-owned run directory, copy the tarball INTO it
# (one read, so nothing can change afterwards), refuse unless the copy's SHA-256
# is the one passed in argv, extract the copy, and hand over to the extracted
# portable-root.sh. Exit codes: 12 hash mismatch, 13 no directory that can run
# programs, 15 another session is still shutting down, 16 bad arguments,
# 17 payload cannot be extracted. Everything else is reported by the helper
# through $RD/data/state.
#
# Trust: the escalation tool (sudo env_reset, pkexec, run0, doas) is trusted to
# hand over a clean environment; the unset below only covers what bash itself
# reads. A caller that is already root and wants a test directory cannot get
# one: the DPIGATE_TEST_BASE override is ignored when the effective uid is 0.

unset BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT
IFS=$' \t\n'
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 022

fail() {   # fail CODE MESSAGE
    echo "[dpigate-boot] ERROR: $2" >&2
    exit "$1"
}

IS_ROOT=0
[ "$(id -u)" = "0" ] && IS_ROOT=1
# Test runs (effective uid != 0, so they gain nothing) may put stub tools first.
if [ "$IS_ROOT" -eq 0 ] && [ -n "${DPIGATE_TEST_PATH:-}" ]; then
    PATH="$DPIGATE_TEST_PATH:$PATH"
fi

uid="${1:-}"; watch="${2:-}"; tarball="${3:-}"; want="${4:-}"
roles="${5:-}"; usercfg="${6:-}"; nonce="${7:-}"

case "$uid" in ''|*[!0-9]*|0|0[0-9]*) fail 16 "bad uid" ;; esac
case "$watch" in ''|*[!0-9]*|0) fail 16 "bad pid to watch" ;; esac
case "$want" in
    *[!0-9a-f]*) fail 16 "bad hash" ;;
esac
[ "${#want}" -eq 64 ] || fail 16 "bad hash"
case "$tarball" in /*) ;; *) fail 16 "tarball path must be absolute" ;; esac
case "$usercfg" in /*) ;; *) fail 16 "settings path must be absolute" ;; esac
case "$nonce" in ''|*[!0-9A-Za-z.]*) fail 16 "bad nonce" ;; esac
[ "${#nonce}" -le 64 ] || fail 16 "bad nonce"
case "$tarball$usercfg" in *$'\n'*) fail 16 "newline in a path" ;; esac
for _r in $roles; do
    case "$_r" in nfq|tray) ;; *) fail 16 "bad role '$_r'" ;; esac
done
if [ "$IS_ROOT" -eq 1 ]; then
    _asked="${PKEXEC_UID:-${SUDO_UID:-}}"
    if [ -n "$_asked" ] && [ "$_asked" != "$uid" ]; then
        fail 16 "uid $uid is not the user who asked for root ($_asked)"
    fi
fi
gid="$(id -g "$uid" 2>/dev/null)" || fail 16 "no such user"
case "$gid" in ''|*[!0-9]*) fail 16 "no such user" ;; esac
# Open the tarball ONCE and judge and copy that open file, never the path again:
# a check on the path followed by a second open is a race (the user may swap the
# path for a symlink in between), and a symlink in a PARENT directory is not
# caught by testing the last component. The kernel's own name for an open file
# never contains a symlink, so it must equal the path we were given.
{ exec 9< "$tarball"; } 2>/dev/null || fail 16 "cannot open the payload tarball"
[ "$(readlink "/proc/$$/fd/9" 2>/dev/null)" = "$tarball" ] \
    || fail 16 "payload tarball path is not canonical (a symlink in it, or '..')"
[ -f "/proc/$$/fd/9" ] || fail 16 "payload tarball is not a regular file"
[ "$(stat -L -c %u "/proc/$$/fd/9" 2>/dev/null)" = "$uid" ] || fail 16 "payload tarball is not owned by uid $uid"

# ── run directory: root-owned, created fresh, parent root-owned ─────────────
if [ "$IS_ROOT" -eq 1 ]; then
    BASES="/run/dpigate /dev/shm/dpigate"
    OWNER=0
else
    BASES="${DPIGATE_TEST_BASE:-/run/dpigate}"
    OWNER="$(id -u)"
fi

prepare_base() {   # prepare_base DIR: a real directory owned by $OWNER, 0755
    local b="$1"
    if [ -e "$b" ] || [ -L "$b" ]; then
        [ -d "$b" ] && [ ! -L "$b" ] || return 1
        [ "$(stat -c %u "$b")" = "$OWNER" ] || return 1
    else
        mkdir -m 0755 "$b" 2>/dev/null || return 1
    fi
    chmod 0755 "$b" 2>/dev/null || return 1
}

RD=""
for base in $BASES; do
    prepare_base "$base" || continue
    cand="$base/$uid"
    # A session of this user that is still shutting down: give it a moment.
    if [ -e "$cand/data/helper.pid" ]; then
        _hp="$(cat "$cand/data/helper.pid" 2>/dev/null)"
        case "$_hp" in ''|*[!0-9]*) _hp=0 ;; esac
        _w=0
        while [ "$_hp" -gt 0 ] && [ -d "/proc/$_hp" ] && [ "$_w" -lt 20 ]; do
            sleep 0.5; _w=$((_w + 1))
        done
        if [ "$_hp" -gt 0 ] && [ -d "/proc/$_hp" ]; then
            fail 15 "a previous DPIGate session (helper $_hp) is still running"
        fi
    fi
    # Anything left behind is a dead session: the new start.sh removes its
    # rules and engine, so only the directory has to go.
    if [ -e "$cand" ] || [ -L "$cand" ]; then
        rm -rf -- "$cand" 2>/dev/null || continue
    fi
    # (the last session of another user may have just removed the then-empty base)
    mkdir -m 0755 "$cand" 2>/dev/null || { prepare_base "$base" && mkdir -m 0755 "$cand" 2>/dev/null; } || continue
    mkdir -m 0755 "$cand/app" "$cand/data" "$cand/cfg" "$cand/fakehome" || { rm -rf -- "$cand"; continue; }
    # Programs must be able to run from here (/run is "noexec" on some hosts).
    if ! cp /bin/true "$cand/.exectest" 2>/dev/null || ! "$cand/.exectest" 2>/dev/null; then
        rm -rf -- "$cand"; continue
    fi
    rm -f "$cand/.exectest"
    RD="$cand"
    break
done
if [ -z "$RD" ]; then
    for base in $BASES; do rmdir -- "$base" 2>/dev/null; done   # only an empty one, only ours
fi
[ -n "$RD" ] || fail 13 "no root-owned directory that can run programs (tried: $BASES)"

# The base directory is removed again by the last session that leaves it empty
# (rmdir: it refuses a directory that still holds another user's run dir).
abort() { rm -rf -- "$RD"; rmdir -- "$(dirname "$RD")" 2>/dev/null; fail "$1" "$2"; }

# ── copy first, then verify THE COPY, then extract the copy ─────────────────
# At most 32 MiB: /run is memory.
( umask 077; head -c 33554433 <&9 > "$RD/payload.tar" ) 2>/dev/null \
    || abort 16 "cannot read the payload tarball"
exec 9<&-
[ "$(stat -c %s "$RD/payload.tar")" -le 33554432 ] || abort 16 "payload tarball is too large"
have="$(sha256sum "$RD/payload.tar" 2>/dev/null | cut -d' ' -f1)"
if [ "$have" != "$want" ]; then
    abort 12 "payload checksum mismatch; refusing to run it as root"
fi
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
    tar -xf "$RD/payload.tar" -C "$RD/app" --no-same-owner || abort 17 "cannot extract the payload"
else
    tar -xf "$RD/payload.tar" -C "$RD/app" || abort 17 "cannot extract the payload"
fi
rm -f "$RD/payload.tar"
if [ "$IS_ROOT" -eq 1 ]; then
    chown -R 0:0 "$RD/app" || abort 17 "cannot take ownership of the payload"
fi
chmod -R go-w "$RD/app"
[ -f "$RD/app/portable-root.sh" ] && [ -f "$RD/app/start.sh" ] || abort 17 "the payload has no portable-root.sh/start.sh"
[ -f "$RD/app/goodbyedpi" ] && chmod 0700 "$RD/app/goodbyedpi"

cd / || exit 1
exec "$BASH" --noprofile --norc "$RD/app/portable-root.sh" "$uid" "$gid" "$watch" "$roles" "$usercfg" "$RD" "$nonce" </dev/null
