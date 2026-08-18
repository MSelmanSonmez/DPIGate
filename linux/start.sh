#!/bin/bash
# start.sh — GoodByeDPI-Plus Linux launcher (start.ps1 counterpart)
#
# Kills existing instances, runs DNS auto-detect, loads firewall rules
# (nftables or iptables, see lib/platform.sh), starts goodbyedpi (root),
# spawns tray.py (user space), exits.
#
# Usage:
#   ./start.sh                    # auto-detect DNS, tray enabled
#   ./start.sh --no-tray          # headless (no tray icon)
#   ./start.sh --no-dns-detect    # use fallback DNS
#   ./start.sh --force-dns=N      # force Nth candidate (0-based, from tray menu)
#   ./start.sh --auto-dns         # ignore the saved DNS choice, re-detect
#   ./start.sh --bypass-all       # bypass every program, not just the list
#   ./start.sh --foreground       # exec goodbyedpi in the foreground (implies
#                                  # --no-tray; for runit-style supervisors)
#
# Requires root for the firewall + goodbyedpi (NFQUEUE + raw socket). Tray
# runs as user. If goodbyedpi has cap_net_raw+cap_net_admin via setcap, root
# is only needed for the firewall load. See lib/platform.sh for the
# distro/init/firewall/privilege-escalation portability layer.

set -e

# ── Config ───────────────────────────────────────────────────────────────────
BYPASS_MODE="${BYPASS_MODE:--p -q -f 2 -e 2 --native-frag --reverse-frag --frag-by-sni --set-ttl 7 --wrong-seq --max-payload=1200}"

# The firewall rejects outbound QUIC only when the daemon is asked to block it
# (-q / --block-quic); otherwise HTTP/3 must keep working. plat_fw_load reads
# this.
case " $BYPASS_MODE " in
    *" -q "*|*--block-quic*|*" -9 "*) PLAT_BLOCK_QUIC=1 ;;
    *)                                PLAT_BLOCK_QUIC=0 ;;
esac
export PLAT_BLOCK_QUIC

# ── Paths ────────────────────────────────────────────────────────────────────
APP_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Load the portability layer ──────────────────────────────────────────────
for _p in "$APP_DIR/lib/platform.sh" "$APP_DIR/platform.sh" \
          "$APP_DIR/../share/GoodbyeDPI-Plus/lib/platform.sh"; do
    [ -f "$_p" ] && { . "$_p"; break; }
done
if [ -z "${PLAT_SH_LOADED:-}" ]; then
    echo "FATAL: lib/platform.sh not found next to $0" >&2; exit 1
fi

# The caller may have handed us the sudo password with an env prefix
# (`SUDO_PASSWORD=... this-script`). Keep the value, drop the export bit,
# before anything below forks — otherwise every child inherits the plaintext
# password in its environment. See plat_password_unexport in lib/platform.sh.
plat_password_unexport

# die MSG — fatal error on stderr AND as a desktop notification, then exit 1.
# Launched from the .desktop entry there is no terminal (Terminal=false) and
# tray.py's restart path sends stdout/stderr to DEVNULL, so an stderr-only
# failure is indistinguishable from "nothing happened".
die() {
    echo "ERROR: $*" >&2
    notify-send -a "GoodByeDPI-Plus" -i dialog-error "GoodByeDPI-Plus" "$*" 2>/dev/null || true
    exit 1
}

DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/GoodbyeDPI-Plus"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/GoodbyeDPI-Plus"
SETTINGS_FILE="$CONFIG_DIR/settings"
PID_FILE="$DATA_DIR/goodbyedpi.pid"
RESTART_MARKER="$DATA_DIR/restart.pid"
GDPI_LOG="$DATA_DIR/goodbyedpi.log"
# _config_get KEY DEFAULT — read a KEY=VALUE line from the settings file
# ($CONFIG_DIR/settings, written by the tray). Echoes DEFAULT when the file,
# the key, or the value is missing; last occurrence wins.
#
# The `| tail | cut` pipeline is load-bearing under `set -e`: a bare
# val="$(grep ...)" exits the script when the key is absent (grep rc 1).
# The pipeline's status is cut's (0), so a missing key degrades to DEFAULT.
_config_get() {
    local key="$1" default="$2" val=""
    if [ -f "$SETTINGS_FILE" ]; then
        val="$(grep "^${key}=" "$SETTINGS_FILE" 2>/dev/null | tail -n1 | cut -d= -f2-)"
    fi
    [ -n "$val" ] && printf '%s\n' "$val" || printf '%s\n' "$default"
}

# ProgramFilters resolution: user override, then user config, then system-wide
# (root-mode / OpenRC / runit installs — see install.sh --system).
if [ -n "${GDPI_PROGRAMS:-}" ] && [ -f "$GDPI_PROGRAMS" ]; then
    PROGRAMS_LIST="$GDPI_PROGRAMS"
elif [ -f "$CONFIG_DIR/ProgramFilters" ]; then
    PROGRAMS_LIST="$CONFIG_DIR/ProgramFilters"
elif [ -f /etc/GoodbyeDPI-Plus/ProgramFilters ]; then
    PROGRAMS_LIST="/etc/GoodbyeDPI-Plus/ProgramFilters"
else
    PROGRAMS_LIST="$CONFIG_DIR/ProgramFilters"
fi
# Icon: try same dir first (regular install), then share dir (AppImage).
# Fall back to "network-server" (standard GTK theme icon) if neither exists.
if [ -f "$APP_DIR/icon.png" ]; then
    ICON_PATH="$APP_DIR/icon.png"
elif [ -f "$APP_DIR/../share/GoodbyeDPI-Plus/icon.png" ]; then
    ICON_PATH="$APP_DIR/../share/GoodbyeDPI-Plus/icon.png"
else
    ICON_PATH="network-server"
fi
# NFT rules: same dir first, then share dir (AppImage layout).
if [ -f "$APP_DIR/goodbyedpi.nft" ]; then
    NFT_FILE="$APP_DIR/goodbyedpi.nft"
elif [ -f "$APP_DIR/../share/GoodbyeDPI-Plus/goodbyedpi.nft" ]; then
    NFT_FILE="$APP_DIR/../share/GoodbyeDPI-Plus/goodbyedpi.nft"
fi
# Binary: same dir, then share dir (AppImage ships binary in usr/bin).
if [ -f "$APP_DIR/goodbyedpi" ]; then
    GOODBYEDPI_BIN="$APP_DIR/goodbyedpi"
elif [ -f "$APP_DIR/../share/GoodbyeDPI-Plus/goodbyedpi" ]; then
    GOODBYEDPI_BIN="$APP_DIR/../share/GoodbyeDPI-Plus/goodbyedpi"
fi

# _pick_exec_dir — first of $DATA_DIR/bin, $XDG_RUNTIME_DIR, $TMPDIR, /tmp
# that is actually writable AND executable (real exec test, not just -w).
# Fixes the noexec-/tmp failure mode: some hardened hosts mount /tmp noexec.
_pick_exec_dir() {
    local d t
    for d in "$DATA_DIR/bin" "${XDG_RUNTIME_DIR:-}" "${TMPDIR:-}" "/tmp"; do
        [ -n "$d" ] || continue
        mkdir -p "$d" 2>/dev/null || continue
        # mktemp, not ".gdpi-exec-test-$$": $$ is predictable, and $d can be
        # /tmp. A symlink pre-planted at that name would make this write
        # truncate someone else's file, and the chmod +x / execute that
        # follows would then run whatever landed there.
        t="$(mktemp "$d/.gdpi-exec-test-XXXXXX" 2>/dev/null)" || continue
        printf '#!/bin/sh\nexit 0\n' > "$t" 2>/dev/null || { rm -f "$t"; continue; }
        chmod +x "$t" 2>/dev/null || { rm -f "$t"; continue; }
        if "$t" 2>/dev/null; then rm -f "$t"; echo "$d"; return 0; fi
        rm -f "$t"
    done
    return 1
}

# ── AppImage / read-only fs: copy binary to writable+executable dir ─────────
# squashfs is read-only; xattrs (capabilities) can't be stored.

# ── Single EXIT handler ─────────────────────────────────────────────────────
# One trap only — a second `trap … EXIT` replaces the first, it does not chain.
GITMP=""
GDPI_STAGED=0        # 1 once the daemon is running out of $GITMP
MARKER_OWNED=0       # 1 once WE wrote $RESTART_MARKER
_cleanup() {
    [ "$MARKER_OWNED" -eq 1 ] && rm -f "$RESTART_MARKER"
    # Never delete the staging dir while the daemon runs from it.
    [ -n "$GITMP" ] && [ "$GDPI_STAGED" -eq 0 ] && rm -rf "$GITMP"
    return 0
}
trap _cleanup EXIT

if [ -f "$GOODBYEDPI_BIN" ] && [ ! -w "$GOODBYEDPI_BIN" ]; then
    if EXEC_DIR="$(_pick_exec_dir)"; then
        GITMP="$(mktemp -d "$EXEC_DIR/goodbyedpi-XXXXXX")"
        cp "$GOODBYEDPI_BIN" "$GITMP/goodbyedpi"
        GOODBYEDPI_BIN="$GITMP/goodbyedpi"
        chmod +x "$GOODBYEDPI_BIN"
        # Also copy nft file so load_nft finds it
    fi
fi

# Fallback DNS (used when --no-dns-detect or detection fails, or python3 missing)
FALLBACK_DNS_ADDR="1.1.1.1"
FALLBACK_DNS_PORT="53"
FALLBACK_DNS_V6="2606:4700:4700::1111"
FALLBACK_DNS_V6PORT="53"

# ── Parse args ───────────────────────────────────────────────────────────────
ENABLE_TRAY=1
AUTO_DETECT_DNS=1
FORCE_DNS_INDEX=-1
BYPASS_ALL=0
BYPASS_ALL_FROM_CLI=0
DNS_FROM_CLI=0
DEBUG_PROC=0
SKIP_NFT=0
FOREGROUND=0
GDPI_RESTART=0
GDPI_FORCE_NAT=0
for arg in "$@"; do
    case "$arg" in
        --no-tray)         ENABLE_TRAY=0 ;;
        --no-dns-detect)   AUTO_DETECT_DNS=0 ;;
        --force-dns=*)     FORCE_DNS_INDEX="${arg#*=}"; DNS_FROM_CLI=1 ;;
        --auto-dns)        FORCE_DNS_INDEX=-1; DNS_FROM_CLI=1 ;;
        --bypass-all)      BYPASS_ALL=1; BYPASS_ALL_FROM_CLI=1 ;;
        --no-bypass-all)   BYPASS_ALL=0; BYPASS_ALL_FROM_CLI=1 ;;
        --debug-proc)      DEBUG_PROC=1 ;;
        --debug-proc=*)    DEBUG_PROC=1; DEBUG_PROC_LIMIT="${arg#*=}" ;;
        --skip-nft)        SKIP_NFT=1 ;;
        --foreground)      FOREGROUND=1 ;;
        --help|-h)
            sed -n '2,20p' "$0"
            exit 0 ;;
        --restart)         GDPI_RESTART=1 ;;
        --force-nat)       GDPI_FORCE_NAT=1 ;;
    esac
done
# Adopt the settings the tray persisted to $SETTINGS_FILE. A CLI flag always
# wins: --bypass-all/--no-bypass-all and --force-dns=N/--auto-dns each mark
# their setting as CLI-sourced above, so this only fills in what wasn't given.
# Nothing is written back here — start.sh reads settings, the tray writes them.
if [ "$BYPASS_ALL_FROM_CLI" -eq 0 ]; then
    BYPASS_ALL="$(_config_get BYPASS_ALL 0)"
    case "$BYPASS_ALL" in 0|1) ;; *) BYPASS_ALL=0 ;; esac
fi
if [ "$DNS_FROM_CLI" -eq 0 ]; then
    FORCE_DNS_INDEX="$(_config_get FORCE_DNS_INDEX -1)"
fi
# Validate --force-dns before any arithmetic context evaluates it.
case "$FORCE_DNS_INDEX" in
    -1) ;;
    ''|*[!0-9]*) echo "[start] WARN: invalid DNS index '$FORCE_DNS_INDEX' (--force-dns or $SETTINGS_FILE) — using auto-detect" >&2
                 FORCE_DNS_INDEX=-1 ;;
esac
if [ "$FOREGROUND" -eq 1 ] && [ "$ENABLE_TRAY" -eq 1 ]; then
    echo "[start] WARN: --foreground implies --no-tray" >&2
    ENABLE_TRAY=0
fi

# Refuse duplicate start unless --restart is set.
if [ "${GDPI_RESTART:-0}" -eq 0 ] && [ -n "$(plat_gdpi_pids 2>/dev/null)" ]; then
    echo "[start] goodbyedpi is already running. Stop it with: $APP_DIR/kill.sh" >&2
    notify-send -a "GoodByeDPI-Plus" -i "${ICON_PATH:-network-server}" "GoodByeDPI-Plus" \
        "Already running — click Exit in the tray to stop." 2>/dev/null || true
    exit 0
fi

mkdir -p "$DATA_DIR" "$CONFIG_DIR"
# Marker consulted by reaper.sh: while this PID lives, a launch is in flight
# and no reaper may tear the daemon down.
printf '%s\n' "$$" > "$RESTART_MARKER"
MARKER_OWNED=1


# ── Ensure ProgramFilters exists & is up to date ───────────────────────────────
# Seed once, then NEVER clobber user edits. An mtime test cannot tell "shipped
# defaults changed" from "the user edited their copy", so a newer shipped file
# used to silently revert deliberate edits — including deleting every entry,
# which then looked like the tray had forgotten the setting.
#
# .ProgramFilters.shipped records what was last seeded: while the user's file
# still matches it byte for byte the copy is untouched and may be refreshed
# with new defaults; the moment it differs, the file is theirs — hands off.
_SHIPPED_FILTERS="$APP_DIR/ProgramFilters"
_FILTERS_STAMP="$CONFIG_DIR/.ProgramFilters.shipped"
if [ "$PROGRAMS_LIST" = "$CONFIG_DIR/ProgramFilters" ] && [ -f "$_SHIPPED_FILTERS" ]; then
    if [ ! -f "$PROGRAMS_LIST" ]; then
        cp "$_SHIPPED_FILTERS" "$PROGRAMS_LIST"
        cp "$_SHIPPED_FILTERS" "$_FILTERS_STAMP"
    elif ! command -v cmp >/dev/null 2>&1 || [ ! -f "$_FILTERS_STAMP" ]; then
        # Cannot prove the copy is unmodified (no cmp, or an install predating
        # the stamp) → assume user-owned and leave it. Record what is shipped
        # now so a later defaults change can still be detected.
        cp "$_SHIPPED_FILTERS" "$_FILTERS_STAMP" 2>/dev/null || true
    elif cmp -s "$PROGRAMS_LIST" "$_FILTERS_STAMP" \
         && ! cmp -s "$_SHIPPED_FILTERS" "$_FILTERS_STAMP"; then
        cp "$_SHIPPED_FILTERS" "$PROGRAMS_LIST"
        cp "$_SHIPPED_FILTERS" "$_FILTERS_STAMP"
        echo "[start] ProgramFilters refreshed from shipped defaults (was unmodified)" >&2
    fi
fi
if [ ! -f "$PROGRAMS_LIST" ]; then
    # Only a fact, never a mode change: with BYPASS_ALL=0 the block further
    # down creates an empty list and bypasses nothing; with BYPASS_ALL=1 the
    # list is irrelevant.
    echo "[start] WARN: no ProgramFilters at '$PROGRAMS_LIST' and none shipped in $APP_DIR" >&2
fi

# ── Check binary (BEFORE any destructive action) ─────────────────────────────
# Validate first: the kill region below tears down the running daemon AND the
# tray, so bailing out after it would leave the user with no tray and no way
# to restart from the GUI (this is what made the tray-driven DNS re-test look
# like "closes and never comes back").
if [ -z "${GOODBYEDPI_BIN:-}" ] || [ ! -x "$GOODBYEDPI_BIN" ]; then
    die "goodbyedpi binary not found at '${GOODBYEDPI_BIN:-$APP_DIR/goodbyedpi}'. Run 'make' in $APP_DIR first."
fi

# ── VirtualBox NAT detection ──────────────────────────────────────────────
# VirtualBox's slirp NAT terminates the guest's TCP connection and
# regenerates it from the host side. This reassembles fragmented TLS
# ClientHellos, strips TTL manipulation, and consumes fake/desync packets
# before they reach the ISP — the fragmentation/desync DPI bypass engine
# is structurally ineffective. DNS override (resolvectl) still works, but
# SNI bypass for sites like discord.com cannot succeed under NAT.
DEFAULT_GW="$(ip route show default 2>/dev/null | awk '/^default/ {print $3; exit}')"
case "$DEFAULT_GW" in
    10.0.2.*)
        if [ "${GDPI_FORCE_NAT:-0}" -ne 1 ]; then
            echo "[start] ERROR: VirtualBox NAT detected (gw=$DEFAULT_GW)." >&2
            echo "[start]        The DPI bypass engine cannot work under NAT —" >&2
            echo "[start]        fragmented/desync packets are reassembled by" >&2
            echo "[start]        the NAT stack before reaching the ISP." >&2
            echo "[start]        Switch the VM network to 'Bridged Adapter' in" >&2
            echo "[start]        VirtualBox settings, or override with --force-nat." >&2
            notify-send -a "GoodByeDPI-Plus" -i dialog-error "GoodByeDPI-Plus" \
                "VirtualBox NAT detected — bypass cannot work. Switch to Bridged Adapter." 2>/dev/null || true
            exit 1
        else
            echo "[start] WARN: VirtualBox NAT detected (gw=$DEFAULT_GW) — --force-nat overrides the block." >&2
            echo "[start]       The DPI bypass engine will be ineffective for TCP-based DPI." >&2
        fi
        ;;
esac

# ── Acquire root BEFORE anything destructive ─────────────────────────────────
# Need root for: setcap (once) and the firewall load. plat_run_root (from
# lib/platform.sh) resolves sudo/doas/pkexec/run0 and never silently
# swallows a failure — it logs to $PLAT_LOG and prints one diagnostic line.
#
# Ordering is load-bearing: prompting after the kill region means a cancelled
# password dialog leaves the user with no daemon, no firewall rules and no
# tray to restart from. Asking here, die() aborts while the previous launch
# is still running untouched.
NEED_SUDO=0
if [ "$(id -u)" -ne 0 ]; then
    NEED_SUDO=1
fi

# Single password prompt: credentials from plat_root_acquire are reused by
# subsequent plat_run_root calls (via $SUDO_PASSWORD) without re-prompting.
# rc 2 = the user pressed Cancel: abort with a notification, nothing was
# touched (the kill region below has not run yet). rc 1 = no escalation
# mechanism at all: abort too - the firewall load cannot work.
if [ "$NEED_SUDO" -eq 1 ]; then
    _acq_rc=0
    plat_root_acquire || _acq_rc=$?
    if [ "$_acq_rc" -eq 2 ]; then
        die "Start cancelled — the password prompt was cancelled. Nothing was changed."
    fi
    if [ "$_acq_rc" -ne 0 ]; then
        die "Root access required to load firewall rules. Start cancelled."
    fi
fi

# ── Kill existing goodbyedpi + tray ──────────────────────────────────────────
if [ -f "$PID_FILE" ]; then
    OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        kill "$OLD_PID" 2>/dev/null || true
        sleep 0.3
    fi
    rm -f "$PID_FILE"
fi
# Kill the PREVIOUS launch's reaper FIRST. It watches the tray we are about to
# kill, and would otherwise run kill.sh against the daemon we are starting.
plat_kill_cmdline "$APP_DIR/reaper.sh" || true
plat_kill_cmdline "GoodbyeDPI-Plus/reaper.sh" || true
for _p in $(plat_gdpi_pids); do kill "$_p" 2>/dev/null || true; done
# Exact-path patterns: a bare "tray.py" also TERMs `vim …/tray.py` and friends.
plat_kill_cmdline "$APP_DIR/tray.py" || true
plat_kill_cmdline "GoodbyeDPI-Plus/tray.py" || true

# Wait for goodbyedpi to fully exit and release NFQUEUE num. A killed
# instance lingers briefly on the kernel queue; starting a fresh one
# immediately races it and dies with "nfq_create_queue(N) failed:
# Operation not permitted" → tray shows "goodbyedpi exited unexpectedly".
for _ in $(seq 1 20); do
    [ -n "$(plat_gdpi_pids)" ] || break
    sleep 0.1
done

# ── DNS auto-detection ───────────────────────────────────────────────────────
DNS_ADDR="$FALLBACK_DNS_ADDR"
DNS_PORT="$FALLBACK_DNS_PORT"
DNS_V6="$FALLBACK_DNS_V6"
DNS_V6PORT="$FALLBACK_DNS_V6PORT"
DNS_LABEL="Cloudflare 1.1.1.1:53 (fallback)"
DNS_CURRENT=0
DNS_INFO=""
SYS_DNS_POISONED=0

if command -v python3 >/dev/null 2>&1; then
    # ONE probe run produces the selection, the full candidate list and the
    # system-resolver verdict. Running it twice (the old code did) measured
    # different latencies each time, so the tray header disagreed with the
    # list row it pointed at.
    DETECT_ARGS=()
    if [ "$FORCE_DNS_INDEX" -ge 0 ]; then
        echo "[start] DNS: manual selection (index $FORCE_DNS_INDEX), probing for latencies..." >&2
        DETECT_ARGS=(--force "$FORCE_DNS_INDEX")
    elif [ "$AUTO_DETECT_DNS" -eq 1 ]; then
        echo "[start] DNS auto-detection..." >&2
    fi

    if [ "$FORCE_DNS_INDEX" -ge 0 ] || [ "$AUTO_DETECT_DNS" -eq 1 ]; then
        DETECT_OUT="$(timeout 8 python3 "$APP_DIR/dns_detect.py" "${DETECT_ARGS[@]}" 2>/dev/null || true)"
    fi

    if [ -n "${DETECT_OUT:-}" ]; then
        SEL_LINE="$(echo "$DETECT_OUT" | grep '^SELECTED' || true)"
        if [ -n "$SEL_LINE" ]; then
            IFS=$'\t' read -r _ DNS_NAME DNS_ADDR DNS_PORT DNS_V6 DNS_V6PORT DNS_MS DNS_STATUS <<<"$SEL_LINE"
            if [ "${DNS_MS:--1}" -ge 0 ] 2>/dev/null; then
                DNS_LABEL="$DNS_NAME $DNS_ADDR:$DNS_PORT (${DNS_MS}ms)"
            else
                DNS_LABEL="$DNS_NAME $DNS_ADDR:$DNS_PORT (${DNS_STATUS:-n/a})"
            fi
        fi
        INFO_LINE="$(echo "$DETECT_OUT" | grep '^INFO' || true)"
        [ -n "$INFO_LINE" ] && DNS_INFO="${INFO_LINE#INFO$'\t'}"
        IDX_LINE="$(echo "$DETECT_OUT" | grep '^IDX' || true)"
        if [ -n "$IDX_LINE" ]; then
            DNS_CURRENT="${IDX_LINE#IDX$'\t'}"
            case "$DNS_CURRENT" in ''|*[!0-9]*) DNS_CURRENT=0 ;; esac
        fi
    fi

    if [ -z "$DNS_INFO" ]; then
        # Detection skipped or failed — list the candidates with unknown status
        # so the tray menu still offers a manual choice.
        DNS_INFO="$(python3 -c "
import sys; sys.path.insert(0,'$APP_DIR')
from dns_detect import DNS_CANDIDATES
parts=[f'{n}|{a}|{p}|-1|unknown' for n,a,p,v6,v6p in DNS_CANDIDATES]
print(';'.join(parts))
" 2>/dev/null || true)"
    fi
else
    echo "[start] WARN: python3 missing — DNS auto-detect disabled, using fallback" >&2
fi

# DNS redirect is intentionally NOT done: goodbyedpi.nft:40 (`oifname "lo"
# accept`) and :52 (`meta skuid 0 return`) make systemd-resolved's DNS
# packets bypass the NFQUEUE entirely, so --dns-addr would be a dead path.
# Instead, we detect whether the system resolver is poisoned and report it.
SYS_DNS_LINE="$(echo "${DETECT_OUT:-}" | grep '^SYSDNS' || true)"
IFS=$'\t' read -r _ SYS_DNS_ADDR SYS_DNS_VERDICT SYS_DNS_ANSWER <<<"$SYS_DNS_LINE" || true
if [ "${SYS_DNS_VERDICT:-}" = "poisoned" ]; then
    SYS_DNS_POISONED=1
    echo "[start] WARN: system DNS ($SYS_DNS_ADDR) is poisoned — discord.com -> $SYS_DNS_ANSWER" >&2
    echo "[start]       Overriding system resolver upstream to $DNS_ADDR:53 (reverted on exit)." >&2
else
    echo "[start] DNS: system resolver ${SYS_DNS_ADDR:-unknown} (${SYS_DNS_VERDICT:-unknown}), fastest clean server $DNS_ADDR:$DNS_PORT" >&2
fi
PARAMS=()
if [ -n "$BYPASS_MODE" ]; then
    # shellcheck disable=SC2206
    PARAMS+=($BYPASS_MODE)
fi
PARAMS+=(--queue "$PLAT_QUEUE_NUM")
# _has_entries FILE — rc 0 when the filter file holds at least one real
# (non-comment, non-blank) program entry.
_has_entries() {
    [ -f "$1" ] && grep -c -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$1" 2>/dev/null | grep -qv '^0$'
}
if [ "$BYPASS_ALL" -eq 0 ]; then
    # Per-program mode honours the list exactly as it stands. An empty list
    # means "bypass nothing" and is left that way: the mode is the user's
    # setting, and only the user may change it. Promoting an empty list to
    # bypass-all would silently route ALL traffic through the bypass that the
    # user deliberately turned off.
    #
    # goodbyedpi die()s when --only-programs names a file it cannot open
    # (goodbyedpi.c:751-754), whereas a 0-entry file is a valid gate that
    # matches nothing (proctrack_linux.c:1103 only rejects n < 0). So make
    # sure the file exists, then always pass it.
    if [ ! -f "$PROGRAMS_LIST" ]; then
        : > "$PROGRAMS_LIST" 2>/dev/null || true
    fi
    if [ ! -r "$PROGRAMS_LIST" ]; then
        die "cannot read or create $PROGRAMS_LIST - per-program mode needs a filter list. Fix the permissions on $CONFIG_DIR, or enable Bypass All Traffic in the tray."
    fi
    PARAMS+=(--only-programs "$PROGRAMS_LIST")
    if ! _has_entries "$PROGRAMS_LIST"; then
        # Loud, but purely informational: the mode is NOT changed.
        echo "[start] WARN: ProgramFilters is empty - per-program mode bypasses nothing" >&2
        notify-send -a "GoodByeDPI-Plus" -i "${ICON_PATH:-network-server}" "GoodByeDPI-Plus" \
            "ProgramFilters is empty - no traffic is being bypassed" 2>/dev/null || true
    fi
fi
if [ "$DEBUG_PROC" -eq 1 ]; then
    PARAMS+=(--debug-proc)
    [ -n "${DEBUG_PROC_LIMIT:-}" ] && PARAMS+=(--debug-proc="$DEBUG_PROC_LIMIT")
fi

# ── Load firewall rules (nft or iptables, via lib/platform.sh) ─────────────
# goodbyedpi needs NFQUEUE to receive packets. Degrades gracefully: if no
# backend is usable, goodbyedpi still starts but receives no packets, and
# that fact is logged (never fails silently).
load_nft() {
    # Record the outcome where a NON-ROOT caller can read it. tray-launcher.sh
    # runs us with >/dev/null 2>&1, so the WARNs below are discarded: without
    # this marker a failed load is completely invisible and the user gets a
    # healthy-looking tray icon over a totally inert bypass.
    _fw_state() { printf '%s\n' "$1" > "$DATA_DIR/fw_state" 2>/dev/null || true; }
    if [ "$SKIP_NFT" -eq 1 ]; then
        _fw_state skipped
        return 0
    fi
    export PLAT_NFT_FILE="$NFT_FILE"
    _fw_rc=0
    plat_fw_preflight || _fw_rc=$?
    if [ "$_fw_rc" -eq 2 ]; then
        die "Start cancelled — the password prompt was cancelled."
    fi
    if [ "$_fw_rc" -ne 0 ]; then
        echo "[start] WARN: firewall preflight failed — goodbyedpi will receive no packets" >&2
        _fw_state failed
        return 0
    fi
    _fw_rc=0
    plat_fw_load || _fw_rc=$?
    if [ "$_fw_rc" -eq 2 ]; then
        die "Start cancelled — the password prompt was cancelled."
    fi
    if [ "$_fw_rc" -ne 0 ]; then
        echo "[start] WARN: firewall rule load failed (backend=$(plat_fw_backend 2>/dev/null || echo none)) — goodbyedpi will receive no packets" >&2
        _fw_state failed
        return 0
    fi
    _fw_state ok
}

# Domains like discord.com are poisoned in upstream DNS. --dns-addr via NFQUEUE
# is a dead path (see comment at DNS detection above), so we change the system
# resolver's upstream to the discovered clean server and revert via kill.sh's
# dns_override marker. resolvectl is runtime-only (reset by reboot/NM restart).
if [ "${SYS_DNS_POISONED:-0}" -eq 1 ] && [ -n "${DNS_ADDR:-}" ] \
   && command -v resolvectl >/dev/null 2>&1; then
    DEF_IFACE="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"
    if [ -n "$DEF_IFACE" ]; then
        _dns_rc=0
        if plat_run_root resolvectl dns "$DEF_IFACE" "$DNS_ADDR" \
           && plat_run_root resolvectl domain "$DEF_IFACE" '~.' ; then
            plat_run_root resolvectl flush-caches 2>/dev/null || true
            printf '%s\n' "$DEF_IFACE" > "$DATA_DIR/dns_override"
            echo "[start] system DNS upstream set to $DNS_ADDR (iface=$DEF_IFACE, reverted on exit)" >&2
        else
            _dns_rc=$?
            if [ "$_dns_rc" -eq 2 ]; then
                die "Start cancelled — the password prompt was cancelled."
            fi
            echo "[start] WARN: system DNS override failed — discord.com may still be poisoned" >&2
        fi
    fi
fi

# Set caps so goodbyedpi can bind NFQUEUE as a regular user, avoiding the
# sudo-wrapper pitfalls (SIGHUP death on start.sh exit, wrong PID tracking).
GDPI_HAS_CAPS=0
if command -v setcap >/dev/null 2>&1; then
    _cap_rc=0
    plat_run_root setcap cap_net_raw,cap_net_admin+ep "$GOODBYEDPI_BIN" || _cap_rc=$?
    if [ "$_cap_rc" -eq 2 ]; then
        die "Start cancelled — the password prompt was cancelled."
    fi
    if [ "$_cap_rc" -eq 0 ]; then
        GDPI_HAS_CAPS=1
    fi
fi
# find_gdpi_pid — real goodbyedpi PID (comm == goodbyedpi), newest first.
# Never matches a sudo/setsid wrapper (their comm is "sudo"/"setsid").
find_gdpi_pid() {
    local pid
    for pid in $(plat_pids_comm goodbyedpi | sort -rn); do
        # Confirm this process belongs to our queue before trusting it.
        if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null \
           | grep -q -- "--queue $PLAT_QUEUE_NUM"; then
            echo "$pid"
            return 0
        fi
    done
    return 1
}

# ── Start goodbyedpi ─────────────────────────────────────────────────────────
start_goodbyedpi() {
    # Run in its own session via setsid so it survives start.sh exiting
    # (immune to SIGHUP). Caps already set on the binary → runs as the
    # user, no sudo wrapper, so $! is goodbyedpi itself and PID tracking is
    # trivial. Sudo+setsid is the fallback when caps couldn't be set.
    local tries=0
    : > "$GDPI_LOG"
    while [ $tries -lt 2 ]; do
        if [ $tries -eq 0 ]; then
            if command -v setsid >/dev/null 2>&1; then
                setsid "$GOODBYEDPI_BIN" "${PARAMS[@]}" >>"$GDPI_LOG" 2>&1 < /dev/null &
            else
                nohup "$GOODBYEDPI_BIN" "${PARAMS[@]}" >>"$GDPI_LOG" 2>&1 < /dev/null &
            fi
        elif [ "$NEED_SUDO" -eq 1 ]; then
            # Password goes over the child's stdin — NEVER into argv, which is
            # world-readable via /proc/PID/cmdline. "${PARAMS[@]}" (not [*])
            # so a path with spaces stays one argument.
            if [ -n "${SUDO_PASSWORD:-}" ]; then
                if command -v setsid >/dev/null 2>&1; then
                    printf '%s\n' "$SUDO_PASSWORD" \
                        | setsid sudo -S -- "$GOODBYEDPI_BIN" "${PARAMS[@]}" >>"$GDPI_LOG" 2>&1 &
                else
                    printf '%s\n' "$SUDO_PASSWORD" \
                        | nohup sudo -S -- "$GOODBYEDPI_BIN" "${PARAMS[@]}" >>"$GDPI_LOG" 2>&1 &
                fi
            else
                if command -v setsid >/dev/null 2>&1; then
                    setsid sudo -n -- "$GOODBYEDPI_BIN" "${PARAMS[@]}" >>"$GDPI_LOG" 2>&1 < /dev/null &
                else
                    nohup sudo -n -- "$GOODBYEDPI_BIN" "${PARAMS[@]}" >>"$GDPI_LOG" 2>&1 < /dev/null &
                fi
            fi
        else
            break
        fi
        # Give the process time to bind the queue (or die trying).
        sleep 0.5
        GDPI_PID=$(find_gdpi_pid || true)
        [ -n "$GDPI_PID" ] && break
        tries=$((tries+1))
    done

    if [ -z "$GDPI_PID" ]; then
        echo "[start] last goodbyedpi output:" >&2
        tail -n 20 "$GDPI_LOG" >&2
        die "cannot start goodbyedpi (need setcap or passwordless sudo) — see $GDPI_LOG"
    fi
    echo "$GDPI_PID" > "$PID_FILE"
    GDPI_STAGED=1
}

# ── Execute ──────────────────────────────────────────────────────────────────
load_nft

if [ "$FOREGROUND" -eq 1 ]; then
    # runit-style supervised mode: exec goodbyedpi directly (no PID file, no
    # detach). The supervisor owns the process lifecycle.
    : > "$GDPI_LOG"
    echo "[start] running in foreground (PID $$)" >&2
    _cleanup
    MARKER_OWNED=0
    exec "$GOODBYEDPI_BIN" "${PARAMS[@]}"
fi

start_goodbyedpi

# Health check — goodbyedpi can exit between PID write and here.
# Clean up PID_FILE so tray-launcher doesn't read a dead PID and
# tray.py shows "exited unexpectedly".
sleep 0.5
if ! kill -0 "$GDPI_PID" 2>/dev/null; then
    rm -f "$PID_FILE"
    echo "[start] last goodbyedpi output:" >&2
    tail -n 20 "$GDPI_LOG" >&2
    die "goodbyedpi exited immediately — check firewall rules + capabilities; see $GDPI_LOG"
fi

echo "[start] goodbyedpi started (PID $GDPI_PID)" >&2

# ── Tray precondition probe ─────────────────────────────────────────────────
# Check python3/gi/GTK3 up front so a missing stack fails clearly and stops
# the daemon (see below), rather than crashing tray.py after the fact.
TRAY_PRECONDITION_OK=0
if command -v python3 >/dev/null 2>&1 && \
   python3 -c 'import gi; gi.require_version("Gtk", "3.0")' >/dev/null 2>&1; then
    TRAY_PRECONDITION_OK=1
fi
if [ "$ENABLE_TRAY" -eq 1 ] && [ "$TRAY_PRECONDITION_OK" -eq 0 ]; then
    # The daemon must NEVER run without a visible tray (see tray.py's Null-
    # tier refusal and tray-launcher.sh's precondition probe for the other
    # two entry points guarding the same invariant) — degrading to headless
    # here would be exactly the bug this fixes. Tear the just-started
    # daemon down and refuse, rather than silently flip ENABLE_TRAY=0.
    "$APP_DIR/kill.sh" >/dev/null 2>&1 || true
    die "tray unavailable (python3-gi/GTK3 missing) — refusing to run without a visible tray. Pass --no-tray only for supervised/headless deployments (systemd/OpenRC/runit units)."
fi

# ── Spawn tray (user space) ──────────────────────────────────────────────────
if [ "$ENABLE_TRAY" -eq 1 ]; then
    # Tray must run as the user, not root — use SUDO_USER.
    # CRITICAL: `env VAR=... sudo -u` DROPS vars (sudo sanitizes env).
    # Put env INSIDE sudo so the tray inherits them. Also forward
    # DISPLAY/WAYLAND/DBUS/XDG_RUNTIME_DIR so the GUI + xdg-open work.
    #
    # This is a privilege DROP (root -> TRAY_USER), not an escalation, so it
    # stays a direct `sudo -u` call rather than plat_run_root (which only
    # models escalating TO root).
    TRAY_USER="${SUDO_USER:-${USER:-$(id -un 2>/dev/null || true)}}"
    TRAY_UID="$(id -u "$TRAY_USER" 2>/dev/null || true)"
    USER_HOME="$(getent passwd "$TRAY_USER" 2>/dev/null | cut -d: -f6)"
    if [ -z "$TRAY_USER" ] || [ -z "$TRAY_UID" ] || [ -z "$USER_HOME" ]; then
        "$APP_DIR/kill.sh" >/dev/null 2>&1 || true
        die "cannot resolve the desktop user (SUDO_USER/USER unset) — refusing to run a daemon with no tray."
    fi

    # ── Ensure the systemd user service is installed (best-effort) ──────────
    # The tray's "Auto Start" toggle needs goodbyedpi.service in
    # ~/.config/systemd/user/. plat_service_install is init-agnostic; on
    # OpenRC/runit hosts there is no per-user service (see lib/platform.sh),
    # so this only does anything meaningful under systemd.
    #
    # Also copy ALL runtime files (incl. lib/) to ~/.local/share/GoodbyeDPI-Plus/
    # so the systemd service (and platform.sh itself) can find them at boot.
    USER_DATA_DIR="$USER_HOME/.local/share/GoodbyeDPI-Plus"
    mkdir -p "$USER_DATA_DIR" "$USER_DATA_DIR/lib"
    for f in goodbyedpi start.sh kill.sh reaper.sh tray.py tray-launcher.sh dns_detect.py icon.png goodbyedpi.nft goodbyedpi.service; do
        if [ -f "$APP_DIR/$f" ]; then
            if [ ! -f "$USER_DATA_DIR/$f" ] || [ "$APP_DIR/$f" -nt "$USER_DATA_DIR/$f" ]; then
                cp "$APP_DIR/$f" "$USER_DATA_DIR/"
            fi
        fi
    done
    for f in "$APP_DIR"/lib/*.sh; do
        [ -f "$f" ] || continue
        base="$(basename "$f")"
        if [ ! -f "$USER_DATA_DIR/lib/$base" ] || [ "$f" -nt "$USER_DATA_DIR/lib/$base" ]; then
            cp "$f" "$USER_DATA_DIR/lib/"
        fi
    done
    # Glob, not a hand-kept list — tray-launcher.sh was missing here too,
    # leaving Auto Start dead on the AppImage self-install path.
    chmod +x "$USER_DATA_DIR/goodbyedpi" "$USER_DATA_DIR"/*.sh "$USER_DATA_DIR"/*.py 2>/dev/null || true

    # Set capabilities so goodbyedpi can run without root via systemd
    if command -v setcap >/dev/null 2>&1; then
        plat_run_root setcap cap_net_raw,cap_net_admin+ep "$USER_DATA_DIR/goodbyedpi" || true
    fi

    if plat_service_available && ! plat_service_is_enabled >/dev/null 2>&1 && [ ! -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/goodbyedpi.service" ]; then
        plat_service_install && echo "[start] installed service (init=$(plat_init_system))" >&2 || true
    fi

    # Read the user's graphical session env via lib/platform.sh's
    # desktop-list-free discovery (logind -> /proc scan -> last resort).
    SESSION_ENV="$(plat_session_env "$TRAY_USER" 2>/dev/null || true)"
    USER_DISPLAY=$(printf '%s\n' "$SESSION_ENV" | grep -m1 '^DISPLAY=' | cut -d= -f2-)
    USER_WAYLAND=$(printf '%s\n' "$SESSION_ENV" | grep -m1 '^WAYLAND_DISPLAY=' | cut -d= -f2-)
    USER_DBUS=$(printf '%s\n' "$SESSION_ENV" | grep -m1 '^DBUS_SESSION_BUS_ADDRESS=' | cut -d= -f2-)
    USER_XDG_RUNTIME=$(printf '%s\n' "$SESSION_ENV" | grep -m1 '^XDG_RUNTIME_DIR=' | cut -d= -f2-)
    USER_XDG_CONFIG=$(printf '%s\n' "$SESSION_ENV" | grep -m1 '^XDG_CONFIG_HOME=' | cut -d= -f2-)
    USER_XDG_DATA=$(printf '%s\n' "$SESSION_ENV" | grep -m1 '^XDG_DATA_HOME=' | cut -d= -f2-)
    USER_XDG_DESKTOP=$(printf '%s\n' "$SESSION_ENV" | grep -m1 '^XDG_CURRENT_DESKTOP=' | cut -d= -f2-)

    TRAY_ENV=(
        GDPI_PID="$GDPI_PID"
        GDPI_PROGRAMS="$PROGRAMS_LIST"
        GDPI_START_SH="$APP_DIR/start.sh"
        GDPI_ICON="$ICON_PATH"
        GDPI_DNS_LABEL="$DNS_LABEL"
        GDPI_DNS_CURRENT="$DNS_CURRENT"
        GDPI_DNS_INFO="$DNS_INFO"
        GDPI_BYPASS_ALL="$BYPASS_ALL"
        # The tray's watchdog reloads the firewall if another manager flushes
        # it; it must reproduce the same QUIC policy this run chose.
        PLAT_BLOCK_QUIC="$PLAT_BLOCK_QUIC"
        WAYLAND_DISPLAY="${USER_WAYLAND:-${WAYLAND_DISPLAY:-}}"
        DBUS_SESSION_BUS_ADDRESS="${USER_DBUS:-${DBUS_SESSION_BUS_ADDRESS:-}}"
        XDG_RUNTIME_DIR="${USER_XDG_RUNTIME:-/run/user/$TRAY_UID}"
        XDG_CONFIG_HOME="${USER_XDG_CONFIG:-$USER_HOME/.config}"
        XDG_DATA_HOME="${USER_XDG_DATA:-$USER_HOME/.local/share}"
        XDG_CURRENT_DESKTOP="${USER_XDG_DESKTOP:-${XDG_CURRENT_DESKTOP:-}}"
    )
    if [ -n "$USER_DISPLAY" ]; then
        TRAY_ENV+=(DISPLAY="$USER_DISPLAY")
    fi
    # Spawn tray as the user, not root. When start.sh runs as root (direct
    # sudo or restart_start_sh's `sudo -n start.sh`), drop to SUDO_USER so the
    # tray inherits the user's DBUS/Wayland session and the icon appears.
    # Only spawn directly when we're ALREADY the target user (sudoless run).
    # Log to tray.log for debugging (crash messages, import errors, etc.).
    TRAY_LOG="$DATA_DIR/tray.log"
    : > "$TRAY_LOG"
    if [ "$(id -u)" -eq 0 ] && [ "$TRAY_USER" != "root" ]; then
        sudo -u "$TRAY_USER" env "${TRAY_ENV[@]}" \
            nohup python3 "$APP_DIR/tray.py" >>"$TRAY_LOG" 2>&1 &
    else
        env "${TRAY_ENV[@]}" nohup python3 "$APP_DIR/tray.py" >>"$TRAY_LOG" 2>&1 &
    fi
    disown 2>/dev/null || true
    TRAY_PID=$!
    sleep 0.3
    if kill -0 "$TRAY_PID" 2>/dev/null; then
        echo "[start] tray spawned (PID $TRAY_PID)" >&2
    else
        echo "[start] tray exited immediately — see $TRAY_LOG" >&2
        tail -n 10 "$TRAY_LOG" >&2
        "$APP_DIR/kill.sh" >/dev/null 2>&1 || true
        die "tray exited immediately — refusing to run without a visible tray; see $TRAY_LOG"
    fi
    # Bind the daemon's lifetime to this tray: tray.py's own atexit/signal
    # handlers cover clean exit/logout/SIGTERM, but not crash/SIGKILL/X
    # disconnect. This reaper watches TRAY_PID and tears the daemon +
    # firewall down the moment it disappears by ANY means. setsid so the
    # reaper outlives start.sh; kill.sh is idempotent, so a race with
    # tray.py's own teardown is harmless.
    if [ -n "${TRAY_PID:-}" ] && kill -0 "$TRAY_PID" 2>/dev/null \
       && [ -x "$APP_DIR/reaper.sh" ]; then
        setsid "$APP_DIR/reaper.sh" "$TRAY_PID" </dev/null >/dev/null 2>&1 &
        disown 2>/dev/null || true
    fi
fi

echo "[start] done" >&2
exit 0
