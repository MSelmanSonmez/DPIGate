#!/bin/bash
# tray-launcher.sh — Launches the DPIGate tray icon independently.
# Designed to be called from ~/.config/autostart/ at login.
#
# Reads the running goodbyedpi PID from the PID file, sets up the
# environment tray.py needs, and spawns it.
#
# This is separate from the systemd service (which runs --no-tray) so
# the DPI bypass works even when no GUI session is active.
#
# Usage:
#   ./tray-launcher.sh           # normal launch (autostart / manual)
#   ./tray-launcher.sh --check   # verify Auto Start state (diagnostic)

set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
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

DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/GoodbyeDPI-Plus"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/GoodbyeDPI-Plus"
PID_FILE="$DATA_DIR/goodbyedpi.pid"
PROGRAMS_LIST="$CONFIG_DIR/ProgramFilters"
SETTINGS_FILE="$CONFIG_DIR/settings"

# _config_get KEY DEFAULT — read a KEY=VALUE line from the settings file the
# tray writes; echoes DEFAULT when the file, the key, or the value is missing.
# The `| tail | cut` pipeline keeps a missing key from tripping `set -e`
# (grep would exit 1 and kill the login-path launcher).
_config_get() {
    local key="$1" default="$2" val=""
    if [ -f "$SETTINGS_FILE" ]; then
        val="$(grep "^${key}=" "$SETTINGS_FILE" 2>/dev/null | tail -n1 | cut -d= -f2-)"
    fi
    [ -n "$val" ] && printf '%s\n' "$val" || printf '%s\n' "$default"
}

ICON_PATH="$APP_DIR/icon.png"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
SERVICE_FILE="$SYSTEMD_USER_DIR/goodbyedpi.service"
DESKTOP_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/autostart/goodbyedpi-tray.desktop"

# ── Check mode: verify all Auto Start components ──────────────────────────
if [ "${1:-}" = "--check" ]; then
    echo "============================================"
    echo " DPIGate — Auto Start Diagnostics"
    echo "============================================"
    echo ""

    # 1. Service — informational ONLY. Auto Start deliberately never enables
    #    it (see tray.py:toggle_service): a headless unit is precisely the
    #    "daemon running with no tray" bug. A leftover enable from an older
    #    version is a warning, never a requirement.
    echo "[1] service (init=$(plat_init_system)) — not used by Auto Start:"
    if [ -f "$SERVICE_FILE" ]; then
        ENABLED_STATE="$(systemctl --user is-enabled goodbyedpi.service 2>&1 || true)"
        echo "    Service file:  $SERVICE_FILE  (exists)"
        echo "    Status:        $ENABLED_STATE"
        if [ "$ENABLED_STATE" = "enabled" ]; then
            echo "    NOTE: legacy headless enable — runs the daemon with no tray."
            echo "          Clear it with: systemctl --user disable goodbyedpi.service"
        fi
    else
        echo "    Service file:  not installed  (expected — Auto Start uses the .desktop)"
    fi
    echo ""

    # 2. Autostart .desktop file
    echo "[2] Autostart .desktop file:"
    if [ -f "$DESKTOP_FILE" ]; then
        echo "    Desktop file:  $DESKTOP_FILE  (exists)"
        DESKTOP_OK=1
    else
        echo "    Desktop file:  $DESKTOP_FILE  (not found)"
        DESKTOP_OK=0
    fi
    echo ""

    # 3. tray-launcher.sh — the .desktop Exec= runs this path DIRECTLY, so a
    #    present-but-non-executable file makes Auto Start silently do nothing
    #    at login. Existence alone is not enough; test the execute bit.
    echo "[3] tray-launcher.sh:"
    LAUNCHER="$DATA_DIR/tray-launcher.sh"
    [ -f "$LAUNCHER" ] || LAUNCHER="$APP_DIR/tray-launcher.sh"
    if [ ! -f "$LAUNCHER" ]; then
        echo "    Script:        not found  [MISSING]"
        LAUNCHER_OK=0
    elif [ ! -x "$LAUNCHER" ]; then
        echo "    Script:        $LAUNCHER  [NOT EXECUTABLE]"
        echo "    Fix: chmod +x $LAUNCHER"
        LAUNCHER_OK=0
    else
        echo "    Script:        $LAUNCHER  (executable)"
        LAUNCHER_OK=1
    fi
    echo ""

    # 4. goodbyedpi process + firewall. A running daemon alone proves nothing:
    #    without the nft rules nothing reaches NFQUEUE and the bypass is inert.
    echo "[4] goodbyedpi process:"
    if [ -f "$PID_FILE" ]; then
        PID_CANDIDATE="$(cat "$PID_FILE" 2>/dev/null)"
        if [ -n "$PID_CANDIDATE" ] && kill -0 "$PID_CANDIDATE" 2>/dev/null; then
            echo "    PID:           $PID_CANDIDATE  (running)"
        else
            echo "    PID file:      stale ($PID_CANDIDATE not running)"
        fi
    else
        echo "    PID file:      not found  (not running)"
    fi
    case "$(cat "$DATA_DIR/fw_state" 2>/dev/null || true)" in
        ok)      echo "    Firewall:      rules loaded  [OK]" ;;
        skipped) echo "    Firewall:      skipped (--skip-nft)" ;;
        failed)  echo "    Firewall:      LOAD FAILED  [!!]  bypass is INACTIVE"
                 echo "                   (no root at start — run start.sh from a terminal)" ;;
        *)       echo "    Firewall:      unknown (daemon has not run yet)" ;;
    esac
    echo ""

    # 5. Overall verdict — the XDG autostart .desktop is the single source of
    #    truth (tray.py:verify_autostart agrees), and it is only useful when
    #    its Exec= target can actually be executed.
    echo "============================================"
    if [ "$DESKTOP_OK" -eq 1 ] && [ "$LAUNCHER_OK" -eq 1 ]; then
        echo " Auto Start:  [ON]  ACTIVE"
        echo " (goodbyedpi + tray will start at login)"
        _verdict=0
    elif [ "$DESKTOP_OK" -eq 1 ]; then
        echo " Auto Start:  [!!]  BROKEN"
        echo " (autostart entry present, but tray-launcher.sh cannot be run)"
        _verdict=2
    else
        echo " Auto Start:  [OFF]  INACTIVE"
        echo " (goodbyedpi will NOT start at login)"
        _verdict=1
    fi
    echo "============================================"
    exit "$_verdict"
fi

# ── Tray precondition probe ─────────────────────────────────────────────────
# Probe for a working tray stack BEFORE starting the daemon. The daemon's
# lifetime must be bound to a *visible* tray — if the stack can't render a
# tray, don't start goodbyedpi at all (see tray.py's Null-tier refusal for
# the matching post-launch guarantee).
if ! command -v python3 >/dev/null 2>&1 || \
   ! python3 -c 'import gi; gi.require_version("Gtk", "3.0")' >/dev/null 2>&1; then
    echo "[tray-launcher] tray unavailable (python3-gi/GTK3 missing) — bypass NOT started" >&2
    notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
        "Tray unavailable (python3-gi/GTK3 missing) — bypass not started" 2>/dev/null || true
    exit 1
fi

# If goodbyedpi not running, start it.
GDPI_PID=0
if [ -f "$PID_FILE" ]; then
    PID_CANDIDATE="$(cat "$PID_FILE" 2>/dev/null)"
    if [ -n "$PID_CANDIDATE" ] && kill -0 "$PID_CANDIDATE" 2>/dev/null; then
        GDPI_PID="$PID_CANDIDATE"
    fi
fi

if [ "$GDPI_PID" -le 0 ]; then
    # Obtain root for the firewall load, via lib/platform.sh:
    #   rc 0 - root reachable → proceed
    #   rc 2 - user cancelled the dialog → do NOT run start.sh; refuse to
    #          silently waste every DNS probe and leave an inert tray
    #   rc 1 - no mechanism at all → run anyway with a warning
    #         (start.sh's own WARN explains why the bypass is inert)
    SUDO_PASSWORD=""
    rm -f "$DATA_DIR/fw_state" 2>/dev/null || true
    _root_rc=0
    plat_root_acquire || _root_rc=$?
    if [ "$_root_rc" -eq 2 ]; then
        echo "[tray-launcher] password cancelled — bypass not started" >> "$PLAT_LOG" 2>/dev/null || true
        notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
            "Bypass not started — password prompt cancelled" 2>/dev/null || true
        _start_pid=0
    elif [ "$_root_rc" -ne 0 ]; then
        echo "[tray-launcher] WARN: cannot obtain root — firewall rules will not load" >> "$PLAT_LOG" 2>/dev/null || true
        notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
            "Cannot obtain root — firewall rules not loaded" 2>/dev/null || true
        SUDO_PASSWORD="$SUDO_PASSWORD" "$APP_DIR/start.sh" --no-tray >/dev/null 2>&1 &
        _start_pid=$!
    else
        SUDO_PASSWORD="$SUDO_PASSWORD" "$APP_DIR/start.sh" --no-tray >/dev/null 2>&1 &
        _start_pid=$!
    fi
    # Poll for the PID file instead of sleeping a fixed 2s. start.sh probes
    # every DNS candidate before it ever launches the daemon, which routinely
    # takes far longer than 2s; the old fixed sleep therefore handed tray.py
    # GDPI_PID=0 on a perfectly healthy start. That is not cosmetic:
    # tray.py:check_alive returns early on GDPI_PID<=0, which disables BOTH
    # the crash watchdog AND the firewall self-heal that restores our rules
    # after firewalld flushes them — so the bypass dies at the next
    # `firewall-cmd --reload` and never comes back.
    # Every test is a plain `if`: under `set -e` a short-circuiting
    # `a && b && break` list would abort the script instead of looping.
    _waited=0
    _no_start=0
    [ "$_start_pid" -le 0 ] 2>/dev/null && _no_start=1
    while [ "$_waited" -lt 60 ]; do
        if [ "$_no_start" -eq 1 ]; then
            break
        fi
        GDPI_PID=0
        if [ -f "$PID_FILE" ]; then
            GDPI_PID="$(cat "$PID_FILE" 2>/dev/null || echo 0)"
            case "$GDPI_PID" in ''|*[!0-9]*) GDPI_PID=0 ;; esac
            if [ "$GDPI_PID" -gt 0 ]; then
                if kill -0 "$GDPI_PID" 2>/dev/null; then
                    break
                fi
                GDPI_PID=0
            fi
        fi
        # start.sh is gone and left no live PID — nothing more to wait for.
        if ! kill -0 "$_start_pid" 2>/dev/null; then
            break
        fi
        sleep 0.5
        _waited=$((_waited + 1))
    done

    # A running daemon does NOT mean a working bypass. goodbyedpi holds
    # cap_net_raw/cap_net_admin, so it starts fine without root and logs
    # "NFQUEUE queue 200 activated" — but the nft rules that steer packets
    # into that queue need root. Lose the password prompt at login and you
    # get a healthy-looking tray over a completely inert bypass. start.sh
    # records the verdict in fw_state precisely because we discard its
    # stderr above; refusing to surface it is the whole bug.
    if [ "$GDPI_PID" -gt 0 ]; then
        _fw="$(cat "$DATA_DIR/fw_state" 2>/dev/null || true)"
        if [ "$_fw" != "ok" ] && [ "$_fw" != "skipped" ]; then
            echo "[tray-launcher] WARN: firewall rules not loaded (fw_state=${_fw:-unknown}) — bypass INACTIVE" >> "$PLAT_LOG" 2>/dev/null || true
            notify-send -a "DPIGate" -i dialog-error -u critical "DPIGate" \
                "Firewall rules not loaded — bypass is INACTIVE. Run start.sh from a terminal to enter your password." 2>/dev/null || true
        fi
    fi
fi

# Build DNS info from the dns_detect module (same logic as start.sh)
DNS_LABEL="DNS"
DNS_INFO=""
DNS_CURRENT=0
if [ -f "$APP_DIR/dns_detect.py" ] && command -v python3 >/dev/null 2>&1; then
    DNS_DATA="$(python3 -c "
import sys; sys.path.insert(0,'$APP_DIR')
from dns_detect import test_all
results = test_all()
parts = []
best_idx = 0
best_ms = 999999
for i, r in enumerate(results):
    parts.append(f\"{r['name']}|{r['addr']}|{r['port']}|{r['time_ms']}|{r['status']}\")
    if r['status'] == 'ok' and isinstance(r.get('time_ms'), (int,float)) and r['time_ms'] < best_ms:
        best_ms = r['time_ms']
        best_idx = i
print(';'.join(parts))
print(f'BEST={best_idx}')
" 2>/dev/null)" || true
    if [ -n "$DNS_DATA" ]; then
        DNS_INFO="$(echo "$DNS_DATA" | grep -v '^BEST=')"
        BEST_LINE="$(echo "$DNS_DATA" | grep '^BEST=')"
        DNS_CURRENT="${BEST_LINE#BEST=}"
        # A server picked in the tray outranks this probe's own "best":
        # start.sh reads the same persisted index, so the radio button has to
        # point at the entry the daemon actually uses. Never advertise a
        # selection that isn't running. Out-of-range/absent keeps the probe's
        # pick — dns_detect.py degrades to auto-detect the same way.
        _st_dns="$(_config_get FORCE_DNS_INDEX -1)"
        # Get label for the selected DNS
        if [ -n "$DNS_INFO" ]; then
            IFS=';' read -ra ENTRIES <<< "$DNS_INFO"
            case "$_st_dns" in
                ''|*[!0-9]*) ;;
                *) if [ -n "${ENTRIES[$_st_dns]:-}" ]; then DNS_CURRENT="$_st_dns"; fi ;;
            esac
            if [ -n "${ENTRIES[$DNS_CURRENT]:-}" ]; then
                IFS='|' read -r DNS_NAME DNS_ADDR DNS_PORT DNS_MS DNS_STATUS <<< "${ENTRIES[$DNS_CURRENT]}"
                DNS_LABEL="$DNS_NAME $DNS_ADDR:$DNS_PORT (${DNS_MS}ms)"
            fi
        fi
    fi
fi

# Bind the daemon's lifetime to this tray. start.sh only spawns a reaper on
# its own tray path, and we invoked it with --no-tray above, so on the
# autostart path nothing watches the tray: a SIGKILL or a hard session
# teardown would orphan goodbyedpi and the nft rules. The exec below replaces
# this shell with tray.py, so $$ is exactly the PID the reaper must watch.
if [ "$GDPI_PID" -gt 0 ] && [ -x "$APP_DIR/reaper.sh" ]; then
    setsid "$APP_DIR/reaper.sh" "$$" </dev/null >/dev/null 2>&1 &
    disown 2>/dev/null || true
fi

# Launch the tray
exec env \
    GDPI_PID="$GDPI_PID" \
    GDPI_PROGRAMS="$PROGRAMS_LIST" \
    GDPI_START_SH="$APP_DIR/start.sh" \
    GDPI_ICON="$ICON_PATH" \
    GDPI_DNS_LABEL="$DNS_LABEL" \
    GDPI_DNS_CURRENT="$DNS_CURRENT" \
    GDPI_DNS_INFO="$DNS_INFO" \
    GDPI_BYPASS_ALL="$(_config_get BYPASS_ALL 0)" \
    python3 "$APP_DIR/tray.py"
