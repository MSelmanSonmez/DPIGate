#!/bin/bash
# kill.sh — EMERGENCY SHUTDOWN: kill goodbyedpi and remove firewall rules.
#
# Usage:
#   ./kill.sh          # stop everything (firewall + goodbyedpi + tray)
#   ./kill.sh --nft    # remove firewall rules only
#   ./kill.sh --proc   # kill goodbyedpi process only
#
# This script is safe — it restores internet connectivity, never breaks it.
# When the firewall table/chain is deleted, the kernel accepts packets normally.
# Backend-agnostic: tears down whichever of nftables or iptables is loaded
# (see lib/platform.sh plat_fw_unload).

set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
for _p in "$APP_DIR/lib/platform.sh" "$APP_DIR/platform.sh" \
          "$APP_DIR/../share/GoodbyeDPI-Plus/lib/platform.sh"; do
    [ -f "$_p" ] && { . "$_p"; break; }
done
if [ -z "${PLAT_SH_LOADED:-}" ]; then
    echo "FATAL: lib/platform.sh not found next to $0" >&2; exit 1
fi

KILL_NFT=1
KILL_PROC=1
KILL_TRAY=1

for arg in "$@"; do
    case "$arg" in
        --nft)  KILL_PROC=0; KILL_TRAY=0 ;;
        --proc) KILL_NFT=0; KILL_TRAY=0 ;;
        --help|-h) sed -n '2,12p' "$0"; exit 0 ;;
    esac
done

# Single password prompt: acquire root once so subsequent plat_run_root calls
# reuse credentials via $SUDO_PASSWORD (see start.sh, lib/platform.sh).
#
# Who may be asked is decided ONLY by PLAT_NOPROMPT, never by guessing from
# the terminal. The old `[ ! -t 0 ]` test classified the tray - a GUI app with
# a perfectly usable zenity dialog but no TTY - as "cannot ask", so a dialog
# was shown anyway and cancelling it was then IGNORED: the daemon (owned by
# the user, so no root needed) and the tray were killed regardless, leaving
# the firewall rules behind. Clicking Cancel now aborts, as it must.
#
# PLAT_NOPROMPT=1 callers - goodbyedpi.service ExecStop, reaper.sh, the tray's
# logout/signal path - genuinely have nobody to ask, so they tear down what is
# reachable without root. That is safe: every queue rule carries the `bypass`
# flag, so rules left loaded with no daemon pass traffic instead of dropping it.
if [ "$KILL_NFT" -eq 1 ] || [ "$KILL_PROC" -eq 1 ]; then
    if [ "${PLAT_NOPROMPT:-0}" = "1" ]; then
        plat_root_acquire >/dev/null 2>&1 || \
            echo "[kill] WARN: no root - tearing down what is possible without it" >&2
    else
        _acq_rc=0
        plat_root_acquire || _acq_rc=$?
        if [ "$_acq_rc" -eq 2 ]; then
            echo "[kill] ERROR: Kill cancelled — the password prompt was cancelled. Nothing was changed." >&2
            notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
                "Kill cancelled — password prompt was cancelled" 2>/dev/null || true
            exit 1
        fi
        if [ "$_acq_rc" -ne 0 ]; then
            echo "[kill] ERROR: Root access required to unload firewall rules. Kill cancelled." >&2
            exit 1
        fi
    fi
fi

# ── 1) Remove firewall rules ────────────────────────────────────────────
if [ "$KILL_NFT" -eq 1 ]; then
    echo "[kill] firewall: removing goodbyedpi rules..."
    _fw_rc=0
    plat_fw_unload || _fw_rc=$?
    if [ "$_fw_rc" -eq 2 ]; then
        # User declined the prompt - abort BEFORE touching the daemon.
        echo "[kill] ERROR: Kill cancelled — the password prompt was cancelled. Nothing was changed." >&2
        notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
            "Kill cancelled — password prompt was cancelled" 2>/dev/null || true
        exit 1
    fi
    if ! plat_fw_is_loaded; then
        echo "  ✓ Rules removed — packets now flow normally."
    else
        echo "  • No rules present (clean)."
    fi
fi

# ── 2) Kill goodbyedpi process ───────────────────────────────────────────
if [ "$KILL_PROC" -eq 1 ]; then
    echo "[kill] stopping goodbyedpi process..."
    if [ -n "$(plat_gdpi_pids)" ]; then
        for _p in $(plat_gdpi_pids); do
            kill -TERM "$_p" 2>/dev/null || true
        done
        echo "  ✓ goodbyedpi killed."
    else
        echo "  • goodbyedpi not running."
    fi
    # Remove PID file if present
    DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/GoodbyeDPI-Plus"
    rm -f "$DATA_DIR/goodbyedpi.pid" 2>/dev/null || true
    # If setcap failed, daemon may have started as root — user-level kill
    # may be insufficient; escalate with cached root ticket (no re-prompt).
    for _p in $(plat_gdpi_pids); do
        _krc=0
        plat_run_root kill -TERM "$_p" 2>/dev/null || _krc=$?
        if [ "$_krc" -eq 2 ]; then
            echo "[kill] ERROR: Kill cancelled — the password prompt was cancelled." >&2
            notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
                "Kill cancelled — password prompt was cancelled" 2>/dev/null || true
            exit 1
        fi
    done
fi

# ── 3) Stop tray ────────────────────────────────────────────────────────
if [ "$KILL_TRAY" -eq 1 ]; then
    echo "[kill] stopping tray..."
    plat_kill_cmdline "$APP_DIR/reaper.sh" || true
    plat_kill_cmdline "$APP_DIR/tray.py" || true
    plat_kill_cmdline "GoodbyeDPI-Plus/tray.py" || true
    echo "  ✓ tray stopped."
fi

# ── 4) Stop service (if installed — systemd/OpenRC/runit) ───────────────────
if [ "$KILL_PROC" -eq 1 ]; then
    plat_service_stop >/dev/null 2>&1 && echo "  ✓ service stopped (init=$(plat_init_system))." || true
fi

# ── Revert DNS override (start.sh changed system DNS upstream) ───
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/GoodbyeDPI-Plus"
if [ -f "$DATA_DIR/dns_override" ] && command -v resolvectl >/dev/null 2>&1; then
    _ovr_if="$(cat "$DATA_DIR/dns_override" 2>/dev/null || true)"
    if [ -n "$_ovr_if" ]; then
        echo "[kill] reverting DNS override (iface=$_ovr_if)..."
        _dns_rc=0
        plat_run_root resolvectl revert "$_ovr_if" >/dev/null 2>&1 || _dns_rc=$?
        if [ "$_dns_rc" -eq 2 ]; then
            echo "[kill] ERROR: Kill cancelled — the password prompt was cancelled." >&2
            notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
                "Kill cancelled — password prompt was cancelled" 2>/dev/null || true
            exit 1
        fi
        plat_run_root resolvectl flush-caches >/dev/null 2>&1 || true
    fi
    rm -f "$DATA_DIR/dns_override" 2>/dev/null || true
fi

# The bypass is down, so the recorded firewall verdict is no longer true of
# anything; a stale "ok" would make the next --check lie. Unconditional: the
# daemon may have run without ever touching the DNS override above.
rm -f "$DATA_DIR/fw_state" 2>/dev/null || true

# ── 5) Verify ─────────────────────────────────────────────────────────────
echo ""
echo "[kill] verification:"
if plat_fw_is_loaded >/dev/null 2>&1; then
    echo "  ⚠  Firewall rules still present! Manual: sudo $APP_DIR/lib/platform.sh fw-unload"
else
    echo "  ✓ no firewall rules (clean)."
fi
if [ -n "$(plat_gdpi_pids)" ]; then
    echo "  ⚠  goodbyedpi still running! Manual: sudo pkill -9 -f goodbyedpi"
else
    echo "  ✓ goodbyedpi not running."
fi

echo ""
echo "[kill] Internet test:"
if timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' >/dev/null 2>&1; then
    echo "  ✓ Internet reachable — all good."
else
    echo "  ⚠  No internet! If not firewall-related:"
    echo "    sudo systemctl restart NetworkManager"
    echo "    sudo systemctl restart nftables  (if nftables is active)"
fi
