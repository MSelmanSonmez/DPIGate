#!/bin/bash
# uninstall.sh — DPIGate Linux uninstaller (uninstall.ps1 counterpart)
#
# Stops goodbyedpi, removes firewall rules, deletes ALL files including
# user config (ProgramFilters), disables service. Leaves nothing behind.
# Backend/init-agnostic via lib/platform.sh.
#
# Usage:
#   ./uninstall.sh           # stop + remove everything
#   ./uninstall.sh --help

set -e

APP_NAME="DPIGate"
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
for _p in "$APP_DIR/lib/platform.sh" "$APP_DIR/platform.sh" \
          "$APP_DIR/../share/DPIGate/lib/platform.sh"; do
    [ -f "$_p" ] && { . "$_p"; break; }
done
if [ -z "${PLAT_SH_LOADED:-}" ]; then
    echo "FATAL: lib/platform.sh not found next to $0" >&2; exit 1
fi

DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/$APP_NAME"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/$APP_NAME"
PID_FILE="$DATA_DIR/goodbyedpi.pid"

for arg in "$@"; do
    case "$arg" in
        --help|-h) sed -n '2,10p' "$0"; exit 0 ;;
    esac
done

# ── Single password prompt ───────────────────────────────────────────────────
# Service removal (plat_service_*) and firewall unload (plat_fw_unload) make
# 4-6 separate root calls; a single prompt here lets all run via `sudo -S`.
if [ "$(id -u)" -ne 0 ]; then
    if [ "${PLAT_NOPROMPT:-0}" = "1" ]; then
        # Unattended caller: nobody to ask, so remove what is reachable.
        plat_root_acquire >/dev/null 2>&1 || {
            echo "[uninstall] WARN: cannot obtain root - firewall rules may remain" >&2
            echo "  Manual cleanup: sudo nft delete table inet goodbyedpi" >&2
        }
    else
        _acq_rc=0
        plat_root_acquire || _acq_rc=$?
        if [ "$_acq_rc" -eq 2 ]; then
            # Cancelling the dialog means "do not uninstall" - it must NOT
            # proceed to delete every file and leave the firewall rules loaded.
            echo "[uninstall] Uninstall cancelled — the password prompt was cancelled. Nothing was removed." >&2
            notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
                "Uninstall cancelled — password prompt was cancelled" 2>/dev/null || true
            exit 1
        fi
        if [ "$_acq_rc" -ne 0 ]; then
            echo "[uninstall] Root access required. Uninstall cancelled - nothing was removed." >&2
            exit 1
        fi
    fi
fi

# ── Stop processes ────────────────────────────────────────────────────────────
echo "[uninstall] stopping processes..."

# Kill goodbyedpi
if [ -f "$PID_FILE" ]; then
    OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        kill "$OLD_PID" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
fi
plat_kill_cmdline "--queue $PLAT_QUEUE_NUM" || true

# Kill tray
plat_kill_cmdline "tray.py" || true

# ── Disable + remove service (systemd/OpenRC/runit) ─────────────────────────
# A decline on any of these prompts aborts: deleting the files while the
# firewall rules stay loaded is exactly the half-uninstalled state a cancelled
# dialog must never produce.
_svc_cancel() {
    echo "[uninstall] Uninstall cancelled — the password prompt was cancelled. Files were kept." >&2
    notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
        "Uninstall cancelled — password prompt was cancelled" 2>/dev/null || true
    exit 1
}
echo "[uninstall] removing service (init=$(plat_init_system))..."
_svc_rc=0
plat_service_disable >/dev/null 2>&1 || _svc_rc=$?
[ "$_svc_rc" -eq 2 ] && _svc_cancel
_svc_rc=0
plat_service_stop >/dev/null 2>&1 || _svc_rc=$?
[ "$_svc_rc" -eq 2 ] && _svc_cancel
_svc_rc=0
plat_service_remove >/dev/null 2>&1 || _svc_rc=$?
[ "$_svc_rc" -eq 2 ] && _svc_cancel
# System-mode systemd unit lives under a different name path; PLAT_SERVICE_SYSTEM
# is not known at uninstall time, so also try the system-mode remove directly.
_svc_rc=0
PLAT_SERVICE_SYSTEM=1 plat_service_disable >/dev/null 2>&1 || _svc_rc=$?
[ "$_svc_rc" -eq 2 ] && _svc_cancel
_svc_rc=0
PLAT_SERVICE_SYSTEM=1 plat_service_stop >/dev/null 2>&1 || _svc_rc=$?
[ "$_svc_rc" -eq 2 ] && _svc_cancel
_svc_rc=0
PLAT_SERVICE_SYSTEM=1 plat_service_remove >/dev/null 2>&1 || _svc_rc=$?
[ "$_svc_rc" -eq 2 ] && _svc_cancel

# ── Remove firewall rules ───────────────────────────────────────────────────
echo "[uninstall] removing firewall rules..."
_fw_rc=0
plat_fw_unload || _fw_rc=$?
[ "$_fw_rc" -eq 2 ] && _svc_cancel

# ── Remove files ──────────────────────────────────────────────────────────────
echo "[uninstall] removing files..."
rm -rf "$DATA_DIR"

# Desktop integration installed by install.sh / the tray's Auto Start toggle.
# Leaving these behind is what produces a start-menu entry with a dangling
# Exec= and a missing icon after an uninstall.
APPS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
rm -f "$APPS_DIR/dpigate.desktop" "$APPS_DIR/goodbyedpi-plus.desktop"
rm -f "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/64x64/apps/dpigate.png" \
      "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/64x64/apps/goodbyedpi-plus.png"
# Leftovers of GoodByeDPI-Plus (the name before DPIGate), if install.sh never migrated them
rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/GoodbyeDPI-Plus" "${XDG_CONFIG_HOME:-$HOME/.config}/GoodbyeDPI-Plus"
rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/autostart/goodbyedpi-tray.desktop"
update-desktop-database "$APPS_DIR" 2>/dev/null || true
gtk-update-icon-cache -f -t "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" 2>/dev/null || true

rm -rf "$CONFIG_DIR"
echo "  Removed config: $CONFIG_DIR"

# ── Notify ────────────────────────────────────────────────────────────────────
notify-send -a "DPIGate" -i dialog-warning "DPIGate" "Uninstalled." 2>/dev/null || true

echo "[uninstall] complete."
