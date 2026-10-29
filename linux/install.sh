#!/bin/bash
# install.sh — DPIGate Linux installer (install.ps1 counterpart)
#
# Builds the binary (if needed), copies files to XDG dirs, loads the
# firewall rules (nftables or iptables), installs a service definition
# (systemd/OpenRC/runit) when --system is given, sets capabilities
# (rootless NFQUEUE). Distro/package-manager/init/firewall portability
# lives in lib/platform.sh — see that file for the full capability matrix.
#
# Usage:
#   ./install.sh              # full install (build + copy + firewall + setcap)
#                             #   With no controlling terminal (double-clicked
#                             #   in a file manager) this opens the graphical
#                             #   setup wizard instead — see --gui/--cli.
#   ./install.sh --gui        # force the graphical wizard (Next/Next/Finish)
#   ./install.sh --cli        # force the plain text install (never opens a GUI)
#   ./install.sh --no-build   # skip make, assume binary exists
#   ./install.sh --system     # install as a root/system service
#                              #   (systemd system unit, OpenRC, or runit —
#                              #    whichever init the host actually runs)
#   ./install.sh --start      # also start goodbyedpi now
#   ./install.sh --autostart  # start the tray (and the bypass) at login
#   ./install.sh --no-autostart # remove any login autostart entry
#   ./install.sh --no-shortcut  # do not create the application-menu entry
#   ./install.sh --assume-deps  # skip dependency probing/auto-install
#   ./install.sh --check-only   # probe distro/pkgmgr/build/deps only, exit 0
#                                # (no setcap/firewall/service/desktop/notify —
#                                #  this is what CI runs; containers lack
#                                #  CAP_NET_ADMIN so runtime steps are skipped;
#                                #  never opens the wizard)
#   ./install.sh --help
#
# Requires root (via lib/platform.sh: sudo/doas/pkexec/run0) for: firewall
# load, setcap, and --system's /usr/local + /etc staging.

set -e

# ── Config ───────────────────────────────────────────────────────────────────
APP_NAME="DPIGate"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/$APP_NAME"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/$APP_NAME"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Load the portability layer ──────────────────────────────────────────────
for _p in "$SCRIPT_DIR/lib/platform.sh" "$SCRIPT_DIR/platform.sh"; do
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

# ── Parse args ───────────────────────────────────────────────────────────────
DO_BUILD=1
SYSTEM_SERVICE=0
DO_START=0
ASSUME_DEPS=0
CHECK_ONLY=0
DO_SHORTCUT=1
DO_AUTOSTART=0
FORCE_GUI=0
FORCE_CLI=0
for arg in "$@"; do
    case "$arg" in
        --no-build)     DO_BUILD=0 ;;
        --system)       SYSTEM_SERVICE=1 ;;
        --start)        DO_START=1 ;;
        --assume-deps)  ASSUME_DEPS=1 ;;
        --check-only)   CHECK_ONLY=1 ;;
        --no-shortcut)  DO_SHORTCUT=0 ;;
        --autostart)    DO_AUTOSTART=1 ;;
        --no-autostart) DO_AUTOSTART=2 ;;
        --gui)          FORCE_GUI=1 ;;
        --cli)          FORCE_CLI=1 ;;
        --help|-h)
            # Print the header block itself: line 1 is the shebang, then every
            # leading comment line until the first non-comment. Self-maintaining
            # — a fixed `sed -n '2,20p'` silently truncated once flags were
            # added below line 20.
            awk 'NR==1{next} /^#/{print; next} {exit}' "$0"; exit 0 ;;
    esac
done

# ── Graphical setup wizard dispatch ──────────────────────────────────────────
# Double-clicking install.sh in a file manager runs it with no controlling
# terminal: every echo below goes nowhere and the sudo/zenity prompts are the
# only visible sign of life. In that situation hand over to the wizard
# (installer-gui.py — GTK Assistant, Next/Next/Finish) which collects the
# options, then re-runs THIS script with --cli and streams its output into a
# progress page. The install logic itself is never duplicated.
#
# --check-only is CI's entry point and must stay headless even when a display
# happens to exist. GDPI_INSTALL_GUI=0 is what the wizard sets on its child, so
# the handover can never recurse.
_gui_wanted() {
    [ "$FORCE_CLI" -eq 1 ] && return 1
    [ "$CHECK_ONLY" -eq 1 ] && return 1
    [ "${GDPI_INSTALL_GUI:-1}" = "0" ] && return 1
    [ "$FORCE_GUI" -eq 1 ] && return 0
    # Auto: a terminal on both stdin and stdout means a human typed the
    # command — stay in text mode. Otherwise a display is required.
    if [ -t 0 ] && [ -t 1 ]; then return 1; fi
    [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]
}

# Strip the mode flags before handing the rest to the wizard: they are the
# dispatch decision itself, and --gui passed through would make the wizard's
# child re-enter this block.
_wizard_presets() {
    for a in "$@"; do
        case "$a" in
            --gui|--cli|--help|-h) ;;
            *) printf '%s\n' "$a" ;;
        esac
    done
}

_run_gui_wizard() {
    local presets=()
    local a
    while IFS= read -r a; do [ -n "$a" ] && presets+=("$a"); done < <(_wizard_presets "$@")

    # 1. GTK Assistant (same PyGObject stack the tray already needs).
    if [ -f "$SCRIPT_DIR/installer-gui.py" ] && command -v python3 >/dev/null 2>&1 \
       && python3 -c 'import gi; gi.require_version("Gtk","3.0"); from gi.repository import Gtk' 2>/dev/null; then
        exec python3 "$SCRIPT_DIR/installer-gui.py" --installer "$SCRIPT_DIR/install.sh" "${presets[@]}"
    fi

    # 2. zenity wizard — same page order, no PyGObject.
    if [ -f "$SCRIPT_DIR/lib/wizard-zenity.sh" ] && command -v zenity >/dev/null 2>&1; then
        . "$SCRIPT_DIR/lib/wizard-zenity.sh"
        wizard_zenity_main "$SCRIPT_DIR/install.sh" "${presets[@]}"
        exit $?
    fi

    # 3. No dialog toolkit at all: reopen in a terminal so the text installer
    #    is at least visible and can ask for a password.
    local term
    for term in x-terminal-emulator konsole gnome-terminal xfce4-terminal \
                mate-terminal tilix alacritty kitty foot xterm; do
        command -v "$term" >/dev/null 2>&1 || continue
        case "$term" in
            gnome-terminal|tilix)
                exec "$term" -- bash "$SCRIPT_DIR/install.sh" --cli "${presets[@]}" ;;
            *)
                exec "$term" -e bash "$SCRIPT_DIR/install.sh" --cli "${presets[@]}" ;;
        esac
    done

    # 4. Nothing can show anything. Say so where the user will see it.
    notify-send -a "DPIGate" -i dialog-error "DPIGate" \
        "No graphical installer available. Open a terminal and run: ./install.sh" 2>/dev/null || true
    echo "ERROR: no GUI toolkit (python3-gi/zenity) and no terminal emulator found." >&2
    echo "       Run ./install.sh from a terminal instead." >&2
    exit 1
}

if _gui_wanted; then
    _run_gui_wizard "$@"
fi

# ── Root access ──────────────────────────────────────────────────────────────
# plat_root_acquire caches a sudo password when it can, so the dependency
# install, setcap, firewall load, --system layout and service setup below all
# run without asking again. When no cached-credential path exists it still
# returns success if pkexec/run0 are usable — those prompt per call, which is
# noisier but works. Only a host with no escalation mechanism at all lands in
# the branch below.
# A DECLINE (rc 2) is different from "no mechanism at all" (rc 1). Cancelling
# the dialog means the user does not want to install, so stop; carrying on
# would lay down a half-installed tree with no capabilities and no firewall
# rules. rc 1 still continues with a warning - see plat_root_acquire.
#
# NEVER set PLAT_NOPROMPT here: it disables pkexec/run0 in plat_root_cmd, and
# on a stock Fedora (sudo needs a password, no zenity, no TTY) that turned a
# working polkit install into "plat_run_root failed via none" for every step.
if [ "$(id -u)" -ne 0 ]; then
    _root_rc=0
    plat_root_acquire || _root_rc=$?
    if [ "$_root_rc" -eq 2 ]; then
        echo "[install] Password prompt cancelled. Install aborted - nothing was changed." >&2
        notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
            "Install cancelled — password prompt was cancelled" 2>/dev/null || true
        exit 1
    fi
    if [ "$_root_rc" -ne 0 ]; then
        echo "[install] WARN: no way to become root (sudo/doas/pkexec/run0 all unusable)." >&2
        echo "[install]       Dependency install, setcap and firewall rules will fail." >&2
        echo "[install]       Re-run as: sudo ./install.sh" >&2
    fi
fi

echo "[install] distro: $(plat_distro)  pkgmgr: $(plat_pkgmgr)  init: $(plat_init_system)" >&2

# ── Dependency resolution ────────────────────────────────────────────────────
# Probe capabilities (never package names) and auto-install what's missing.
# plat_deps_install re-probes afterwards, so a package manager that "succeeded"
# without actually providing a compiler fails here instead of at `make`.
if [ "$ASSUME_DEPS" -ne 1 ] && ! plat_deps_check; then
    _deps_rc=0
    plat_deps_install all || _deps_rc=$?
    if [ "$_deps_rc" -eq 2 ]; then
        echo "[install] Password prompt cancelled. Install aborted - nothing was changed." >&2
        notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
            "Install cancelled — password prompt was cancelled" 2>/dev/null || true
        exit 1
    fi
    if [ "$_deps_rc" -ne 0 ]; then
        echo "ERROR: dependency resolution failed. Install the packages listed above" >&2
        echo "       ('missing:' lines) and re-run, or use --assume-deps to skip this check." >&2
        exit 1
    fi
fi

# ── Build ─────────────────────────────────────────────────────────────────────
if [ "$DO_BUILD" -eq 1 ]; then
    if ! command -v make >/dev/null 2>&1; then
        echo "ERROR: 'make' is not installed and could not be installed automatically." >&2
        echo "       Install the build tools for $(plat_distro), then re-run ./install.sh" >&2
        exit 1
    fi
    echo "[install] building..."
    (cd "$SCRIPT_DIR" && make clean >/dev/null 2>&1 || true)
    (cd "$SCRIPT_DIR" && make)
fi

if [ ! -x "$SCRIPT_DIR/goodbyedpi" ]; then
    echo "ERROR: goodbyedpi binary not found. Run 'make' first." >&2
    exit 1
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
    plat_deps_check || true
    echo "[install] --check-only: distro detection, package resolution, and build all OK." >&2
    exit 0
fi

# ── Migrate from GoodByeDPI-Plus (the name before DPIGate) ───────────────────
# Runs only when the old per-user folders exist. The config folder (the user's
# ProgramFilters and settings) is moved, never overwritten; the old runtime
# folder and menu entry are removed; the user unit and autostart entry keep
# their names, so only the paths inside them are rewritten.
OLD_DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/GoodbyeDPI-Plus"
OLD_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/GoodbyeDPI-Plus"
if [ -d "$OLD_DATA_DIR" ] || [ -d "$OLD_CONFIG_DIR" ]; then
    echo "[install] migrating from GoodByeDPI-Plus..."
    [ -x "$OLD_DATA_DIR/kill.sh" ] && { "$OLD_DATA_DIR/kill.sh" >/dev/null 2>&1 || true; }
    if [ -d "$OLD_CONFIG_DIR" ] && [ ! -e "$CONFIG_DIR" ]; then
        mv "$OLD_CONFIG_DIR" "$CONFIG_DIR"
    fi
    rm -rf "$OLD_DATA_DIR"
    rm -f "${XDG_DATA_HOME:-$HOME/.local/share}/applications/goodbyedpi-plus.desktop" \
          "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/64x64/apps/goodbyedpi-plus.png"
    for f in "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/goodbyedpi.service" \
             "${XDG_CONFIG_HOME:-$HOME/.config}/autostart/goodbyedpi-tray.desktop"; do
        [ -f "$f" ] && sed -i 's#/GoodbyeDPI-Plus/#/DPIGate/#g; s#goodbyedpi-plus\.png#dpigate.png#g' "$f"
    done
    systemctl --user daemon-reload 2>/dev/null || true
fi

# ── Copy files ───────────────────────────────────────────────────────────────
echo "[install] copying files to $DATA_DIR ..."
mkdir -p "$DATA_DIR" "$CONFIG_DIR" "$DATA_DIR/lib"

# Runtime files (DATA_DIR). Copy to a temp name and rename: plain cp over a
# RUNNING binary fails with ETXTBSY ("Text file busy"), which is exactly what
# an in-place upgrade does. rename() swaps the directory entry instead, so the
# live process keeps its old inode and the next start picks up the new one.
_install_file() {
    local src="$1" dst="$2"
    cp "$src" "$dst.new" && mv -f "$dst.new" "$dst"
}
for f in goodbyedpi start.sh kill.sh uninstall.sh reaper.sh tray.py tray-launcher.sh dns_detect.py icon.png goodbyedpi.nft goodbyedpi.service ProgramFilters; do
    if [ -f "$SCRIPT_DIR/$f" ]; then
        _install_file "$SCRIPT_DIR/$f" "$DATA_DIR/$f"
    fi
done
# Portability layer (lib/platform.sh) — required at runtime by every
# consumer script; miss this and start.sh/kill.sh FATAL out.
for f in "$SCRIPT_DIR"/lib/*.sh; do
    if [ -f "$f" ]; then
        _install_file "$f" "$DATA_DIR/lib/$(basename "$f")"
    fi
done

# ── Install icon to theme path so tray + notifications find it by name ─────
ICON_THEME_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/64x64/apps"
mkdir -p "$ICON_THEME_DIR"
DESKTOP_ICON="$DATA_DIR/icon.png"     # fallback: absolute path
if [ -f "$SCRIPT_DIR/icon.png" ] && cp "$SCRIPT_DIR/icon.png" "$ICON_THEME_DIR/dpigate.png"; then
    # Theme icon installed — reference by ABSOLUTE path. A bare theme-name
    # Icon= relies on GTK/Cinnamon's icon-theme cache, which on a *fresh*
    # install doesn't monitor a hicolor dir that didn't exist at session
    # start, so the menu entry renders blank until re-login. The absolute
    # path resolves immediately via GFileIcon regardless of cache state.
    # uninstall.sh removes this same file, so it never dangles.
    DESKTOP_ICON="$ICON_THEME_DIR/dpigate.png"
    gtk-update-icon-cache -f -t "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" 2>/dev/null || true
else
    echo "  WARN: icon.png missing or not installable — menu entry will use $DESKTOP_ICON" >&2
fi
# Every shipped entry point must be executable. Two silent failures came from
# hand-keeping this list: the autostart .desktop Exec= runs tray-launcher.sh
# directly (non-exec ⇒ Auto Start silently does nothing at login), and
# start.sh gates the reaper on [ -x reaper.sh ] (non-exec ⇒ daemon+firewall
# survive a tray SIGKILL). Glob instead of a list so a newly shipped script
# can never land non-executable again. lib/*.sh is sourced, never executed.
chmod +x "$DATA_DIR/goodbyedpi" "$DATA_DIR"/*.sh "$DATA_DIR"/*.py

# ProgramFilters → CONFIG_DIR (user-editable, hot-reloaded). Seed once and
# never overwrite: the copy in CONFIG_DIR is the user's file.
# .ProgramFilters.shipped records what was seeded so start.sh can tell an
# untouched copy (safe to refresh with new defaults) from an edited one
# (never touch) — see the matching block in start.sh.
if [ ! -f "$CONFIG_DIR/ProgramFilters" ]; then
    cp "$SCRIPT_DIR/ProgramFilters" "$CONFIG_DIR/ProgramFilters"
    cp "$SCRIPT_DIR/ProgramFilters" "$CONFIG_DIR/.ProgramFilters.shipped"
fi

# ── Set capabilities (rootless NFQUEUE + raw socket) ────────────────────────
# Single root call: also clean up old sudoers.d from previous installs.
# Auto Start now uses plat_askpass per session; sudoers.d is no longer needed.
# Single call = single pkexec window in pkexec-only environments.
echo "[install] setting capabilities..."
_cap_rc=0
plat_run_root sh -c 'setcap "$1" "$2"; rc=$?; rm -f /etc/sudoers.d/goodbyedpi 2>/dev/null || true; exit $rc' \
        sh cap_net_raw,cap_net_admin+ep "$DATA_DIR/goodbyedpi" || _cap_rc=$?
if [ "$_cap_rc" -eq 2 ]; then
    echo "[install] Password prompt cancelled. Install aborted." >&2
    notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
        "Install cancelled — password prompt was cancelled" 2>/dev/null || true
    exit 1
fi
if [ "$_cap_rc" -eq 0 ]; then
    echo "  OK: goodbyedpi has cap_net_raw,cap_net_admin"
else
    echo "  WARN: setcap failed — goodbyedpi will need sudo/root to run" >&2
fi

# ── Firewall rules ────────────────────────────────────────────────────────────
# Loaded fresh on every install/start (no filesystem persistence — see
# lib/platform.sh plat_fw_load; rules are reloaded by start.sh and by the
# service definition's start action, so nothing needs to survive a reboot
# on its own).
echo "[install] loading firewall rules (backend: $(plat_fw_backend 2>/dev/null || echo none))..."
export PLAT_NFT_FILE="$DATA_DIR/goodbyedpi.nft"
# No daemon is running yet, so do NOT install the QUIC reject rule here — it
# would cut HTTP/3 for every app while nothing is bypassing anything. start.sh
# reloads the ruleset (with the reject) whenever the daemon comes up.
export PLAT_BLOCK_QUIC=0
_fw_rc=0
if plat_fw_preflight && plat_fw_load; then
    echo "  OK: firewall rules loaded"
else
    _fw_rc=$?
    if [ "$_fw_rc" -eq 2 ]; then
        echo "[install] Password prompt cancelled. Install aborted." >&2
        notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
            "Install cancelled — password prompt was cancelled" 2>/dev/null || true
        exit 1
    fi
    echo "  WARN: firewall rule load failed — install nftables or iptables (see plat_deps_check)" >&2
fi

# ── Service installation ─────────────────────────────────────────────────────
if [ "$SYSTEM_SERVICE" -eq 1 ]; then
    echo "[install] installing as a system service (init=$(plat_init_system))..."
    # Root-mode file layout: OpenRC/runit have no per-user services, so the
    # daemon runs as root and needs its runtime files + config outside $HOME.
    # systemd --system uses the same layout for a single code path across
    # all three inits.
    _sys_rc=0
    plat_run_root sh -c '
        src="$1"
        mkdir -p /usr/local/lib/DPIGate/lib /etc/DPIGate
        for f in goodbyedpi start.sh kill.sh dns_detect.py goodbyedpi.nft goodbyedpi.service; do
            [ -f "$src/$f" ] && cp "$src/$f" /usr/local/lib/DPIGate/
        done
        for f in "$src"/lib/*.sh; do
            [ -f "$f" ] && cp "$f" /usr/local/lib/DPIGate/lib/
        done
        chmod +x /usr/local/lib/DPIGate/start.sh \
                 /usr/local/lib/DPIGate/kill.sh
        # The root daemon needs no file caps; a 755 binary carrying
        # cap_net_raw/cap_net_admin would let any local user grab the queue.
        chmod 0700 /usr/local/lib/DPIGate/goodbyedpi
        if command -v setcap >/dev/null 2>&1; then
            setcap -r /usr/local/lib/DPIGate/goodbyedpi 2>/dev/null || true
        fi
        # GoodByeDPI-Plus root layout: keep the system filter list, drop the old runtime copy
        if [ -f /etc/GoodbyeDPI-Plus/ProgramFilters ] && [ ! -f /etc/DPIGate/ProgramFilters ]; then
            cp /etc/GoodbyeDPI-Plus/ProgramFilters /etc/DPIGate/ProgramFilters
        fi
        rm -rf /usr/local/lib/GoodbyeDPI-Plus /etc/GoodbyeDPI-Plus
        [ -f /etc/DPIGate/ProgramFilters ] || cp "$src/ProgramFilters" /etc/DPIGate/ProgramFilters
    ' sh "$SCRIPT_DIR" || _sys_rc=$?
    if [ "$_sys_rc" -eq 2 ]; then
        echo "[install] Password prompt cancelled. Install aborted." >&2
        notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
            "Install cancelled — password prompt was cancelled" 2>/dev/null || true
        exit 1
    fi
    if [ "$_sys_rc" -ne 0 ]; then
        echo "  WARN: system-mode file layout failed — see $PLAT_LOG" >&2
    fi
    if PLAT_SERVICE_SYSTEM=1 plat_service_install; then
        _ena_rc=0
        PLAT_SERVICE_SYSTEM=1 plat_service_enable || _ena_rc=$?
        if [ "$_ena_rc" -eq 2 ]; then
            echo "[install] Password prompt cancelled. Install aborted." >&2
            notify-send -a "DPIGate" -i dialog-warning "DPIGate" \
                "Install cancelled — password prompt was cancelled" 2>/dev/null || true
            exit 1
        fi
        echo "  OK: system service installed (init=$(plat_init_system))"
    else
        echo "  WARN: no service definition available for init=$(plat_init_system) (s6/sysvinit: no service files — see README)." >&2
        echo "  Manual supervised run: /usr/local/lib/DPIGate/start.sh --no-tray --foreground" >&2
    fi
else
    echo "[install] user-mode install — no service installed by default."
    echo "  goodbyedpi starts via the XDG autostart entry (tray-launcher.sh) at login."
    echo "  The tray will also lazily install a systemd --user unit if systemd is present"
    echo "  (toggle via the tray's Auto Start menu item, or: systemctl --user enable --now goodbyedpi)"
fi

# ── GNOME extension check ────────────────────────────────────────────────────
if [ "$XDG_CURRENT_DESKTOP" = "GNOME" ] || [ "$XDG_CURRENT_DESKTOP" = "ubuntu:GNOME" ]; then
    if ! gnome-extensions list 2>/dev/null | grep -q "appindicator"; then
        echo "" >&2
        echo "=========================================================" >&2
        echo "GNOME detected. For the system tray icon to appear," >&2
        echo "install the 'AppIndicator and KStatusNotifierItem Support'" >&2
        echo "extension (ID 615) via Extensions Manager or:" >&2
        echo "  https://extensions.gnome.org/extension/615/" >&2
        echo "=========================================================" >&2
    fi
fi

# ── Start menu shortcut ──────────────────────────────────────────────────────
# Install a .desktop file so the app appears in the application menu.
# User launches it from there — install.sh does NOT auto-start.
APPS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
if [ "$DO_SHORTCUT" -eq 1 ]; then
    mkdir -p "$APPS_DIR"
    # Categories=Network; ONLY. Adding System; put a second copy of the entry
    # in the menu's System section (KDE/XFCE/Cinnamon all render one entry per
    # matching category) — a DPI bypass belongs under Internet/Network, and
    # duplicated menu entries were exactly the reported bug.
    cat > "$APPS_DIR/dpigate.desktop" <<DESKTOP_EOF
[Desktop Entry]
Type=Application
Name=DPIGate
Comment=DPI bypass with per-program filtering
Exec=$DATA_DIR/start.sh
Icon=$DESKTOP_ICON
Terminal=false
Categories=Network;
StartupNotify=false
DESKTOP_EOF
    chmod +x "$APPS_DIR/dpigate.desktop"
    echo "  OK: start menu shortcut: $APPS_DIR/dpigate.desktop"
    # Update desktop database (best-effort)
    update-desktop-database "$APPS_DIR" 2>/dev/null || true
else
    echo "  skip: --no-shortcut given, no application-menu entry created"
fi

# ── Autostart entry (--autostart) ────────────────────────────────────────────
# Same file the tray's "Auto Start" toggle writes (tray.py: DESKTOP_PATH), so
# the tray reports Auto Start = ON afterwards and its toggle removes this file.
# Keep the key set identical to tray.py's writer — a divergence here shows up
# as a menu item that disagrees with what happens at login.
AUTOSTART_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"
if [ "$DO_AUTOSTART" -eq 1 ]; then
    mkdir -p "$AUTOSTART_DIR"
    cat > "$AUTOSTART_DIR/goodbyedpi-tray.desktop" <<AUTOSTART_EOF
[Desktop Entry]
Type=Application
Name=DPIGate Tray
Comment=DPI bypass system tray icon
Exec=$DATA_DIR/tray-launcher.sh
Icon=$DESKTOP_ICON
Terminal=false
StartupNotify=false
X-GNOME-Autostart-enabled=true
X-KDE-autostart-after=panel
AUTOSTART_EOF
    echo "  OK: autostart entry: $AUTOSTART_DIR/goodbyedpi-tray.desktop"
elif [ "$DO_AUTOSTART" -eq 2 ]; then
    rm -f "$AUTOSTART_DIR/goodbyedpi-tray.desktop" 2>/dev/null || true
    echo "  OK: autostart entry removed"
fi
# DO_AUTOSTART=0 (no flag): leave whatever the tray's Auto Start toggle set.
# An upgrade re-run must not silently disable a login autostart the user chose.

if [ "$DO_START" -eq 1 ]; then
    echo "[install] starting goodbyedpi..."
    SUDO_PASSWORD="${SUDO_PASSWORD:-}" "$DATA_DIR/start.sh"
else
    echo "" >&2
    echo "Done. Launch DPIGate from your application menu." >&2
    echo "Or run: $DATA_DIR/start.sh" >&2
fi

# ── Notify ────────────────────────────────────────────────────────────────────
notify-send -a "DPIGate" -i "$DATA_DIR/icon.png" \
    "DPIGate" "Installed. Launch from application menu." 2>/dev/null || true

# Machine-readable last line: the wizard's progress page keys its success
# banner off this, so a truncated/killed run can never look successful.
echo "[install] RESULT: ok"
echo "[install] complete."
