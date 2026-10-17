#!/usr/bin/env python3
"""
tray.py — System tray icon for DPIGate (Linux port).

Indicator backend, in order of preference (see the fallback chain below):
  1. AyatanaAppIndicator3   2. AppIndicator3
  3. Gtk.StatusIcon shim (SNI-less WMs: i3, dwm, bspwm, minimal GNOME, ...)
  4. Null shim (headless — never crash for lack of a tray backend)

Mirrors the Windows tray (start.ps1 TrayMode):
  - DNS dropdown (candidates + auto-detect re-test)
  - Edit Program Filters
  - Auto Start toggle (service, via lib/platform.sh — systemd/OpenRC/runit)
  - Uninstall (runs uninstall.sh — stop daemon, remove firewall, delete all files)
  - Exit

Launched by start.sh with these env vars:
  GDPI_PID            — goodbyedpi process PID (crash watchdog)
  GDPI_PROGRAMS       — path to ProgramFilters
  GDPI_START_SH       — path to start.sh (for DNS restart)
  GDPI_ICON           — path to icon.png
  GDPI_DNS_LABEL      — "Name addr:port (Xms)"
  GDPI_DNS_CURRENT    — index of current DNS in candidates list
  GDPI_DNS_INFO       — "name|addr|port|ms|status;name|..." (per candidate)
  GDPI_CONFIG_DIR     — XDG_CONFIG_HOME/GoodbyeDPI-Plus (systemd unit location)
"""
import os
import sys
import signal
import atexit
import shlex
import subprocess

# ── Env config ──────────────────────────────────────────────────────────────
def _env_int(name: str, default: int) -> int:
    """Env ints are attacker-adjacent (start.sh copies --force-dns straight
    through); a ValueError here kills the tray before atexit is registered."""
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default

GDPI_PID       = _env_int("GDPI_PID", 0)
GDPI_PROGRAMS  = os.environ.get("GDPI_PROGRAMS", "")
GDPI_START_SH  = os.environ.get("GDPI_START_SH", "")
GDPI_ICON      = os.environ.get("GDPI_ICON", "")
GDPI_DNS_LABEL = os.environ.get("GDPI_DNS_LABEL", "DNS")
GDPI_DNS_CURRENT = _env_int("GDPI_DNS_CURRENT", -1)
GDPI_DNS_INFO  = os.environ.get("GDPI_DNS_INFO", "")
GDPI_BYPASS_ALL = os.environ.get("GDPI_BYPASS_ALL", "") == "1"

# ── Settings persistence (KEY=VALUE file in ~/.config/GoodbyeDPI-Plus) ─────
# The tray is the only writer: every menu toggle lands here, and start.sh /
# tray-launcher.sh read the same file at startup so the choice survives a
# restart, a logout and a reboot. A missing or corrupt file degrades to {} —
# losing a preference must never stop the tray from coming up.
_CONFIG_DIR = os.path.join(
    os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")),
    "GoodbyeDPI-Plus")
SETTINGS_FILE = os.path.join(_CONFIG_DIR, "settings")


def _load_settings():
    """Read the KEY=VALUE settings file → dict. Never raises."""
    out = {}
    try:
        with open(SETTINGS_FILE) as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def _save_setting(key, value):
    """Write one KEY=VALUE line, preserving the other keys. Never raises.

    Writes a temp file and os.replace()s it: a crash mid-write must not
    truncate the file that start.sh reads on the next boot."""
    try:
        os.makedirs(_CONFIG_DIR, exist_ok=True)
        settings = _load_settings()
        settings[key] = str(value)
        tmp = SETTINGS_FILE + ".tmp"
        with open(tmp, "w") as f:
            for k, v in settings.items():
                f.write(f"{k}={v}\n")
        os.replace(tmp, SETTINGS_FILE)
    except OSError:
        pass


if "GDPI_BYPASS_ALL" not in os.environ:
    # Launched directly (python3 tray.py) rather than by start.sh or
    # tray-launcher.sh: no env to inherit, so read the persisted value and
    # keep the menu honest instead of defaulting to OFF.
    GDPI_BYPASS_ALL = _load_settings().get("BYPASS_ALL", "0") == "1"

# Derive APP_DIR (where start.sh / lib/platform.sh live) from GDPI_START_SH.
_APP_DIR = os.path.dirname(os.path.abspath(GDPI_START_SH)) if GDPI_START_SH else ""
TRAY_LAUNCHER_SH = os.path.join(_APP_DIR, "tray-launcher.sh") if _APP_DIR else ""

# ── Platform helper — routes every distro/init/firewall-specific call ──────
# through lib/platform.sh so this file never shells out to systemctl (or any
# other init-specific tool) directly. Never raises: a missing platform.sh or
# missing subprocess binary degrades to rc=127, not a crash.
PLATFORM_SH = os.path.join(_APP_DIR, "lib", "platform.sh") if _APP_DIR else ""


def _plat(verb, *args, noprompt=False):
    """Run platform.sh <verb>; returns (rc, stdout). Never raises.
    noprompt=True → lib/platform.sh refuses pkexec/run0, so a background
    caller can never pop a password dialog."""
    if not PLATFORM_SH or not os.path.exists(PLATFORM_SH):
        return (127, "")
    env = {**os.environ, "PLAT_NOPROMPT": "1"} if noprompt else None
    try:
        r = subprocess.run(["bash", PLATFORM_SH, verb, *args],
                           capture_output=True, text=True, env=env)
        return (r.returncode, r.stdout.strip())
    except OSError:
        return (127, "")


import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib

# ── Indicator fallback chain ────────────────────────────────────────────────
# Exposes a module-like object `AppIndicator` with the exact four-call
# surface used at the bottom of this file: Indicator.new(id, icon, category),
# IndicatorCategory.APPLICATION_STATUS, IndicatorStatus.ACTIVE, plus the
# instance methods set_title/set_status/set_menu.
AppIndicator = None
INDICATOR_TIER = "none"
try:
    gi.require_version("AyatanaAppIndicator3", "0.1")
    from gi.repository import AyatanaAppIndicator3 as AppIndicator
    INDICATOR_TIER = "ayatana"
except (ImportError, ValueError):
    try:
        gi.require_version("AppIndicator3", "0.1")
        from gi.repository import AppIndicator3 as AppIndicator
        INDICATOR_TIER = "appindicator3"
    except (ImportError, ValueError):
        AppIndicator = None

if AppIndicator is None:
    # Tier 3 — Gtk.StatusIcon shim. Deprecated in GTK3 but present wherever
    # GTK3 is, which covers every SNI-less WM (no AppIndicator host).
    try:
        _ = Gtk.StatusIcon  # probe: raises AttributeError if truly absent

        class _IndicatorCategory:
            APPLICATION_STATUS = "application-status"

        class _IndicatorStatus:
            ACTIVE = "active"
            PASSIVE = "passive"

        class _StatusIconIndicator:
            def __init__(self, icon):
                if icon and os.path.exists(icon):
                    self._icon = Gtk.StatusIcon.new_from_file(icon)
                else:
                    self._icon = Gtk.StatusIcon.new_from_icon_name(icon or "network-server")
                self._menu = None

            def set_title(self, title):
                self._icon.set_title(title)
                self._icon.set_tooltip_text(title)

            def set_status(self, status):
                self._icon.set_visible(status == _IndicatorStatus.ACTIVE)

            def set_menu(self, menu):
                self._menu = menu
                self._icon.connect("popup-menu", self._on_popup)
                self._icon.connect("activate", self._on_activate)

            def _on_popup(self, icon, button, act_time):
                if self._menu:
                    self._menu.popup(None, None, Gtk.StatusIcon.position_menu, icon, button, act_time)

            def _on_activate(self, icon):
                if self._menu:
                    self._menu.popup(None, None, Gtk.StatusIcon.position_menu,
                                      icon, 0, Gtk.get_current_event_time())

        class _StatusIconModule:
            IndicatorCategory = _IndicatorCategory
            IndicatorStatus = _IndicatorStatus

            class Indicator:
                @staticmethod
                def new(id_, icon, category):
                    return _StatusIconIndicator(icon)

        AppIndicator = _StatusIconModule
        INDICATOR_TIER = "statusicon"
    except AttributeError:
        AppIndicator = None

if AppIndicator is None:
    # Tier 4 — Null shim. Headless: the GLib main loop and the check_alive
    # watchdog still run (the daemon is still supervised), only the icon is
    # gone. Never crash for lack of a tray backend.
    class _NullIndicatorCategory:
        APPLICATION_STATUS = "application-status"

    class _NullIndicatorStatus:
        ACTIVE = "active"

    class _NullIndicator:
        def __init__(self, *a, **kw):
            pass

        def set_title(self, *a, **kw):
            pass

        def set_status(self, *a, **kw):
            pass

        def set_menu(self, *a, **kw):
            pass

    class _NullModule:
        IndicatorCategory = _NullIndicatorCategory
        IndicatorStatus = _NullIndicatorStatus

        class Indicator:
            @staticmethod
            def new(id_, icon, category):
                return _NullIndicator()

    AppIndicator = _NullModule
    INDICATOR_TIER = "null"


def parse_dns_info(info: str):
    """Parse 'name|addr|port|ms|status;...' → list of dicts."""
    items = []
    for entry in info.split(";"):
        if not entry:
            continue
        parts = entry.split("|")
        if len(parts) >= 5:
            items.append({
                "name":   parts[0],
                "addr":   parts[1],
                "port":   parts[2],
                "time_ms": parts[3],
                "status": parts[4],
            })
    return items


DNS_ITEMS = parse_dns_info(GDPI_DNS_INFO)

# Suppress crash watchdog during intentional restarts (DNS switch / exit).
_shutting_down = False
# Firewall self-heal tick counter (see check_alive()).
_watchdog_tick = 0
# Restart token — monotonic counter incremented on every restart_start_sh()
# call. _teardown() returns True immediately when > 0, preventing kill.sh
# from re-running during a restart (which would pop a second sudo dialog).
_restart_token = 0
# Poll attempt counter for restart PID verification (_poll_restart).
_restart_attempt = 0


# ── Helpers ──────────────────────────────────────────────────────────────────
# Exit-time cleanup: kill goodbyedpi + remove the firewall rules so packets
# flow normally again. Tray runs as a normal user, so goodbyedpi (root)
# needs escalation for the kill + firewall teardown — routed through
# lib/platform.sh's plat_run_root (sudo/doas/pkexec/run0), not a bare sudo.
KILL_SH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kill.sh")
# uninstall.sh is copied into DATA_DIR by install.sh.
UNINSTALL_SH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uninstall.sh")
# goodbyedpi PID file — written by start.sh:start_goodbyedpi, used by the
# restart poll loop to verify the new daemon is alive before quitting.
_DATA_DIR = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
PID_FILE = os.path.join(_DATA_DIR, "GoodbyeDPI-Plus", "goodbyedpi.pid")


def kill_goodbyedpi(noprompt=False):
    """Tear down goodbyedpi + firewall rules + DNS override via kill.sh. Run as the
    invoking user (not pkexec): kill.sh acquires root once itself, so the user
    sees a single password dialog, and $HOME resolves to the user's data dir.

    noprompt=True forbids that dialog (lib/platform.sh PLAT_NOPROMPT) and asks
    for a best-effort teardown instead. Use it wherever nobody can answer:
    logout, SIGTERM, atexit. A menu click must NEVER use it — the user has to
    be able to cancel.

    Returns True on success, False on failure INCLUDING a cancelled dialog."""
    if os.path.exists(KILL_SH):
        env = os.environ.copy()
        if noprompt:
            env["PLAT_NOPROMPT"] = "1"
        try:
            result = subprocess.run(["bash", KILL_SH], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return result.returncode == 0
        except OSError:
            return False
    elif GDPI_PID > 0:
        try:
            os.kill(GDPI_PID, signal.SIGTERM)
            return True
        except OSError:
            return False
    return True


def _teardown(noprompt=False):
    """Idempotent daemon+firewall teardown, safe to call from on_exit,
    atexit, and OS signal handlers — guarded by _shutting_down so it never
    double-fires (also suppresses the crash watchdog during intentional
    shutdown).

    Releases the guards again when the teardown fails, so a cancelled password
    dialog leaves a fully operational tray instead of a half-dead one that has
    stopped watching the daemon."""
    global _shutting_down, _restart_token
    if _shutting_down or _restart_token > 0:
        return True
    _shutting_down = True
    if kill_goodbyedpi(noprompt=noprompt):
        return True
    _shutting_down = False
    _restart_token = 0
    return False

# The AppIndicator, so a failed action can rebuild the menu from live state
# instead of leaving a widget claiming a mode the daemon is not in.
_indicator = None

# A menu action persists its choice BEFORE restarting, so the choice survives a
# power loss between the click and the daemon coming up. The flip side: when
# the restart never happens — cancelled password dialog, start.sh died — that
# persisted value would silently take effect at the NEXT boot. A cancelled
# action must not apply itself later, so the write is undone here.
_pending_revert = None      # (settings_key, previous_value)


def _arm_revert(key, old_value):
    """Record how to undo a persisted menu choice if its restart never lands."""
    global _pending_revert
    _pending_revert = (key, old_value)


def _run_revert():
    """Undo the armed choice and resync the menu with reality. Never raises."""
    global _pending_revert
    if _pending_revert is None:
        return
    key, old_value = _pending_revert
    _pending_revert = None
    _save_setting(key, old_value)
    # Nothing about the running daemon changed, so rebuilding from the
    # unchanged module state puts every widget back where it belongs.
    if _indicator is not None:
        try:
            _indicator.set_menu(build_menu())
        except Exception:
            pass


def restart_start_sh(force_dns_index=None, bypass_all=None):
    """Relaunch start.sh (which kills existing instances + respawns tray).
    We must NOT kill our own tray process first — start.sh itself does
    `pkill -f tray.py` early in its run, so the new tray supersedes us.
    Run start.sh in the background so it outlives this dying tray.

    Run start.sh AS THE USER (not via sudo). start.sh internally escalates
    only the root bits (firewall + goodbyedpi), so it preserves HOME and
    resolves CONFIG_DIR to the user's ~/.config — keeping the same
    ProgramFilters the original launch used. Running start.sh via sudo
    here would flip HOME to /root and switch to the wrong config dir."""
    global _shutting_down, _restart_token, _restart_attempt
    _shutting_down = True
    _restart_token += 1
    _restart_attempt = 0
    if not GDPI_START_SH or not os.path.exists(GDPI_START_SH):
        show_notify("Cannot restart — start.sh path missing", "dialog-warning")
        _shutting_down = False
        _restart_token -= 1
        _run_revert()
        return
    args = [GDPI_START_SH]
    if force_dns_index is not None:
        # -1 means "auto-detect". It must travel as an explicit flag: with no
        # flag at all start.sh re-reads the persisted index, which would make
        # auto-detect unreachable once any server has been picked.
        args.append(f"--force-dns={force_dns_index}" if force_dns_index >= 0
                    else "--auto-dns")
    if bypass_all is not None:
        args.append("--bypass-all" if bypass_all else "--no-bypass-all")
    args.append("--restart")
    try:
        subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    except OSError:
        show_notify("Cannot restart — start.sh is not executable", "dialog-warning")
        _shutting_down = False
        _restart_token -= 1
        _run_revert()
        return
    # Poll for new goodbyedpi PID (up to 5s). If the new daemon is up, quit
    # normally so the new tray takes over. If start.sh fails, show error and
    # stay alive (the old daemon is still running).
    GLib.timeout_add(200, _poll_restart)


def _poll_restart():
    """GLib timeout callback: poll for new goodbyedpi PID after restart.
    Returns True to keep polling, False to stop.
    After ~5 seconds (25 × 200ms) the old tray stays alive and shows a
    notification (the old daemon is presumably still running)."""
    global _restart_attempt, _shutting_down, _restart_token
    _restart_attempt += 1
    try:
        with open(PID_FILE) as f:
            new_pid = int(f.read().strip())
        if new_pid > 0 and new_pid != GDPI_PID:
            os.kill(new_pid, 0)
            # New daemon is alive — switch to the new tray.
            Gtk.main_quit()
            return False
    except (FileNotFoundError, ValueError, OSError):
        pass
    if _restart_attempt >= 25:
        # start.sh never produced a new daemon: cancelled password dialog,
        # missing binary, ... Reset the guards so the crash watchdog resumes
        # and the tray stays open, and undo the choice that was persisted in
        # advance — an action the user cancelled must not apply at next boot.
        _shutting_down = False
        _restart_token = 0
        _restart_attempt = 0
        _run_revert()
        # Root acquisition happens before start.sh touches anything (see its
        # kill region), so a cancel leaves the old daemon untouched. Report
        # what is actually true rather than guessing.
        still_up = False
        if GDPI_PID > 0:
            try:
                os.kill(GDPI_PID, 0)
                still_up = True
            except OSError:
                still_up = False
        if still_up:
            show_notify("Change cancelled — previous settings kept, bypass still running")
        else:
            show_notify("Restart failed — bypass is NOT running", "dialog-warning")
        return False
    return True


def is_service_enabled():
    """Check if Auto Start is enabled (service enabled AND autostart
    .desktop file present). Both must be checked so the tray menu
    accurately reflects whether goodbyedpi will start at boot."""
    s = _plat("service-is-enabled")[0] == 0
    d = is_autostart_desktop_installed()
    # If only one is active, prefer the .desktop file state since
    # that's what actually causes the tray to launch at login.
    return s or d


def is_autostart_desktop_installed():
    """Check if the autostart .desktop file exists."""
    return os.path.exists(DESKTOP_PATH)


def verify_autostart():
    """Verify all Auto Start components and return a detailed status dict.
    Returns: {
        'active': bool,          # overall: will goodbyedpi start at boot?
        'consistent': bool,      # are both mechanisms in sync?
        'service_available': bool,  # is a service definition installed?
        'service_enabled': bool,
        'desktop_present': bool,
        'launcher_present': bool,
        'pid_running': bool,
        'detail': str,           # one-line summary for menu label
    }"""
    status = {
        'active': False,
        'consistent': False,
        'service_available': False,
        'service_enabled': False,
        'desktop_present': False,
        'launcher_present': False,
        'pid_running': False,
        'detail': 'Auto Start',
    }

    # Service (systemd/OpenRC/runit — whichever lib/platform.sh resolved)
    status['service_available'] = _plat("service-available")[0] == 0
    if status['service_available']:
        status['service_enabled'] = _plat("service-is-enabled")[0] == 0

    # Desktop file
    status['desktop_present'] = os.path.exists(DESKTOP_PATH)

    # Tray launcher script
    status['launcher_present'] = bool(TRAY_LAUNCHER_SH and os.path.exists(TRAY_LAUNCHER_SH))

    # goodbyedpi process
    if GDPI_PID > 0:
        try:
            os.kill(GDPI_PID, 0)
            status['pid_running'] = True
        except (OSError, PermissionError):
            pass

    # Auto Start ON only ever goes through the XDG autostart .desktop (tray
    # path) — see toggle_service(). The headless service unit is no longer
    # coupled into "active" so a stale/foreign service enable can't report
    # Auto Start as ON while no tray will ever show.
    status['active'] = status['desktop_present']
    status['consistent'] = True
    status['detail'] = 'Auto Start [ON]' if status['desktop_present'] else 'Auto Start [OFF]'

    return status


def toggle_service(enable: bool):
    """Enable/disable the service (via lib/platform.sh) AND manage the
    autostart .desktop file that launches the tray at login. Both must be
    toggled together so that disabling Auto Start prevents both the DPI
    bypass AND the tray from starting.

    Returns (ok, cancelled): cancelled is True when the user dismissed the
    root prompt (plat_run_root rc 2) — the caller shows a distinct message."""
    ok_service = True
    ok_desktop = True

    # ── Service (systemd/OpenRC/runit) ──────────────────────────────────
    # Auto Start ON goes through the tray ONLY (XDG autostart .desktop below
    # → tray-launcher.sh → tray → daemon), never the headless service unit —
    # a headless service is exactly the "daemon without a tray" bug. Auto
    # Start OFF still disables any previously-enabled headless unit so a
    # stale enable from an older version can't survive.
    cancelled = False
    if not enable and _plat("service-available")[0] == 0:
        rc, _out = _plat("service-disable")
        cancelled = (rc == 2)
        ok_service = (rc == 0)

    # ── Autostart .desktop file ──────────────────────────────────────
    if enable:
        if TRAY_LAUNCHER_SH and os.path.exists(TRAY_LAUNCHER_SH):
            os.makedirs(AUTOSTART_DIR, exist_ok=True)
            desktop_content = (
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Name=DPIGate Tray\n"
                "Comment=DPI bypass system tray icon\n"
                f"Exec={TRAY_LAUNCHER_SH}\n"
                f"Icon={GDPI_ICON if GDPI_ICON and os.path.exists(GDPI_ICON) else 'network-server'}\n"
                "Terminal=false\n"
                "StartupNotify=false\n"
                "X-GNOME-Autostart-enabled=true\n"
                "X-KDE-autostart-after=panel\n"
            )
            try:
                with open(DESKTOP_PATH, "w") as f:
                    f.write(desktop_content)
            except OSError:
                ok_desktop = False
        else:
            # No tray-launcher.sh — can't create the desktop file
            ok_desktop = False
    else:
        # Remove the desktop file if it exists
        try:
            if os.path.exists(DESKTOP_PATH):
                os.remove(DESKTOP_PATH)
        except OSError:
            ok_desktop = False

    return ok_service and ok_desktop, cancelled


# Autostart .desktop file that launches tray-launcher.sh at login.
# This is separate from the service: the .desktop launches the tray icon,
# while the service (when available) runs goodbyedpi headless.
AUTOSTART_DIR = os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "autostart")
DESKTOP_FILE = "goodbyedpi-tray.desktop"
DESKTOP_PATH = os.path.join(AUTOSTART_DIR, DESKTOP_FILE)


# ── Menu callbacks ───────────────────────────────────────────────────────────
def on_dns_selected(item, index):
    if not item.get_active():   # RadioMenuItem emits on both active and inactive
        return
    # Persist before restarting: DNS_CANDIDATES is a fixed, ordered list
    # (dns_detect.py), so the index stays meaningful across reboots, and an
    # out-of-range value degrades to auto-detect inside dns_detect.py.
    # Armed for undo first: if the restart never lands, the write is rolled
    # back so a cancelled click cannot apply itself at the next boot.
    _arm_revert("FORCE_DNS_INDEX", _load_settings().get("FORCE_DNS_INDEX", "-1"))
    _save_setting("FORCE_DNS_INDEX", index)
    restart_start_sh(force_dns_index=index)


def on_dns_autodetect(item):
    _arm_revert("FORCE_DNS_INDEX", _load_settings().get("FORCE_DNS_INDEX", "-1"))
    _save_setting("FORCE_DNS_INDEX", -1)
    restart_start_sh(force_dns_index=-1)


def _is_real_editor(val: str) -> bool:
    """Reject empty/no-op values like 'true', 'false', '/bin/true'."""
    if not val:
        return False
    base = os.path.basename(val.split()[0])
    return base not in ("true", "false")


# Direct-launch fallbacks, only reached when no desktop opener is available.
# This list is NOT a requirement — the desktop's own default handler is tried
# first and wins on every distro that has one configured.
_KNOWN_EDITORS = ("kwrite", "kate", "gedit", "mousepad", "geany", "code",
                  "xed", "pluma", "featherpad", "codium", "gnome-text-editor",
                  "leafpad", "notepadqq", "sublime_text")


def _run_opener(cmd: list, env: dict, wait: float = 2.0) -> bool:
    """Launch cmd and report whether the file got opened.

    Desktop openers (xdg-open, gio) fork the real editor and exit 0; a
    non-zero exit means "no handler" / "launch failed". A GUI editor started
    directly keeps running instead, so an expired wait also counts as success.
    """
    try:
        p = subprocess.Popen(cmd, start_new_session=True, env=env,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    except (OSError, ValueError):
        return False
    try:
        return p.wait(timeout=wait) == 0
    except subprocess.TimeoutExpired:
        return True


def on_edit_programs(item):
    path = GDPI_PROGRAMS
    if not path or not os.path.exists(path):
        show_notify("Program Filters file not found", "dialog-warning")
        return
    # Launch order:
    #   1. the desktop's own default handler (xdg-open / gio open) — this is
    #      what respects the user's "default text editor" setting, whatever
    #      editor that happens to be;
    #   2. well-known GUI editors, only if no handler is configured at all;
    #   3. $VISUAL / $EDITOR when they name a GUI editor.
    # Terminal editors are never launched — they would open an empty terminal.
    gui_env = {**os.environ,
               "DISPLAY": os.environ.get("DISPLAY", ":0"),
               "WAYLAND_DISPLAY": os.environ.get("WAYLAND_DISPLAY", ""),
               "DBUS_SESSION_BUS_ADDRESS": os.environ.get("DBUS_SESSION_BUS_ADDRESS", "")}

    candidates = [["xdg-open", path], ["gio", "open", path]]
    for ed in _KNOWN_EDITORS:
        candidates.append([ed, path])
    for env_var in ("VISUAL", "EDITOR"):
        val = os.environ.get(env_var, "")
        if _is_real_editor(val):
            base = os.path.basename(val.split()[0])
            if base not in ("nano", "vim", "vi", "nvim", "emacs", "pico", "joe"):
                candidates.append(["sh", "-c", f"{val} {shlex.quote(path)}"])

    for cmd in candidates:
        if _run_opener(cmd, gui_env):
            return

    # Nothing could open it — tell the user WHERE the file is instead of
    # naming editors they may not want; any editor can edit it by hand.
    show_notify(f"Program Filters file: {path}", "dialog-information")


def on_autostart_toggle(item):
    """Toggle Auto Start. At each login, tray-launcher.sh will show a
    password dialog (see lib/platform.sh plat_askpass) to get root for the
    firewall — no passwordless sudo needed."""
    active = item.get_active()
    ok, cancelled = toggle_service(active)
    # Re-verify after toggle to get accurate status
    status = verify_autostart()
    if ok:
        if status['consistent']:
            label = status['detail']
        else:
            label = "Auto Start partial — run 'tray-launcher.sh --check'"
    else:
        label = ("Auto Start change cancelled — password prompt was cancelled"
                 if cancelled
                 else "Auto Start toggle failed — is the service installed?")
        item.set_active(not active)  # revert
    show_notify(label, "dialog-warning" if cancelled else None)


def on_bypass_all_toggle(item):
    """Toggle between per-program filtering and bypass-all-traffic mode."""
    active = item.get_active()
    # Persist FIRST: if the machine loses power between here and the daemon
    # coming up, the user's choice must still be there on the next start.
    # _arm_revert covers the other branch: a restart that never lands (the
    # password dialog was cancelled) rolls this write back, so the mode the
    # user cancelled is not silently applied at the next boot.
    _arm_revert("BYPASS_ALL", _load_settings().get("BYPASS_ALL", "0"))
    _save_setting("BYPASS_ALL", "1" if active else "0")
    mode = "all traffic" if active else "per-program"
    show_notify(f"Restarting — bypass mode: {mode}")
    restart_start_sh(bypass_all=active)


def show_notify(msg, icon=None):
    # Prefer theme icon name (works cross-DE), fall back to file path.
    if icon is None:
        icon = "goodbyedpi-plus"
        if GDPI_ICON and os.path.exists(GDPI_ICON):
            icon = GDPI_ICON
    icon_arg = icon if (icon and ("/" not in icon or os.path.exists(icon))) else "dialog-information"
    try:
        subprocess.run(["notify-send", "-a", "DPIGate", "-i", icon_arg,
                        "DPIGate", msg],
                       stderr=subprocess.DEVNULL)
    except OSError:
        pass

def on_uninstall(item):
    """Run uninstall.sh: stop daemon, remove firewall rules, delete all files,
    remove desktop entry and icon. Then quit the tray.

    uninstall.sh needs root and exits non-zero when its password dialog is
    cancelled. Honour that: cancelling must leave the installation intact and
    the tray running, not delete everything and close the menu anyway."""
    if not os.path.exists(UNINSTALL_SH):
        show_notify("uninstall.sh not found", "dialog-warning")
        return
    show_notify("Uninstalling — this will remove all DPIGate files")
    global _shutting_down
    _shutting_down = True
    try:
        rc = subprocess.run(["bash", UNINSTALL_SH],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL).returncode
    except OSError:
        rc = 1
    if rc != 0:
        _shutting_down = False
        show_notify("Uninstall cancelled — nothing was removed", "dialog-warning")
        return
    Gtk.main_quit()


def on_exit(item):
    show_notify("Exiting — cleaning up goodbyedpi + firewall rules")
    if not _teardown():
        # _teardown released the guards, so the tray is fully live again:
        # watchdog armed, menu usable, bypass untouched.
        show_notify("Exit cancelled — bypass still running", "dialog-warning")
        return
    Gtk.main_quit()


# ── Crash watchdog ────────────────────────────────────────────────────────────
def check_alive():
    global _shutting_down, _watchdog_tick
    if _shutting_down or GDPI_PID <= 0:
        return True
    try:
        os.kill(GDPI_PID, 0)   # signal 0 = existence check
    except PermissionError:
        # EPERM — process exists but we lack rights (it's root). Still alive.
        return True
    except OSError:
        # ESRCH — no such process. goodbyedpi died → clean up firewall + exit.
        # Read last log lines for debugging (e.g. "nfq_create_queue failed").
        data_dir = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
        log_path = os.path.join(data_dir, "GoodbyeDPI-Plus", "goodbyedpi.log")
        log_tail = ""
        try:
            if os.path.exists(log_path):
                with open(log_path) as f:
                    lines = f.readlines()
                    log_tail = "".join(lines[-3:]).strip().replace("\n", " | ")
        except Exception:
            pass
        msg = "goodbyedpi exited unexpectedly"
        if log_tail:
            msg += f"\n{log_tail}"
        _shutting_down = True
        show_notify(msg, "dialog-warning")
        return False

    # Daemon alive — self-heal against another firewall manager (firewalld/
    # ufw/nftables.service reload) flushing our rules. Checked every 15th
    # tick (~30s at the 2s timer interval below) to keep the subprocess
    # cost low; this is the only mechanism that survives a ruleset flush
    # from outside DPIGate.
    _watchdog_tick += 1
    if _watchdog_tick % 15 == 0:
        rc, _out = _plat("fw-is-loaded", noprompt=True)
        if rc == 1 and _plat("fw-load", noprompt=True)[0] == 0:
            show_notify("Firewall rules reloaded")
    return True   # keep timer alive


# ── Build menu ────────────────────────────────────────────────────────────────
def build_menu():
    menu = Gtk.Menu()

    # DNS dropdown
    dns_item = Gtk.MenuItem(label=f"DNS: {GDPI_DNS_LABEL}")
    submenu = Gtk.Menu()
    group = None
    for i, d in enumerate(DNS_ITEMS):
        time_str = f"{d['time_ms']}ms" if d["time_ms"] and d["time_ms"] != "-1" else "n/a"
        label = f"{d['name']} {d['addr']}:{d['port']} ({time_str})"
        if d["status"] != "ok":
            label += f" [{d['status']}]"
        radio = Gtk.RadioMenuItem.new_with_label([group] if group else None, label)
        if group is None:
            group = radio
        if i == GDPI_DNS_CURRENT:
            radio.set_active(True)
        radio.connect("activate", on_dns_selected, i)
        submenu.append(radio)

    submenu.append(Gtk.SeparatorMenuItem())
    auto = Gtk.MenuItem(label="Auto-detect (re-test)")
    auto.connect("activate", on_dns_autodetect)
    submenu.append(auto)

    dns_item.set_submenu(submenu)
    menu.append(dns_item)

    menu.append(Gtk.SeparatorMenuItem())

    edit = Gtk.MenuItem(label="Edit Program Filters")
    edit.connect("activate", on_edit_programs)
    menu.append(edit)

    # Bypass-all toggle: when ON, bypass all traffic (no per-program filter).
    # When OFF, only programs in ProgramFilters get bypassed.
    bypass_label = "Bypass All Traffic [ON]" if GDPI_BYPASS_ALL else "Bypass All Traffic [OFF]"
    bypass_item = Gtk.CheckMenuItem(label=bypass_label)
    bypass_item.set_active(GDPI_BYPASS_ALL)
    bypass_item.connect("activate", on_bypass_all_toggle)
    menu.append(bypass_item)

    menu.append(Gtk.SeparatorMenuItem())

    status = verify_autostart()
    autostart = Gtk.CheckMenuItem(label=status['detail'])
    autostart.set_active(status['active'])
    autostart.connect("activate", on_autostart_toggle)
    menu.append(autostart)

    menu.append(Gtk.SeparatorMenuItem())

    uninstall_item = Gtk.MenuItem(label="Uninstall")
    uninstall_item.connect("activate", on_uninstall)
    menu.append(uninstall_item)

    menu.append(Gtk.SeparatorMenuItem())
    exit_item = Gtk.MenuItem(label="Exit")
    exit_item.connect("activate", on_exit)
    menu.append(exit_item)

    menu.show_all()
    return menu


def main():
    # Use theme icon name (installed to ~/.local/share/icons/hicolor).
    # Falls back to file path if theme icon not found, then to "network-server".
    icon_name = "goodbyedpi-plus"
    if GDPI_ICON and os.path.exists(GDPI_ICON):
        icon_name = GDPI_ICON  # file path (backward compat)
    global _indicator
    _indicator = AppIndicator.Indicator.new(
        "GoodbyeDPI-Plus",
        icon_name,
        AppIndicator.IndicatorCategory.APPLICATION_STATUS,
    )
    ind = _indicator
    ind.set_title("GoodbyeDPI")
    ind.set_status(AppIndicator.IndicatorStatus.ACTIVE)
    ind.set_menu(build_menu())

    if INDICATOR_TIER == "null":
        sys.stderr.write("[tray] No system tray backend available — stopping bypass (a visible tray is required)\n")
        show_notify("No system tray available — bypass stopped", "dialog-error")
        _teardown(noprompt=True)
        sys.exit(1)

    # Crash watchdog — every 2s
    GLib.timeout_add_seconds(2, check_alive)

    show_notify(f"Running — DNS: {GDPI_DNS_LABEL}")
    # Interpreter exit (crash, sys.exit): nobody is waiting at a dialog, and
    # reaper.sh covers whatever cannot be reached without root.
    atexit.register(lambda: _teardown(noprompt=True))

    def _sig_quit(*_a):
        # SIGTERM/SIGHUP arrive from logout, the session manager, or kill.sh
        # itself (it stops the tray as part of its teardown). Prompting here
        # would either hang with nobody to answer or pop a SECOND password
        # dialog on top of the kill.sh run that sent the signal.
        _teardown(noprompt=True)
        Gtk.main_quit()
        return False

    for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, _sig, _sig_quit)

    Gtk.main()


if __name__ == "__main__":
    main()
