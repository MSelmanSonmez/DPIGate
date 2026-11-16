# tray-probe.py — exit 0 when the tray stack can load, 1 otherwise.
#
# Run as `python3 -I lib/tray-probe.py` (AppRun, and the root helper of the
# AppImage's run-without-installing mode). It checks what tray.py needs: GTK 3
# and AyatanaAppIndicator3 0.1, or AppIndicator3 0.1.
import importlib
import sys

try:
    import gi
    gi.require_version("Gtk", "3.0")
    importlib.import_module("gi.repository.Gtk")
except (ImportError, ValueError):
    sys.exit(1)
for name in ("AyatanaAppIndicator3", "AppIndicator3"):
    try:
        gi.require_version(name, "0.1")
        importlib.import_module("gi.repository." + name)
        sys.exit(0)
    except (ImportError, ValueError):
        pass
sys.exit(1)
