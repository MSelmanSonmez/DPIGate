#!/bin/bash
# Installs DPIGate.app for the current user: ~/Applications/DPIGate.app. No admin rights, no sudo.
# It only copies the app. It never touches network settings, launchctl, LaunchAgents or app settings.
#   ./install.sh [--open] [--help]
# Test/override variables: DPIGATE_INSTALL_DIR (default ~/Applications), DPIGATE_PGREP (default pgrep).
set -e

HERE=$(cd "$(dirname "$0")" && pwd)
DEST_DIR=${DPIGATE_INSTALL_DIR:-$HOME/Applications}
DEST=$DEST_DIR/DPIGate.app
OPEN=0

for a in "$@"; do
  case "$a" in
    --open) OPEN=1;;
    -h|--help) sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//'; echo "  --open   open the app after installing"; exit 0;;
    *) echo "install.sh: unknown option $a (try --help)" >&2; exit 2;;
  esac
done

# Source: an app next to this script (unpacked release zip), else build it in a repo checkout.
if [ -d "$HERE/DPIGate.app" ]; then
  SRC=$HERE/DPIGate.app
else
  if ! xcode-select -p >/dev/null 2>&1; then
    echo "install.sh: no DPIGate.app next to this script and no compiler to build one." >&2
    echo "Install the Command Line Tools first: xcode-select --install" >&2
    exit 1
  fi
  make -C "$HERE" app
  SRC=$HERE/build/DPIGate.app
fi
[ -d "$SRC" ] || { echo "install.sh: $SRC not found" >&2; exit 1; }

# Never replace an app that is running (and never kill anything).
if ${DPIGATE_PGREP:-pgrep} -f "$DEST/Contents/MacOS/DPIGate" >/dev/null 2>&1; then
  echo "install.sh: DPIGate is running from $DEST - quit DPIGate from its menu first." >&2
  exit 1
fi

mkdir -p "$DEST_DIR"
TMP=$DEST_DIR/.DPIGate.app.new.$$
rm -rf "$TMP"
ditto "$SRC" "$TMP"
xattr -dr com.apple.quarantine "$TMP" 2>/dev/null || true
rm -rf "$DEST"
mv "$TMP" "$DEST"

echo "Installed $DEST"
if [ "$OPEN" = 1 ]; then
  open "$DEST"
else
  echo "Open it from there (or: open \"$DEST\"); its icon appears in the menu bar."
  echo "If macOS blocks the first launch: right-click the app, Open."
fi
