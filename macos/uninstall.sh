#!/bin/bash
# Removes DPIGate for the current user, for when the app's own Uninstall item is out of reach.
# Restores network settings (only if a saved state exists), deletes the Auto Start entry, the settings,
# state and log files, and the app itself. Asks first unless --yes.
#   ./uninstall.sh [--yes] [--help]
# Test/override variables: DPIGATE_INSTALL_DIR, DPIGATE_LAUNCH_AGENTS_DIR, STATE_DIR (as the app and
# script use them), DPIGATE_CONFIG_DIR, DPIGATE_APP_LOG, DPIGATE_PGREP, DPIGATE_APP_PATH (the app to remove).
set -u

DEST=${DPIGATE_APP_PATH:-${DPIGATE_INSTALL_DIR:-$HOME/Applications}/DPIGate.app}
STATE_DIR=${STATE_DIR:-$HOME/Library/Application Support/DPIGate}
CONFIG_DIR=${DPIGATE_CONFIG_DIR:-$STATE_DIR/config}
LOG_FILE=${DPIGATE_APP_LOG:-$HOME/Library/Logs/DPIGate/dpigate.log}
AGENT=${DPIGATE_LAUNCH_AGENTS_DIR:-$HOME/Library/LaunchAgents}/org.dpigate.menubar.plist
YES=0

for a in "$@"; do
  case "$a" in
    --yes|-y) YES=1;;
    -h|--help) sed -n "2,5p" "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "uninstall.sh: unknown option $a (try --help)" >&2; exit 2;;
  esac
done

case "$DEST" in
  */DPIGate.app) ;;
  *) echo "uninstall.sh: $DEST does not end in /DPIGate.app; refusing." >&2; exit 1;;
esac

if ${DPIGATE_PGREP:-pgrep} -f "$DEST/Contents/MacOS/DPIGate" >/dev/null 2>&1; then
  echo "uninstall.sh: DPIGate is running from $DEST - quit DPIGate from its menu first." >&2
  exit 1
fi

if [ "$YES" != 1 ]; then
  echo "This restores your network settings and permanently deletes DPIGate.app ($DEST),"
  echo "its settings, log and Auto Start entry. It cannot be undone."
  printf 'Continue? [y/N] '
  read -r ans || ans=
  case "$ans" in y|Y|yes) ;; *) echo "Cancelled."; exit 1;; esac
fi

# Put the saved proxy/DNS settings back first (the script itself needs the state file to do anything).
if [ -f "$STATE_DIR/state" ]; then
  if [ -x "$DEST/Contents/Resources/dpigate" ]; then
    STATE_DIR=$STATE_DIR "$DEST/Contents/Resources/dpigate" restore || {
      echo "uninstall.sh: restore failed; nothing was deleted. Fix that first (or run it again)." >&2; exit 1; }
  else
    echo "uninstall.sh: a saved state exists but there is no app to restore it with; nothing was deleted." >&2
    exit 1
  fi
fi

# Only the file is deleted, no launchctl: the agent is loaded at login only, and a stale copy
# in this session's launchd does nothing once the app is gone.
rm -f "$AGENT"
for f in "$CONFIG_DIR/config" "$CONFIG_DIR/apps.txt" "$CONFIG_DIR/sites.txt"; do rm -f "$f"; done
rmdir "$CONFIG_DIR" 2>/dev/null || true
for f in state state.tmp app.lock; do rm -f "$STATE_DIR/$f"; done
rmdir "$STATE_DIR" 2>/dev/null || true
rm -f "$LOG_FILE"
rmdir "$(dirname "$LOG_FILE")" 2>/dev/null || true

rm -rf "$DEST"
echo "DPIGate removed."
