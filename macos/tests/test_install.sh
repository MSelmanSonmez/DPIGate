#!/bin/bash
# Tests for install.sh, uninstall.sh and `make dist`. Temporary directories only: nothing under the real
# ~/Applications, ~/Library or network settings is touched, and no app is started.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
MAC=$HERE/..
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dpigate-installtest.XXXXXX") || exit 1
. "$(cd "$(dirname "$0")" && pwd)/isolate.sh"; iso_init
PASSED=0 FAILED=0
trap 'rm -rf "$ROOT"' EXIT

ok() { PASSED=$((PASSED + 1)); echo "ok   - $1"; }
bad() { FAILED=$((FAILED + 1)); echo "FAIL - $1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# A fake app bundle: marker file $2 inside, and a dpigate script that logs "restore" to $LOG.
make_app() {
  mkdir -p "$1/DPIGate.app/Contents/MacOS" "$1/DPIGate.app/Contents/Resources"
  echo "$2" > "$1/DPIGate.app/Contents/MacOS/DPIGate"
  printf '#!/bin/bash\necho "$1 STATE_DIR=$STATE_DIR" >> "$LOG"\nrm -f "$STATE_DIR/state"\n' > "$1/DPIGate.app/Contents/Resources/dpigate"
  chmod +x "$1/DPIGate.app/Contents/Resources/dpigate"
}
# Fake pgrep: "running" if the file named by $RUNNING exists.
printf '#!/bin/bash\n[ -f "$RUNNING" ]\n' > "$ROOT/pgrep"; chmod +x "$ROOT/pgrep"
export DPIGATE_PGREP=$ROOT/pgrep RUNNING=$ROOT/running LOG=$ROOT/log

# (i) install from an app next to the script
R=$ROOT/rel; mkdir -p "$R"; cp "$MAC/install.sh" "$R/"; make_app "$R" v1
INST=$ROOT/Applications/sub; export DPIGATE_INSTALL_DIR=$INST
xattr -w com.apple.quarantine "0081;00000000;Test;" "$R/DPIGate.app" 2>/dev/null
out=$(bash "$R/install.sh" 2>&1); rc=$?
check "install: exits 0 and creates the install dir" '[ $rc = 0 ] && [ -d "$INST/DPIGate.app" ]'
check "install: app content copied" '[ "$(cat "$INST/DPIGate.app/Contents/MacOS/DPIGate")" = v1 ]'
check "install: quarantine attribute removed from the copy" '! xattr "$INST/DPIGate.app" | grep -q quarantine'
# Never let a later step execute a quarantined file (Gatekeeper would pop a dialog): strip the flag test-side now.
xattr -dr com.apple.quarantine "$INST/DPIGate.app" "$R/DPIGate.app" 2>/dev/null
check "install: source app left alone" '[ -d "$R/DPIGate.app" ]'
check "install: no temp copy left behind" '[ "$(ls -A "$INST")" = DPIGate.app ]'
check "install: prints next steps, does not open" 'echo "$out" | grep -q "menu bar"'

# (ii) reinstall replaces
echo v2 > "$R/DPIGate.app/Contents/MacOS/DPIGate"; touch "$INST/DPIGate.app/old-file"
bash "$R/install.sh" >/dev/null 2>&1; rc=$?
check "reinstall: content replaced, old files gone" '[ $rc = 0 ] && [ "$(cat "$INST/DPIGate.app/Contents/MacOS/DPIGate")" = v2 ] && [ ! -e "$INST/DPIGate.app/old-file" ]'

# (iii) refuses while running
echo v3 > "$R/DPIGate.app/Contents/MacOS/DPIGate"; touch "$RUNNING"
out=$(bash "$R/install.sh" 2>&1); rc=$?
check "running: install refuses with a quit message, app untouched" '[ $rc != 0 ] && echo "$out" | grep -q "quit DPIGate" && [ "$(cat "$INST/DPIGate.app/Contents/MacOS/DPIGate")" = v2 ]'
rm -f "$RUNNING"

# (iv) bad option
bash "$R/install.sh" --bogus >/dev/null 2>&1; rc=$?
check "install: unknown option fails" '[ $rc = 2 ]'

# (v) uninstall deletes only the expected files and the bundle
export DPIGATE_LAUNCH_AGENTS_DIR=$ROOT/LA STATE_DIR=$ROOT/AS/DPIGate DPIGATE_APP_LOG=$ROOT/Logs/DPIGate/dpigate.log
mkdir -p "$ROOT/LA" "$STATE_DIR/config" "$ROOT/Logs/DPIGate"
touch "$ROOT/LA/org.dpigate.menubar.plist" "$ROOT/LA/other.plist" "$STATE_DIR/config/config" "$STATE_DIR/config/sites.txt" \
  "$STATE_DIR/config/apps.txt" "$STATE_DIR/state" "$STATE_DIR/app.lock" "$ROOT/Logs/DPIGate/dpigate.log"
touch "$STATE_DIR/config/mine.txt" "$ROOT/Logs/DPIGate/other.log"
: > "$LOG"; cp "$MAC/uninstall.sh" "$ROOT/uninstall.sh"
printf 'n\n' | bash "$ROOT/uninstall.sh" >/dev/null 2>&1; rc=$?
check "uninstall: answering no cancels and deletes nothing" '[ $rc != 0 ] && [ -d "$INST/DPIGate.app" ] && [ -f "$STATE_DIR/state" ]'
printf 'y\n' | bash "$ROOT/uninstall.sh" >/dev/null 2>&1; rc=$?
check "uninstall: exits 0, bundle gone" '[ $rc = 0 ] && [ ! -e "$INST/DPIGate.app" ]'
check "uninstall: restore ran once with the state dir" '[ "$(cat "$LOG")" = "restore STATE_DIR=$STATE_DIR" ]'
check "uninstall: LaunchAgent, config files, state, lock and log removed" '[ ! -e "$ROOT/LA/org.dpigate.menubar.plist" ] && [ ! -e "$STATE_DIR/config/config" ] && [ ! -e "$STATE_DIR/config/sites.txt" ] && [ ! -e "$STATE_DIR/config/apps.txt" ] && [ ! -e "$STATE_DIR/state" ] && [ ! -e "$STATE_DIR/app.lock" ] && [ ! -e "$ROOT/Logs/DPIGate/dpigate.log" ]'
check "uninstall: unrelated files and folders that are not empty survive" '[ -f "$ROOT/LA/other.plist" ] && [ -f "$STATE_DIR/config/mine.txt" ] && [ -f "$ROOT/Logs/DPIGate/other.log" ]'

# (vi) without a saved state: no restore; empty folders are removed
make_app "$INST" v4
rm -rf "$ROOT/AS" "$ROOT/Logs"; mkdir -p "$STATE_DIR/config" "$ROOT/Logs/DPIGate"; touch "$STATE_DIR/config/config"; : > "$LOG"
bash "$ROOT/uninstall.sh" --yes >/dev/null 2>&1; rc=$?
check "uninstall --yes: no restore without a state file, empty folders removed" '[ $rc = 0 ] && [ ! -s "$LOG" ] && [ ! -e "$STATE_DIR" ] && [ ! -e "$ROOT/Logs/DPIGate" ] && [ ! -e "$INST/DPIGate.app" ]'

# (vii) refuses while running, and refuses a path that is not DPIGate.app
make_app "$INST" v5; touch "$RUNNING"
bash "$ROOT/uninstall.sh" --yes >/dev/null 2>&1; rc=$?
check "uninstall: refuses while running" '[ $rc != 0 ] && [ -d "$INST/DPIGate.app" ]'
rm -f "$RUNNING"
mkdir -p "$ROOT/Precious"; touch "$ROOT/Precious/file"
DPIGATE_APP_PATH=$ROOT/Precious bash "$ROOT/uninstall.sh" --yes >/dev/null 2>&1; rc=$?
check "uninstall: refuses a path not ending in /DPIGate.app" '[ $rc != 0 ] && [ -f "$ROOT/Precious/file" ]'

# (viii) make dist: the zip holds the app and both scripts under DPIGate-macos/
make -C "$MAC" dist >"$ROOT/dist.log" 2>&1; rc=$?
ZIP=$MAC/build/DPIGate-macos.zip
check "dist: make dist succeeds and writes the zip" '[ $rc = 0 ] && [ -f "$ZIP" ]'
LIST=$(unzip -Z1 "$ZIP" 2>/dev/null)
check "dist: zip has DPIGate-macos/install.sh, uninstall.sh and DPIGate.app" 'echo "$LIST" | grep -qx "DPIGate-macos/install.sh" && echo "$LIST" | grep -qx "DPIGate-macos/uninstall.sh" && echo "$LIST" | grep -q "^DPIGate-macos/DPIGate.app/Contents/MacOS/DPIGate\$"'
check "dist: nothing outside DPIGate-macos/ (no __MACOSX)" '! echo "$LIST" | grep -v "^DPIGate-macos/" | grep -q .'
check "dist: scripts in the zip are executable" 'unzip -Zv "$ZIP" DPIGate-macos/install.sh 2>/dev/null | grep -q "Unix file attributes.*755"'

iso_guard_end
echo "$PASSED passed, $FAILED failed"
[ $FAILED -eq 0 ]
