#!/bin/bash
# Lifecycle tests for the DPIGate menu bar app. A fake dpigate script stands in for the
# real one, so no system setting is touched. A status item flashes in the menu bar meanwhile.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
APPBIN=${DPIGATE_APP_BIN:-$HERE/../build/DPIGate.app/Contents/MacOS/DPIGate}
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dpigate-apptest.XXXXXX") || exit 1
PASSED=0 FAILED=0 APP_PID=

cleanup() { [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null; rm -rf "$ROOT"; }
trap cleanup EXIT

ok() { PASSED=$((PASSED + 1)); echo "ok   - $1"; }
bad() { FAILED=$((FAILED + 1)); echo "FAIL - $1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# wait_for <seconds> <command...>: poll until the command succeeds
wait_for() { local n=$(($1 * 10)); shift; while [ $n -gt 0 ]; do "$@" && return 0; sleep 0.1; n=$((n - 1)); done; return 1; }
has_line() { grep -q "$2" "$1" 2>/dev/null; }
gone() { ! kill -0 "$1" 2>/dev/null; }
count() { grep -c "^$2" "$1" 2>/dev/null || true; }

# Fake script: logs the call, announces itself, restores on SIGINT.
# With a "short" file next to it, it exits by itself after one second.
make_fake() {
  cat > "$1/fake" <<'EOF2'
#!/bin/bash
D=$(dirname "$0")
echo "call $*" >> "$D/calls"
case "$1" in
  restore) exit 0;;
esac
trap 'echo "signal INT" >> "$D/calls"; echo "restored" >> "$D/calls"; exit 0' INT
trap 'echo "signal TERM" >> "$D/calls"; exit 0' TERM
echo "dpigate: running on 'Fake' (test)"
if [ -f "$D/short" ]; then sleep 1; exit 3; fi
while true; do sleep 0.2; done
EOF2
  chmod +x "$1/fake"
}

launch() { # <dir>
  local d=$1
  env DPIGATE_APP_SCRIPT="$d/fake" DPIGATE_APP_AUTOSTART=1 DPIGATE_APP_LOG="$d/app.log" \
      DPIGATE_APP_NOTIFY_LOG="$d/notify" STATE_DIR="$d/state" "$APPBIN" </dev/null >"$d/out" 2>&1 &
  APP_PID=$!
}

RES=$(cd "$(dirname "$APPBIN")/../Resources" 2>/dev/null && pwd)
[ -x "$APPBIN" ] || { echo "app binary missing: $APPBIN (run: make -C macos app)"; exit 1; }

# 0. bundle icons: menu bar logo at 18 and 36 px, app icon
w() { sips -g pixelWidth "$1" 2>/dev/null | awk '/pixelWidth/{print $2}'; }
check "menubar.png is 18 px wide" '[ "$(w "$RES/menubar.png")" = 18 ]'
check "menubar@2x.png is 36 px wide" '[ "$(w "$RES/menubar@2x.png")" = 36 ]'
check "AppIcon.icns exists and is a valid icon file" '[ -s "$RES/AppIcon.icns" ] && file "$RES/AppIcon.icns" | grep -q "Mac OS X icon"'
check "Info.plist names the icon" '[ "$(plutil -extract CFBundleIconFile raw "$RES/../Info.plist")" = AppIcon ]'

# 1. autostart runs the script; SIGTERM makes the app interrupt it and wait for its restore
A=$ROOT/a; mkdir -p "$A"; make_fake "$A"
launch "$A"
wait_for 10 has_line "$A/calls" "call run"
check "autostart calls 'run'" 'has_line "$A/calls" "call run"'
wait_for 5 has_line "$A/app.log" "running on"
check "script output reaches the log" 'has_line "$A/app.log" "running on"'
kill -TERM "$APP_PID"
wait_for 12 gone "$APP_PID"
check "app exits within 12s of SIGTERM" 'gone "$APP_PID"'
check "script got SIGINT" 'has_line "$A/calls" "signal INT"'
check "script restored before the app left" 'has_line "$A/calls" "restored"'
check "script was not sent SIGTERM" '! has_line "$A/calls" "signal TERM"'
APP_PID=

# 2. unexpected exits: restart, give up after 3 failures
B=$ROOT/b; mkdir -p "$B"; make_fake "$B"; touch "$B/short"
launch "$B"
wait_for 20 has_line "$B/notify" "Stopped - see log"
check "3 failures end in a 'Stopped' notification" 'has_line "$B/notify" "Stopped - see log"'
check "script was run 3 times" '[ "$(count "$B/calls" "call run")" = 3 ]'
sleep 3
check "no fourth attempt" '[ "$(count "$B/calls" "call run")" = 3 ]'
kill -TERM "$APP_PID"; wait_for 12 gone "$APP_PID"
check "app still exits cleanly after giving up" 'gone "$APP_PID"'
APP_PID=

# 3. stale state file: restore runs before the first run
C=$ROOT/c; mkdir -p "$C/state"; make_fake "$C"; echo stale > "$C/state/state"
launch "$C"
wait_for 10 has_line "$C/calls" "call run"
check "stale state triggers 'restore'" 'has_line "$C/calls" "call restore"'
check "restore comes before run" '[ "$(grep -n "call restore" "$C/calls" | head -1 | cut -d: -f1)" -lt "$(grep -n "call run" "$C/calls" | head -1 | cut -d: -f1)" ]'
kill -TERM "$APP_PID"; wait_for 12 gone "$APP_PID"; APP_PID=

echo "$PASSED passed, $FAILED failed"
[ $FAILED -eq 0 ]
