# Test isolation, sourced by every test script after it set $ROOT (its temp dir).
# 1. HOME and every path/tool the app and the script read are redirected into $ROOT, so even a test that
#    forgets its own overrides cannot reach the real ~/Library or run a real system tool.
# 2. iso_guard_end compares the real files (read only) with a snapshot taken by iso_init and fails on a change.
REAL_HOME=${DPIGATE_REAL_HOME:-$HOME}   # only ever read, never written

iso_snap() {
  local P=$REAL_HOME/Library/LaunchAgents/org.dpigate.menubar.plist
  if [ -f "$P" ]; then echo "plist $(shasum "$P" | cut -d' ' -f1) $(stat -f %m "$P")"; else echo "plist none"; fi
  # names only: a running DPIGate may legitimately append to its log
  echo "agents: $(ls "$REAL_HOME/Library/LaunchAgents" 2>/dev/null | tr '\n' ' ')"
  echo "support: $(ls -R "$REAL_HOME/Library/Application Support/DPIGate" 2>/dev/null | tr '\n' ' ')"
  echo "logs: $(ls -R "$REAL_HOME/Library/Logs/DPIGate" 2>/dev/null | tr '\n' ' ')"
}

iso_init() {
  ISO=$ROOT/iso; mkdir -p "$ISO/home/Library" "$ISO/LA" "$ISO/bin"
  iso_snap > "$ISO/snapshot.before"
  # Any real system tool that is not replaced by a test logs a violation and fails.
  printf '#!/bin/bash\necho "$0 $*" >> "%s/violations"\nexit 1\n' "$ISO" > "$ISO/bin/deny"; chmod +x "$ISO/bin/deny"
  printf '#!/bin/bash\necho "$*" >> "%s/launchctl.log"\n' "$ISO" > "$ISO/bin/launchctl"; chmod +x "$ISO/bin/launchctl"
  export HOME=$ISO/home
  export DPIGATE_LAUNCH_AGENTS_DIR=$ISO/LA STATE_DIR=$ISO/home/Library/Application\ Support/DPIGate
  export DPIGATE_APP_LOG=$ISO/home/Library/Logs/DPIGate/dpigate.log DPIGATE_APP_NOTIFY_LOG=$ISO/notify
  export LAUNCHCTL=$ISO/bin/launchctl DPIGATE_APP_OPEN=$ISO/bin/deny
  export NETWORKSETUP=$ISO/bin/deny ROUTE=$ISO/bin/deny DSCACHEUTIL=$ISO/bin/deny OSASCRIPT=$ISO/bin/deny
  export RESOLVE_CMD="$ISO/bin/deny"
}

iso_guard_end() {
  iso_snap > "$ISO/snapshot.after"
  if cmp -s "$ISO/snapshot.before" "$ISO/snapshot.after" && [ ! -s "$ISO/violations" ]; then
    PASSED=$((PASSED + 1)); echo "ok   - isolation: real LaunchAgent, Application Support and Logs unchanged, no real tool called"
  else
    FAILED=$((FAILED + 1)); echo "FAIL - isolation: real files changed or a real tool was called"
    diff "$ISO/snapshot.before" "$ISO/snapshot.after" | sed 's/^/     /'; cat "$ISO/violations" 2>/dev/null | sed 's/^/     tool: /'
  fi
}
