#!/bin/bash
# Tests for macos/dpigate. Everything runs against a fake networksetup/route and a
# fake proxy in a temporary directory; the real system settings are never touched.
set -u
set -m   # background jobs get default signal handling, so INT can reach dpigate

HERE=$(cd "$(dirname "$0")" && pwd)
DPIGATE=$HERE/../dpigate
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dpigate-test.XXXXXX") || exit 1
PASSED=0
FAILED=0
RUN_PID=
PORT=

# ---- fakes ------------------------------------------------------------------

make_fakes() {
  local T=$1
  mkdir -p "$T/fake"
  cat > "$T/networksetup" <<'EOF'
#!/bin/bash
# Fake networksetup: state lives in files under $FAKE, every call is logged.
echo "$*" >> "$FAKE/calls.log"
SVC="Test Ethernet"
f() { cat "$FAKE/$1" 2>/dev/null; }
case "${1:-}" in
  -listnetworkserviceorder)
    printf 'An asterisk (*) denotes that a network service is disabled.\n'
    printf '(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en1)\n\n'
    printf '(2) %s\n(Hardware Port: Ethernet, Device: en0)\n\n' "$SVC";;
  -getsocksfirewallproxy)
    if [ "$(f socks_enabled)" = yes ]; then echo "Enabled: Yes"; else echo "Enabled: No"; fi
    echo "Server: $(f socks_server)"
    echo "Port: $(f socks_port)"
    echo "Authenticated Proxy Enabled: 0";;
  -getdnsservers)
    if [ -s "$FAKE/dns" ]; then tr ' ' '\n' < "$FAKE/dns"
    else echo "There aren't any DNS Servers set on $2."; fi;;
  -getproxybypassdomains)
    if [ -s "$FAKE/bypass" ]; then tr ' ' '\n' < "$FAKE/bypass"
    else echo "There aren't any bypass domains set on $2."; fi;;
  -set*)
    if [ "${2:-}" != "$SVC" ]; then echo "** Error: $2 is not a recognized network service."; exit 1; fi
    case "$1" in
      -setsocksfirewallproxy) echo "$3" > "$FAKE/socks_server"; echo "$4" > "$FAKE/socks_port"; echo yes > "$FAKE/socks_enabled";;
      -setsocksfirewallproxystate) if [ "$3" = on ]; then echo yes; else echo no; fi > "$FAKE/socks_enabled";;
      -setdnsservers) shift 2; if [ "$*" = Empty ]; then : > "$FAKE/dns"; else echo "$*" > "$FAKE/dns"; fi;;
      -setproxybypassdomains) shift 2; if [ "$*" = Empty ]; then : > "$FAKE/bypass"; else echo "$*" > "$FAKE/bypass"; fi;;
    esac;;
  *) echo "fake networksetup: unsupported: $*" >&2; exit 1;;
esac
EOF
  cat > "$T/route" <<'EOF'
#!/bin/bash
printf '   route to: default\ndestination: default\n    gateway: 192.168.1.1\n  interface: en0\n'
EOF
  cat > "$T/proxy" <<'EOF'
#!/bin/bash
# Fake proxy: listens on the port given with -p until killed.
port=1080
while [ $# -gt 0 ]; do [ "$1" = -p ] && port=$2; shift; done
echo PROXY_START >> "$FAKE/calls.log"
exec nc -lk 127.0.0.1 "$port"
EOF
  cat > "$T/dscacheutil" <<'EOF'
#!/bin/bash
echo "DSCACHE $*" >> "$FAKE/calls.log"
EOF
  cat > "$T/osascript" <<'EOF'
#!/bin/bash
echo "OSASCRIPT" >> "$FAKE/calls.log"
[ -e "$FAKE/osa_fail" ] && exit 1
exit 0
EOF
  # Fake resolver: the old (poisoned) answer until the DNS servers are ours.
  cat > "$T/resolve" <<'EOF'
#!/bin/bash
echo "RESOLVE $*" >> "$FAKE/calls.log"
if [ "$(cat "$FAKE/dns" 2>/dev/null)" = "1.1.1.1 1.0.0.1" ]; then ip=162.159.1.1; else ip=212.175.180.11; fi
printf 'name: %s\nip_address: %s\n' "$5" "$ip"
EOF
  chmod +x "$T/networksetup" "$T/route" "$T/proxy" "$T/dscacheutil" "$T/osascript" "$T/resolve"
}

# setup <socks_enabled> <socks_server> <socks_port> <dns> <bypass>
setup() {
  T=$ROOT/t$((PASSED + FAILED + 1))
  make_fakes "$T"
  export FAKE=$T/fake
  printf '%s\n' "$1" > "$FAKE/socks_enabled"
  printf '%s\n' "$2" > "$FAKE/socks_server"
  printf '%s\n' "$3" > "$FAKE/socks_port"
  printf '%s\n' "$4" > "$FAKE/dns"
  printf '%s\n' "$5" > "$FAKE/bypass"
  : > "$FAKE/calls.log"
  PORT=$((20000 + RANDOM % 20000))
  while lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t </dev/null >/dev/null 2>&1; do PORT=$((PORT + 1)); done
  export NETWORKSETUP=$T/networksetup ROUTE=$T/route PROXY_BIN=$T/proxy
  export DSCACHEUTIL=$T/dscacheutil OSASCRIPT=$T/osascript RESOLVE_CMD="$T/resolve -q host -a name"
  export DPIGATE_WARMUP_SECS=3
  export STATE_DIR=$T/state DPIGATE_PORT=$PORT
  RUN_PID=
}

listener_pid() { lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t </dev/null 2>/dev/null | head -1; }

# Kill only what this test started: the dpigate pid and the listener on its private port.
teardown() {
  local p
  [ -n "$RUN_PID" ] && kill -KILL "$RUN_PID" 2>/dev/null
  p=$(listener_pid)
  [ -n "$p" ] && kill -KILL "$p" 2>/dev/null
  wait 2>/dev/null
  return 0
}

start_run() {
  /bin/bash "$DPIGATE" run </dev/null >"$T/run.out" 2>&1 &
  RUN_PID=$!
  wait_for "grep -q 'running on' '$T/run.out'" || return 1
}

wait_for() {   # wait_for <shell condition>, up to ~15 s
  local i=0
  while [ $i -lt 150 ]; do
    eval "$1" && return 0
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

# ---- assertions ---------------------------------------------------------------

FAILMSG=
check() {   # check <description> <condition>
  if ! eval "$2"; then FAILMSG="$FAILMSG
    - $1"; return 1; fi
  return 0
}

finish() {   # finish <name>
  teardown
  if [ -z "$FAILMSG" ]; then
    PASSED=$((PASSED + 1)); echo "ok   - $1"
  else
    FAILED=$((FAILED + 1)); echo "FAIL - $1$FAILMSG"
    [ -f "$T/run.out" ] && sed 's/^/      run.out: /' "$T/run.out" | head -20
  fi
  FAILMSG=
}

# ---- tests --------------------------------------------------------------------

test_1_run_applies_then_int_restores() {
  setup no "" 0 "8.8.8.8" "localhost *.local"
  start_run
  check "socks on, pointed at 127.0.0.1" "[ \"\$(cat '$FAKE/socks_enabled')\" = yes ] && [ \"\$(cat '$FAKE/socks_server')\" = 127.0.0.1 ] && [ \"\$(cat '$FAKE/socks_port')\" = $PORT ]"
  check "bypass list set" "grep -q '192.168/16' '$FAKE/bypass'"
  check "state file written" "[ -f '$STATE_DIR/state' ]"
  kill -INT "$RUN_PID"; wait "$RUN_PID" 2>/dev/null; RUN_PID=
  check "socks off again" "[ \"\$(cat '$FAKE/socks_enabled')\" = no ]"
  check "old DNS back" "[ \"\$(cat '$FAKE/dns')\" = 8.8.8.8 ]"
  check "empty SOCKS server/port back" "[ -z \"\$(cat '$FAKE/socks_server')\" ] && [ \"\$(cat '$FAKE/socks_port')\" = 0 ]"
  check "old bypass back" "[ \"\$(cat '$FAKE/bypass')\" = 'localhost *.local' ]"
  check "state file removed" "[ ! -f '$STATE_DIR/state' ]"
  check "proxy stopped" "[ -z \"\$(listener_pid)\" ]"
  finish "run sets proxy+DNS, INT restores previous settings"
}

test_2_empty_dns_restored_as_Empty() {
  setup no "" 0 "" ""
  start_run
  kill -INT "$RUN_PID"; wait "$RUN_PID" 2>/dev/null; RUN_PID=
  check "-setdnsservers ... Empty was called" "grep -qx -- '-setdnsservers Test Ethernet Empty' '$FAKE/calls.log'"
  check "DNS empty again" "[ ! -s '$FAKE/dns' ]"
  check "bypass empty again" "[ ! -s '$FAKE/bypass' ]"
  finish "empty DNS is restored with 'Empty'"
}

test_3_previous_socks_restored() {
  setup yes 10.0.0.5 9050 "8.8.4.4" "localhost"
  start_run
  check "our proxy replaced theirs" "[ \"\$(cat '$FAKE/socks_server')\" = 127.0.0.1 ]"
  kill -INT "$RUN_PID"; wait "$RUN_PID" 2>/dev/null; RUN_PID=
  check "previous server back" "[ \"\$(cat '$FAKE/socks_server')\" = 10.0.0.5 ]"
  check "previous port back" "[ \"\$(cat '$FAKE/socks_port')\" = 9050 ]"
  check "previous proxy still enabled" "[ \"\$(cat '$FAKE/socks_enabled')\" = yes ]"
  finish "previously enabled SOCKS proxy is restored as it was"
}

test_4_proxy_dies_settings_restored() {
  setup no "" 0 "8.8.8.8" "localhost"
  start_run
  kill -KILL "$(listener_pid)"
  wait_for "! kill -0 $RUN_PID 2>/dev/null"
  check "dpigate exited after proxy died" "! kill -0 $RUN_PID 2>/dev/null"
  wait "$RUN_PID" 2>/dev/null; RUN_PID=
  check "socks off again" "[ \"\$(cat '$FAKE/socks_enabled')\" = no ]"
  check "old DNS back" "[ \"\$(cat '$FAKE/dns')\" = 8.8.8.8 ]"
  check "state file removed" "[ ! -f '$STATE_DIR/state' ]"
  finish "proxy dying on its own restores settings"
}

test_5_kill9_then_restore() {
  setup no "" 0 "8.8.8.8" "localhost"
  start_run
  kill -KILL "$RUN_PID"; wait "$RUN_PID" 2>/dev/null; RUN_PID=
  check "state file survives kill -9" "[ -f '$STATE_DIR/state' ]"
  check "settings still applied" "[ \"\$(cat '$FAKE/dns')\" = '1.1.1.1 1.0.0.1' ]"
  /bin/bash "$DPIGATE" restore </dev/null >"$T/restore.out" 2>&1
  check "restore exits 0" "[ $? -eq 0 ]"
  check "socks off again" "[ \"\$(cat '$FAKE/socks_enabled')\" = no ]"
  check "old DNS back" "[ \"\$(cat '$FAKE/dns')\" = 8.8.8.8 ]"
  check "state file removed" "[ ! -f '$STATE_DIR/state' ]"
  check "orphaned proxy stopped" "[ -z \"\$(listener_pid)\" ]"
  /bin/bash "$DPIGATE" restore </dev/null 2>&1 | grep -q 'nothing to restore'
  check "second restore says nothing to restore" "[ ${PIPESTATUS[1]:-1} -eq 0 ]"
  finish "kill -9 leaves state; restore recovers"
}

test_6_proxy_fails_dns_restored_no_socks() {
  setup no "" 0 "8.8.8.8" "localhost"
  export PROXY_BIN=/usr/bin/false
  /bin/bash "$DPIGATE" run </dev/null >"$T/run.out" 2>&1
  check "dpigate exits non-zero" "[ $? -ne 0 ]"
  check "DNS was changed, then put back" "[ \$(grep -c -- '^-setdnsservers' '$FAKE/calls.log') -eq 2 ] && grep -- '^-setdnsservers' '$FAKE/calls.log' | head -1 | grep -q 1.1.1.1"
  check "SOCKS/bypass never touched" "! grep -q -e '^-setsocks' -e '^-setproxybypass' '$FAKE/calls.log'"
  check "no state file" "[ ! -f '$STATE_DIR/state' ]"
  check "DNS restored" "[ \"\$(cat '$FAKE/dns')\" = 8.8.8.8 ]"
  finish "proxy that fails to start restores DNS and never touches SOCKS"
}

# Line number of the first calls.log line matching a pattern (empty if none).
first_line() { grep -n -e "$1" "$FAKE/calls.log" | head -1 | cut -d: -f1; }
count_lines() { grep -c -e "$1" "$FAKE/calls.log"; }

test_7_order_dns_flush_proxy_socks() {
  setup no "" 0 "8.8.8.8" "localhost"
  start_run
  local d f p s
  d=$(first_line '^-setdnsservers Test Ethernet 1.1.1.1'); f=$(first_line '^DSCACHE -flushcache')
  p=$(first_line '^PROXY_START'); s=$(first_line '^-setsocksfirewallproxy ')
  check "all four calls happened" "[ -n '$d' ] && [ -n '$f' ] && [ -n '$p' ] && [ -n '$s' ]"
  check "DNS set before flush" "[ '${d:-0}' -lt '${f:-0}' ]"
  check "flush before proxy start" "[ '${f:-0}' -lt '${p:-0}' ]"
  check "proxy start before SOCKS" "[ '${p:-0}' -lt '${s:-0}' ]"
  check "one password prompt (osascript)" "[ \$(count_lines '^OSASCRIPT') -eq 1 ]"
  kill -INT "$RUN_PID"; wait "$RUN_PID" 2>/dev/null; RUN_PID=
  check "second flush on exit" "[ \$(count_lines '^DSCACHE -flushcache') -eq 2 ]"
  check "no second password prompt" "[ \$(count_lines '^OSASCRIPT') -eq 1 ]"
  check "exit flush comes after DNS restore" "[ \$(first_line '^-setdnsservers Test Ethernet 8.8.8.8') -lt \$(grep -n '^DSCACHE' '$FAKE/calls.log' | tail -1 | cut -d: -f1) ]"
  finish "order: DNS, flush, proxy, SOCKS; flush again on exit"
}

test_8_osascript_cancelled_still_runs() {
  setup no "" 0 "8.8.8.8" "localhost"
  : > "$FAKE/osa_fail"
  start_run
  check "SOCKS applied anyway" "[ \"\$(cat '$FAKE/socks_enabled')\" = yes ] && [ \"\$(cat '$FAKE/socks_server')\" = 127.0.0.1 ]"
  check "warning printed" "grep -q 'DNS cache not flushed; first loads may be slow' '$T/run.out'"
  kill -INT "$RUN_PID"; wait "$RUN_PID" 2>/dev/null; RUN_PID=
  check "old DNS back" "[ \"\$(cat '$FAKE/dns')\" = 8.8.8.8 ]"
  finish "cancelled password prompt warns and run continues"
}

test_9_warmup() {
  setup no "" 0 "8.8.8.8" "localhost"
  # Resolver: old answer for the first 3 calls (baseline + 2 polls), then a new one.
  cat > "$T/resolve" <<'EOF'
#!/bin/bash
echo "RESOLVE $*" >> "$FAKE/calls.log"
n=$(grep -c '^RESOLVE' "$FAKE/calls.log")
if [ "$n" -le 3 ]; then ip=212.175.180.11; else ip=162.159.1.1; fi
printf 'name: %s\nip_address: %s\n' "$5" "$ip"
EOF
  export DPIGATE_WARMUP_SECS=8
  start_run
  local s
  s=$(first_line '^-setsocksfirewallproxy ')
  check "at least 4 resolver calls before SOCKS" "[ \$(head -n $((s - 1)) '$FAKE/calls.log' | grep -c '^RESOLVE') -ge 4 ]"
  check "no warm-up warning" "! grep -q 'still answers' '$T/run.out'"
  kill -INT "$RUN_PID"; wait "$RUN_PID" 2>/dev/null; RUN_PID=
  finish "warm-up waits until the resolver answer changes"
}

test_10_warmup_timeout() {
  setup no "" 0 "8.8.8.8" "localhost"
  cat > "$T/resolve" <<'EOF'
#!/bin/bash
printf 'name: %s\nip_address: 212.175.180.11\n' "$5"
EOF
  export DPIGATE_WARMUP_SECS=1
  start_run
  check "warning printed" "grep -q 'still answers' '$T/run.out'"
  check "run continued: SOCKS applied" "[ \"\$(cat '$FAKE/socks_server')\" = 127.0.0.1 ]"
  kill -INT "$RUN_PID"; wait "$RUN_PID" 2>/dev/null; RUN_PID=
  finish "unchanged resolver answer: warns after the limit and continues"
}

trap 'teardown; rm -rf "$ROOT"' EXIT

test_1_run_applies_then_int_restores
test_2_empty_dns_restored_as_Empty
test_3_previous_socks_restored
test_4_proxy_dies_settings_restored
test_5_kill9_then_restore
test_6_proxy_fails_dns_restored_no_socks
test_7_order_dns_flush_proxy_socks
test_8_osascript_cancelled_still_runs
test_9_warmup
test_10_warmup_timeout

echo "SUMMARY: $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
