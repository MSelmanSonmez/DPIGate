#!/bin/bash
# Tests for the menu actions of the DPIGate app (Auto Start, Bypass All, Only Listed Sites, DNS, Uninstall, program launch).
# Menu clicks are replaced by DPIGATE_APP_ACTION (one action, then exit). Every system tool is a fake in a
# temporary directory; no real setting, LaunchAgent or folder is touched. A status item flashes meanwhile.
set -u
set -m
HERE=$(cd "$(dirname "$0")" && pwd)
DPIGATE=${DPIGATE_SCRIPT:-$HERE/../dpigate}
APPBIN=${DPIGATE_APP_BIN:-$HERE/../build/DPIGate.app/Contents/MacOS/DPIGate}
APPBIN=$(cd "$(dirname "$APPBIN")" && pwd -P)/$(basename "$APPBIN")
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dpigate-menutest.XXXXXX") || exit 1
. "$(cd "$(dirname "$0")" && pwd)/isolate.sh"; iso_init
PASSED=0 FAILED=0 APP_PID= DNS_PID=
. "$HERE/fakes.sh"

cleanup() {
  [ -n "$APP_PID" ] && kill -TERM "$APP_PID" 2>/dev/null
  [ -n "$DNS_PID" ] && kill -KILL "$DNS_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$ROOT"
}
trap cleanup EXIT

ok() { PASSED=$((PASSED + 1)); echo "ok   - $1"; }
bad() { FAILED=$((FAILED + 1)); echo "FAIL - $1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
wait_for() { local n=$(($1 * 10)); shift; while [ $n -gt 0 ]; do "$@" && return 0; sleep 0.1; n=$((n - 1)); done; return 1; }
has_line() { grep -q -e "$2" "$1" 2>/dev/null; }
gone() { ! kill -0 "$1" 2>/dev/null; }

# Common environment for one test directory $1; extra variables come after it.
app_env() {
  local d=$1; shift
  env DPIGATE_APP_LOG="$d/Logs/DPIGate/dpigate.log" DPIGATE_APP_NOTIFY_LOG="$d/notify" \
      STATE_DIR="$d/AppSupport/DPIGate" DPIGATE_LAUNCH_AGENTS_DIR="$d/LA" LAUNCHCTL="$d/launchctl" \
      DPIGATE_APP_NO_DELETE=1 DPIGATE_APP_ASSUME_YES=1 "$@" "$APPBIN" </dev/null >"$d/out" 2>&1 &
  APP_PID=$!
}
# Waits for the app to exit by itself and returns its status.
app_exit() { wait_for "${1:-15}" gone "$APP_PID"; wait "$APP_PID" 2>/dev/null; local rc=$?; APP_PID=; return $rc; }

fake_launchctl() { printf '#!/bin/bash\necho "$*" >> "%s/launchctl.log"\n' "$1" > "$1/launchctl"; chmod +x "$1/launchctl"; }

# Fake dpigate script for tests that do not need the real one: logs calls, restores on SIGINT.
make_fake() {
  cat > "$1/fake" <<'EOF2'
#!/bin/bash
D=$(dirname "$0")
echo "call $*" >> "$D/calls"
echo "${DPIGATE_DNS-unset}" > "$D/script_dns"
case "$1" in restore) exit 0;; esac
trap 'echo "signal INT" >> "$D/calls"; echo "restored" >> "$D/calls"; exit 0' INT
echo "dpigate: running on 'Fake' (test)"
while true; do sleep 0.2; done
EOF2
  chmod +x "$1/fake"
}

[ -x "$APPBIN" ] || { echo "app binary missing: $APPBIN (run: make -C macos app)"; exit 1; }
UIDN=$(id -u)

# (a) Auto Start: plist written/removed, launchctl called through $LAUNCHCTL
A=$ROOT/a; mkdir -p "$A"; fake_launchctl "$A"; make_fake "$A"
app_env "$A" DPIGATE_APP_SCRIPT="$A/fake" DPIGATE_APP_ACTION=autostart-on
app_exit; rc=$?
check "autostart-on: app exits 0" '[ $rc = 0 ]'
P=$A/LA/org.dpigate.menubar.plist
check "plist exists and is valid (plutil -lint)" '[ -f "$P" ] && plutil -lint "$P" >/dev/null 2>&1'
check "plist runs this app binary at load with DPIGATE_APP_AUTOSTART=1" '[ "$(plutil -extract ProgramArguments.0 raw "$P")" = "$APPBIN" ] && [ "$(plutil -extract RunAtLoad raw "$P")" = true ] && [ "$(plutil -extract EnvironmentVariables.DPIGATE_APP_AUTOSTART raw "$P")" = 1 ]'
check "launchctl enable called (no load: that would start a second copy)" 'has_line "$A/launchctl.log" "^enable gui/$UIDN/org.dpigate.menubar" && ! has_line "$A/launchctl.log" "bootstrap"'
app_env "$A" DPIGATE_APP_SCRIPT="$A/fake" DPIGATE_APP_ACTION=autostart-off
app_exit; rc=$?
check "autostart-off: plist removed" '[ $rc = 0 ] && [ ! -e "$P" ]'
check "launchctl bootout called" 'has_line "$A/launchctl.log" "^bootout gui/$UIDN/org.dpigate.menubar"'

# (a2) Auto Start entry written for a moved app: the path is rewritten at launch; a current entry is left alone
A2=$ROOT/a2; mkdir -p "$A2/LA"; fake_launchctl "$A2"; make_fake "$A2"
P2=$A2/LA/org.dpigate.menubar.plist
cat > "$P2" <<EOF2
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>org.dpigate.menubar</string><key>ProgramArguments</key><array><string>/old/place/DPIGate.app/Contents/MacOS/DPIGate</string></array><key>RunAtLoad</key><true/></dict></plist>
EOF2
app_env "$A2" DPIGATE_APP_SCRIPT="$A2/fake" DPIGATE_APP_ACTION=noop
app_exit; rc=$?
check "stale Auto Start path: rewritten to this app binary at launch" '[ $rc = 0 ] && [ "$(plutil -extract ProgramArguments.0 raw "$P2")" = "$APPBIN" ] && [ "$(plutil -extract EnvironmentVariables.DPIGATE_APP_AUTOSTART raw "$P2")" = 1 ]'
touch -t 200001010000 "$P2"
app_env "$A2" DPIGATE_APP_SCRIPT="$A2/fake" DPIGATE_APP_ACTION=noop
app_exit
check "current Auto Start entry: left untouched" '[ "$(stat -f %Sm -t %Y "$P2")" = 2000 ]'
rm -f "$P2"
app_env "$A2" DPIGATE_APP_SCRIPT="$A2/fake" DPIGATE_APP_ACTION=noop
app_exit
check "no Auto Start entry: none is created" '[ ! -e "$P2" ]'

# (a3) HOME decides the default LaunchAgents and log folders (NSHomeDirectory ignores HOME)
A3=$ROOT/a3; mkdir -p "$A3/home"; fake_launchctl "$A3"; make_fake "$A3"
env -u DPIGATE_LAUNCH_AGENTS_DIR -u DPIGATE_APP_LOG HOME="$A3/home" STATE_DIR="$A3/AS" LAUNCHCTL="$A3/launchctl" \
    DPIGATE_APP_NOTIFY_LOG="$A3/notify" DPIGATE_APP_SCRIPT="$A3/fake" DPIGATE_APP_ACTION=autostart-on "$APPBIN" </dev/null >"$A3/out" 2>&1 &
APP_PID=$!; app_exit
check "HOME: Auto Start entry and log go under \$HOME/Library" '[ -f "$A3/home/Library/LaunchAgents/org.dpigate.menubar.plist" ] && [ -f "$A3/home/Library/Logs/DPIGate/dpigate.log" ]'

# (e) apps.txt is created on first launch with Discord; the app is left in place when edited
check "apps.txt created with Discord" '[ "$(cat "$A/AppSupport/DPIGate/config/apps.txt")" = "/Applications/Discord.app" ]'

# (b) Bypass All off: the proxy runs, system proxy settings and launchctl env stay untouched
bypass_case() { # <name> <bypass_all value or empty>
  local d=$ROOT/$1; mkdir -p "$d/AppSupport/DPIGate/config"
  make_fakes "$d"; fake_launchctl_keep "$d"
  export FAKE=$d/fake
  printf 'no\n' > "$FAKE/socks_enabled"; : > "$FAKE/socks_server"; echo 0 > "$FAKE/socks_port"; echo 8.8.8.8 > "$FAKE/dns"; : > "$FAKE/bypass"
  printf 'no\n' > "$FAKE/web_enabled"; : > "$FAKE/web_server"; echo 0 > "$FAKE/web_port"
  printf 'no\n' > "$FAKE/secureweb_enabled"; : > "$FAKE/secureweb_server"; echo 0 > "$FAKE/secureweb_port"
  : > "$FAKE/calls.log"
  [ -n "$2" ] && printf 'bypass_all=%s\n' "$2" > "$d/AppSupport/DPIGate/config/config"
  BPORT=$((20000 + RANDOM % 20000))
  while lsof -nP -iTCP:"$BPORT" -sTCP:LISTEN -t </dev/null >/dev/null 2>&1; do BPORT=$((BPORT + 1)); done
  app_env "$d" DPIGATE_APP_SCRIPT="$DPIGATE" DPIGATE_APP_AUTOSTART=1 DPIGATE_PORT=$BPORT PROXY_BIN="$d/proxy" \
      NETWORKSETUP="$d/networksetup" ROUTE="$d/route" DSCACHEUTIL="$d/dscacheutil" OSASCRIPT="$d/osascript" \
      RESOLVE_CMD="$d/resolve -q host -a name" DPIGATE_WARMUP_SECS=3 DPIGATE_APP_DNS_CANDIDATES="$3" LAUNCHCTL="$d/launchctl"
  wait_for 20 has_line "$d/Logs/DPIGate/dpigate.log" "running on"
  kill -TERM "$APP_PID"
  wait_for 15 gone "$APP_PID"
  APP_PID=
}
# The app test fakes' launchctl is the shared fake (state in $FAKE), so no extra wrapper is needed.
fake_launchctl_keep() { :; }

CAND="Good|127.0.0.1|9"   # unreachable on purpose: the measurement result is irrelevant here, index 0 is forced below
B1=$ROOT/b1
bypass_case b1 0 "$CAND"
F=$B1/fake
check "bypass off: proxy started" '[ -s "$F/proxy_args" ]'
check "bypass off: no networksetup -set*proxy*" '! grep -q -e "^-set.*proxy" "$F/calls.log"'
check "bypass off: no launchctl setenv/unsetenv" '! grep -q -e "^LAUNCHCTL setenv" -e "^LAUNCHCTL unsetenv" "$F/calls.log"'
check "bypass off: DNS cache is still flushed" 'grep -q "^DSCACHE -flushcache" "$F/calls.log"'
B2=$ROOT/b2
bypass_case b2 "" "$CAND"
F=$B2/fake
check "bypass on (default): SOCKS, web, secure web set" 'grep -q "^-setsocksfirewallproxy " "$F/calls.log" && grep -q "^-setwebproxy " "$F/calls.log" && grep -q "^-setsecurewebproxy " "$F/calls.log"'
check "bypass on (default): launchctl setenv HTTPS_PROXY" 'grep -q "^LAUNCHCTL setenv HTTPS_PROXY" "$F/calls.log"'
check "bypass on: settings restored after the app got SIGTERM" '[ "$(cat "$F/socks_enabled")" = no ] && [ "$(cat "$F/dns")" = 8.8.8.8 ]'

# (c) DNS measurement: dead server n/a, poisoned answer invalid, good answer valid, selection reaches the proxy
cat > "$ROOT/dnssrv.py" <<'EOF2'
import socket, sys, threading
out = sys.argv[1]
def answer(q, ip):
    r = bytearray(q[:2]) + b"\x81\x80" + q[4:6] + b"\x00\x01\x00\x00\x00\x00" + q[12:]
    r += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes(int(x) for x in ip.split("."))
    return bytes(r)
socks = {}
for name, ip in (("dead", None), ("poison", "195.175.254.2"), ("good", "162.159.1.1")):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); socks[name] = (s, ip)
def serve(s, ip):
    while True:
        q, a = s.recvfrom(512)
        if ip: s.sendto(answer(q, ip), a)
for s, ip in socks.values(): threading.Thread(target=serve, args=(s, ip), daemon=True).start()
open(out, "w").write(" ".join(str(socks[n][0].getsockname()[1]) for n in ("dead", "poison", "good")))
threading.Event().wait()
EOF2
C=$ROOT/c; mkdir -p "$C"; fake_launchctl "$C"; make_fake "$C"
/usr/bin/python3 -I "$ROOT/dnssrv.py" "$C/ports" </dev/null >/dev/null 2>&1 &
DNS_PID=$!
wait_for 10 test -s "$C/ports"
read -r PD PP PG < "$C/ports"
CANDS="Dead|127.0.0.1|$PD;Poison|127.0.0.1|$PP;Good|127.0.0.1|$PG"
app_env "$C" DPIGATE_APP_SCRIPT="$C/fake" DPIGATE_APP_ACTION=dns-detect DPIGATE_APP_DNS_CANDIDATES="$CANDS"
app_exit; rc=$?
L=$C/Logs/DPIGate/dpigate.log
check "dns-detect finished and exited 0" '[ $rc = 0 ]'
check "silent server: no-response, no time (n/a)" 'has_line "$L" "^dns: Dead 127.0.0.1:$PD no-response -1ms"'
check "poisoned answer: invalid" 'has_line "$L" "^dns: Poison 127.0.0.1:$PP poisoned "'
check "clean answer: valid with a time" 'grep -Eq "^dns: Good 127.0.0.1:$PG ok [0-9]+ms" "$L"'
# auto selection: Turn On waits for the measurement, then the best server goes to the script as DPIGATE_DNS
: > "$C/calls"
app_env "$C" DPIGATE_APP_SCRIPT="$C/fake" DPIGATE_APP_AUTOSTART=1 DPIGATE_APP_DNS_CANDIDATES="$CANDS"
wait_for 15 has_line "$C/calls" "call run"
check "auto: DPIGATE_DNS is the valid server" '[ "$(cat "$C/script_dns")" = "127.0.0.1:$PG" ]'
kill -TERM "$APP_PID"; wait_for 12 gone "$APP_PID"; APP_PID=
# forced selection (saved index 0 = the dead one) is used as is
printf 'dns_index=0\n' > "$C/AppSupport/DPIGate/config/config"
: > "$C/calls"   # else the first run's "call run" satisfies the wait below
app_env "$C" DPIGATE_APP_SCRIPT="$C/fake" DPIGATE_APP_AUTOSTART=1 DPIGATE_APP_DNS_CANDIDATES="$CANDS"
wait_for 15 has_line "$C/calls" "call run"
sleep 0.5
check "forced index: DPIGATE_DNS is the chosen server" '[ "$(cat "$C/script_dns")" = "127.0.0.1:$PD" ]'
kill -TERM "$APP_PID"; wait_for 12 gone "$APP_PID"; APP_PID=
kill -KILL "$DNS_PID" 2>/dev/null; DNS_PID=

# (e) Launch via DPIGate: proxy argument and environment
E=$ROOT/e; mkdir -p "$E"; fake_launchctl "$E"; make_fake "$E"
printf '#!/bin/bash\necho "$*" >> "%s/open.log"\n' "$E" > "$E/open"; chmod +x "$E/open"
app_env "$E" DPIGATE_APP_SCRIPT="$E/fake" DPIGATE_PORT=4321 DPIGATE_APP_OPEN="$E/open" DPIGATE_APP_ACTION="launch:/Applications/Fake.app"
app_exit
check "open gets proxy env and --proxy-server" 'grep -q -e "-a /Applications/Fake.app --env HTTPS_PROXY=http://127.0.0.1:4321 --env HTTP_PROXY=http://127.0.0.1:4321 --args --proxy-server=socks5://127.0.0.1:4321" "$E/open.log"'

# (d) Uninstall: Turn Off (SIGINT -> restore), LaunchAgent and folders gone, app exits
D=$ROOT/d; mkdir -p "$D/LA"; fake_launchctl "$D"; make_fake "$D"
echo placeholder > "$D/LA/org.dpigate.menubar.plist"
app_env "$D" DPIGATE_APP_SCRIPT="$D/fake" DPIGATE_APP_AUTOSTART=1 DPIGATE_APP_ACTION=uninstall
app_exit 20; rc=$?
check "uninstall: app exits 0" '[ $rc = 0 ]'
check "uninstall: script got SIGINT and restored" 'has_line "$D/calls" "signal INT" && has_line "$D/calls" "^restored"'
check "uninstall: LaunchAgent removed" '[ ! -e "$D/LA/org.dpigate.menubar.plist" ]'
check "uninstall: config, state and log folders removed" '[ ! -e "$D/AppSupport/DPIGate" ] && [ ! -e "$D/Logs/DPIGate" ]'

# (f) Only Listed Sites: the proxy gets ByeDPI's host list (-H) plus an empty second group (-An)
stop_app() { kill -TERM "$APP_PID" 2>/dev/null; wait_for 12 gone "$APP_PID"; APP_PID=; }
DEFS=":discord.com discord.gg discordapp.com discordapp.net discord.media discordcdn.com"
F1=$ROOT/f1; mkdir -p "$F1/AppSupport/DPIGate/config"; fake_launchctl "$F1"; make_fake "$F1"
printf 'bypass_all=0\nsite_mode=1\n' > "$F1/AppSupport/DPIGate/config/config"
app_env "$F1" DPIGATE_APP_SCRIPT="$F1/fake" DPIGATE_APP_AUTOSTART=1
wait_for 10 has_line "$F1/calls" "call run"
check "site mode on: sites.txt created with the Discord defaults" '[ "$(grep -v "^#" "$F1/AppSupport/DPIGate/config/sites.txt" | paste -sd " " -)" = "${DEFS#:}" ]'
check "site mode on: run gets -- -H <defaults> -An" 'has_line "$F1/calls" "^call run --no-system-proxy -- -H $DEFS -An\$"'
: > "$F1/calls"
printf '# my sites\nExample.ORG   # note\n*.sub.example.net\nbad_domain!\n\n' > "$F1/AppSupport/DPIGate/config/sites.txt"
wait_for 10 has_line "$F1/calls" "call run"
check "edited site list restarts the proxy with the new list (lowercase, wildcard stripped, invalid and notes dropped)" 'has_line "$F1/calls" "^call run --no-system-proxy -- -H :example.org sub.example.net -An\$"'
: > "$F1/calls"
printf '# nothing\n' > "$F1/AppSupport/DPIGate/config/sites.txt"
wait_for 10 has_line "$F1/calls" "call run"
check "empty list falls back to a host that never occurs (ByeDPI rejects an empty list)" 'has_line "$F1/calls" "^call run --no-system-proxy -- -H :dpigate.invalid -An\$"'
stop_app

F2=$ROOT/f2; mkdir -p "$F2/AppSupport/DPIGate/config"; fake_launchctl "$F2"; make_fake "$F2"
printf 'bypass_all=0\n' > "$F2/AppSupport/DPIGate/config/config"
app_env "$F2" DPIGATE_APP_SCRIPT="$F2/fake" DPIGATE_APP_AUTOSTART=1 DPIGATE_APP_ACTION=site-toggle
wait_for 10 has_line "$F2/calls" "^call run --no-system-proxy -- -H"
check "site mode off by default: first run has no host list" 'has_line "$F2/calls" "^call run --no-system-proxy\$"'
check "toggling on restarts the proxy with the host list" 'has_line "$F2/calls" "^call run --no-system-proxy -- -H $DEFS -An\$"'
check "toggle is saved as site_mode=1" 'has_line "$F2/AppSupport/DPIGate/config/config" "^site_mode=1\$" && has_line "$F2/AppSupport/DPIGate/config/config" "^bypass_all=0\$"'
stop_app

# The real script with the fake proxy: the host list reaches the proxy after --tlsrec 1+s, in the same group
G=$ROOT/g; mkdir -p "$G/AppSupport/DPIGate/config"; make_fakes "$G"; fake_launchctl_keep "$G"; export FAKE=$G/fake
echo 8.8.8.8 > "$FAKE/dns"; : > "$FAKE/bypass"; : > "$FAKE/calls.log"
printf 'bypass_all=0\nsite_mode=1\ndns_index=0\n' > "$G/AppSupport/DPIGate/config/config"
GPORT=$((20000 + RANDOM % 20000))
app_env "$G" DPIGATE_APP_SCRIPT="$DPIGATE" DPIGATE_APP_AUTOSTART=1 DPIGATE_PORT=$GPORT PROXY_BIN="$G/proxy" \
    NETWORKSETUP="$G/networksetup" ROUTE="$G/route" DSCACHEUTIL="$G/dscacheutil" OSASCRIPT="$G/osascript" \
    RESOLVE_CMD="$G/resolve -q host -a name" DPIGATE_WARMUP_SECS=3 DPIGATE_APP_DNS_CANDIDATES="Good|127.0.0.1|9" LAUNCHCTL="$G/launchctl"
wait_for 20 has_line "$G/Logs/DPIGate/dpigate.log" "running on"
stop_app
check "real script: proxy args are '... --tlsrec 1+s -H <list> -An'" 'grep -q -e "--tlsrec 1+s -H $DEFS -An\$" "$FAKE/proxy_args"'

iso_guard_end
echo "$PASSED passed, $FAILED failed"
[ $FAILED -eq 0 ]
