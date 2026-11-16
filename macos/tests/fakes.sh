#!/bin/bash
# Shared fakes (networksetup, route, proxy, launchctl, ...) for the dpigate and app tests.

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
  -getwebproxy|-getsecurewebproxy)
    k=${1#-get}; k=${k%proxy}
    if [ "$(f ${k}_enabled)" = yes ]; then echo "Enabled: Yes"; else echo "Enabled: No"; fi
    echo "Server: $(f ${k}_server)"
    echo "Port: $(f ${k}_port)"
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
      -setwebproxy|-setsecurewebproxy) k=${1#-set}; k=${k%proxy}; echo "$3" > "$FAKE/${k}_server"; echo "$4" > "$FAKE/${k}_port"; echo yes > "$FAKE/${k}_enabled";;
      -setwebproxystate|-setsecurewebproxystate) k=${1#-set}; k=${k%proxystate}; if [ "$3" = on ]; then echo yes; else echo no; fi > "$FAKE/${k}_enabled";;
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
echo "$*" > "$FAKE/proxy_args"
echo "${DPIGATE_DNS-unset}" > "$FAKE/proxy_dns"
port=1080
while [ $# -gt 0 ]; do [ "$1" = -p ] && port=$2; shift; done
echo PROXY_START >> "$FAKE/calls.log"
exec nc -lk 127.0.0.1 "$port"
EOF
  cat > "$T/launchctl" <<'EOF'
#!/bin/bash
# Fake launchctl: environment variables live in $FAKE/env_<NAME>; every call is logged.
echo "LAUNCHCTL $*" >> "$FAKE/calls.log"
case "${1:-}" in
  getenv) cat "$FAKE/env_$2" 2>/dev/null; exit 0;;
  setenv) echo "$3" > "$FAKE/env_$2";;
  unsetenv) rm -f "$FAKE/env_$2";;
  *) exit 1;;
esac
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
  chmod +x "$T/networksetup" "$T/route" "$T/proxy" "$T/dscacheutil" "$T/osascript" "$T/resolve" "$T/launchctl"
}
