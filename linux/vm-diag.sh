#!/bin/bash
# vm-diag.sh — VM diagnostics tool for DPIGate (Bug 2: discord.com/Vesktop
# unreachable, Bug 3: --bypass-all triggers "captive portal" + no internet under
# NetworkManager).
#
# Usage:
#   ./vm-diag.sh env        Environment info (network mode, DNS, firewall backend)
#   ./vm-diag.sh base        Block type measurement WITH BYPASS OFF
#   ./vm-diag.sh bypassall   Bug 3: internet health under --bypass-all
#   ./vm-diag.sh rungs       Bug 2: flag ladder (R1..R8), stops at first pass
#   ./vm-diag.sh wire [mod]  On-wire fragmentation check (tcpdump)
#   ./vm-diag.sh endpoints   Individual Discord/Vesktop endpoint status
#   ./vm-diag.sh vesktop     Vesktop proctrack gate match check (requires GUI)
#   ./vm-diag.sh all         env+base+bypassall+rungs+wire+endpoints
#
# Report: $HOME/gdpi-vm-diag.txt (appended each run, never overwritten).
# Before use, see docs/vm-diagnostics.md — prerequisites (no root, SUDO_PASSWORD,
# ./install.sh) are documented there, not here.
#
# Intentionally-failing measurements mean set -e is NOT used; only set -u.

set -u

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
for _p in "$APP_DIR/lib/platform.sh" "$APP_DIR/platform.sh" \
          "$APP_DIR/../share/DPIGate/lib/platform.sh"; do
    [ -f "$_p" ] && { . "$_p"; break; }
done
if [ -z "${PLAT_SH_LOADED:-}" ]; then
    echo "FATAL: lib/platform.sh not found next to $0" >&2; exit 1
fi

DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/DPIGate"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/DPIGate"
GDPI_LOG="$DATA_DIR/goodbyedpi.log"
REPORT="$HOME/gdpi-vm-diag.txt"

# Keep daemon + firewall rules clean regardless of measurement outcome.
# `bash "…"` everywhere below, never a bare path: a checkout whose scripts lost
# their execute bit made every start/kill here a silent no-op (EACCES swallowed
# by `|| true`), and the measurements were then taken with no daemon running.
trap 'bash "$APP_DIR/kill.sh" >/dev/null 2>&1 || true' EXIT

# ── Common helpers ─────────────────────────────────────────────────────

section() {
    { printf '\n=== %s %s ===\n' "$1" "$(date -Iseconds)"; } | tee -a "$REPORT"
}

kv() {
    printf '%s=%s\n' "$1" "$2" | tee -a "$REPORT"
}

note() {
    printf '[vm-diag] %s\n' "$1" | tee -a "$REPORT"
}

# code_of URL -> HTTP status code; "000" on error/timeout.
code_of() {
    local url="$1" code
    code="$(curl -sS -o /dev/null -L -w '%{http_code}' --max-time 12 "$url" 2>/dev/null)"
    [ -z "$code" ] && code="000"
    printf '%s' "$code"
}

is_2xx3xx() {
    case "$1" in
        2??|3??) return 0 ;;
        *) return 1 ;;
    esac
}

# resolve_iface -> $IFACE / $MYIP (default route interface + source IP).
resolve_iface() {
    local route
    route="$(ip route get 1.1.1.1 2>/dev/null)"
    IFACE="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$route")"
    MYIP="$(awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' <<<"$route")"
}

# resolve_target_ip -> discord.com A record queried via 1.1.1.1 (Cloudflare
# used to get a clean result even when system resolver is poisoned).
resolve_target_ip() {
    PYTHONPATH="$APP_DIR" python3 - <<'PYEOF' 2>/dev/null
import socket
import dns_detect as d
ip = ""
try:
    q = d.build_dns_query(d.DNS_TEST_DOMAIN)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(d.DNS_TIMEOUT_MS / 1000.0)
    s.sendto(q, ("1.1.1.1", 53))
    data, _ = s.recvfrom(2048)
    ip = d.parse_dns_response_a(data) or ""
except OSError:
    pass
print(ip)
PYEOF
}

# banner_field PATTERN -> value N from goodbyedpi.log line "PATTERN N".
banner_field() {
    grep -m1 "$1" "$GDPI_LOG" 2>/dev/null | sed -E 's/^[^:]*:[[:space:]]*([0-9]+).*/\1/'
}

nmcli_conn() {
    local conn="absent"
    if command -v nmcli >/dev/null 2>&1; then
        conn="$(nmcli -t -f CONNECTIVITY general status 2>/dev/null | tail -1)"
        [ -z "$conn" ] && conn="unknown"
    fi
    printf '%s' "$conn"
}

daemon_alive() {
    if [ -n "$(plat_pids_cmdline -- "--queue $PLAT_QUEUE_NUM")" ]; then
        printf 'yes'
    else
        printf 'no'
    fi
}

# ── env ────────────────────────────────────────────────────────────────────

cmd_env() {
    section env
    resolve_iface
    kv ENV_UID "$(id -u)"
    kv ENV_USER "$(id -un)"
    kv ENV_DISTRO "$(plat_distro)"
    kv ENV_KERNEL "$(uname -r)"
    kv ENV_IFACE "${IFACE:-unknown}"
    kv ENV_IP "${MYIP:-unknown}"

    local gw
    gw="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')"
    kv ENV_GW "${gw:-unknown}"

    local netmode
    if [ "${gw:-}" = "10.0.2.2" ]; then
        netmode="vbox-nat"
    elif [[ "${MYIP:-}" == 192.168.56.* ]]; then
        netmode="vbox-hostonly"
    else
        netmode="bridged-or-real"
    fi
    kv ENV_NETMODE "$netmode"

    local nic
    nic="$(lspci -nn 2>/dev/null | grep -i ethernet | head -1)"
    kv ENV_NIC "${nic:-unknown}"

    kv ENV_FW_BACKEND "$(plat_fw_backend 2>/dev/null || echo none)"
    if command -v nft >/dev/null 2>&1; then kv ENV_NFT "$(nft -v)"; else kv ENV_NFT "none"; fi
    if command -v iptables >/dev/null 2>&1; then kv ENV_IPT "$(iptables -V)"; else kv ENV_IPT "none"; fi
    if command -v tcpdump >/dev/null 2>&1; then kv ENV_TCPDUMP "present"; else kv ENV_TCPDUMP "none"; fi

    local sysdns
    sysdns="$(awk '$1=="nameserver"{print $2; exit}' /etc/resolv.conf 2>/dev/null)"
    kv ENV_SYSDNS "${sysdns:-unknown}"
    if [[ "${sysdns:-}" == 127.* ]]; then
        kv ENV_SYSDNS_LOOPBACK yes
    else
        kv ENV_SYSDNS_LOOPBACK no
    fi

    if command -v systemctl >/dev/null 2>&1; then
        kv ENV_RESOLVED "$(systemctl is-active systemd-resolved 2>/dev/null || echo inactive)"
    else
        kv ENV_RESOLVED absent
    fi

    if grep -q -- '--native-frag' "$APP_DIR/start.sh" 2>/dev/null; then
        kv ENV_SRC_ROUND2 yes
    else
        kv ENV_SRC_ROUND2 no
    fi

    if [ -x "$APP_DIR/goodbyedpi" ]; then kv ENV_BIN yes; else kv ENV_BIN no; fi

    local progs="$CONFIG_DIR/ProgramFilters"
    [ -f "$progs" ] || progs="$APP_DIR/ProgramFilters"
    kv ENV_PROGRAMS "$progs"
}

# ── base ───────────────────────────────────────────────────────────────────

cmd_base() {
    section base
    bash "$APP_DIR/kill.sh" >/dev/null 2>&1 || true

    local dns_out
    dns_out="$(PYTHONPATH="$APP_DIR" python3 -c '
import dns_detect as d
a, v, ip = d.probe_system_resolver()
print(f"{a}\t{v}\t{ip}")
' 2>/dev/null)"
    local sys_addr sys_verdict sys_answer
    IFS=$'\t' read -r sys_addr sys_verdict sys_answer <<<"$dns_out"
    kv BASE_DNS_SYS_ADDR "${sys_addr:-none}"
    kv BASE_DNS_SYS_VERDICT "${sys_verdict:-unknown}"
    kv BASE_DNS_SYS_ANSWER "${sys_answer:-}"

    local cf_ip
    cf_ip="$(resolve_target_ip)"
    kv BASE_DNS_CF "${cf_ip:-}"

    local base_ip="${cf_ip:-${sys_answer:-}}"
    kv BASE_IP "${base_ip:-unknown}"

    local tcp443="fail"
    if [ -n "$base_ip" ] && timeout 8 bash -c "exec 3<>/dev/tcp/$base_ip/443" 2>/dev/null; then
        tcp443="ok"
    fi
    kv BASE_TCP443 "$tcp443"

    local tls_discord="fail:NoIP" tls_example="fail:NoIP"
    if [ -n "$base_ip" ]; then
        local tls_out
        tls_out="$(python3 - "$base_ip" <<'PYEOF'
import socket, ssl, sys
ip = sys.argv[1]
def probe(sni):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as s:
                return f"ok:{s.version()}"
    except Exception as e:
        return f"fail:{type(e).__name__}"
print(probe("discord.com"))
print(probe("example.com"))
PYEOF
)"
        tls_discord="$(sed -n '1p' <<<"$tls_out")"
        tls_example="$(sed -n '2p' <<<"$tls_out")"
        [ -z "$tls_discord" ] && tls_discord="fail:NoOutput"
        [ -z "$tls_example" ] && tls_example="fail:NoOutput"
    fi
    kv BASE_TLS_DISCORD "$tls_discord"
    kv BASE_TLS_EXAMPLE "$tls_example"

    local rst="unknown"
    if ! command -v tcpdump >/dev/null 2>&1; then
        note "tcpdump missing: sudo apt-get install -y tcpdump"
    elif [ -n "$base_ip" ]; then
        resolve_iface
        # mktemp, never a fixed /tmp name: root writes this file (tcpdump -w
        # runs through plat_run_root) and then chowns it to us. On a shared
        # host a pre-planted symlink at a predictable path would make root
        # truncate — and hand ownership of — an arbitrary file.
        local pcap
        pcap="$(mktemp "${TMPDIR:-/tmp}/gdpi-base-rst.XXXXXX.pcap")" || return 0
        plat_run_root timeout 12 tcpdump -i "$IFACE" -n -q -w "$pcap" \
            "host $base_ip and tcp[tcpflags] & tcp-rst != 0" >/dev/null 2>&1 &
        local tdpid=$!
        sleep 1
        python3 - "$base_ip" <<'PYEOF' >/dev/null 2>&1
import socket, ssl, sys
ip = sys.argv[1]
try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, 443), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="discord.com"):
            pass
except Exception:
    pass
PYEOF
        wait "$tdpid" 2>/dev/null || true
        plat_run_root chown "$(id -un)" "$pcap" >/dev/null 2>&1 || true
        if [ -s "$pcap" ]; then rst="yes"; else rst="no"; fi
        rm -f "$pcap"
    fi
    kv BASE_RST "$rst"

    local http_discord http_google http_nmcheck
    http_discord="$(code_of https://discord.com/)"
    http_google="$(code_of https://www.google.com/)"
    http_nmcheck="$(code_of http://nmcheck.gnome.org/check_network_status.txt)"
    kv BASE_HTTP_DISCORD "$http_discord"
    kv BASE_HTTP_GOOGLE "$http_google"
    kv BASE_HTTP_NMCHECK "$http_nmcheck"

    local verdict
    if [ "$sys_verdict" = "poisoned" ]; then
        verdict="DNS_POISON"
    elif is_2xx3xx "$http_discord"; then
        verdict="NO_BLOCK"
    elif [ "$tcp443" = "fail" ] || { [[ "$tls_discord" == fail:* ]] && [[ "$tls_example" == fail:* ]]; }; then
        verdict="IP_BLOCK"
    elif [[ "$tls_discord" == fail:* ]] && [[ "$tls_example" == ok:* ]]; then
        verdict="SNI_DPI"
    else
        verdict="UNKNOWN"
    fi
    kv BASE_VERDICT "$verdict"
}

# ── bypassall ─────────────────────────────────────────────────────────────

cmd_bypassall() {
    section bypassall
    bash "$APP_DIR/kill.sh" >/dev/null 2>&1 || true
    bash "$APP_DIR/start.sh" --no-tray --bypass-all >/dev/null 2>&1 || true
    sleep 3

    local daemon
    daemon="$( [ "$(daemon_alive)" = yes ] && echo alive || echo dead )"
    kv BA_DAEMON "$daemon"

    kv BA_BANNER_NATIVE "$(banner_field 'Native fragmentation (splitting):')"
    kv BA_BANNER_SNI "$(banner_field 'Fragment by SNI:')"
    kv BA_BANNER_REVERSE "$(banner_field 'Fragments sending in reverse:')"
    kv BA_BANNER_WSEQ "$(banner_field 'Fake requests, wrong SEQ/ACK:')"
    kv BA_BANNER_QUIC "$(banner_field 'Block QUIC/HTTP3:')"

    local icmp="fail"
    ping -c2 -W3 1.1.1.1 >/dev/null 2>&1 && icmp="ok"
    kv BA_ICMP "$icmp"

    local dns_t0 dns_t1 dns_out dns_ms dns_verdict
    dns_t0="$(date +%s%3N)"
    dns_out="$(PYTHONPATH="$APP_DIR" python3 -c '
import dns_detect as d
a, v, ip = d.probe_system_resolver()
print(f"{a}\t{v}\t{ip}")
' 2>/dev/null)"
    dns_t1="$(date +%s%3N)"
    dns_ms=$((dns_t1 - dns_t0))
    dns_verdict="$(cut -f2 <<<"$dns_out")"
    [ -z "$dns_verdict" ] && dns_verdict="unknown"
    kv BA_DNS_MS "$dns_ms"
    kv BA_DNS_VERDICT "$dns_verdict"

    # Generate traffic first (for counter measurement below), then read counters.
    local http80 https_google https_discord
    http80="$(code_of http://nmcheck.gnome.org/check_network_status.txt)"
    https_google="$(code_of https://www.google.com/)"
    https_discord="$(code_of https://discord.com/)"
    kv BA_HTTP80 "$http80"
    kv BA_HTTPS_GOOGLE "$https_google"
    kv BA_HTTPS_DISCORD "$https_discord"

    local conn
    conn="$(nmcli_conn)"
    kv BA_CONN "$conn"

    local backend counters="" pkt_nonzero=0
    backend="$(plat_fw_backend 2>/dev/null || echo none)"
    if [ "$backend" = "nft" ]; then
        counters="$(plat_run_root nft list table inet goodbyedpi 2>/dev/null | grep -E 'counter packets')"
        if grep -oE 'packets [0-9]+' <<<"$counters" | awk '{if ($2>0) f=1} END{exit !f}'; then
            pkt_nonzero=1
        fi
    elif [ "$backend" = "iptables" ]; then
        counters="$(plat_run_root iptables -t mangle -vnL "$PLAT_IPT_CHAIN_OUT" 2>/dev/null)"
        if awk 'NR>2{gsub(/[A-Za-z]/,"",$1); if ($1+0>0) f=1} END{exit !f}' <<<"$counters"; then
            pkt_nonzero=1
        fi
    fi
    kv BA_COUNTERS "$(tr '\n' ';' <<<"$counters")"

    local nfq
    nfq="$(plat_run_root cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null | awk -v q="$PLAT_QUEUE_NUM" '$1==q')"
    kv BA_NFQ "${nfq:-absent}"

    local verdict
    if [ "$daemon" = "dead" ]; then
        verdict="DAEMON_DEAD"
    elif [ "$pkt_nonzero" -eq 0 ]; then
        verdict="NOT_QUEUED"
    elif [ "$icmp" = "ok" ] && [ "$https_google" = "000" ] && [ "$http80" = "000" ]; then
        verdict="ALL_TCP_BROKEN"
    elif [ "$dns_verdict" = "unknown" ] || [ "$dns_ms" -gt 2000 ]; then
        verdict="DNS_BROKEN"
    elif [ "$http80" = "000" ] && is_2xx3xx "$https_google"; then
        verdict="HTTP80_BROKEN"
    elif is_2xx3xx "$https_google" && is_2xx3xx "$http80" && { [ "$conn" = full ] || [ "$conn" = tam ]; }; then
        verdict="OK"
    else
        verdict="UNKNOWN"
    fi
    kv BA_VERDICT "$verdict"

    bash "$APP_DIR/kill.sh" >/dev/null 2>&1 || true
}

# ── rungs ─────────────────────────────────────────────────────────────────

cmd_rungs() {
    section rungs
    local rung_ids=(R1 R2 R3 R4 R5 R6 R7 R8)
    local rung_flags=(
        "-p -q -f 2 -e 2 --native-frag --reverse-frag --frag-by-sni --set-ttl 7 --wrong-seq --max-payload=1200"
        "-p -q -f 2 -e 2 --native-frag --reverse-frag --frag-by-sni --max-payload=1200"
        "-p -q -f 1 -e 1 --native-frag --reverse-frag --frag-by-sni --max-payload=1200"
        "-p -q -f 2 -e 2 --native-frag --reverse-frag --frag-by-sni --auto-ttl --wrong-seq --max-payload=1200"
        "-p -q -f 2 -e 2 --native-frag --reverse-frag --frag-by-sni --set-ttl 3 --wrong-seq --max-payload=1200"
        "-p -q -f 2 -e 40 --native-frag --reverse-frag --max-payload=1200"
        "-p -q -f 2 -e 2 --native-frag --reverse-frag --frag-by-sni --set-ttl 7 --wrong-chksum --max-payload=1200"
        "-p -q -f 2 -e 2 --native-frag --reverse-frag --frag-by-sni --set-ttl 7 --wrong-seq --fake-with-sni=discord.com --fake-resend=2 --max-payload=1200"
    )
    local winner="none" winner_mode=""
    local i
    for i in "${!rung_ids[@]}"; do
        local id="${rung_ids[$i]}" mode="${rung_flags[$i]}"
        bash "$APP_DIR/kill.sh" >/dev/null 2>&1 || true
        BYPASS_MODE="$mode" bash "$APP_DIR/start.sh" --no-tray --bypass-all >/dev/null 2>&1 || true
        sleep 3
        local alive discord google nmcheck conn result
        alive="$(daemon_alive)"
        discord="$(code_of https://discord.com/)"
        google="$(code_of https://www.google.com/)"
        nmcheck="$(code_of http://nmcheck.gnome.org/check_network_status.txt)"
        conn="$(nmcli_conn)"
        result="FAIL"
        if is_2xx3xx "$discord" && is_2xx3xx "$google" && is_2xx3xx "$nmcheck" \
           && { [ "$conn" = full ] || [ "$conn" = tam ]; } && [ "$alive" = yes ]; then
            result="PASS"
        fi
        printf '%s discord=%s google=%s nmcheck=%s conn=%s alive=%s %s\n' \
            "$id" "$discord" "$google" "$nmcheck" "$conn" "$alive" "$result" | tee -a "$REPORT"
        if [ "$result" = "PASS" ]; then
            winner="$id"
            winner_mode="$mode"
            break
        fi
    done
    kv WINNER "$winner"
    kv WINNER_MODE "$winner_mode"
    bash "$APP_DIR/kill.sh" >/dev/null 2>&1 || true
}

# ── wire ──────────────────────────────────────────────────────────────────

cmd_wire() {
    section wire
    local mode="${1:--p -q -f 2 -e 2 --native-frag --reverse-frag --frag-by-sni --set-ttl 7 --wrong-seq --max-payload=1200}"
    bash "$APP_DIR/kill.sh" >/dev/null 2>&1 || true
    BYPASS_MODE="$mode" bash "$APP_DIR/start.sh" --no-tray --bypass-all >/dev/null 2>&1 || true
    sleep 2
    kv WIRE_DAEMON "$(daemon_alive)"

    local verdict="unknown" wire_http="000" actual_ip="" out_data=0 sizes="" ttl7=0
    if ! command -v tcpdump >/dev/null 2>&1; then
        note "tcpdump yok: sudo apt-get install -y tcpdump"
        local curl_out
        curl_out="$(curl -sS -o /dev/null -L --max-time 12 -w '%{http_code} %{remote_ip}' https://discord.com/ 2>/dev/null)"
        wire_http="$(awk '{print $1}' <<<"$curl_out")"
        actual_ip="$(awk '{print $2}' <<<"$curl_out")"
        [ -z "$wire_http" ] && wire_http="000"
        kv WIRE_IP "${actual_ip:-unknown}"
        kv WIRE_HTTP "$wire_http"
        kv WIRE_OUT_DATA unknown
        kv WIRE_SEG_SIZES ""
        kv WIRE_TTL7 unknown
    else
        # discord.com has multiple round-robin A records — resolving the
        # target IP separately (e.g. via 1.1.1.1) and filtering tcpdump on
        # it races curl's own (possibly different) pick. Capture broadly on
        # tcp/443 instead, then narrow the analysis to the IP curl actually
        # used (reported by curl itself), eliminating the race entirely.
        resolve_iface
        # mktemp — see the note in the base measurement above.
        local pcap
        pcap="$(mktemp "${TMPDIR:-/tmp}/gdpi-wire.XXXXXX.pcap")" || return 0
        plat_run_root timeout 15 tcpdump -i "$IFACE" -n -s 96 -w "$pcap" \
            "tcp port 443" >/dev/null 2>&1 &
        local tdpid=$!
        sleep 1
        local curl_out
        curl_out="$(curl -sS -o /dev/null -L --max-time 12 -w '%{http_code} %{remote_ip}' https://discord.com/ 2>/dev/null)"
        wire_http="$(awk '{print $1}' <<<"$curl_out")"
        actual_ip="$(awk '{print $2}' <<<"$curl_out")"
        [ -z "$wire_http" ] && wire_http="000"
        sleep 0.3
        wait "$tdpid" 2>/dev/null || true
        plat_run_root chown "$(id -un)" "$pcap" >/dev/null 2>&1 || true
        kv WIRE_IP "${actual_ip:-unknown}"
        kv WIRE_HTTP "$wire_http"

        if [ -s "$pcap" ] && [ -n "$actual_ip" ]; then
            sizes="$(tcpdump -r "$pcap" -n 2>/dev/null | grep " > $actual_ip.443:" | grep -oE 'length [0-9]+' | awk '{print $2}')"
            out_data="$(awk '$1>0' <<<"$sizes" | wc -l)"
            ttl7="$(tcpdump -r "$pcap" -n -v 2>/dev/null | grep -c 'ttl 7,')"
        fi
        kv WIRE_OUT_DATA "$out_data"
        kv WIRE_SEG_SIZES "$(tr '\n' ',' <<<"$sizes" | sed 's/,$//')"
        kv WIRE_TTL7 "$ttl7"
        rm -f "$pcap"

        if [ -z "$actual_ip" ]; then
            verdict="unknown"
        elif [ "$out_data" -ge 2 ] && is_2xx3xx "$wire_http"; then
            verdict="GUEST_OK_AND_WORKS"
        elif [ "$out_data" -ge 2 ] && [ "$wire_http" = "000" ]; then
            verdict="GUEST_OK_DOWNSTREAM_NULLIFIES"
        else
            verdict="GUEST_NOT_MANGLING"
        fi
    fi
    kv WIRE_VERDICT "$verdict"
    bash "$APP_DIR/kill.sh" >/dev/null 2>&1 || true
}

# ── endpoints ─────────────────────────────────────────────────────────────

cmd_endpoints() {
    section endpoints
    bash "$APP_DIR/kill.sh" >/dev/null 2>&1 || true
    bash "$APP_DIR/start.sh" --no-tray --bypass-all >/dev/null 2>&1 || true
    sleep 3

    local ep_root ep_api ep_gateway ep_cdn ep_media
    ep_root="$(code_of https://discord.com/)"
    ep_api="$(code_of https://discord.com/api/v9/gateway)"
    ep_gateway="$(code_of https://gateway.discord.gg/)"
    ep_cdn="$(code_of https://cdn.discordapp.com/)"
    ep_media="$(code_of https://media.discordapp.net/)"
    kv EP_ROOT "$ep_root"
    kv EP_API "$ep_api"
    kv EP_GATEWAY "$ep_gateway"
    kv EP_CDN "$ep_cdn"
    kv EP_MEDIA "$ep_media"

    local blocked=""
    for pair in "EP_ROOT:$ep_root" "EP_API:$ep_api" "EP_GATEWAY:$ep_gateway" \
                "EP_CDN:$ep_cdn" "EP_MEDIA:$ep_media"; do
        local k="${pair%%:*}" v="${pair##*:}"
        [ "$v" = "000" ] && blocked="$blocked $k"
    done
    blocked="${blocked# }"
    if [ -z "$blocked" ]; then
        kv EP_VERDICT OK
        kv EP_BLOCKED ""
    else
        kv EP_VERDICT BLOCKED
        kv EP_BLOCKED "$blocked"
    fi
    bash "$APP_DIR/kill.sh" >/dev/null 2>&1 || true
}

# ── vesktop ───────────────────────────────────────────────────────────────

cmd_vesktop() {
    section vesktop
    if ! command -v vesktop >/dev/null 2>&1; then
        kv VESK_PID none
        kv VESK_NOTE "vesktop is not installed"
        return 0
    fi

    bash "$APP_DIR/kill.sh" >/dev/null 2>&1 || true
    # bash "…" instead of "…": a repo checkout whose scripts lost the execute
    # bit turned this into a silent no-op — start.sh failed with EACCES, `||
    # true` swallowed it, and every measurement below was then taken with NO
    # daemon running (reported as "Vesktop not bypassed" for weeks).
    # --debug-proc=5000: the gate log caps at N packets per daemon run, and
    # unrelated traffic (a browser's reconnect burst when the daemon reloads
    # the firewall) can consume the default 300 before Vesktop's gateway
    # sockets even exist — the measurement would then report zero decisions
    # while the bypass works fine.
    bash "$APP_DIR/start.sh" --no-tray --debug-proc=5000 >/dev/null 2>&1 || true
    sleep 2
    kv VESK_DAEMON "$(daemon_alive)"
    if [ "$(daemon_alive)" != "yes" ]; then
        kv VESK_VERDICT DAEMON_DEAD
        note "daemon did not start — see $PLAT_LOG and $GDPI_LOG"
        return 0
    fi

    # mktemp, not a fixed /tmp name: a symlink pre-planted at a predictable
    # path would make this redirect truncate an arbitrary file we can write.
    local vesklog
    vesklog="$(mktemp "${TMPDIR:-/tmp}/gdpi-vesktop.XXXXXX.log")" || vesklog=/dev/null
    local log_mark
    log_mark="$(wc -l < "$GDPI_LOG" 2>/dev/null || echo 0)"
    setsid vesktop >"$vesklog" 2>&1 < /dev/null &
    sleep 35

    # Vesktop is packaged two ways and only one of them has a "vesktop" exe:
    #   bundled electron  -> /proc/<pid>/exe = /usr/lib/vesktop/vesktop
    #   system electron   -> /proc/<pid>/exe = /usr/lib/electron<N>/electron
    #                        and the app path only shows up in the cmdline
    #                        ("electron /usr/lib/vesktop/app.asar", Arch/Fedora)
    # Keying on the exe alone reported PID=none on every system-electron host,
    # i.e. exactly the packaging this check exists for. proctrack matches on
    # exe OR cmdline OR comm (proctrack_linux.c match_ident); mirror that.
    local pid="" exe="unreadable" cmd="" cand cexe ccmd
    local vpids=""
    for cand in $(pgrep -f vesktop 2>/dev/null); do
        [ "$cand" = "$$" ] && continue
        # cat|tr, not a redirect: a pid listed by pgrep can exit before this
        # line runs, and the redirect's failure is printed by bash itself.
        ccmd="$(cat "/proc/$cand/cmdline" 2>/dev/null | tr '\0' ' ')"
        case "$ccmd" in
            *vm-diag*) continue ;;      # this script's own process
        esac
        cexe="$(readlink -f "/proc/$cand/exe" 2>/dev/null)"
        vpids="$vpids $cand"
        [ -n "$pid" ] && continue
        case "$cexe" in
            */vesktop) pid="$cand"; exe="$cexe"; cmd="$ccmd"; continue ;;
        esac
        case "$ccmd" in
            */vesktop/*|*/vesktop\ *|*vesktop.asar*)
                pid="$cand"; exe="${cexe:-unreadable}"; cmd="$ccmd" ;;
        esac
    done
    kv VESK_PID "${pid:-none}"
    kv VESK_EXE "$exe"
    kv VESK_CMD "$(cut -c1-160 <<<"$cmd")"

    # Gate decisions for VESKTOP's OWN sockets. A global count answers "did
    # anything get bypassed", never "did Vesktop get bypassed" — the old
    # global counters reported PASS while Vesktop itself was being blocked.
    # Electron opens its sockets in a "NetworkService" child whose cmdline no
    # longer mentions vesktop, so pgrep alone misses exactly the sockets under
    # test; walk the whole descendant tree instead (proctrack does the mirror
    # image of this with its 4-hop parent walk).
    local ports="" gate_pass=0 gate_block=0 port n vp tree=""
    if [ -n "$pid" ]; then
        local queue="$pid" cur kid
        while [ -n "$queue" ]; do
            cur="${queue%% *}"
            [ "$cur" = "$queue" ] && queue="" || queue="${queue#* }"
            tree="$tree $cur"
            for kid in $(cat /proc/"$cur"/task/*/children 2>/dev/null); do
                queue="$queue $kid"
            done
        done
    fi
    [ -z "$tree" ] && tree="$vpids"
    if [ -n "$tree" ] && command -v ss >/dev/null 2>&1; then
        for vp in $tree; do
            ports="$ports
$(ss -tnp 2>/dev/null | awk -v p="pid=$vp," '$0 ~ p {print $4}' | sed 's/.*://')"
        done
        ports="$(printf '%s\n' "$ports" | sed '/^$/d' | sort -u)"
    fi
    kv VESK_TREE "$(echo $tree)"
    kv VESK_PORTS "$(tr '\n' ',' <<<"$ports" | sed 's/,$//')"
    for port in $ports; do
        n="$(awk -v m="$log_mark" -v p=":$port ->" \
             'NR>m && index($0,p) && /\[GATE\]/ && /PASS/ {c++} END{print c+0}' \
             "$GDPI_LOG" 2>/dev/null)"
        gate_pass=$((gate_pass + n))
        n="$(awk -v m="$log_mark" -v p=":$port ->" \
             'NR>m && index($0,p) && /\[GATE\]/ && /BLOCK/ {c++} END{print c+0}' \
             "$GDPI_LOG" 2>/dev/null)"
        gate_block=$((gate_block + n))
    done
    kv VESK_GATE_PASS "$gate_pass"
    kv VESK_GATE_BLOCK "$gate_block"

    # ProgramFilters match, using proctrack's rules: path patterns are a
    # substring of exe OR cmdline, bare names are basename-exact on exe or a
    # whole path component of the cmdline.
    local list_hit="no" progs="$CONFIG_DIR/ProgramFilters"
    [ -f "$progs" ] || progs="$APP_DIR/ProgramFilters"
    if [ -f "$progs" ] && [ -n "$pid" ]; then
        local exe_l="${exe,,}" cmd_l="${cmd,,}" pattern pat_l
        while IFS= read -r pattern; do
            pattern="${pattern%%$'\r'}"
            [ -z "$pattern" ] && continue
            case "$pattern" in \#*) continue ;; esac
            pat_l="${pattern,,}"
            if [[ "$pat_l" == */* ]]; then
                [[ "$exe_l" == *"$pat_l"* || "$cmd_l" == *"$pat_l"* ]] && list_hit="yes"
            else
                [ "$(basename "$exe_l")" = "$pat_l" ] && list_hit="yes"
                [[ " ${cmd_l//\// } " == *" $pat_l "* ]] && list_hit="yes"
            fi
            [ "$list_hit" = "yes" ] && break
        done < "$progs"
    fi
    kv VESK_LIST_HIT "$list_hit"

    # Outcome, not just intent: Chromium logs -101 (connection reset) for every
    # handshake the DPI kills.
    local tls_err
    tls_err="$(grep -c 'handshake failed\|net_error -101' "$vesklog" 2>/dev/null)"
    kv VESK_TLS_ERRORS "${tls_err:-0}"
    kv VESK_STDERR "$(grep -m1 -i 'rror' "$vesklog" 2>/dev/null || true)"

    local verdict
    if [ -z "$pid" ]; then
        verdict="NOT_RUNNING"
    elif [ "$list_hit" != "yes" ]; then
        verdict="NOT_IN_PROGRAMFILTERS"
    elif [ "$gate_pass" -gt 0 ] && [ "${tls_err:-0}" -eq 0 ]; then
        verdict="BYPASSED"
    elif [ "$gate_pass" -gt 0 ]; then
        verdict="BYPASSED_WITH_TLS_ERRORS"
    else
        verdict="NO_GATE_DECISIONS"
    fi
    kv VESK_VERDICT "$verdict"
    note "[GATE] log label naming is INVERTED relative to netfilter verdict (log-PASS = listed = bypassed)"

    pkill -f vesktop >/dev/null 2>&1 || true
    bash "$APP_DIR/kill.sh" >/dev/null 2>&1 || true
}

# ── all ───────────────────────────────────────────────────────────────────

cmd_all() {
    cmd_env
    cmd_base
    cmd_bypassall
    cmd_rungs
    cmd_wire
    cmd_endpoints
}

# ── main ──────────────────────────────────────────────────────────────────

usage() {
    sed -n '2,17p' "$0"
}

case "${1:-}" in
    env)        cmd_env ;;
    base)       cmd_base ;;
    bypassall)  cmd_bypassall ;;
    rungs)      cmd_rungs ;;
    wire)       cmd_wire "${2:-}" ;;
    endpoints)  cmd_endpoints ;;
    vesktop)    cmd_vesktop ;;
    all)        cmd_all ;;
    *)          usage; exit 2 ;;
esac

echo "[vm-diag] report: $REPORT"
