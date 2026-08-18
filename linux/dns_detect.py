#!/usr/bin/env python3
"""
dns_detect.py — DNS auto-detection helper for GoodByeDPI-Plus (Linux port).

Tests candidate DNS servers in parallel (non-blocking UDP), picks the
fastest one that returns a non-poisoned A record. Falls back to
Yandex 77.88.8.8:1253 if none valid.

stderr: human-readable per-server log + selected line.
stdout: machine-readable "SELECTED\t<name>\t<addr>\t<port>\t<v6>\t<v6port>\t<ms>\t<status>"
"""
import socket
import struct
import time
import sys
import select

# ── Config ──────────────────────────────────────────────────────────────────
DNS_TEST_DOMAIN = "discord.com"
DNS_TIMEOUT_MS = 800
BLOCK_PAGE_RANGES = ("195.175.254.",)  # Turk Telekom ISP block-page IPs

DNS_CANDIDATES = [
    # (name, addr, port, v6addr, v6port)
    ("Yandex",     "77.88.8.8",    1253, "2a02:6b8::feed:0ff",    1253),
    ("Yandex",     "77.88.8.8",    53,   "2a02:6b8::feed:0ff",    53),
    ("Cloudflare", "1.1.1.1",      53,   "2606:4700:4700::1111",  53),
    ("Quad9",      "9.9.9.9",      53,   "2620:fe::fe",           53),
    ("AdGuard",    "94.140.14.14", 53,   "2a10:50c0::ad1:ff",     53),
]

FALLBACK = ("Cloudflare", "1.1.1.1", 53, "2606:4700:4700::1111", 53)


def build_dns_query(domain: str) -> bytes:
    """Build a minimal A-record DNS query (RFC 1035)."""
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in domain.split(".")
    ) + b"\x00"
    qtype_qclass = struct.pack("!HH", 1, 1)  # A, IN
    return header + qname + qtype_qclass


def parse_dns_response_a(data: bytes):
    """Return first A-record IP string, or None."""
    if len(data) < 12:
        return None
    pos = 12
    while pos < len(data) and data[pos] != 0:   # skip question name
        pos += data[pos] + 1
    pos += 5  # null + qtype(2) + qclass(2)
    answer_count = (data[6] << 8) | data[7]
    for _ in range(answer_count):
        if pos >= len(data):
            break
        if data[pos] & 0xC0:                    # compressed name pointer
            pos += 2
        else:
            while pos < len(data) and data[pos] != 0:
                pos += data[pos] + 1
            pos += 1
        if pos + 10 > len(data):
            break
        rtype = (data[pos] << 8) | data[pos + 1]
        pos += 8                                # type(2) + class(2) + ttl(4)
        rdlength = (data[pos] << 8) | data[pos + 1]
        pos += 2
        if rtype == 1 and rdlength == 4 and pos + 4 <= len(data):
            return f"{data[pos]}.{data[pos+1]}.{data[pos+2]}.{data[pos+3]}"
        pos += rdlength
    return None


def is_poisoned(ip: str) -> bool:
    return any(ip.startswith(r) for r in BLOCK_PAGE_RANGES)


def system_resolver():
    """First `nameserver` entry from /etc/resolv.conf, or None."""
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
    except OSError:
        pass
    return None


def probe_system_resolver():
    """Query the system resolver for DNS_TEST_DOMAIN.

    Returns (addr, verdict, answer): verdict is "clean", "poisoned" or
    "unknown". Only a returned A record that matches a known block-page
    pattern counts as poisoned — a timeout stays "unknown" so a transient
    failure never produces a false alarm.
    """
    addr = system_resolver()
    if not addr:
        return (None, "unknown", "")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(DNS_TIMEOUT_MS / 1000.0)
        sock.sendto(build_dns_query(DNS_TEST_DOMAIN), (addr, 53))
        data, _ = sock.recvfrom(2048)
    except OSError:
        return (addr, "unknown", "")
    finally:
        sock.close()
    # RCODE != 0 (SERVFAIL=2, NXDOMAIN=3) from an ISP resolver for a known
    # domain is a block response — treat as poisoned even without a block-page IP.
    rcode = data[3] & 0x0f if len(data) >= 4 else 0
    ip = parse_dns_response_a(data)
    if not ip:
        if rcode == 2 or rcode == 3:  # SERVFAIL / NXDOMAIN = blocking by ISP
            return (addr, "poisoned", f"RCODE={rcode}")
        return (addr, "unknown", "")
    if is_poisoned(ip) or ip == "0.0.0.0" or ip.startswith("127."):
        return (addr, "poisoned", ip)
    return (addr, "clean", ip)


def test_all():
    """Probe all candidates in parallel; return list of result dicts (aligned to DNS_CANDIDATES)."""
    query = build_dns_query(DNS_TEST_DOMAIN)
    results = []
    socks = []   # (sock, rec)

    for (name, addr, port, v6, v6p) in DNS_CANDIDATES:
        rec = {"name": name, "addr": addr, "port": port,
               "v6": v6, "v6p": v6p, "time_ms": -1, "status": "no-response", "ip": None}
        results.append(rec)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setblocking(False)
            s.sendto(query, (addr, port))
            socks.append((s, rec))
        except OSError:
            rec["status"] = "unreachable"

    start = time.monotonic()
    deadline = start + DNS_TIMEOUT_MS / 1000.0

    while True:
        pending = [r for _, r in socks if r["ip"] is None and r["status"] == "no-response"]
        if not pending:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        rlist, _, _ = select.select([s for s, _ in socks], [], [], min(0.05, remaining))
        if not rlist:
            continue
        for s in rlist:
            rec = next(r for ss, r in socks if ss is s)
            try:
                data, _ = s.recvfrom(4096)
            except OSError:
                continue
            rec["time_ms"] = int((time.monotonic() - start) * 1000)
            ip = parse_dns_response_a(data)
            if ip and not is_poisoned(ip):
                rec["ip"] = ip
                rec["status"] = "ok"
            elif ip:
                rec["status"] = "poisoned"
            else:
                rec["status"] = "no-record"

    for s, _ in socks:
        try: s.close()
        except OSError: pass

    return results


def main():
    """Probe every candidate ONCE and emit selection + full list together.

    stdout contract (consumed by start.sh, forwarded to tray.py):
        SELECTED <name> <addr> <port> <v6> <v6port> <ms> <status>
        INFO     name|addr|port|ms|status;...     (one entry per candidate)
        IDX      <index of SELECTED within INFO>
        SYSDNS   <addr> <verdict> <answer>

    SELECTED and INFO come from the SAME measurement, so the tray header can
    never advertise a different latency than the list row it points at — two
    separate probe runs used to disagree by several ms.
    """
    force = -1
    argv = sys.argv[1:]
    if len(argv) >= 2 and argv[0] == "--force":
        try:
            force = int(argv[1])
        except ValueError:
            force = -1

    results = test_all()
    for r in results:
        print(f"[dns] {r['name']} {r['addr']}:{r['port']} -> {r['status']} ({r['time_ms']}ms)", file=sys.stderr)

    idx = -1
    if 0 <= force < len(results):
        idx = force
        print(f"[dns] manual override: index {idx}", file=sys.stderr)
    else:
        best_time = 10 ** 9
        for i, r in enumerate(results):
            if r["status"] == "ok" and 0 <= r["time_ms"] < best_time:
                idx, best_time = i, r["time_ms"]

    if idx < 0:
        name, addr, port, v6, v6p = FALLBACK
        best = {"name": name, "addr": addr, "port": port,
                "v6": v6, "v6p": v6p, "time_ms": -1, "status": "fallback"}
        print(f"[dns] no valid server, using fallback {addr}:{port}", file=sys.stderr)
    else:
        best = results[idx]
        print(f"[dns] selected {best['addr']}:{best['port']} ({best['time_ms']}ms)", file=sys.stderr)

    info = ";".join(f"{r['name']}|{r['addr']}|{r['port']}|{r['time_ms']}|{r['status']}"
                    for r in results)

    print(f"SELECTED\t{best['name']}\t{best['addr']}\t{best['port']}\t{best['v6']}\t{best['v6p']}\t{best['time_ms']}\t{best['status']}")
    print(f"INFO\t{info}")
    print(f"IDX\t{idx if idx >= 0 else 0}")
    sys_addr, sys_verdict, sys_answer = probe_system_resolver()
    print(f"SYSDNS\t{sys_addr or ''}\t{sys_verdict}\t{sys_answer}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
