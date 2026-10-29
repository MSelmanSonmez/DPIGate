> **Internal document — historical design notes, not user documentation.**
>
> This is the original planning/roadmap document for the Linux port, kept for
> context on *why* the port is built the way it is. It predates the shipped
> code and is **stale in places** (file names, CLI flags, config directory
> names and the systemd unit design all changed during implementation).
> For anything you intend to rely on, see [`README.md`](../README.md) — it
> documents the behaviour that actually ships.

# DPIGate — Linux Port Roadmap

> **Created:** 14 July 2026
> **Purpose:** Single source to refresh context in later sessions.
> The Windows port (existing) works; this file is the detailed
> implementation plan for the Linux port. All technical details are
> self-contained.

> **Note (later change):** The Windows folder was afterwards renamed from
> `src/` to `windows/`, so that the two platforms are named symmetrically
> (`windows/` and `linux/`). Path references throughout this document
> reflect the repository layout at the time of writing; read every `src/`
> below as `windows/`.

---

## 0. Summary

**Question:** Can a Linux version of this application be made?
**Answer:** YES. The most suitable path is porting the existing C code to Linux.

**Approach:** (c) Port the existing C code — NFQUEUE + sock_diag.
**Structure:** Separate `linux/` folder (src/ UNTOUCHED, zero build dependency).
Drift check: `make check-sync` (Section 4.1).
- Per-program UX preserved (programs.txt, --only-programs, --debug-proc, hot-reload)
- Bypass algorithms are ported (COPY+MODIFY — WinDivert types translated to Linux counterparts, logic preserved)
- WinDivert → NFQUEUE (packet capture/modify/reinject)
- WinDivert FLOW layer → sock_diag + inode→PID cache (per-program tracking)
- PowerShell tray → Python/GTK AyatanaAppIndicator
- Windows SCM → systemd user service
- kernel rules instead of iptables/nftables filter string

**Effort estimate:** ~5-7 weeks (single developer)
**Competitive advantage:** No Linux DPI tool offers exe-name-based, transparent,
hot-reloadable per-program filtering. This will be the main value
proposition of the Linux port.

**Target distributions:** Ubuntu/Debian, Arch/Fedora
**Priority features:** Per-program filtering, DNS redirect + auto-detect,
System tray (GUI), Auto Start (systemd)

---

## 1. Linux DPI Tools Market — Competitive Analysis

| Tool | Star | Mechanism | Per-program? | Note |
|------|------|-----------|--------------|-----|
| **zapret** (bol-van/zapret) | 15.8k | NFQUEUE + raw socket | NO (hostlist/ipset/port/L7) | Most powerful bypass. EOL (zapret2 active, Lua) |
| **byedpi** (hufrea/byedpi) | 3.3k | SOCKS proxy | NO (proxy → app SOCKS config) | ByeDPIAndroid 5.4k on Android |
| **GreenTunnel** | 4.9k | Node.js proxy | NO | DoH is the main feature |
| **SpoofDPI** (xvzc/spoofdpi) | 4.9k | Go proxy | NO | Apache-2.0 (same license as yours) |

**Critical observation:** No Linux DPI tool offers exe-name-based, transparent,
hot-reloadable per-program filtering. "Per-program" in these
tools = "pointing the app at a proxy" (manual SOCKS config).
DPIGate's programs.txt + --only-programs + WinDivert FLOW
architecture is UNIQUE in the Linux world.

**zapret detail:** It does NOT use WinDivert on Linux — it uses NFQUEUE.
WinDivert only exists in zapret2's Windows engine (winws2).
zapret's nfqws program uses libnetfilter_queue + raw socket.
It does NOT do per-program filtering — filters are hostlist/ipset/port/L7/SSID.

---

## 2. Comparison of the Three Approaches

| Approach | Effort | Bypass power | Per-program UX | Risk |
|----------|------|-------------|----------------|------|
| **(a) Write from scratch** | Very high (months) | From scratch | From scratch | Reinventing the wheel — not recommended |
| **(b) Fork zapret + add per-program** | Medium-high | Maximum (zapret) | B1: shift to cgroup / B2: intervene inside nfqws (complex C+Lua) | zapret2 Lua learning curve |
| **(c) Port the existing C code** | Medium | Good (--auto-ttl --max-payload proven on ISP) | Preserved as-is | Lowest risk — architecture is settled |

**Selected: (c)**

---

## 3. Technical Obstacles and Solutions

### 3.1 The 3 critical challenges (WinDivert dependency)

| Windows (existing) | Linux counterpart | Status |
|------------------|-----------------|-------|
| WinDivert NETWORK layer (packet capture/modify/reinject) | NFQUEUE (libnetfilter_queue) — capture packets, change/reinject with nfq_set_verdict2. Raw socket for fake packets (SOCK_RAW, IP_HDRINCL) | Proven — zapret has used it for years |
| WinDivert FLOW layer (5-tuple + PID notification from the kernel for each new flow) | No direct counterpart. Alternative: sock_diag (netlink INET_DIAG) → socket inode from 5-tuple → PID via readlink on /proc/<pid>/fd/*. Or eBPF sockops (kernel 5.7+) | Hardest part — proctrack.c's FLOW thread must be redesigned |
| Fake packet inject (TTL/checksum/seq damage, above the kernel TCP stack) | Raw socket + conntrack bypass (nftables NOTRACK or fwmark). Otherwise the kernel conntrack may interpret the fake packet as RST and cut the real connection. zapret solves it with --dpi-desync-fwmark | Finest point — but there is a zapret example |

### 3.2 Medium difficulty

| Windows | Linux | Note |
|---------|-------|-----|
| WinDivertHelperCalcChecksums + WinDivertHelperParsePacket | Own implementation (IP/TCP/UDP checksum + header parse). ~200 lines. checksum.c/.h | Mechanical work |
| GetExtendedTcpTable/UdpTable (seed + OS fallback) | /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6 parse + inode → PID cache | proctrack.c ~128 lines rewritten |
| OpenProcess + QueryFullProcessImageNameW | Single line: readlink("/proc/<pid>/exe", buf, sizeof buf) — UTF-8 on Linux, no handle needed | Simpler |
| CRITICAL_SECTION / CreateThread / WaitForSingleObject / Sleep | pthread_mutex_t / pthread_create / pthread_join / nanosleep | Mechanical translation (~20 places) |
| GetFileAttributesExA (mtime) | stat() + st_mtim (nanosecond precision) | Better |
| Windows service (SCM) — service.c | Dropped entirely, replaced by a systemd .service file | Easy |
| Filter string (WinDivert language: tcp.DstPort==80 and ...) | nftables/iptables rules — rewrite | Medium |
| flush_dns_cache() (dnsapi.dll) | resolvectl flush-caches (systemd-resolved) or nscd -i hosts | Distro-dependent |
| rand_s() | getrandom() / /dev/urandom | Simple |

### 3.3 Easy (platform-independent logic — porting required but the logic is the same)

- All of the bypass algorithms: SNI extraction, Host header manipulation,
  native fragmentation, auto-TTL formula, fake packet templates, DNS conntrack —
  fakepackets.c (441 lines), dnsredir.c (244), ttltrack.c (252),
  blackwhitelist.c work on raw buffers.
- **However:** They use WinDivert types (WINDIVERT_ADDRESS, PWINDIVERT_IPHDR) and
  functions (WinDivertSend, WinDivertHelperParsePacket,
  WinDivertHelperCalcChecksums). In the Linux port COPY+MODIFY:
  WinDivert types -> Linux structs, WinDivert functions ->
  pio_send_raw + parse_packet + calc_checksums. The file logic stays untouched.
- uthash (pure C), getopt_long, inet_pton, htons/ntohs

---

## 4. Directory Structure (Linux port)

**Decision:** Windows `src/` is UNTOUCHED. The Linux port lives in a separate
folder named `linux/`, with ZERO build dependency. The bypass algorithm files
fakepackets.c, dnsredir.c, ttltrack.c, blackwhitelist.c — are ported
to Linux (COPY+MODIFY — WinDivert types translated to Linux counterparts).
Only utils/ stays as COPY (genuinely platform-independent). Drift check
only for utils/ (Section 4.1).

```
goodbyedpi-sel/
  src/                       # WINDOWS — UNTOUCHED
    goodbyedpi.c/.h
    proctrack.c/.h
    fakepackets.c/.h
    dnsredir.c/.h
    ttltrack.c/.h
    blackwhitelist.c/.h
    service.c/.h
    utils/ (uthash.h, repl_str.c/.h, getline.c/.h)
    Makefile
    ...

  linux/                     # LINUX PORT — separate folder, zero dependency
    goodbyedpi.c             # COPY + MODIFY: Windows headers removed, pio_* API
    goodbyedpi.h             # COPY (same — only constants)
    proctrack.c              # COPY + MODIFY: FLOW -> sock_diag + inode cache
    proctrack.h              # COPY + MODIFY: remove windivert.h dependency
    packet_io.h              # NEW: platform abstraction (NFQUEUE)
    packet_io_linux.c        # NEW: NFQUEUE backend
    checksum.c               # NEW: IP/TCP/UDP checksum + parse
    checksum.h               # NEW
    rawsend_linux.c          # NEW: raw socket fake packet + fwmark
    rawsend_linux.h          # NEW
    sockdiag.c               # NEW: NETLINK_INET_DIAG (5-tuple -> inode)
    sockdiag.h               # NEW
    fakepackets.c/.h         # COPY+MODIFY (WinDivert types -> Linux)
    dnsredir.c/.h            # COPY+MODIFY (windows.h -> Linux)
    ttltrack.c/.h            # COPY+MODIFY (windows.h -> Linux)
    blackwhitelist.c/.h      # COPY+MODIFY (windows.h -> Linux)
    utils/                   # COPY (uthash.h, repl_str.c/.h, getline.c/.h)
    Makefile                 # NEW: Linux target (independent of src/)
    .sync-checksums          # NEW: drift detection (Section 4.1)
    start.sh                 # NEW: Linux counterpart of start.ps1
    tray.py                  # NEW: GTK AyatanaAppIndicator tray
    dns_detect.py            # NEW: DNS auto-detect helper
    goodbyedpi.service       # NEW: systemd user unit
    goodbyedpi.nft           # NEW: nftables rules
    install.sh               # NEW: Linux counterpart of install.ps1
    uninstall.sh             # NEW: Linux counterpart of uninstall.ps1
    programs.txt             # NEW (with Linux exe names)
    icon.png                 # NEW: GTK SVG/PNG
```

### 4.1 Drift Detection (check-sync mechanism)

Because the bypass files are copied, there is a drift risk between Windows
src/ and Linux linux/. Solution:

**`.sync-checksums` file:** The SHA256 checksum of each copied file is
stored. Format:
```
# .sync-checksums — auto-generated, do NOT edit by hand
# format: <relative_path> <sha256_of_src> <sha256_of_linux_copy>
fakepackets.c a1b2c3... d4e5f6...
dnsredir.c   ...
```

**`make check-sync` target:**
1. Compute the SHA256 of the original files in `src/`
2. Compute the SHA256 of the copies in `linux/`
3. Compare with `.sync-checksums`:
   - src changed, linux copy is stale → "DRIFT: src/fakepackets.c updated,
     synchronize linux/fakepackets.c (make sync)"
   - linux copy changed, src is stale → "DRIFT: linux/fakepackets.c
     differs from src/ — manual change? overwrite with make sync"
   - both changed → "DRIFT: both sides changed — manual merge required"

**`make sync` target:** src/ -> linux/ copy + checksum update.
Only for COPY files (MODIFY/COPY+MODIFY/NEW files EXCLUDED).

**CI / pre-commit hook:** If `make check-sync` fails, the build STOPS.
This prevents drift from accumulating silently.

**COPY vs COPY+MODIFY classification:**
| File | Class | Sync? |
|-------|-------|-------|
| utils/* (uthash.h, repl_str.c/.h, getline.c/.h) | COPY | YES |
| fakepackets.c/.h, dnsredir.c/.h, ttltrack.c/.h, blackwhitelist.c/.h, goodbyedpi.c/.h, proctrack.c/.h | COPY+MODIFY | NO (manual port) |
| packet_io.*, checksum.*, rawsend_linux.*, sockdiag.*, Makefile, .sync-checksums, *.sh, *.py, *.nft, *.service | NEW | NO |

---

## 5. Packet I/O Layer (packet_io.h)

There is NO WinDivert in the Linux port. packet_io.h hides NFQUEUE behind a
single interface. The linux/goodbyedpi.c main loop uses this API.

**Important:** packet_io.h is Linux-only. Windows src/goodbyedpi.c
continues to use WinDivert — no platform abstraction is done (src/
is untouched). There is NO packet_io_win.c.

### 5.1 API

```c
/* packet_io.h — linux/ only */
typedef enum { PKT_OUTBOUND, PKT_INBOUND } pkt_dir_t;
typedef enum { VERDICT_PASS, VERDICT_MODIFY, VERDICT_DROP } pkt_verdict_t;

typedef struct {
    uint8_t  *data;        /* IP packet (modifiable, in-place) */
    size_t    len;         /* packet length */
    size_t    cap;         /* buffer capacity */
    pkt_dir_t dir;         /* outbound / inbound */
    uint32_t  fwmark;      /* current fwmark (fake detection) */
    uint32_t  packet_id;   /* NFQUEUE: required for verdict */
    void     *backend_data;/* platform-specific opaque */
} packet_ctx_t;

int   pio_init(int qnum);
void  pio_deinit(void);
int   pio_recv(packet_ctx_t *ctx);                    /* blocking */
int   pio_send(packet_ctx_t *ctx, pkt_verdict_t v);   /* verdict + reinject */
int   pio_send_raw(const void *pkt, size_t len,       /* fake packet: raw socket */
                   const void *dst_ip, int is_ipv6, uint32_t fwmark);
int   pio_flow_start(void);   /* no-op — no FLOW layer on Linux */
void  pio_flow_stop(void);   /* no-op */
```

### 5.2 packet_io_linux.c

NFQUEUE backend. Pattern extracted from zapret's nfqws.c:

| pio_* function | NFQUEUE counterpart |
|------------------|-------------------|
| pio_init | nfq_open → nfq_unbind_pf → nfq_bind_pf → nfq_create_queue(qnum, cb) → nfq_set_mode(NFQNL_COPY_PACKET, 0xffff) → nfq_set_queue_maxlen → nfq_set_queue_flags(FAIL_OPEN) → nfnl_rcvbufsiz(1MB) → raw socket preinit |
| pio_recv | recv(nfq_fd, buf, 16384) → nfq_handle_packet → callback nfq_get_payload(&data) + nfq_get_msg_packet_hdr(&id) + nfq_get_nfmark → fill the ctx |
| pio_send(MODIFY) | nfq_set_verdict2(qh, id, NF_ACCEPT, mark, len, data) |
| pio_send(PASS) | nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, NULL) |
| pio_send(DROP) | nfq_set_verdict2(qh, id, NF_DROP, mark, 0, NULL) |
| pio_send_raw | sendto(raw_sock, pkt, len, 0, &dst, ...) — SO_MARK=fwmark |
| pio_flow_start/stop | no-op — no FLOW layer on Linux, proctrack via lazy-resolve |

**Critical:** in the callback `if (fwmark & DESYNC_FWMARK) return PASS` — prevents
fake packets from falling back into the queue (software layer). Kernel
layer: the nftables rule does not enqueue packets with fwmark.

---

## 6. NFQUEUE API Details (zapret nfqws reference)

### 6.1 Init pattern

```c
#include <libnetfilter_queue/libnetfilter_queue.h>
#define NF_DROP 0
#define NF_ACCEPT 1

static bool nfq_init(struct nfq_handle **h, struct nfq_q_handle **qh)
{
    *h = nfq_open();
    if (!*h) goto err;

    if (nfq_unbind_pf(*h, AF_INET) < 0) goto err;   /* clean up previous residue */
    if (nfq_bind_pf(*h, AF_INET) < 0) goto err;     /* bind for AF_INET */

    *qh = nfq_create_queue(*h, qnum, &nfq_cb, &params);  /* queue + callback */
    if (!*qh) goto err;

    nfq_set_mode(*qh, NFQNL_COPY_PACKET, 0xffff);   /* copy the FULL packet */
    nfq_set_queue_maxlen(*qh, 4986);
    nfq_set_queue_flags(*qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN);
    nfnl_rcvbufsiz(nfq_nfnlh(*h), 1024*1024);       /* 1MB rcv buffer */

    /* suppress the ENOBUFS error */
    int yes = 1, fd = nfq_fd(*h);
#ifdef SOL_NETLINK
#ifdef NETLINK_NO_ENOBUFS
    setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &yes, sizeof(yes));
#endif
#endif
    return true;
err:
    nfq_deinit(h, qh);
    return false;
}
```

### 6.2 Main loop

```c
static int nfq_main(void)
{
    uint8_t buf[16384] __attribute__((aligned));  /* alignment required */
    struct nfq_handle *h = NULL;
    struct nfq_q_handle *qh = NULL;
    int fd, e;
    ssize_t rd;

    if (!nfq_init(&h, &qh)) goto err;
    fd = nfq_fd(h);

    do {
        while ((rd = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            if (rd) nfq_handle_packet(h, (char *)buf, (int)rd);
        }
        e = errno;
    } while (e == ENOBUFS);   /* buffer overflow → retry, don't die */

    nfq_deinit(&h, &qh);
    return 0;
}
```

### 6.3 Callback — accessing the packet data

```c
static int nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                  struct nfq_data *nfa, void *cookie)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    int id = ph ? ntohl(ph->packet_id) : 0;        /* REQUIRED for verdict */
    uint32_t mark = nfq_get_nfmark(nfa);            /* fwmark (fake detection) */
    uint8_t *data;
    int ilen = nfq_get_payload(nfa, &data);         /* POINTER into the kernel buffer */
    /* NO copy — in-place modification */

    if (ilen >= 0) {
        size_t len = ilen;
        uint8_t verdict = processPacketData(&mark, data, &len);
        switch (verdict) {
        case VERDICT_MODIFY:
            return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, len, data);
        case VERDICT_DROP:
            return nfq_set_verdict2(qh, id, NF_DROP, mark, 0, NULL);
        }
    }
    return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, NULL);  /* PASS */
}
```

### 6.4 Used nfq_get_* functions

| Function | Return | Description |
|-----------|-------|----------|
| nfq_get_msg_packet_hdr(nfa) | nfqnl_msg_packet_hdr* | packet_id + hw_protocol. packet_id is required for verdict |
| nfq_get_nfmark(nfa) | uint32_t | The packet's fwmark. Used in fake packet detection |
| nfq_get_payload(nfa, &data) | int (length, <0=error) | Returns a pointer to the kernel buffer in data. No copy → in-place modification |
| nfq_get_outdev(nfa) | uint32_t | Output interface index (filled in the outbound direction) |
| nfq_get_indev(nfa) | uint32_t | Input interface index (filled in the inbound direction) |

### 6.5 nfq_set_verdict2 signature

```c
int nfq_set_verdict2(struct nfq_q_handle *qh,
                     uint32_t id,            /* packet_id */
                     uint32_t verdict,       /* NF_ACCEPT / NF_DROP */
                     uint32_t mark,          /* new fwmark */
                     uint32_t data_len,      /* mangle data length (0 = no change) */
                     const uint8_t *data);   /* mangle data (NULL = no change) */
```

- data != NULL && data_len > 0 → the kernel replaces the packet contents with this data (mangle)
- data_len=0, data=NULL → pass through unchanged

### 6.6 Verdict constants

```c
#define VERDICT_PASS     0
#define VERDICT_MODIFY   1
#define VERDICT_DROP     2
#define VERDICT_MASK     3
#define VERDICT_NOCSUM   4   /* don't recompute the checksum */
```

---

## 7. Raw Socket — Sending Fake Packets (rawsend_linux.c)

Pattern extracted from zapret's darkmagic.c.

### 7.1 Creating the socket

```c
static int raw_sock4 = -1, raw_sock6 = -1;

static int rawsend_socket(sa_family_t family)
{
    int *sock = (family == AF_INET) ? &raw_sock4 : &raw_sock6;
    if (*sock == -1) {
        int yes = 1, pri = 6;

        /* SOCK_RAW + IPPROTO_RAW → IP_HDRINCL implicit (data is a full IP packet) */
        *sock = socket(family, SOCK_RAW, IPPROTO_RAW);
        if (*sock == -1) return -1;

        setsockopt(*sock, SOL_SOCKET, SO_PRIORITY, &pri, sizeof(pri));

        if (family == AF_INET) {
            /* BLOCK kernel defragmentation (for IP fragment sending) */
            setsockopt(*sock, IPPROTO_IP, IP_NODEFRAG, &yes, sizeof(yes));
            /* allow bind to a nonexistent src IP (for spoofed src) */
            setsockopt(*sock, IPPROTO_IP, IP_FREEBIND, &yes, sizeof(yes));
        }
        if (family == AF_INET6) {
            /* IPv6 freebind (kernel 4.15+) — may not be supported, silently skip */
            setsockopt(*sock, SOL_IPV6, IPV6_FREEBIND, &yes, sizeof(yes));
        }
    }
    return *sock;
}
```

**Critical sockopts:**
- SOCK_RAW + IPPROTO_RAW → IP_HDRINCL is implicitly implied. The data passed
  to sendto is a full IP packet (including the IP header). The kernel does not add an IP header.
- IP_NODEFRAG → prevents the kernel from reassembling IPv4 fragments.
- IP_FREEBIND → allows bind() even if the source IP has not yet been assigned to the interface.
- SO_PRIORITY=6 → high priority for fake packets (so the order is not broken).

### 7.2 Setting fwmark

```c
static bool set_socket_fwmark(int sock, uint32_t fwmark)
{
    return setsockopt(sock, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark)) != -1;
}
```

SO_MARK → fwmark is stamped on every packet leaving this socket. This is
the kernel layer that prevents fake packets from falling back into NFQUEUE.

### 7.3 fwmark constant

```c
#define DPI_DESYNC_FWMARK_DEFAULT 0x40000000
```

During desync the mark is OR'd: `uint32_t fwmark = mark | DPI_DESYNC_FWMARK_DEFAULT;`

### 7.4 Sending

```c
bool rawsend(const struct sockaddr* dst, uint32_t fwmark,
             const char *ifout, const void *data, size_t len)
{
    int sock = rawsend_socket(dst->sa_family);
    if (sock == -1) return false;
    if (!set_socket_fwmark(sock, fwmark)) return false;

    int salen = (dst->sa_family == AF_INET) ? sizeof(struct sockaddr_in)
                                            : sizeof(struct sockaddr_in6);
    struct sockaddr_storage dst2;
    memcpy(&dst2, dst, salen);
    if (dst->sa_family == AF_INET6)
        ((struct sockaddr_in6 *)&dst2)->sin6_port = 0;  /* prevent Linux EINVAL */

    /* exit via the correct interface with SO_BINDTODEVICE (optional) */
    /* bind the source IP with bind(src IP) (bind-fix mode) */

    ssize_t bytes = sendto(sock, data, len, 0, (struct sockaddr*)&dst2, salen);
    return bytes != -1;
}
```

### 7.5 Raw socket preinit

Opening a raw socket requires ROOT → called inside pio_init, BEFORE the
privilege drop.

---

## 8. Preventing Fake Packets from Falling Back into NFQUEUE

TWO-layer defense:

### 8.1 Layer 1 — Kernel: fwmark + nftables mark filter

SO_MARK sockopt → fwmark is stamped on every packet leaving the raw socket.
The nftables rule does NOT enqueue marked packets:

```nft
# nftables
mark 0x40000000/0x40000000 accept   # bypass the fakes
```

**Documentation (zapret README):** "the mark filter must be considered
REQUIRED — otherwise deadlock and packet order corruption occur."

### 8.2 Layer 2 — Software: mark check inside the callback

```c
/* packet_io_linux.c — processPacketData */
if (fwmark & DPI_DESYNC_FWMARK_DEFAULT) {
    return VERDICT_PASS;   /* our own sent fake packet, don't touch */
}
```

---

## 9. Conntrack Bypass

### 9.1 Own userspace conntrack (NOT tied to the kernel conntrack)

goodbyedpi already uses its own conntrack (dnsredir.c, ttltrack.c).
It is not tied to the kernel nf_conntrack.

### 9.2 NOTRACK (for transit traffic)

Fake packets can enter the kernel nf_conntrack and fall into the INVALID
state (especially in badsum, datanoack, ipfrag modes). Solution:

```nft
# nftables — keep fake packets out of conntrack
table ip raw {
    chain output {
        mark 0x40000000/0x40000000 notrack
    }
}
```

Kernel 4.16+ keeps packets in the NOTRACK state exempt from defrag.

### 9.3 Disabling conntrack checksum for badsum

```bash
sysctl net.netfilter.nf_conntrack_checksum=0
```

### 9.4 Liberal mode for RST ack mismatch

```bash
sysctl net.netfilter.nf_conntrack_tcp_be_liberal=1
```

---

## 10. Checksum Implementation (checksum.c/.h)

There is no WinDivertHelperCalcChecksums or WinDivertHelperParsePacket on
Linux. Our own implementation.

### 10.1 Generic internet checksum (RFC 1071)

```c
uint16_t inet_checksum(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        uint16_t w = ((uint16_t)p[0] << 8) | p[1];  /* read big-endian */
        sum += w;
        p   += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += (uint16_t)p[0] << 8;  /* single remaining byte: pad with 0 */
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);  /* fold the carries */
    return (uint16_t)(~sum);  /* 1's complement */
}
```

### 10.2 IPv4 header checksum

```c
uint16_t ipv4_header_checksum(struct iphdr *hdr)
{
    hdr->check = 0;
    size_t hdr_len = (size_t)hdr->ihl * 4;
    return inet_checksum(hdr, hdr_len);  /* header only */
}
```

### 10.3 TCP checksum (IPv4 pseudo-header)

```c
uint16_t tcp_checksum_v4(const struct iphdr *iph,
                         const struct tcphdr *tcph, size_t tcp_len)
{
    struct __attribute__((packed)) {
        uint32_t src;
        uint32_t dst;
        uint8_t  zero;
        uint8_t  proto;       /* IPPROTO_TCP = 6 */
        uint16_t tcp_len;
    } pseudo = { iph->saddr, iph->daddr, 0, IPPROTO_TCP, htons((uint16_t)tcp_len) };

    size_t total = sizeof(pseudo) + tcp_len;
    uint8_t *buf = malloc(total);
    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), tcph, tcp_len);
    uint16_t csum = inet_checksum(buf, total);
    free(buf);
    return csum;
}
```

### 10.4 IPv6 differences

- No checksum in the header (the IPv6 header is a fixed 40 bytes)
- Pseudo-header is 40 bytes (addresses are 128-bit)
- Length field is 32 bits (16 bits in IPv4) — jumbogram support
- UDP checksum is MANDATORY (optional in IPv4)
- For UDP, if the calculation yields 0, send 0xFFFF (0 = "no checksum")

### 10.5 Parse — counterpart of WinDivertHelperParsePacket

```c
int parse_packet(uint8_t *pkt, size_t len,
                 struct iphdr **out_ip4, struct ipv6hdr **out_ip6,
                 uint8_t *out_proto, struct tcphdr **out_tcp,
                 struct udphdr **out_udp,
                 uint8_t **out_payload, size_t *out_payload_len);
```

- Look at the version nibble of the first byte (4 or 6)
- Cast to struct iphdr* or struct ipv6hdr*
- Transport header at offset ihl*4 (IPv4) or fixed 40 (IPv6)
- Cast to struct tcphdr* / struct udphdr* according to the protocol field
- Extension headers are not followed (same behavior as WinDivert)

**Linux headers:** <linux/ip.h>, <linux/ipv6.h>, <linux/tcp.h>, <linux/udp.h>
**Note:** Linux kernel structs use native-endian bit-fields — including
these headers is enough to cast directly in userspace.

---

## 11. Linux Port of proctrack.c

Of the existing 884 lines, ~40% change and ~60% (uthash map, whitelist
load, match_exe, normalize, hot-reload watcher) are preserved.

### 11.1 Unchanged parts (platform-independent)

- fill_key, proc_map_lookup/set/del/clear/count_targets (uthash)
- whitelist_load, whitelist_add, trim
- match_exe (basename matching — only \\ → / changes)
- normalize_lower (on Linux / → / stays, only lowercase)
- proctrack_reload (hot-reload logic — GetFileAttributesExA instead of stat())
- watcher_thread_proc (Sleep(2000) → nanosleep(2s))
- proctrack_is_target 4-level fallback structure AS-IS

### 11.2 Changed parts

| Windows function | Linux counterpart | Lines |
|--------------------|-----------------|-------|
| match_pid (OpenProcess + QueryFullProcessImageNameW + WideCharToMultiByte) | readlink("/proc/<pid>/exe", buf) → normalize_lower → match_exe | ~10 lines (30 on Windows) |
| seed_tcp_v4/v6 (GetExtendedTcpTable) | /proc/net/tcp + /proc/net/tcp6 parse → 5-tuple + inode → inode_to_pid_cached → match_pid → proc_map_set | ~80 lines |
| seed_udp_v4/v6 (GetExtendedUdpTable) | /proc/net/udp + /proc/net/udp6 parse (local-only, remote=0) | ~50 lines |
| flow_thread_proc (WinDivert FLOW layer) | REMOVED — no FLOW layer on Linux | — |
| proctrack_start/stop_flow_thread | no-op (pio_flow_start/stop is also no-op) | — |
| resolve_pid_from_tcp_os (GetExtendedTcpTable) | sockdiag_lookup_inode(5-tuple) → inode_to_pid_cached(inode) → match_pid → proc_map_set | ~40 lines |
| CRITICAL_SECTION proc_lock | pthread_mutex_t proc_lock | ~20 places |
| CreateThread / WaitForSingleObject / CloseHandle | pthread_create / pthread_join / (no HANDLE) | watcher thread |
| GetFileAttributesExA (mtime) | stat() + st_mtim.tv_sec | watcher + whitelist_load |
| Sleep(2000) | nanosleep({2,0}) | watcher |
| volatile LONG flow_stop/watcher_stop | _Atomic int or volatile sig_atomic_t | — |

### 11.3 NEW: inode → PID cache (thread)

On Windows the WinDivert FLOW layer reports (5-tuple, PID) from the
kernel for each new connection. On Linux, instead:

1. **inode_pid_cache thread** (every 2-5 s): scan /proc/*/fd/* →
   fill the inode → pid hashmap (uthash). Protected with pthread_rwlock_t
   (reader: hot path, writer: refresh thread).

2. **proctrack_is_target OS fallback (method=2):** cache miss →
   sockdiag_lookup_inode(5-tuple) (single netlink query, ~0.1ms) →
   inode_to_pid_cached(inode) (O(1) hashmap) → match_pid →
   proc_map_set (now method=0).

3. **Seed:** a single read of /proc/net/tcp → all 5-tuples + inodes →
   the inode→PID cache is also built for the first time at the same time.

```
proctrack_is_target() flow (Linux):
  (1) proc_map_lookup → hit? return (method=0)
  (2) UDP? proc_map_lookup(remote=0) → hit? return (method=1)
  (3) TCP? sockdiag_lookup_inode(5-tuple) → inode
         → inode_to_pid_cached(inode) → pid
         → match_pid(pid) → is_target
         → proc_map_set(...) → return (method=2)
  (4) unknown → return 0 (method=3, safe default)
```

### 11.4 Linux counterpart of match_pid

```c
static int match_pid(pid_t pid)
{
    if (pid <= 0) return 0;
    char link[64], exe[PATH_MAX];
    snprintf(link, sizeof link, "/proc/%lu/exe", (unsigned long)pid);
    ssize_t n = readlink(link, exe, sizeof exe - 1);
    if (n <= 0) return 0;
    exe[n] = 0;
    normalize_lower(exe);  /* on Linux / stays /, lowercase only */
    return match_exe(exe);
}
```

**Caution:** on Linux, normalize_lower MUST NOT do the / → \\ conversion.
When match_exe looks for the basename, strrchr(path, '\\') → strrchr(path, '/').

---

## 12. sock_diag (NETLINK_INET_DIAG) API

### 12.1 Opening the socket

```c
#include <linux/netlink.h>
#include <linux/sock_diag.h>   /* SOCK_DIAG_BY_FAMILY = 20 */
#include <linux/inet_diag.h>   /* inet_diag_req_v2, inet_diag_msg */

int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_INET_DIAG);
```

NETLINK_INET_DIAG needs Linux 2.6.14+. Practical minimum ~2.6.27 (SOCK_CLOEXEC).

### 12.2 Request structs

```c
/* Socket identity — 5-tuple. All fields in NETWORK byte order. */
struct inet_diag_sockid {
    __be16  idiag_sport;          /* local port  (network order) */
    __be16  idiag_dport;          /* remote port (network order) */
    __be32  idiag_src[4];         /* local addr; IPv4 uses [0], [1..3]=0 */
    __be32  idiag_dst[4];         /* remote addr */
    __u32   idiag_if;             /* interface index; 0 = any */
    __u32   idiag_cookie[2];      /* INET_DIAG_NOCOOKIE = ~0U */
};

struct inet_diag_req_v2 {
    __u8    sdiag_family;         /* AF_INET / AF_INET6 */
    __u8    sdiag_protocol;       /* IPPROTO_TCP / IPPROTO_UDP */
    __u8    idiag_ext;            /* extra info bitmask */
    __u8    pad;
    __u32   idiag_states;         /* socket state bitmask */
    struct inet_diag_sockid id;   /* in a single query = which socket */
};

/* Reply struct */
struct inet_diag_msg {
    __u8    idiag_family;
    __u8    idiag_state;
    __u8    idiag_timer;
    __u8    idiag_retrans;
    struct inet_diag_sockid id;
    __u32   idiag_expires;
    __u32   idiag_rqueue;
    __u32   idiag_wqueue;
    __u32   idiag_uid;
    __u32   idiag_inode;          /* THE FIELD WE ARE AFTER */
};
```

**Critical:** inet_diag_msg gives idiag_inode and idiag_uid BUT NO PID.
The kernel keeps no notion of a socket's "owning PID" — for inode → PID a
/proc/<pid>/fd/* scan is mandatory.

### 12.3 Single socket query (5-tuple → inode)

```c
static int sockdiag_lookup_inode(int fd, uint8_t proto, int is_ipv6,
                                 const uint32_t local[4],  uint16_t local_port,
                                 const uint32_t remote[4], uint16_t remote_port,
                                 uint32_t *inode_out)
{
    struct { struct nlmsghdr nlh; struct inet_diag_req_v2 req; } req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len   = sizeof(req);
    req.nlh.nlmsg_type  = SOCK_DIAG_BY_FAMILY;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;  /* NO NLM_F_DUMP = get_exact */
    req.nlh.nlmsg_seq   = 1;
    req.nlh.nlmsg_pid   = 0;

    req.req.sdiag_family   = is_ipv6 ? AF_INET6 : AF_INET;
    req.req.sdiag_protocol = proto;
    req.req.idiag_states   = (1u << TCP_ESTABLISHED) | (1u << TCP_SYN_SENT) |
                             (1u << TCP_LISTEN);
    req.req.id.idiag_sport = htons(local_port);
    req.req.id.idiag_dport = htons(remote_port);
    if (!is_ipv6) {
        req.req.id.idiag_src[0] = htonl(local[0]);
        req.req.id.idiag_dst[0] = htonl(remote[0]);
    } else {
        for (int i = 0; i < 4; i++) {
            req.req.id.idiag_src[i] = htonl(local[i]);
            req.req.id.idiag_dst[i] = htonl(remote[i]);
        }
    }
    req.req.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    req.req.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;

    /* send + receive reply + parse inet_diag_msg → idiag_inode */
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    /* sendmsg(...) + recvmsg(...) + NLMSG_OK loop */
    /* reply: NLMSG_ERROR → ENOENT (no such socket); SOCK_DIAG_BY_FAMILY → idiag_inode */
}
```

### 12.4 Dump (list) mode — for seeding

If you set NLM_F_REQUEST | NLM_F_DUMP the kernel returns every socket as a
multipart message. id is left empty (all zeros), state filtering via idiag_states.
A single netlink stream yields every TCP socket + its inode.

### 12.5 sock_diag vs /proc/net/tcp speed

| Metric | sock_diag (netlink) | /proc/net/tcp |
|-------|---------------------|---------------|
| Single lookup speed | ~1 netlink round-trip (kernel hash) | File read + parse every line (O(N_sockets)) |
| Bulk (seed) speed | One dump stream, binary | One file read, text parse |
| Memory | Request buffer (~8KB) | Whole file contents, transiently |
| Complexity | High (netlink format, multipart, byte-order) | Medium (text parse, hex byte-order traps) |
| Min. kernel | NETLINK_INET_DIAG 2.6.14+ | /proc/net/tcp on every Linux |
| inode→PID | SAME — both give an inode; a /proc fd scan is still needed for the PID | Same |

**Choice:**
- Seed: /proc/net/tcp + /proc/net/udp (simple, present on every Linux)
- Hot-path OS fallback: sock_diag single-query (speed)
- Fallback: /proc/net/tcp if sock_diag fails (layered safety)

---

## 13. /proc/net/tcp + inode → PID

### 13.1 /proc/net/tcp column layout

```
46: 010310AC:9C4C 030310AC:1770 01
|      |      |      |      |   |--> st (state)
|      |      |      |      |------> remote port
|      |      |      |-------------> remote IPv4 addr (hex)
|      |      |--------------------> local port
|      |---------------------------> local IPv4 addr (hex)
|----------------------------------> sl (entry number)

00000150:00000000 01:00000019 00000000
1000        0 54165785 4 cd1e6040 25 4 27 3 -1
|          |    |     |
|          |    |     |--> ref count
|          |    |--> INODE (column 9, 0-based)
|          |--> timeout
|--> uid
```

**Byte-order traps:**
- Address: printed as a network-order 32-bit value with %08X. The hex string shows
  the 4 octets in network order (big-endian). Conversion: `val = strtoul(hex, NULL, 16);
  addr = htonl(val);`
- Port: the kernel applies ntohs and prints %04X → the hex is already HOST order.
  `port = strtoul(hex, NULL, 16);` — no ntohs needed.

State codes: 01=ESTABLISHED, 02=SYN_SENT, 03=SYN_RECV, 04=FIN_WAIT1,
05=FIN_WAIT2, 06=TIME_WAIT, 07=CLOSE, 08=CLOSE_WAIT, 09=LAST_ACK,
0A=LISTEN, 0B=CLOSING.

### 13.2 inode → PID cache strategy

```c
typedef struct ino_pid {
    uint32_t inode;
    pid_t    pid;
    UT_hash_handle hh;
} ino_pid_t;

static ino_pid_t *ino_map = NULL;   /* guarded by pthread_rwlock_t */

/* Scan all of /proc, rebuild the hashmap. Called from the periodic thread. */
static void refresh_inode_pid_map(void)
{
    ino_pid_t *fresh = NULL, *rec, *tmp;
    DIR *proc = opendir("/proc");
    if (!proc) return;
    struct dirent *e;
    while ((e = readdir(proc)) != NULL) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char fdpath[64]; snprintf(fdpath, sizeof(fdpath), "/proc/%s/fd", e->d_name);
        DIR *fdd = opendir(fdpath); if (!fdd) continue;
        pid_t pid = (pid_t)atoi(e->d_name);
        struct dirent *f; char link[80], target[64];
        while ((f = readdir(fdd)) != NULL) {
            snprintf(link, sizeof(link), "%s/%s", fdpath, f->d_name);
            ssize_t rl = readlink(link, target, sizeof(target)-1);
            if (rl <= 0) continue; target[rl] = 0;
            uint32_t ino;
            if (sscanf(target, "socket:[%u]", &ino) == 1) {
                HASH_FIND_INT(fresh, &ino, rec);
                if (!rec) {
                    rec = malloc(sizeof(*rec));
                    rec->inode = ino; rec->pid = pid;
                    HASH_ADD_INT(fresh, inode, rec);
                }
            }
        }
        closedir(fdd);
    }
    closedir(proc);
    /* atomic swap */
    pthread_rwlock_wrlock(&ino_lock);
    ino_pid_t *old = ino_map; ino_map = fresh;
    pthread_rwlock_unlock(&ino_lock);
    HASH_ITER(hh, old, rec, tmp) { HASH_DEL(old, rec); free(rec); }
}

/* Fast lookup — called from the packet hot path, under rdlock. */
static pid_t inode_to_pid_cached(uint32_t inode)
{
    ino_pid_t *rec;
    pthread_rwlock_rdlock(&ino_lock);
    HASH_FIND_INT(ino_map, &inode, rec);
    pid_t pid = rec ? rec->pid : 0;
    pthread_rwlock_unlock(&ino_lock);
    return pid;
}
```

Refresh: a separate thread calls refresh_inode_pid_map() every 2-5 s.
This reduces the inode→PID step to an O(1) hashmap lookup per packet.

Cost: O(N_procs × avg_fds). On a busy system (500 processes × 50 fds = 25000
readlinks) a full scan takes a few ms. That many syscalls per packet is IMPOSSIBLE
— which is why the cache is mandatory.

### 13.3 For UDP: the local-only lookup pattern

/proc/net/udp carries NO remote address (the same limitation as Windows
GetExtendedUdpTable). For unconnected UDP sockets remote = 00000000:0000.

proctrack_is_target's UDP local-fallback pattern is preserved VERBATIM:
```c
if (proto == IPPROTO_UDP) {
    uint32_t zero[4] = {0,0,0,0};
    r = proc_map_lookup(proto, is_ipv6, local, local_port, zero, 0);
    if (r >= 0) { proctrack_last_method = 1; return r; }
}
```

During seeding /proc/net/udp is scanned and every entry is added with
proc_map_set(IPPROTO_UDP, ..., local, lp, zero, 0, is_target) (remote=0).

---

## 14. linux/goodbyedpi.c — Copy + Modify

src/goodbyedpi.c is copied, then modified. The main loop is refactored to
use pio_recv/pio_send. There is no #ifdef _WIN32 — linux/goodbyedpi.c is
Linux ONLY.

| Current (Windows) | Linux port |
|------------------|------------|
| WinDivertRecv(w_filter, ...) | pio_recv(&ctx) |
| WinDivertHelperParsePacket(...) | parse_packet(ctx.data, ctx.len, ...) |
| WinDivertHelperCalcChecksums(...) | calc_checksums(ctx.data, ctx.len) (checksum.c) |
| WinDivertSend(w_filter, pkt, len, NULL, &addr) | pio_send(&ctx, VERDICT_MODIFY/PASS/DROP) |
| service_register() (SCM) | REMOVED — no service.c; a systemd .service instead |
| SetDllDirectory / SetSearchPathMode | REMOVED (Windows-only) |
| rand_s() | getrandom() |
| GetLastError() / FormatMessage | errno / strerror |

**The bypass logic (Stage 5-7) IS UNTOUCHED:** SNI extraction, Host
manipulation, native fragment, fake packet triggering, DNS redirect,
TTL conntrack — all of it operates on the raw buffer, through pio_* and
checksum.*.

**The GATE (proctrack) IS UNTOUCHED:** the proctrack_is_target() call stays in
the same place (after Stage 4), with the same logic. The DNS exemption
(!(ppUdpHdr && DNS redirect)) is unchanged.

---

## 15. linux/Makefile (NEW)

linux/Makefile is entirely separate — src/Makefile is untouched. There is no
`ifndef OS`; this Makefile is Linux ONLY.

```makefile
# linux/Makefile — DPIGate Linux port
TARGET = goodbyedpi
CC = gcc
CFLAGS = -std=c99 -O2 -Wall -Wextra -Wpedantic -fPIE -pie \
         -D_FORTIFY_SOURCE=2 -fstack-protector
LIBS = -lnetfilter_queue -lnfnetlink -lmnl -lpthread -ldl

# C files to compile (the ones inside linux/)
SRCS = goodbyedpi.c proctrack.c packet_io_linux.c checksum.c \
       rawsend_linux.c sockdiag.c \
       fakepackets.c dnsredir.c ttltrack.c blackwhitelist.c \
       utils/repl_str.c utils/getline.c
OBJS = $(SRCS:.c=.o)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

__omp_magic("", ".o: %.c")
	$(CC) $(CFLAGS) -c $< -o $@

# Drift detection (Section 4.1)
SYNC_FILES = fakepackets.c fakepackets.h dnsredir.c dnsredir.h \
              ttltrack.c ttltrack.h blackwhitelist.c blackwhitelist.h \
              utils/uthash.h utils/repl_str.c utils/repl_str.h \
              utils/getline.c utils/getline.h

check-sync:
	@./scripts/check-sync.sh

sync:
	@./scripts/sync-from-src.sh

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: check-sync sync clean
```

**Note:** `make check-sync` is not tied to the build; the developer invokes it
by hand. In the CI pipeline it runs automatically.

**Dependencies (Linux):**
- Arch: `pacman -S libnetfilter_queue`
- Ubuntu/Debian: `apt install libnetfilter-queue-dev libnfnetlink-dev libmnl-dev`
- Fedora: `dnf install libnetfilter_queue-devel`

---

## 16. nftables Rules (goodbyedpi.nft)

```nft
# /etc/nftables.d/99-goodbyedpi.nft

table inet goodbyedpi {
    chain postrouting {
        type filter hook output priority mangle + 10; policy accept;

        # 1) Bypass fake packets (fwmark 0x40000000)
        mark 0x40000000/0x40000000 accept

        # 2) TCP 80 + 443 outbound → NFQUEUE
        tcp dport { 80, 443 } counter queue num 200 bypass

        # 3) UDP 53 outbound → NFQUEUE (for DNS redirect)
        udp dport 53 counter queue num 200 bypass

        # 4) QUIC block (udp 443, payload >= 1200, initial pattern)
        udp dport 443 meta length >= 1200 counter drop
    }
}
```

install.sh drops this into /etc/nftables.d/ and loads it with nft -f.
uninstall.sh removes it. Existing nftables rules are untouched (separate table).

---

## 17. start.sh (NEW — the start.ps1 counterpart)

```bash
#!/bin/bash
# start.sh — DNS auto-detect + start goodbyedpi + spawn tray + exit

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/goodbyedpi-sel"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/goodbyedpi-sel"
PID_FILE="$DATA_DIR/goodbyedpi.pid"
PROGRAMS_LIST="$CONFIG_DIR/programs.txt"

# Config
BYPASS_MODE="--auto-ttl --max-payload"
NFQUEUE_NUM=200
FWMARK=0x40000000

# 1) Kill any running goodbyedpi
pkill -f "goodbyedpi.*--qnum $NFQUEUE_NUM" 2>/dev/null || true

# 2) DNS auto-detect
DNS_ADDR=$(python3 "$APP_DIR/dns_detect.py" 2>/dev/null || echo "77.88.8.8")
DNS_PORT=1253

# 3) Load nftables rules
nft -f "$APP_DIR/goodbyedpi.nft" 2>/dev/null || true

# 4) Start goodbyedpi (background, needs root)
sudo "$APP_DIR/goodbyedpi" \
    --dns-addr "$DNS_ADDR" --dns-port "$DNS_PORT" \
    --qnum $NFQUEUE_NUM \
    $BYPASS_MODE \
    --only-programs "$PROGRAMS_LIST" &
GDPI_PID=$!
echo "$GDPI_PID" > "$PID_FILE"
disown $GDPI_PID

# 5) Spawn the tray (user space)
nohup python3 "$APP_DIR/tray.py" >/dev/null 2>&1 &

# 6) Exit — the terminal closes, goodbyedpi + tray stay in separate processes
```

---

## 18. tray.py (NEW — GTK AyatanaAppIndicator)

### 18.1 Tray on modern Linux — which approach actually works?

| Approach | GNOME 43+ | KDE Plasma 6 | MATE/Cinnamon/LXQt/XFCE | Note |
|--------|-----------|--------------|--------------------------|-----|
| Gtk.StatusIcon | NO (deprecated) | NO | partial | Do not use |
| AppIndicator3 (Unity legacy) | needs extension | native | native | Legacy |
| AyatanaAppIndicator3 (Ayatana fork) | needs extension | native | native | MODERN STANDARD |
| DBus StatusNotifierItem directly | needs extension | native | native | Low level |

**Choice:** AyatanaAppIndicator3 (fallback: AppIndicator3)
- Native on Ubuntu/Debian/MATE/Cinnamon/KDE
- On GNOME 43+ the user is asked to install the "AppIndicator and
  KStatusNotifierItem Support" extension (ID 615)

**Packages:**
- Debian/Ubuntu: gir1.2-ayatanaappindicator3-0.1, python3-gi, python3-gi-cairo
- Arch: libayatana-appindicator, python-gobject

### 18.2 API summary

```python
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib

try:
    gi.require_version("AyatanaAppIndicator3", "0.1")
    from gi.repository import AyatanaAppIndicator3 as AppIndicator
except (ImportError, ValueError):
    gi.require_version("AppIndicator3", "0.1")
    from gi.repository import AppIndicator3 as AppIndicator

# Create the indicator
ind = AppIndicator.Indicator.new(
    "goodbyedpi-sel",
    "goodbyedpi-on",
    AppIndicator.IndicatorCategory.APPLICATION_STATUS,
)
ind.set_title("DPIGate")
ind.set_status(AppIndicator.IndicatorStatus.ACTIVE)
ind.set_menu(Gtk.Menu())
```

### 18.3 Menu structure

- **DNS dropdown:** Gtk.MenuItem + set_submenu(Gtk.Menu) +
  Gtk.RadioMenuItem.new_with_label(group, label). 5 servers + auto-detect.
  On the "activate" signal check widget.get_active() (it emits in both states).
- **"Edit programs.txt":** subprocess.Popen(["xdg-open", path])
- **"Auto Start" toggle:** Gtk.CheckMenuItem + state read via systemctl --user
  is-enabled. Toggle: enable --now / disable --now
- **"Exit":** os.kill(pid, SIGTERM) + Gtk.main_quit()

### 18.4 Crash detection

GLib.timeout_add_seconds(2, check_alive) + os.kill(pid, 0).
Do NOT use a Timer or a thread — GTK demands thread safety.
GLib.timeout runs thread-safely on the main loop.

### 18.5 IPC

A PID file (~/.local/share/goodbyedpi-sel/goodbyedpi.pid) — the simplest option.
In systemd-managed mode systemctl --user is-active is more reliable.

### 18.6 Changing the DNS

Kill goodbyedpi with SIGTERM, then call start.sh with the new DNS argument.
Kill the old tray processes (pkill -f tray.py).

---

## 19. goodbyedpi.service (systemd user unit)

```ini
[Unit]
Description=DPIGate
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart = __omp_magic("", "h/.local/share/goodbyedpi-sel/start.sh")
ExecStopPost=/bin/bash -c 'pkill -f "goodbyedpi.*--qnum 200"'
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

**Note:** goodbyedpi needs root (NFQUEUE + raw socket). Two options:
1. systemd system service (User=root) — /etc/systemd/system/
2. setcap cap_net_raw,cap_net_admin+ep goodbyedpi — user-level service

install.sh offers both options.

---

## 20. install.sh / uninstall.sh

### 20.1 install.sh

1. Dependencies: apt install libnetfilter-queue-dev / pacman -S libnetfilter_queue
2. Build the binary: make (Linux target)
3. Copy the files:
   - ~/.local/share/goodbyedpi-sel/ (binary + start.sh + tray.py + dns_detect.py + icon.png + goodbyedpi.nft)
   - ~/.config/goodbyedpi-sel/ (programs.txt)
4. Load the nftables rule: /etc/nftables.d/99-goodbyedpi.nft
5. Copy the systemd user unit: ~/.config/systemd/user/goodbyedpi.service (does NOT enable it — that is done from the tray menu)
6. capabilities: sudo setcap cap_net_raw,cap_net_admin+ep goodbyedpi (to run without root)
7. GNOME extension check: is gnome-shell-extension-appindicator installed? If not, print instructions.
8. Notify with notify-send or zenity instead of a MessageBox

### 20.2 uninstall.sh

1. systemd service stop + disable
2. Remove the nftables rule
3. Delete the files (~/.local/share/goodbyedpi-sel/, ~/.config/goodbyedpi-sel/,
   ~/.config/systemd/user/goodbyedpi.service)
4. Kill the goodbyedpi + tray processes

---

## 21. programs.txt (Linux executable names)

```
# Browsers
chrome, chromium, firefox, opera, brave, vivaldi, epiphany
# Discord
discord, Vesktop, telegram-desktop
```

There is no .exe on Linux — match_exe's basename matching comes from the
readlink result of proc/<pid>/exe.

---

## 22. Test Strategy

| Test | Method |
|------|--------|
| proctrack unit test | pt_test.c Linux port: /proc/net/tcp parse + inode cache + match_pid |
| NFQUEUE smoke test | Minimal program: take a packet from NFQUEUE, pass it through, verify it went back out via the kernel |
| Checksum test | Known packet + expected checksum values (RFC 1071 examples) |
| Fake packet test | Gate log via --debug-proc (must work on Linux too) + confirm with tcpdump that the fake went out over the raw socket |
| Bypass test | goodbyedpi OFF → Discord times out (SNI block). goodbyedpi ON → HTTP 200 (curl) + Discord works in the browser |
| Per-program test | 256 BLOCK / 2 PASS pattern via --debug-proc (same as Windows) |
| Hot-reload test | Change programs.txt → within 2s the [proctrack] watcher: mtime changed, reloading... log line |
| Tray test | Tray icon appears, DNS dropdown works, the Auto Start toggle enables/disables the systemd service |

---

## 23. Effort Estimate (Phases)

| Phase | Contents | Estimate |
|-----|--------|--------------|
| 0. Skeleton | linux/ directory + bypass copies + .sync-checksums + Makefile skeleton | 1 day |
| 1. Packet I/O | packet_io.h + packet_io_linux.c (NFQUEUE) | 1-2 weeks |
| 2. Checksum + parse | checksum.c/.h — RFC 1071 + pseudo-header + parse | 3-5 days |
| 3. Raw socket + fwmark | rawsend_linux.c — sending fake packets + conntrack bypass | 3-5 days |
| 4. proctrack port | sock_diag + inode cache + seed + match_pid Linux | 1 week |
| 5. goodbyedpi.c port | Copy + switch to the pio_* API + drop the Windows headers | 1 week |
| 6. nftables rules | Filter string → nftables rules + install.sh | 3-5 days |
| 7. Tray + start.sh | Python/GTK tray + bash start script + DNS auto-detect | 1 week |
| 8. systemd + install/uninstall | systemd unit + install.sh + uninstall.sh | 3-5 days |
| 9. Test + debugging | Full test matrix + verification on a real ISP | 1-2 weeks |
| **Total** | | **~5-7 weeks** |

---

## 24. Risk Analysis

| Risk | Likelihood | Impact | Mitigation |
|------|----------|------|------------|
| Fake packet clashes with conntrack (kernel RST) | Medium | High | fwmark + nftables NOTRACK + tcp_be_liberal=1 (proven by zapret) |
| sock_diag kernel compatibility (old kernels) | Low | Medium | Fallback: /proc/net/tcp parse (present on every Linux) |
| GNOME extension requirement | Medium | Low | Check + instructions in install.sh; native on KDE/MATE |
| nftables clashing with existing rules | Low | Medium | Separate table inet goodbyedpi (leaves existing ones alone) |
| Root requirement (NFQUEUE + raw socket) | High | Medium | setcap cap_net_raw,cap_net_admin or a systemd system service |

---

## 25. Architecture Recap (after the Linux port)

```
nftables (kernel-space)
  ↓ tcp dport {80,443} → NFQUEUE num 200
  ↓ udp dport 53 → NFQUEUE num 200 (DNS redirect)
  ↓ mark 0x40000000 → accept (bypass fake packets)
  ↓ udp dport 443 length>=1200 → drop (QUIC block)
  │
NFQUEUE userspace (packet_io_linux.c)
  ↓ recv(nfq_fd) → nfq_handle_packet → callback
  ↓ nfq_get_payload(&data) → in-place pointer
  ↓ nfq_get_nfmark → fake detection (mark & 0x40000000 → PASS)
  │
linux/goodbyedpi.c main loop (pio_recv/pio_send)
  ↓ pio_recv → packet_ctx_t
  ↓ parse_packet (checksum.c) → ip/tcp/udp header pointers
  ↓ GATE (per-program):
  │   if do_only_programs && (TCP||UDP) && !(UDP && DNS redirect):
  │     extract 5-tuple → proctrack_is_target()
  │       → proc_map_lookup (hashmap)
  │       → UDP: local-only lookup (remote=0)
  │       → TCP: sockdiag_lookup_inode(5-tuple) → inode_to_pid_cached → match_pid
  │     false → pio_send(PASS) (no bypass) + continue
  │     true  → go on (bypass will be applied)
  ↓ Stage 5: TCP data bypass (fragment, fake packet, SNI, Host)
  │   fake packet → rawsend_linux.c → sendto(raw_sock, SO_MARK=0x40000000)
  ↓ Stage 6: TCP no-data (TTL, window)
  ↓ Stage 7: UDP DNS redirect (when DNS redirect is on, exempt from the gate)
  ↓ pio_send(MODIFY/PASS/DROP) → nfq_set_verdict2

Separate thread: inode_pid_cache (2-5s poll)
  scan /proc/*/fd/* → inode → pid hashmap (uthash)
  guarded by pthread_rwlock_t

Separate thread: Watcher (hot-reload)
  2s poll → stat() → if st_mtim changed
  → proctrack_reload(): whitelist swap + clear map + re-seed

Separate process: tray.py (Python/GTK)
  AyatanaAppIndicator3 + Gtk.Menu
  DNS dropdown, Edit programs.txt, Auto Start toggle, Exit
  GLib.timeout_add_seconds(2) → goodbyedpi PID check
  PID file: ~/.local/share/goodbyedpi-sel/goodbyedpi.pid

Separate process: systemd user service (optional — Auto Start)
  goodbyedpi.service — ExecStart=start.sh
  systemctl --user enable/disable --now
```

---

## 26. Important Notes

- **Project name:** DPIGate (Linux port)
- **GitHub:** github.com/MSelmanSonmez/DPIGate
- **License:** Apache-2.0 (fork of ValdikSS/GoodbyeDPI)
- **Approach:** (c) Port the existing C code — NFQUEUE + sock_diag
- **WinDivert → NFQUEUE:** zapret (15.8k stars) has proven this for years
- **FLOW layer → sock_diag + inode cache:** there is no exact equivalent on Linux,
  but a lazy first-packet lookup + map cache is enough
- **Per-program filtering:** UNIQUE in the Linux world — no Linux DPI
  tool offers it
- **Bypass logic:** platform-independent (raw buffer) — untouched
- **Target distributions:** Ubuntu/Debian, Arch/Fedora
- **Priority features:** Per-program, DNS redirect+auto-detect, Tray, Auto Start
- **Dependencies:** libnetfilter_queue, libnfnetlink, libmnl, pthread, python3-gi,
  gir1.2-ayatanaappindicator3-0.1, nftables
- **Root requirement:** NFQUEUE + raw socket — setcap or a systemd system service
- **GNOME:** needs the AppIndicator extension (ID 615) — instructions in install.sh
- **KDE/MATE/Cinnamon/XFCE:** AyatanaAppIndicator is native
- **fwmark:** 0x40000000 (same as zapret)
- **nftables:** Separate table inet goodbyedpi (leaves existing rules alone)
- **Effort:** ~5-7 weeks (single developer)
- **This file is the Linux port plan** (the Windows port status used to live in STATUS.md, removed in the repo cleanup)
- **Current Windows port:** working (v1.2.0, rev 14) — src/ IS UNTOUCHED.
  The Linux port lives in a separate linux/ directory — zero build coupling, it
  cannot break Windows. Drift check: make check-sync (Section 4.1).

---

## 27. Source References

- **zapret (bol-van/zapret):** github.com/bol-van/zapret — the NFQUEUE + raw socket
  pattern. nfqws.c, darkmagic.c, desync.c, conntrack.c were studied.
- **byedpi (hufrea/byedpi):** github.com/hufrea/byedpi — SOCKS proxy alternative
- **RFC 1071:** Internet Checksum algorithm
- **RFC 8200:** IPv6 pseudo-header format
- **Linux kernel UAPI:** linux/ip.h, linux/ipv6.h, linux/tcp.h, linux/udp.h,
  linux/netlink.h, linux/sock_diag.h, linux/inet_diag.h
- **man 7 sock_diag:** inet_diag_req_v2, inet_diag_sockid, inet_diag_msg
- **man 7 netlink:** nlmsghdr, NLMSG_* macros
- **Kernel documentation:** Documentation/networking/proc_net_tcp.rst
- **AyatanaAppIndicator3:** lazka.github.io/pgi-docs — Indicator API
- **GNOME extension:** gnome-shell-extension-appindicator (ID 615)
- **indicator-sound-switcher:** yktoo/indicator-sound-switcher — Python tray example
- **Arch Wiki:** Desktop entries, xdg-open, autostart

---

## 28. Development Order (Recommended)

0. **Phase 0:** create the linux/ directory + copy the bypass files + .sync-checksums + check-sync/sync scripts + Makefile skeleton

1. **Phase 1:** packet_io.h + packet_io_linux.c (NFQUEUE) — smoke test
2. **Phase 2:** checksum.c/.h — RFC 1071 test
3. **Phase 3:** rawsend_linux.c — fake packet tcpdump test
4. **Phase 4:** proctrack.c port — pt_test.c Linux
5. **Phase 5:** goodbyedpi.c refactor — switch to the pio_* API
6. **Phase 6:** nftables rules + install.sh
7. **Phase 7:** tray.py + start.sh + dns_detect.py
8. **Phase 8:** goodbyedpi.service + install.sh/uninstall.sh
9. **Phase 9:** test + debugging on a real ISP

Test at the end of each phase, then move on to the next.
