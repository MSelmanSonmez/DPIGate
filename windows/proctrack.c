/*
 * proctrack.c — Per-program connection tracker for GoodbyeDPI.
 *
 * Maintains a 5-tuple -> is_target map so that DPI bypass tricks are applied
 * only to traffic owned by whitelisted processes (e.g. browsers).
 *
 * The map is fed by:
 *   - proctrack_seed():           snapshot of already-open sockets at startup
 *   - FLOW layer thread:          live (5-tuple, PID) notifications from WinDivert
 *
 * Queried by the main NETWORK loop via proctrack_is_target().
 * Safe default: unknown 5-tuple -> FALSE (packet left untouched, no bypass).
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <sys/stat.h>
#include <in6addr.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include "windivert.h"
#include "dnsredir.h"
#include "proctrack.h"
#include "utils/uthash.h"

/* WinDivert FLOW layer filter: capture every TCP/UDP flow. */
#define PROCTRACK_FLOW_FILTER "true"

/* key = marker('4'/'6') + local_addr[16] + remote_addr[16]
 *       + local_port[2] + remote_port[2] + proto[1]  = 38 bytes */
#define PROC_KEY_LEN 38

/* HACK: uthash uses strlen() for HASH_FIND_STR; our key has null bytes.
 * The key is always PROC_KEY_LEN long, so override strlen like ttltrack.c. */
#undef uthash_strlen
#define uthash_strlen(s) PROC_KEY_LEN

typedef struct proc_record {
    char key[PROC_KEY_LEN];
    uint8_t is_target;
    UT_hash_handle hh;
} proc_record_t;

typedef struct {
    char *pattern;   /* normalized: lowercased, '/' -> '\\' */
    int   is_path;   /* 1 if pattern contains '\\', else basename-exact */
} wl_entry_t;

static CRITICAL_SECTION proc_lock;
static int proc_lock_init = 0;
static proc_record_t *proc_map = NULL;

static wl_entry_t *whitelist = NULL;
static size_t whitelist_count = 0;
static size_t whitelist_cap = 0;

static HANDLE flow_handle = NULL;
static HANDLE flow_thread = NULL;
static volatile LONG flow_stop = 0;

int proctrack_last_method = 3;

/* Hot-reload: file watcher thread polls programs.txt mtime every 2s.
 * On change, atomically swaps whitelist + clears map + re-seeds. */
static char whitelist_file_path[MAX_PATH] = {0};
static HANDLE watcher_thread = NULL;
static volatile LONG watcher_stop = 0;
static time_t whitelist_last_mtime = 0;


/* ---------- key helpers ---------- */

inline static void fill_key(char *key, int is_ipv6, uint8_t proto,
                            const uint32_t local[4], uint16_t local_port,
                            const uint32_t remote[4], uint16_t remote_port)
{
    unsigned int off = 0;
    *(uint8_t *)(key + off) = is_ipv6 ? '6' : '4';
    off += 1;
    if (is_ipv6) {
        ipv6_copy_addr((uint32_t *)(key + off), local);
    } else {
        ipv4_copy_addr((uint32_t *)(key + off), local);
    }
    off += sizeof(uint32_t) * 4;
    if (is_ipv6) {
        ipv6_copy_addr((uint32_t *)(key + off), remote);
    } else {
        ipv4_copy_addr((uint32_t *)(key + off), remote);
    }
    off += sizeof(uint32_t) * 4;
    *(uint16_t *)(key + off) = local_port;  off += 2;
    *(uint16_t *)(key + off) = remote_port; off += 2;
    *(uint8_t  *)(key + off) = proto;
}

/* Returns is_target (0/1) or -1 if not found. */
static int proc_map_lookup(uint8_t proto, int is_ipv6,
                           const uint32_t local[4], uint16_t local_port,
                           const uint32_t remote[4], uint16_t remote_port)
{
    char key[PROC_KEY_LEN];
    proc_record_t *rec = NULL;
    int result = -1;

    fill_key(key, is_ipv6, proto, local, local_port, remote, remote_port);

    EnterCriticalSection(&proc_lock);
    HASH_FIND_STR(proc_map, key, rec);
    if (rec)
        result = (int)rec->is_target;
    LeaveCriticalSection(&proc_lock);
    return result;
}

static void proc_map_set(uint8_t proto, int is_ipv6,
                         const uint32_t local[4], uint16_t local_port,
                         const uint32_t remote[4], uint16_t remote_port,
                         uint8_t is_target)
{
    char key[PROC_KEY_LEN];
    proc_record_t *rec = NULL;

    fill_key(key, is_ipv6, proto, local, local_port, remote, remote_port);

    EnterCriticalSection(&proc_lock);
    HASH_FIND_STR(proc_map, key, rec);
    if (rec) {
        rec->is_target = is_target;
    } else {
        rec = (proc_record_t *)malloc(sizeof(*rec));
        if (!rec) {
            LeaveCriticalSection(&proc_lock);
            return;
        }
        memcpy(rec->key, key, PROC_KEY_LEN);
        rec->is_target = is_target;
        HASH_ADD_STR(proc_map, key, rec);
    }
    LeaveCriticalSection(&proc_lock);
}

static void proc_map_del(uint8_t proto, int is_ipv6,
                         const uint32_t local[4], uint16_t local_port,
                         const uint32_t remote[4], uint16_t remote_port)
{
    char key[PROC_KEY_LEN];
    proc_record_t *rec = NULL;

    fill_key(key, is_ipv6, proto, local, local_port, remote, remote_port);

    EnterCriticalSection(&proc_lock);
    HASH_FIND_STR(proc_map, key, rec);
    if (rec) {
        HASH_DEL(proc_map, rec);
        free(rec);
    }
    LeaveCriticalSection(&proc_lock);
}

static void proc_map_clear(void)
{
    proc_record_t *rec, *tmp;
    EnterCriticalSection(&proc_lock);
    HASH_ITER(hh, proc_map, rec, tmp) {
        HASH_DEL(proc_map, rec);
        free(rec);
    }
    proc_map = NULL;
    LeaveCriticalSection(&proc_lock);
}

/* Count map entries currently marked as targets. */
static int proc_map_count_targets(void)
{
    proc_record_t *rec, *tmp;
    int n = 0;
    EnterCriticalSection(&proc_lock);
    HASH_ITER(hh, proc_map, rec, tmp) {
        if (rec->is_target) n++;
    }
    LeaveCriticalSection(&proc_lock);
    return n;
}


/* ---------- whitelist loading & matching ---------- */

/* in-place: lowercase ASCII bytes, convert '/' to '\\'. */
static void normalize_lower(char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '/')
            *s = '\\';
        else if (c < 0x80)
            *s = (char)tolower(c);
    }
}

static char *trim(char *s)
{
    char *end;
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == 0) return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) { *end = 0; end--; }
    return s;
}

static int whitelist_add(char *line)
{
    char *p = trim(line);
    if (*p == 0 || *p == '#')
        return 0;

    normalize_lower(p);

    if (whitelist_count == whitelist_cap) {
        size_t ncap = whitelist_cap ? whitelist_cap * 2 : 16;
        wl_entry_t *na = (wl_entry_t *)realloc(whitelist, ncap * sizeof(*na));
        if (!na) return 0;
        whitelist = na;
        whitelist_cap = ncap;
    }

    {
        wl_entry_t *e = &whitelist[whitelist_count];
        e->pattern = _strdup(p);
        if (!e->pattern) return 0;
        e->is_path = (strchr(p, '\\') != NULL) ? 1 : 0;
        whitelist_count++;
    }
    return 1;
}

static int whitelist_load(const char *fname)
{
    FILE *fp = fopen(fname, "r");
    char buf[4096];
    int added = 0;
    if (!fp) return -1;

    while (fgets(buf, sizeof(buf), fp)) {
        if (whitelist_add(buf))
            added++;
    }
    fclose(fp);

    /* Record mtime so the watcher doesn't immediately reload. */
    {
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (GetFileAttributesExA(fname, GetFileExInfoStandard, &fad)) {
            ULARGE_INTEGER uli;
            uli.LowPart = fad.ftLastWriteTime.dwLowDateTime;
            uli.HighPart = fad.ftLastWriteTime.dwHighDateTime;
            whitelist_last_mtime = (time_t)(uli.QuadPart / 10000000ULL - 11644473600ULL);
        }
    }
    return added;
}

/* path: already normalized (lowercased, '\\' separators) */
static int match_exe(const char *path)
{
    size_t i;
    const char *base = strrchr(path, '\\');
    if (base) base++; else base = path;

    for (i = 0; i < whitelist_count; i++) {
        wl_entry_t *e = &whitelist[i];
        if (e->is_path) {
            if (strstr(path, e->pattern) != NULL)
                return 1;
        } else {
            if (strcmp(base, e->pattern) == 0)
                return 1;
        }
    }
    return 0;
}

static int match_pid(DWORD pid)
{
    HANDLE h;
    wchar_t wpath[1024];
    DWORD wlen = sizeof(wpath) / sizeof(wpath[0]);
    char path[2048];
    BOOL ok;
    int n;

    if (pid == 0 || pid == 4)  /* System / System(Idle) */
        return 0;

    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return 0;

    ok = QueryFullProcessImageNameW(h, 0, wpath, &wlen);
    CloseHandle(h);
    if (!ok || wlen == 0)
        return 0;

    n = WideCharToMultiByte(CP_UTF8, 0, wpath, (int)wlen,
                            path, (int)sizeof(path) - 1, NULL, NULL);
    if (n <= 0)
        return 0;
    path[n] = 0;

    normalize_lower(path);
    return match_exe(path);
}


/* ---------- seeding ---------- */

static uint16_t port_from_dword(DWORD dw)
{
    /* Owner-PID tables store the port in the low 16 bits, network byte order. */
    return ntohs((uint16_t)(dw & 0xFFFF));
}

static void seed_tcp_v4(void)
{
    DWORD size = 0;
    DWORD rc;
    MIB_TCPTABLE_OWNER_PID *t;
    DWORD i;

    rc = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                             TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
        return;
    t = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (!t) return;
    rc = GetExtendedTcpTable(t, &size, FALSE, AF_INET,
                             TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != NO_ERROR) { free(t); return; }

    for (i = 0; i < t->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *r = &t->table[i];
        uint32_t local[4], remote[4];
        uint16_t lp, rp;
        if (r->dwRemoteAddr == 0 && r->dwRemotePort == 0)
            continue;  /* listening socket, no remote -> skip */
        ipv4_copy_addr(local,  (uint32_t *)&r->dwLocalAddr);
        ipv4_copy_addr(remote, (uint32_t *)&r->dwRemoteAddr);
        lp = port_from_dword(r->dwLocalPort);
        rp = port_from_dword(r->dwRemotePort);
        proc_map_set(IPPROTO_TCP, 0, local, lp, remote, rp,
                     (uint8_t)match_pid(r->dwOwningPid));
    }
    free(t);
}

static void seed_tcp_v6(void)
{
    DWORD size = 0;
    DWORD rc;
    MIB_TCP6TABLE_OWNER_PID *t;
    DWORD i;

    rc = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6,
                             TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
        return;
    t = (MIB_TCP6TABLE_OWNER_PID *)malloc(size);
    if (!t) return;
    rc = GetExtendedTcpTable(t, &size, FALSE, AF_INET6,
                             TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != NO_ERROR) { free(t); return; }

    for (i = 0; i < t->dwNumEntries; i++) {
        MIB_TCP6ROW_OWNER_PID *r = &t->table[i];
        uint32_t local[4], remote[4];
        uint16_t lp, rp;
        /* skip all-zero remote (listening) */
        if (((uint32_t *)r->ucRemoteAddr)[0] == 0 &&
            ((uint32_t *)r->ucRemoteAddr)[1] == 0 &&
            ((uint32_t *)r->ucRemoteAddr)[2] == 0 &&
            ((uint32_t *)r->ucRemoteAddr)[3] == 0 &&
            r->dwRemotePort == 0)
            continue;
        ipv6_copy_addr(local,  (uint32_t *)r->ucLocalAddr);
        ipv6_copy_addr(remote, (uint32_t *)r->ucRemoteAddr);
        lp = port_from_dword(r->dwLocalPort);
        rp = port_from_dword(r->dwRemotePort);
        proc_map_set(IPPROTO_TCP, 1, local, lp, remote, rp,
                     (uint8_t)match_pid(r->dwOwningPid));
    }
    free(t);
}

static void seed_udp_v4(void)
{
    DWORD size = 0;
    DWORD rc;
    MIB_UDPTABLE_OWNER_PID *t;
    DWORD i;
    uint32_t zero[4] = {0, 0, 0, 0};

    rc = GetExtendedUdpTable(NULL, &size, FALSE, AF_INET,
                             UDP_TABLE_OWNER_PID, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
        return;
    t = (MIB_UDPTABLE_OWNER_PID *)malloc(size);
    if (!t) return;
    rc = GetExtendedUdpTable(t, &size, FALSE, AF_INET,
                             UDP_TABLE_OWNER_PID, 0);
    if (rc != NO_ERROR) { free(t); return; }

    for (i = 0; i < t->dwNumEntries; i++) {
        MIB_UDPROW_OWNER_PID *r = &t->table[i];
        uint32_t local[4];
        uint16_t lp;
        ipv4_copy_addr(local, (uint32_t *)&r->dwLocalAddr);
        lp = port_from_dword(r->dwLocalPort);
        /* UDP table has no remote; store a local-only entry (remote=0). */
        proc_map_set(IPPROTO_UDP, 0, local, lp, zero, 0,
                     (uint8_t)match_pid(r->dwOwningPid));
    }
    free(t);
}

static void seed_udp_v6(void)
{
    DWORD size = 0;
    DWORD rc;
    MIB_UDP6TABLE_OWNER_PID *t;
    DWORD i;
    uint32_t zero[4] = {0, 0, 0, 0};

    rc = GetExtendedUdpTable(NULL, &size, FALSE, AF_INET6,
                             UDP_TABLE_OWNER_PID, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
        return;
    t = (MIB_UDP6TABLE_OWNER_PID *)malloc(size);
    if (!t) return;
    rc = GetExtendedUdpTable(t, &size, FALSE, AF_INET6,
                             UDP_TABLE_OWNER_PID, 0);
    if (rc != NO_ERROR) { free(t); return; }

    for (i = 0; i < t->dwNumEntries; i++) {
        MIB_UDP6ROW_OWNER_PID *r = &t->table[i];
        uint32_t local[4];
        uint16_t lp;
        ipv6_copy_addr(local, (uint32_t *)r->ucLocalAddr);
        lp = port_from_dword(r->dwLocalPort);
        proc_map_set(IPPROTO_UDP, 1, local, lp, zero, 0,
                     (uint8_t)match_pid(r->dwOwningPid));
    }
    free(t);
}


/* ---------- FLOW thread ---------- */

static void flow_handle_event(const WINDIVERT_ADDRESS *addr)
{
    uint8_t proto = addr->Flow.Protocol;
    int is_ipv6 = addr->IPv6 ? 1 : 0;
    uint16_t lp = addr->Flow.LocalPort;   /* FLOW ports are host byte order */
    uint16_t rp = addr->Flow.RemotePort;
    uint32_t local[4], remote[4];

    if (is_ipv6) {
        ipv6_copy_addr(local,  addr->Flow.LocalAddr);
        ipv6_copy_addr(remote, addr->Flow.RemoteAddr);
    } else {
        ipv4_copy_addr(local,  addr->Flow.LocalAddr);
        ipv4_copy_addr(remote, addr->Flow.RemoteAddr);
    }

    if (addr->Event == WINDIVERT_EVENT_FLOW_ESTABLISHED) {
        uint8_t target = (uint8_t)match_pid(addr->Flow.ProcessId);
        proc_map_set(proto, is_ipv6, local, lp, remote, rp, target);
    } else if (addr->Event == WINDIVERT_EVENT_FLOW_DELETED) {
        proc_map_del(proto, is_ipv6, local, lp, remote, rp);
    }
}

static DWORD WINAPI flow_thread_proc(LPVOID arg __attribute__((unused)))
{
    WINDIVERT_ADDRESS addr;
    for (;;) {
        if (flow_stop)
            break;
        if (!WinDivertRecv(flow_handle, NULL, 0, NULL, &addr)) {
            if (!flow_stop)
                printf("[proctrack] FLOW recv error, thread exiting.\n");
            break;
        }
        flow_handle_event(&addr);
    }
    return 0;
}


/* ---------- public API ---------- */

int proctrack_init(const char *whitelist_file)
{
    int n;
    if (!proc_lock_init) {
        InitializeCriticalSection(&proc_lock);
        proc_lock_init = 1;
    }
    if (!whitelist_file)
        return 0;
    n = whitelist_load(whitelist_file);
    if (n < 0) {
        printf("[proctrack] ERROR: cannot open programs list '%s'\n",
               whitelist_file);
        return 0;
    }
    /* Save path for hot-reload. */
    strncpy(whitelist_file_path, whitelist_file, sizeof(whitelist_file_path) - 1);
    whitelist_file_path[sizeof(whitelist_file_path) - 1] = 0;
    printf("[proctrack] loaded %d program%s from '%s'\n",
           n, (n == 1 ? "" : "s"), whitelist_file);
    return 1;
}

int proctrack_seed(void)
{
    int before = 0;
    EnterCriticalSection(&proc_lock);
    before = HASH_COUNT(proc_map);
    LeaveCriticalSection(&proc_lock);

    seed_tcp_v4();
    seed_tcp_v6();
    seed_udp_v4();
    seed_udp_v6();

    {
        int after = 0;
        int targets = 0;
        EnterCriticalSection(&proc_lock);
        after = HASH_COUNT(proc_map);
        LeaveCriticalSection(&proc_lock);
        targets = proc_map_count_targets();
        printf("[proctrack] seeded %d existing connection%s (total map: %d, targets: %d)\n",
               after - before, (after - before == 1 ? "" : "s"), after, targets);
    }
    return 1;
}

int proctrack_start_flow_thread(HANDLE *flow_handle_out)
{
    if (!flow_handle) {
        flow_handle = WinDivertOpen(PROCTRACK_FLOW_FILTER,
                                    WINDIVERT_LAYER_FLOW, 0,
                                    WINDIVERT_FLAG_SNIFF |
                                    WINDIVERT_FLAG_RECV_ONLY);
        if (flow_handle == INVALID_HANDLE_VALUE) {
            DWORD e = GetLastError();
            printf("[proctrack] ERROR: WinDivertOpen(FLOW) failed: %lu\n",
                   (unsigned long)e);
            flow_handle = NULL;
            return 0;
        }
    }

    flow_stop = 0;
    flow_thread = CreateThread(NULL, 0, flow_thread_proc, NULL, 0, NULL);
    if (!flow_thread) {
        printf("[proctrack] ERROR: CreateThread failed: %lu\n",
               (unsigned long)GetLastError());
        WinDivertClose(flow_handle);
        flow_handle = NULL;
        return 0;
    }

    if (flow_handle_out)
        *flow_handle_out = flow_handle;
    printf("[proctrack] FLOW tracker started.\n");
    return 1;
}

void proctrack_stop_flow_thread(void)
{
    if (!flow_thread && !flow_handle)
        return;

    flow_stop = 1;
    if (flow_handle)
        WinDivertShutdown(flow_handle, WINDIVERT_SHUTDOWN_BOTH);

    if (flow_thread) {
        WaitForSingleObject(flow_thread, 3000);
        CloseHandle(flow_thread);
        flow_thread = NULL;
    }
    if (flow_handle) {
        WinDivertClose(flow_handle);
        flow_handle = NULL;
    }
}


/* ---------- hot-reload ---------- */

/* Atomically replace the whitelist and re-seed the map.
 * Called from the watcher thread when programs.txt changes.
 * Thread-safe: builds new whitelist outside lock, swaps under lock. */
static int proctrack_reload(void)
{
    wl_entry_t *old_wl;
    size_t old_count, old_cap;
    int n;

    /* Save old globals, point whitelist globals at fresh array. */
    old_wl = whitelist;
    old_count = whitelist_count;
    old_cap = whitelist_cap;
    whitelist = NULL;
    whitelist_count = 0;
    whitelist_cap = 0;

    n = whitelist_load(whitelist_file_path);
    if (n < 0) {
        /* Failed to reload — restore old whitelist. */
        printf("[proctrack] reload FAILED for '%s', keeping old list\n",
               whitelist_file_path);
        /* Free whatever partial new entries we added. */
        if (whitelist) {
            size_t i;
            for (i = 0; i < whitelist_count; i++)
                free(whitelist[i].pattern);
            free(whitelist);
        }
        whitelist = old_wl;
        whitelist_count = old_count;
        whitelist_cap = old_cap;
        return 0;
    }

    /* Swap done (globals already point to new list). Free old list. */
    if (old_wl) {
        size_t i;
        for (i = 0; i < old_count; i++)
            free(old_wl[i].pattern);
        free(old_wl);
    }

    /* Clear the 5-tuple map so all flows are re-evaluated against the
     * new whitelist (via FLOW thread for new flows, OS fallback for
     * existing TCP, or re-seed below). */
    proc_map_clear();

    printf("[proctrack] reloaded %d program%s from '%s'\n",
           n, (n == 1 ? "" : "s"), whitelist_file_path);
    fflush(stdout);

    /* Re-seed existing connections with the new whitelist. */
    proctrack_seed();
    return 1;
}

static DWORD WINAPI watcher_thread_proc(LPVOID arg __attribute__((unused)))
{
    for (;;) {
        if (watcher_stop)
            break;
        Sleep(2000);  /* poll every 2 seconds */
        if (watcher_stop)
            break;
        if (whitelist_file_path[0]) {
            /* Use Windows native API for reliable mtime detection. */
            WIN32_FILE_ATTRIBUTE_DATA fad;
            if (GetFileAttributesExA(whitelist_file_path, GetFileExInfoStandard, &fad)) {
                /* Convert FILETIME (100ns intervals since 1601) to Unix time_t. */
                ULARGE_INTEGER uli;
                uli.LowPart = fad.ftLastWriteTime.dwLowDateTime;
                uli.HighPart = fad.ftLastWriteTime.dwHighDateTime;
                /* 11644473600 = seconds between 1601-01-01 and 1970-01-01 */
                time_t current_mtime = (time_t)(uli.QuadPart / 10000000ULL - 11644473600ULL);
                if (current_mtime != whitelist_last_mtime) {
                    printf("[proctrack] watcher: mtime changed (%ld -> %ld), reloading...\n",
                           (long)whitelist_last_mtime, (long)current_mtime);
                    fflush(stdout);
                    proctrack_reload();
                }
            }
        }
    }
    return 0;
}

int proctrack_start_watcher_thread(void)
{
    if (!whitelist_file_path[0])
        return 0;
    watcher_stop = 0;
    watcher_thread = CreateThread(NULL, 0, watcher_thread_proc, NULL, 0, NULL);
    if (!watcher_thread) {
        printf("[proctrack] ERROR: watcher CreateThread failed: %lu\n",
               (unsigned long)GetLastError());
        return 0;
    }
    printf("[proctrack] file watcher started (monitoring '%s').\n",
           whitelist_file_path);
    return 1;
}

void proctrack_stop_watcher_thread(void)
{
    if (!watcher_thread)
        return;
    watcher_stop = 1;
    WaitForSingleObject(watcher_thread, 3000);
    CloseHandle(watcher_thread);
    watcher_thread = NULL;
}

void proctrack_stats(int *total, int *targets)
{
    int tot = 0, tgt = 0;
    proc_record_t *rec, *tmp;
    EnterCriticalSection(&proc_lock);
    HASH_ITER(hh, proc_map, rec, tmp) {
        tot++;
        if (rec->is_target) tgt++;
    }
    LeaveCriticalSection(&proc_lock);
    if (total)   *total   = tot;
    if (targets) *targets = tgt;
}

void proctrack_free(void)
{
    proctrack_stop_watcher_thread();
    proctrack_stop_flow_thread();
    if (proc_lock_init)
        proc_map_clear();

    if (whitelist) {
        size_t i;
        for (i = 0; i < whitelist_count; i++)
            free(whitelist[i].pattern);
        free(whitelist);
        whitelist = NULL;
        whitelist_count = 0;
        whitelist_cap = 0;
    }

    if (proc_lock_init) {
        DeleteCriticalSection(&proc_lock);
        proc_lock_init = 0;
    }
}

/* Resolve a specific TCP 5-tuple from the OS connection table and return
 * the owning PID. Returns 0 on failure (not found in table). */
static DWORD resolve_pid_from_tcp_os(int is_ipv6, const uint32_t local[4],
    uint16_t local_port, const uint32_t remote[4], uint16_t remote_port)
{
    DWORD size = 0;
    DWORD rc;
    DWORD pid = 0;
    DWORD i;

    if (!is_ipv6) {
        MIB_TCPTABLE_OWNER_PID *t;
        rc = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                                 TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
            return 0;
        t = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
        if (!t) return 0;
        rc = GetExtendedTcpTable(t, &size, FALSE, AF_INET,
                                 TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc != NO_ERROR) { free(t); return 0; }

        /* ports are stored in the lower 16 bits, network byte order.
         * Compare directly with htons(host_port). */
        uint16_t lpn = htons(local_port);
        uint16_t rpn = htons(remote_port);
        uint32_t la = local[0];
        uint32_t ra = remote[0];

        for (i = 0; i < t->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID *r = &t->table[i];
            if (r->dwLocalAddr == la &&
                (uint16_t)(r->dwLocalPort & 0xFFFF) == lpn &&
                r->dwRemoteAddr == ra &&
                (uint16_t)(r->dwRemotePort & 0xFFFF) == rpn) {
                pid = r->dwOwningPid;
                break;
            }
        }
        free(t);
    } else {
        MIB_TCP6TABLE_OWNER_PID *t;
        uint16_t lpn = htons(local_port);
        uint16_t rpn = htons(remote_port);

        rc = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6,
                                 TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
            return 0;
        t = (MIB_TCP6TABLE_OWNER_PID *)malloc(size);
        if (!t) return 0;
        rc = GetExtendedTcpTable(t, &size, FALSE, AF_INET6,
                                 TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc != NO_ERROR) { free(t); return 0; }

        for (i = 0; i < t->dwNumEntries; i++) {
            MIB_TCP6ROW_OWNER_PID *r = &t->table[i];
            if (memcmp(r->ucLocalAddr, local, 16) == 0 &&
                (uint16_t)(r->dwLocalPort & 0xFFFF) == lpn &&
                memcmp(r->ucRemoteAddr, remote, 16) == 0 &&
                (uint16_t)(r->dwRemotePort & 0xFFFF) == rpn) {
                pid = r->dwOwningPid;
                break;
            }
        }
        free(t);
    }
    return pid;
}

int proctrack_is_target(uint8_t proto,
                        const void *local_addr,  uint16_t local_port,
                        const void *remote_addr, uint16_t remote_port,
                        int is_ipv6)
{
    uint32_t local[4], remote[4];
    int r;

    if (is_ipv6) {
        ipv6_copy_addr(local,  (const uint32_t *)local_addr);
        ipv6_copy_addr(remote, (const uint32_t *)remote_addr);
    } else {
        ipv4_copy_addr(local,  (const uint32_t *)local_addr);
        ipv4_copy_addr(remote, (const uint32_t *)remote_addr);
    }

    /* Fast path: already in the map. */
    r = proc_map_lookup(proto, is_ipv6, local, local_port, remote, remote_port);
    if (r >= 0) {
        proctrack_last_method = 0;
        return r;
    }

    /* UDP fallback: seeded UDP sockets only know the local endpoint. */
    if (proto == IPPROTO_UDP) {
        uint32_t zero[4] = {0, 0, 0, 0};
        r = proc_map_lookup(proto, is_ipv6, local, local_port, zero, 0);
        if (r >= 0) {
            proctrack_last_method = 1;
            return r;
        }
    }

    /* Slow path: try to resolve from the OS connection table and cache.
     * This covers the race where the FLOW ESTABLISHED event has not yet
     * arrived before the first NETWORK packet of a new connection. */
    if (proto == IPPROTO_TCP) {
        DWORD pid = resolve_pid_from_tcp_os(is_ipv6, local, local_port,
                                            remote, remote_port);
        if (pid != 0) {
            uint8_t target = (uint8_t)match_pid(pid);
            proc_map_set(proto, is_ipv6, local, local_port,
                         remote, remote_port, target);
            proctrack_last_method = 2;
            return (int)target;
        }
    }

    /* Safe default: unknown -> not a target (packet left untouched). */
    proctrack_last_method = 3;
    return 0;
}
