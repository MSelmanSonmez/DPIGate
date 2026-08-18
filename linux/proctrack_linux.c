/*
 * proctrack_linux.c — Per-program connection tracker (Linux port).
 *
 * Ported from Windows proctrack.c (Sections 11-13).
 *
 * Preserved (platform-independent):
 *   - fill_key, proc_map_lookup/set/del/clear/count_targets (uthash)
 *   - whitelist_load/add/trim, match_exe, normalize_lower
 *   - proctrack_reload (hot-reload), proctrack_is_target 4-stage fallback
 *
 * Changed:
 *   - match_pid: OpenProcess+QueryFullProcessImageNameW → readlink("/proc/<pid>/exe")
 *   - seed_tcp/udp: GetExtendedTcpTable → /proc/net/tcp + /proc/net/tcp6 parse
 *   - resolve_pid_from_tcp_os: GetExtendedTcpTable → sock_diag + inode→PID cache
 *   - FLOW thread: REMOVED (no FLOW layer on Linux)
 *   - CRITICAL_SECTION → pthread_mutex_t
 *   - CreateThread/Sleep → pthread_create/nanosleep
 *   - GetFileAttributesExA → stat() + st_mtim
 *
 * NEW:
 *   - inode->PID cache (ino_pid_t, /proc/PID/fd scan -> hashmap)
 *   - sock_diag (NETLINK_INET_DIAG) 5-tuple -> inode
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>     /* sig_atomic_t */
#include <netinet/in.h> /* IPPROTO_TCP, IPPROTO_UDP, htons */
#include <fcntl.h>

/* Kernel UAPI headers */
#include <linux/netlink.h>
#include <linux/sock_diag.h>   /* SOCK_DIAG_BY_FAMILY */
#include <linux/inet_diag.h>   /* inet_diag_req_v2, inet_diag_msg */

#include "proctrack_linux.h"
#include "utils/uthash.h"

/* --- SOCK_DIAG_BY_FAMILY fallback (eski header'lar) --- */
#ifndef SOCK_DIAG_BY_FAMILY
#define SOCK_DIAG_BY_FAMILY 20
#endif

/* --- TCP state sabitleri (inet_diag idiag_states icin) --- */
#ifndef TCP_ESTABLISHED
#define TCP_ESTABLISHED  1
#define TCP_SYN_SENT     2
#define TCP_LISTEN       10
#endif

/* --- INET_DIAG_NOCOOKIE fallback --- */
#ifndef INET_DIAG_NOCOOKIE
#define INET_DIAG_NOCOOKIE (~0U)
#endif

/* --- Address copy helpers (Windows windivert.h ipv4_copy_addr/ipv6_copy_addr karsiligi) --- */

inline static void ipv4_copy_addr(uint32_t *out, const uint32_t *src)
{
    out[0] = src[0];
    out[1] = out[2] = out[3] = 0;
}

inline static void ipv6_copy_addr(uint32_t *out, const uint32_t *src)
{
    memcpy(out, src, 16);  /* 4 × uint32_t */
}

/* ================================================================
 * 5-tuple → is_target map (uthash) — AYNEN korundu
 * ================================================================ */

/* key = marker('4'/'6') + local_addr[16] + remote_addr[16]
 *       + local_port[2] + remote_port[2] + proto[1]  = 38 bytes */
#define PROC_KEY_LEN 38

/* HACK: uthash uses strlen() for HASH_FIND_STR; our key has null bytes.
 * The key is always PROC_KEY_LEN long, so override strlen like ttltrack.c. */
#undef uthash_strlen
#define uthash_strlen(s) PROC_KEY_LEN

/* Verdict cache entry. `stamp` is a CLOCK_MONOTONIC second count; entries
 * expire so that a transient resolution failure (process not yet visible in
 * /proc, inode cache miss under load) cannot pin a flow to the wrong verdict
 * for its whole lifetime — the old code cached the first answer forever. */
typedef struct proc_record {
    char key[PROC_KEY_LEN];
    uint8_t is_target;
    time_t  stamp;
    UT_hash_handle hh;
} proc_record_t;

/* Verdict lifetimes. A "not ours" answer expires quickly (a wrong one silently
 * disables the bypass for that connection); a "ours" answer is cheap to keep
 * but still expires so recycled ports cannot inherit it. */
#define PROC_TTL_MISS 5
#define PROC_TTL_HIT  30
/* Hard ceiling on cached flows — a busy browser opens thousands. */
#define PROC_MAP_MAX  20000

typedef struct {
    char *pattern;   /* normalized: lowercased, '/' separators */
    int   is_path;   /* 1 if pattern contains '/', else basename-exact */
} wl_entry_t;

typedef struct { wl_entry_t *v; size_t n, cap; } wl_list_t;

static pthread_mutex_t proc_lock = PTHREAD_MUTEX_INITIALIZER;
static proc_record_t *proc_map = NULL;

static wl_list_t wl_cur = { NULL, 0, 0 };
static pthread_rwlock_t wl_lock = PTHREAD_RWLOCK_INITIALIZER;

int proctrack_last_method = 3;

/* Hot-reload: file watcher thread polls ProgramFilters mtime every 2s. */
static char whitelist_file_path[PATH_MAX] = {0};
static pthread_t watcher_thread;
static volatile sig_atomic_t watcher_stop = 0;
static int watcher_started = 0;
static time_t whitelist_last_mtime = 0;

/* inode→PID cache thread */
static pthread_t inode_pid_thread;
static volatile sig_atomic_t inode_pid_stop = 0;
static int inode_pid_started = 0;

/* sock_diag netlink socket (lazy open) */
static int sockdiag_fd = -1;


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
    memcpy(key + off, &local_port, sizeof local_port);  off += 2;
    memcpy(key + off, &remote_port, sizeof remote_port); off += 2;
    memcpy(key + off, &proto, sizeof proto);
}

/* Monotonic seconds — immune to wall-clock jumps (NTP, suspend/resume). */
static time_t mono_now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ts.tv_sec;
}

static int proc_rec_expired(const proc_record_t *rec, time_t now)
{
    time_t ttl = rec->is_target ? PROC_TTL_HIT : PROC_TTL_MISS;
    return (now - rec->stamp) >= ttl;
}

/* Caller must hold proc_lock. Drops expired entries; when the map is still
 * over the ceiling afterwards it is emptied wholesale (cheaper than an LRU
 * and self-correcting — every live flow re-resolves on its next packet). */
static void proc_map_evict_locked(time_t now)
{
    proc_record_t *rec, *tmp;
    HASH_ITER(hh, proc_map, rec, tmp) {
        if (proc_rec_expired(rec, now)) {
            HASH_DEL(proc_map, rec);
            free(rec);
        }
    }
    if (HASH_COUNT(proc_map) < PROC_MAP_MAX)
        return;
    HASH_ITER(hh, proc_map, rec, tmp) {
        HASH_DEL(proc_map, rec);
        free(rec);
    }
}

/* Returns is_target (0/1) or -1 if not found / expired. */
static int proc_map_lookup(uint8_t proto, int is_ipv6,
                           const uint32_t local[4], uint16_t local_port,
                           const uint32_t remote[4], uint16_t remote_port)
{
    char key[PROC_KEY_LEN];
    proc_record_t *rec = NULL;
    int result = -1;

    fill_key(key, is_ipv6, proto, local, local_port, remote, remote_port);

    pthread_mutex_lock(&proc_lock);
    HASH_FIND_STR(proc_map, key, rec);
    if (rec && !proc_rec_expired(rec, mono_now()))
        result = (int)rec->is_target;
    pthread_mutex_unlock(&proc_lock);
    return result;
}

static void proc_map_set(uint8_t proto, int is_ipv6,
                         const uint32_t local[4], uint16_t local_port,
                         const uint32_t remote[4], uint16_t remote_port,
                         uint8_t is_target)
{
    char key[PROC_KEY_LEN];
    proc_record_t *rec = NULL;
    time_t now = mono_now();

    fill_key(key, is_ipv6, proto, local, local_port, remote, remote_port);

    pthread_mutex_lock(&proc_lock);
    HASH_FIND_STR(proc_map, key, rec);
    if (rec) {
        rec->is_target = is_target;
        rec->stamp = now;
    } else {
        if (HASH_COUNT(proc_map) >= PROC_MAP_MAX)
            proc_map_evict_locked(now);
        rec = (proc_record_t *)malloc(sizeof(*rec));
        if (!rec) {
            pthread_mutex_unlock(&proc_lock);
            return;
        }
        memcpy(rec->key, key, PROC_KEY_LEN);
        rec->is_target = is_target;
        rec->stamp = now;
        HASH_ADD_STR(proc_map, key, rec);
    }
    pthread_mutex_unlock(&proc_lock);
}

static void proc_map_clear(void)
{
    proc_record_t *rec, *tmp;
    pthread_mutex_lock(&proc_lock);
    HASH_ITER(hh, proc_map, rec, tmp) {
        HASH_DEL(proc_map, rec);
        free(rec);
    }
    proc_map = NULL;
    pthread_mutex_unlock(&proc_lock);
}

static int proc_map_count_targets(void)
{
    proc_record_t *rec, *tmp;
    int n = 0;
    pthread_mutex_lock(&proc_lock);
    HASH_ITER(hh, proc_map, rec, tmp) {
        if (rec->is_target) n++;
    }
    pthread_mutex_unlock(&proc_lock);
    return n;
}


/* ================================================================
 * Whitelist loading & matching — normalize_lower Linux: / → / kalir
 * ================================================================ */

/* in-place: lowercase ASCII bytes. Linux'ta / → \ DONUSUMU YAPILMAZ. */
static void normalize_lower(char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x80)
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

static int wl_add(wl_list_t *L, char *line)
{
    char *p = trim(line);
    if (*p == 0 || *p == '#')
        return 0;

    normalize_lower(p);

    if (L->n == L->cap) {
        size_t ncap = L->cap ? L->cap * 2 : 16;
        wl_entry_t *na = (wl_entry_t *)realloc(L->v, ncap * sizeof(*na));
        if (!na) return 0;
        L->v = na;
        L->cap = ncap;
    }

    {
        wl_entry_t *e = &L->v[L->n];
        e->pattern = strdup(p);
        if (!e->pattern) return 0;
        e->is_path = (strchr(p, '/') != NULL) ? 1 : 0;
        L->n++;
    }
    return 1;
}

static int wl_load(const char *fname, wl_list_t *L)
{
    FILE *fp = fopen(fname, "r");
    char buf[4096];
    int added = 0;
    if (!fp) return -1;

    while (fgets(buf, sizeof(buf), fp)) {
        if (wl_add(L, buf))
            added++;
    }
    fclose(fp);
    return added;
}

static void wl_free(wl_list_t *L)
{
    size_t i;
    for (i = 0; i < L->n; i++)
        free(L->v[i].pattern);
    free(L->v);
    L->v = NULL; L->n = 0; L->cap = 0;
}

static void wl_stamp_set_from_file(const char *fname)
{
    struct stat st;
    if (stat(fname, &st) == 0)
        whitelist_last_mtime = st.st_mtim.tv_sec;
}

/* Read /proc/<pid>/cmdline into cmdbuf (NUL→space flattened, lowercased).
 * Returns bytes read (>0) or 0 on failure. */
static ssize_t read_cmdline_flat(pid_t pid, char *cmdbuf, size_t maxlen)
{
    char link[64];
    snprintf(link, sizeof link, "/proc/%ld/cmdline", (long)pid);
    int cfd = open(link, O_RDONLY | O_CLOEXEC);
    if (cfd < 0) return 0;
    ssize_t cn = read(cfd, cmdbuf, maxlen - 1);
    close(cfd);
    if (cn <= 0) return 0;
    cmdbuf[cn] = 0;
    for (ssize_t i = 0; i < cn; i++)
        if (cmdbuf[i] == 0) cmdbuf[i] = ' ';
    normalize_lower(cmdbuf);
    return cn;
}

/* Return PPid of pid, or 0 if not readable. */
static pid_t parent_pid_of(pid_t pid)
{
    char path[64], line[256];
    snprintf(path, sizeof path, "/proc/%ld/status", (long)pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    pid_t ppid = 0;
    while (fgets(line, sizeof line, fp)) {
        if (strncmp(line, "PPid:", 5) == 0) {
            ppid = (pid_t)strtol(line + 5, NULL, 10);
            break;
        }
    }
    fclose(fp);
    return ppid;
}

/* Read /proc/<pid>/comm (kernel task name, <=15 chars) lowercased.
 * Unlike /proc/<pid>/exe this is world-readable and never mediated by
 * ptrace/LSM policy, so it survives sandboxed (snap/flatpak/AppArmor)
 * targets whose exe symlink we are not allowed to resolve. */
static int read_comm(pid_t pid, char *buf, size_t maxlen)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%ld/comm", (long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, maxlen - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    char *nl = strchr(buf, '\n');
    if (nl) *nl = 0;
    if (!buf[0]) return 0;
    normalize_lower(buf);
    return 1;
}

/* Does `pat` appear in `cmd` as a whole path component or bare token?
 * Boundaries are ' ' (argument separator in the flattened cmdline) and '/'.
 *
 *   "/usr/lib/vesktop/app.asar"  vs "vesktop" -> yes (path component)
 *   "https://discord.com/"       vs "discord" -> no  (part of a hostname)
 *
 * A plain substring test — what this used to do — turned every
 * `curl https://discord.com/` into "the Discord app" and bypassed traffic the
 * user never whitelisted. */
static int cmd_has_component(const char *cmd, const char *pat)
{
    size_t plen = strlen(pat);
    const char *p = cmd;
    if (!plen)
        return 0;
    while ((p = strstr(p, pat)) != NULL) {
        char before = (p == cmd) ? ' ' : p[-1];
        char after  = p[plen];
        if ((before == ' ' || before == '/') &&
            (after == '\0' || after == ' ' || after == '/'))
            return 1;
        p++;
    }
    return 0;
}

/* Check one process identity triple against the whitelist. Any of the three
 * may be NULL — a process only needs ONE readable identity source to match.
 *   exe    : /proc/<pid>/exe target (path patterns: substring, bare names:
 *            basename-exact)
 *   cmdbuf : flattened /proc/<pid>/cmdline. Path patterns match as a
 *            substring; bare names must line up with a whole path component,
 *            which is what catches Electron/snap wrappers ("electron
 *            /usr/lib/vesktop/app.asar") without matching URLs or flag values.
 *   comm   : /proc/<pid>/comm (basename-exact; the only source available when
 *            exe is unreadable and the process was exec'd with an empty argv)
 */
static int match_ident(const char *exe, const char *cmdbuf, const char *comm)
{
    int hit = 0;
    const char *base = NULL;

    if (exe) {
        base = strrchr(exe, '/');
        base = base ? base + 1 : exe;
    }

    pthread_rwlock_rdlock(&wl_lock);
    for (size_t i = 0; i < wl_cur.n; i++) {
        wl_entry_t *e = &wl_cur.v[i];
        if (e->is_path) {
            if (exe && strstr(exe, e->pattern) != NULL) { hit = 1; break; }
            if (cmdbuf && strstr(cmdbuf, e->pattern) != NULL) { hit = 1; break; }
        } else {
            if (base && strcmp(base, e->pattern) == 0) { hit = 1; break; }
            if (comm && strcmp(comm, e->pattern) == 0) { hit = 1; break; }
            if (cmdbuf && cmd_has_component(cmdbuf, e->pattern)) { hit = 1; break; }
        }
    }
    pthread_rwlock_unlock(&wl_lock);
    return hit;
}

/* Read /proc/<pid>/exe into buf, normalized. Returns 1 on success.
 * The kernel appends " (deleted)" once the binary is replaced or its mount
 * goes away (package upgrade, snap refresh) — strip it, otherwise the
 * basename becomes "firefox (deleted)" and never matches again. */
static int read_exe_path(pid_t pid, char *buf, size_t maxlen)
{
    char link[64];
    static const char del[] = " (deleted)";
    snprintf(link, sizeof link, "/proc/%ld/exe", (long)pid);
    ssize_t n = readlink(link, buf, maxlen - 1);
    if (n <= 0) return 0;
    buf[n] = 0;
    if ((size_t)n > sizeof(del) - 1 &&
        strcmp(buf + n - (sizeof(del) - 1), del) == 0)
        buf[n - (sizeof(del) - 1)] = 0;
    if (!buf[0]) return 0;
    normalize_lower(buf);
    return 1;
}

/* match_pid — decide whether a PID (or one of its ancestors) is whitelisted.
 *
 * Every identity source is optional and they are tried together, because each
 * one is missing in some real deployment:
 *   - exe is unreadable for sandboxed targets (ptrace/LSM mediation) and
 *     carries a " (deleted)" suffix after an in-place upgrade;
 *   - cmdline is empty for processes that rewrote argv;
 *   - comm is truncated to 15 characters.
 * The old code gave up on the whole chain the moment readlink() failed, which
 * silently disabled the bypass for confined browsers.
 *
 * PARENT-CHAIN FALLBACK: Electron/Chromium apps do their networking in a
 * child ("NetworkService") whose own identity is generic; the distinctive
 * app path lives on an ancestor, so walk up to 4 hops. */
static int match_pid(pid_t pid)
{
    if (pid <= 0)
        return 0;

    char exe[PATH_MAX], cmdbuf[4096], comm[64];
    int depth;

    for (depth = 0; depth < 4 && pid > 0; depth++) {
        int have_exe  = read_exe_path(pid, exe, sizeof exe);
        ssize_t cn    = read_cmdline_flat(pid, cmdbuf, sizeof cmdbuf);
        int have_comm = read_comm(pid, comm, sizeof comm);

        if (!have_exe && cn <= 0 && !have_comm)
            break;              /* process is gone — nothing left to inspect */

        if (match_ident(have_exe ? exe : NULL,
                        cn > 0 ? cmdbuf : NULL,
                        have_comm ? comm : NULL))
            return 1;

        /* Walk up to the parent process. */
        pid_t ppid = parent_pid_of(pid);
        if (ppid <= 0 || ppid == pid)
            break;
        pid = ppid;
    }
    return 0;
}


/* ================================================================
 * inode → PID cache (Bolum 13.2)
 * ================================================================ */

typedef struct ino_pid {
    uint32_t inode;
    pid_t    pid;
    UT_hash_handle hh;
} ino_pid_t;

static ino_pid_t *ino_map = NULL;
static pthread_rwlock_t ino_lock = PTHREAD_RWLOCK_INITIALIZER;

/* Tum /proc'i tara, hashmap'i yeniden insa et. Periyodik thread'ten cagrilir. */
static void refresh_inode_pid_map(void)
{
    ino_pid_t *fresh = NULL, *rec, *tmp;
    DIR *proc = opendir("/proc");
    if (!proc) return;
    struct dirent *e;
    while ((e = readdir(proc)) != NULL) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char fdpath[300];     /* /proc/ + d_name[256] + /fd */
        snprintf(fdpath, sizeof fdpath, "/proc/%s/fd", e->d_name);
        DIR *fdd = opendir(fdpath);
        if (!fdd) continue;
        pid_t pid = (pid_t)atoi(e->d_name);
        struct dirent *f;
        char link[600], target[64];   /* fdpath + / + d_name[256] */
        while ((f = readdir(fdd)) != NULL) {
            snprintf(link, sizeof link, "%s/%s", fdpath, f->d_name);
            ssize_t rl = readlink(link, target, sizeof target - 1);
            if (rl <= 0) continue;
            target[rl] = 0;
            uint32_t ino;
            if (sscanf(target, "socket:[%u]", &ino) == 1) {
                HASH_FIND_INT(fresh, &ino, rec);
                if (!rec) {
                    rec = malloc(sizeof(*rec));
                    if (!rec) continue;
                    rec->inode = ino;
                    rec->pid = pid;
                    HASH_ADD_INT(fresh, inode, rec);
                }
            }
        }
        closedir(fdd);
    }
    closedir(proc);

    /* atomik takas */
    pthread_rwlock_wrlock(&ino_lock);
    ino_pid_t *old = ino_map;
    ino_map = fresh;
    pthread_rwlock_unlock(&ino_lock);

    HASH_ITER(hh, old, rec, tmp) { HASH_DEL(old, rec); free(rec); }
}

/* Hizli lookup — packet hot path'inden cagrilir, rdlock altinda. */
static pid_t inode_to_pid_cached(uint32_t inode)
{
    ino_pid_t *rec;
    pthread_rwlock_rdlock(&ino_lock);
    HASH_FIND_INT(ino_map, &inode, rec);
    pid_t pid = rec ? rec->pid : 0;
    pthread_rwlock_unlock(&ino_lock);
    return pid;
}

/* Rate-limited rescan for the packet hot path. A full /proc/<pid>/fd walk
 * costs milliseconds on a busy desktop; a flow that can never be resolved
 * (socket owned by another user) would otherwise trigger one per packet and
 * stall the NFQUEUE.
 *
 * The floor must stay well below one RTT: a brand-new socket is resolved on
 * its first packet, and the TLS ClientHello follows the SYN by ~10ms on a
 * LAN. 20ms bounds the worst case to 50 scans/s while never starving a fresh
 * connection — and a scan that resolves nothing lets the caller cache a
 * short-lived miss, so repeat scans for the same flow stop entirely. */
#define INO_RESCAN_MIN_MS 20
static pthread_mutex_t ino_rescan_lock = PTHREAD_MUTEX_INITIALIZER;
static long ino_last_rescan_ms = 0;

static long mono_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* Returns 1 when a rescan actually ran. */
static int refresh_inode_pid_map_throttled(void)
{
    long now = mono_ms();
    int go = 0;
    pthread_mutex_lock(&ino_rescan_lock);
    if (now - ino_last_rescan_ms >= INO_RESCAN_MIN_MS) {
        ino_last_rescan_ms = now;
        go = 1;
    }
    pthread_mutex_unlock(&ino_rescan_lock);
    if (go)
        refresh_inode_pid_map();
    return go;
}

/* inode→PID cache thread — her 5 sn'de bir refresh */
static void *inode_pid_thread_proc(void *arg)
{
    (void)arg;
    struct timespec ts = {5, 0};  /* 5 saniye */
    for (;;) {
        if (inode_pid_stop) break;
        nanosleep(&ts, NULL);
        if (inode_pid_stop) break;
        refresh_inode_pid_map();
    }
    return NULL;
}


/* ================================================================
 * sock_diag (NETLINK_INET_DIAG) — 5-tuple → inode (Bolum 12)
 * ================================================================ */

static int sockdiag_open(void)
{
    if (sockdiag_fd != -1) return 0;
    sockdiag_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_INET_DIAG);
    if (sockdiag_fd < 0) {
        fprintf(stderr, "[proctrack] sock_diag: socket failed: %s\n",
                strerror(errno));
        sockdiag_fd = -1;
        return -1;
    }
    return 0;
}

static void sockdiag_close(void)
{
    if (sockdiag_fd != -1) {
        close(sockdiag_fd);
        sockdiag_fd = -1;
    }
}

/*
 * sockdiag_lookup_inode — 5-tuple → inode (single netlink query).
 *   local[], remote[] = network order (consistent with Windows)
 *   local_port, remote_port = host order
 *   returns: 0 = success (inode_out filled), -1 = not found/error
 */
static int sockdiag_lookup_inode(uint8_t proto, int is_ipv6,
                                  const uint32_t local[4], uint16_t local_port,
                                  const uint32_t remote[4], uint16_t remote_port,
                                  uint32_t *inode_out)
{
    if (sockdiag_open() < 0) return -1;

    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len   = sizeof(req);
    req.nlh.nlmsg_type  = SOCK_DIAG_BY_FAMILY;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq   = 1;
    req.nlh.nlmsg_pid   = 0;

    req.req.sdiag_family   = is_ipv6 ? AF_INET6 : AF_INET;
    req.req.sdiag_protocol = proto;
    req.req.idiag_states   = (1u << TCP_ESTABLISHED) | (1u << TCP_SYN_SENT) |
                             (1u << TCP_LISTEN);
    req.req.id.idiag_sport = htons(local_port);
    req.req.id.idiag_dport = htons(remote_port);
    if (!is_ipv6) {
        /* local[0] = network order, idiag_src = __be32 → directly */
        req.req.id.idiag_src[0] = local[0];
        req.req.id.idiag_dst[0] = remote[0];
    } else {
        memcpy(req.req.id.idiag_src, local, 16);
        memcpy(req.req.id.idiag_dst, remote, 16);
    }
    req.req.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    req.req.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;

    /* Gonder */
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    struct iovec iov = { &req, sizeof(req) };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(sockdiag_fd, &msg, 0) < 0) return -1;

    /* Cevap al */
    char buf[8192];
    struct iovec riov = { buf, sizeof(buf) };
    struct msghdr rmsg;
    memset(&rmsg, 0, sizeof(rmsg));
    rmsg.msg_name = &sa;
    rmsg.msg_namelen = sizeof(sa);
    rmsg.msg_iov = &riov;
    rmsg.msg_iovlen = 1;

    ssize_t len = recvmsg(sockdiag_fd, &rmsg, 0);
    if (len < 0) return -1;

    /* Parse netlink multipart cevap */
    struct nlmsghdr *nlh;
    for (nlh = (struct nlmsghdr *)buf;
         NLMSG_OK(nlh, (size_t)len);
         nlh = NLMSG_NEXT(nlh, len)) {
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            return -1;  /* socket bulunamadi (ENOENT) */
        }
        if (nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY) {
            struct inet_diag_msg *diag = (struct inet_diag_msg *)NLMSG_DATA(nlh);
            *inode_out = diag->idiag_inode;
            return 0;
        }
    }
    return -1;
}


/* ================================================================
 * Seeding — /proc/net/tcp + /proc/net/udp parse (Bolum 13)
 * ================================================================ */

/* /proc/net/tcp sutun: "  sl  local:port remote:port st ... uid timeout inode"
 * Byte-order: addr = network order (%08X), port = host order (%04X)
 */

static void seed_tcp_v4(void)
{
    FILE *fp = fopen("/proc/net/tcp", "r");
    if (!fp) return;

    char line[512];
    /* ilk satir = header, atla */
    if (!fgets(line, sizeof line, fp)) { fclose(fp); return; }

    while (fgets(line, sizeof line, fp)) {
        unsigned int la, ra, lp, rp, st, inode;
        int ret = sscanf(line, " %*u: %x:%x %x:%x %x"
                         " %*x:%*x %*x:%*x %*x %*x %*x %u",
                         &la, &lp, &ra, &rp, &st, &inode);
        if (ret != 6) continue;

        /* listening socket (remote=0) skip */
        if (ra == 0 && rp == 0) continue;

        uint32_t local[4], remote[4];
        local[0] = la; remote[0] = ra;  /* network order */
        uint16_t local_port = (uint16_t)lp;   /* host order */
        uint16_t remote_port = (uint16_t)rp;

        /* inode → PID → match */
        pid_t pid = inode_to_pid_cached(inode);
        uint8_t is_target = pid ? (uint8_t)match_pid(pid) : 0;
        proc_map_set(IPPROTO_TCP, 0, local, local_port,
                     remote, remote_port, is_target);
    }
    fclose(fp);
}

static void seed_tcp_v6(void)
{
    FILE *fp = fopen("/proc/net/tcp6", "r");
    if (!fp) return;

    char line[512];
    if (!fgets(line, sizeof line, fp)) { fclose(fp); return; }

    while (fgets(line, sizeof line, fp)) {
        /* Zero-initialized: %32[...] can match FEWER than 32 characters on a
         * short/malformed line, and the 8-byte-word loop below always reads
         * all 32, which would otherwise be an uninitialized-stack read. */
        char la_str[33] = {0}, ra_str[33] = {0};
        unsigned int lp, rp, st, inode;
        int ret = sscanf(line, " %*u: %32[0-9a-fA-F]:%x %32[0-9a-fA-F]:%x %x"
                         " %*x:%*x %*x:%*x %*x %*x %*x %u",
                         la_str, &lp, ra_str, &rp, &st, &inode);
        if (ret != 6) continue;
        if (strlen(la_str) != 32 || strlen(ra_str) != 32) continue;

        /* 4 × 8 hex → 4 × uint32_t (network order) */
        uint32_t local[4], remote[4];
        int ok = 1;
        for (int i = 0; i < 4; i++) {
            char w[9];
            memcpy(w, la_str + 8*i, 8); w[8] = 0;
            local[i] = (uint32_t)strtoul(w, NULL, 16);
            memcpy(w, ra_str + 8*i, 8); w[8] = 0;
            remote[i] = (uint32_t)strtoul(w, NULL, 16);
        }
        (void)ok;

        /* listening socket skip */
        int all_zero = 1;
        for (int i = 0; i < 4; i++) {
            if (remote[i] != 0) { all_zero = 0; break; }
        }
        if (all_zero && rp == 0) continue;

        uint16_t local_port = (uint16_t)lp;
        uint16_t remote_port = (uint16_t)rp;

        pid_t pid = inode_to_pid_cached(inode);
        uint8_t is_target = pid ? (uint8_t)match_pid(pid) : 0;
        proc_map_set(IPPROTO_TCP, 1, local, local_port,
                     remote, remote_port, is_target);
    }
    fclose(fp);
}

static void seed_udp_v4(void)
{
    FILE *fp = fopen("/proc/net/udp", "r");
    if (!fp) return;

    char line[512];
    if (!fgets(line, sizeof line, fp)) { fclose(fp); return; }

    uint32_t zero[4] = {0, 0, 0, 0};

    while (fgets(line, sizeof line, fp)) {
        unsigned int la, lp, st, inode;
        int ret = sscanf(line, " %*u: %x:%x %*x:%*x %x"
                         " %*x:%*x %*x:%*x %*x %*x %*x %u",
                         &la, &lp, &st, &inode);
        if (ret != 4) continue;

        uint32_t local[4] = {la, 0, 0, 0};
        uint16_t local_port = (uint16_t)lp;

        /* UDP: remote = 0 (local-only entry) */
        pid_t pid = inode_to_pid_cached(inode);
        uint8_t is_target = pid ? (uint8_t)match_pid(pid) : 0;
        proc_map_set(IPPROTO_UDP, 0, local, local_port,
                     zero, 0, is_target);
    }
    fclose(fp);
}

static void seed_udp_v6(void)
{
    FILE *fp = fopen("/proc/net/udp6", "r");
    if (!fp) return;

    char line[512];
    if (!fgets(line, sizeof line, fp)) { fclose(fp); return; }

    uint32_t zero[4] = {0, 0, 0, 0};

    while (fgets(line, sizeof line, fp)) {
        /* Zero-initialized + length-checked: see seed_tcp_v6. */
        char la_str[33] = {0};
        unsigned int lp, st, inode;
        int ret = sscanf(line, " %*u: %32[0-9a-fA-F]:%x %*x:%*x %x"
                         " %*x:%*x %*x:%*x %*x %*x %*x %u",
                         la_str, &lp, &st, &inode);
        if (ret != 4) continue;
        if (strlen(la_str) != 32) continue;

        uint32_t local[4];
        for (int i = 0; i < 4; i++) {
            char w[9];
            memcpy(w, la_str + 8*i, 8); w[8] = 0;
            local[i] = (uint32_t)strtoul(w, NULL, 16);
        }

        uint16_t local_port = (uint16_t)lp;

        pid_t pid = inode_to_pid_cached(inode);
        uint8_t is_target = pid ? (uint8_t)match_pid(pid) : 0;
        proc_map_set(IPPROTO_UDP, 1, local, local_port,
                     zero, 0, is_target);
    }
    fclose(fp);
}


/* ================================================================
 * resolve_pid_from_tcp_os — sock_diag + inode cache (method=2)
 * ================================================================ */

/* Resolve the owning PID of a TCP flow. *scanned is set to 1 when the /proc
 * walk actually ran, i.e. the "unknown" answer is authoritative rather than
 * a side effect of the rescan throttle — only then may the caller cache it. */
static pid_t resolve_pid_from_tcp_os(int is_ipv6,
    const uint32_t local[4], uint16_t local_port,
    const uint32_t remote[4], uint16_t remote_port,
    int *scanned)
{
    uint32_t inode;
    *scanned = 0;
    if (sockdiag_lookup_inode(IPPROTO_TCP, is_ipv6,
                              local, local_port,
                              remote, remote_port, &inode) < 0)
        return 0;

    /* inode → PID cache lookup */
    pid_t pid = inode_to_pid_cached(inode);
    if (pid > 0) {
        *scanned = 1;
        return pid;
    }

    /* Cache miss — the socket is newer than the last scan. Rescan (throttled)
     * and retry once. */
    if (refresh_inode_pid_map_throttled()) {
        *scanned = 1;
        pid = inode_to_pid_cached(inode);
    }
    return pid;
}


/* ================================================================
 * proctrack_is_target — 4 kademeli fallback (Bolum 11.3)
 * ================================================================ */

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

    /* (1) Fast path: already in the map */
    r = proc_map_lookup(proto, is_ipv6, local, local_port, remote, remote_port);
    if (r >= 0) {
        proctrack_last_method = 0;
        return r;
    }

    /* (2) UDP fallback: local-only lookup (remote=0) */
    if (proto == IPPROTO_UDP) {
        uint32_t zero[4] = {0, 0, 0, 0};
        r = proc_map_lookup(proto, is_ipv6, local, local_port, zero, 0);
        if (r >= 0) {
            proctrack_last_method = 1;
            return r;
        }
    }

    /* (3) TCP slow path: sock_diag → inode → PID cache → match */
    if (proto == IPPROTO_TCP) {
        int scanned = 0;
        pid_t pid = resolve_pid_from_tcp_os(is_ipv6, local, local_port,
                                            remote, remote_port, &scanned);
        if (pid > 0) {
            uint8_t target = (uint8_t)match_pid(pid);
            proc_map_set(proto, is_ipv6, local, local_port,
                         remote, remote_port, target);
            proctrack_last_method = 2;
            return (int)target;
        }
        /* Unresolvable after a real scan (socket of another user, or already
         * closed): remember it briefly so the next packet of this flow does
         * not trigger another /proc walk. PROC_TTL_MISS keeps it self-healing. */
        if (scanned) {
            proc_map_set(proto, is_ipv6, local, local_port,
                         remote, remote_port, 0);
        }
    }

    /* (4) Safe default: unknown → not a target */
    proctrack_last_method = 3;
    return 0;
}


/* ================================================================
 * Hot-reload — watcher thread (Bolum 11, stat() + st_mtim)
 * ================================================================ */

static int proctrack_reload(void)
{
    wl_list_t fresh = { NULL, 0, 0 };
    int n;

    n = wl_load(whitelist_file_path, &fresh);
    if (n < 0) {
        wl_free(&fresh);
        printf("[proctrack] reload FAILED for '%s'\n",
               whitelist_file_path);
        return 0;
    }

    pthread_rwlock_wrlock(&wl_lock);
    wl_list_t old = wl_cur;
    wl_cur = fresh;
    pthread_rwlock_unlock(&wl_lock);

    wl_free(&old);

    wl_stamp_set_from_file(whitelist_file_path);

    proc_map_clear();

    printf("[proctrack] reloaded %d program%s from '%s'\n",
           n, (n == 1 ? "" : "s"), whitelist_file_path);
    fflush(stdout);

    proctrack_seed();
    return 1;
}

static void *watcher_thread_proc(void *arg)
{
    (void)arg;
    struct timespec ts = {2, 0};  /* 2 saniye */
    for (;;) {
        if (watcher_stop) break;
        nanosleep(&ts, NULL);
        if (watcher_stop) break;
        if (whitelist_file_path[0]) {
            struct stat st;
            if (stat(whitelist_file_path, &st) == 0) {
                time_t current_mtime = st.st_mtim.tv_sec;
                if (current_mtime != whitelist_last_mtime) {
                    printf("[proctrack] watcher: mtime changed (%ld -> %ld), reloading...\n",
                           (long)whitelist_last_mtime, (long)current_mtime);
                    fflush(stdout);
                    proctrack_reload();
                }
            }
        }
    }
    return NULL;
}


/* ================================================================
 * Public API
 * ================================================================ */

int proctrack_init(const char *whitelist_file)
{
    int n;
    /* no lock — runs before threads exist */
    n = wl_load(whitelist_file, &wl_cur);
    if (n < 0) {
        printf("[proctrack] ERROR: cannot open programs list '%s'\n",
               whitelist_file);
        return 0;
    }
    strncpy(whitelist_file_path, whitelist_file, sizeof(whitelist_file_path) - 1);
    whitelist_file_path[sizeof(whitelist_file_path) - 1] = 0;
    wl_stamp_set_from_file(whitelist_file_path);
    printf("[proctrack] loaded %d program%s from '%s'\n",
           n, (n == 1 ? "" : "s"), whitelist_file);

    /* inode→PID cache'i ilk kez insa et */
    refresh_inode_pid_map();
    return 1;
}

int proctrack_seed(void)
{
    int before = 0;
    pthread_mutex_lock(&proc_lock);
    before = HASH_COUNT(proc_map);
    pthread_mutex_unlock(&proc_lock);
    /* inode→PID cache'i yenile — yeni socket'ler cache'de olsun */
    refresh_inode_pid_map();

    seed_tcp_v4();
    seed_tcp_v6();
    seed_udp_v4();
    seed_udp_v6();

    {
        int after = 0;
        int targets = 0;
        pthread_mutex_lock(&proc_lock);
        after = HASH_COUNT(proc_map);
        pthread_mutex_unlock(&proc_lock);
        targets = proc_map_count_targets();
        printf("[proctrack] seeded %d existing connection%s (total map: %d, targets: %d)\n",
               after - before, (after - before == 1 ? "" : "s"), after, targets);
    }
    return 1;
}

int proctrack_start_watcher_thread(void)
{
    if (!whitelist_file_path[0])
        return 0;

    /* inode→PID cache thread */
    inode_pid_stop = 0;
    if (pthread_create(&inode_pid_thread, NULL, inode_pid_thread_proc, NULL) != 0) {
        printf("[proctrack] ERROR: inode_pid pthread_create failed: %s\n",
               strerror(errno));
        return 0;
    }
    inode_pid_started = 1;

    /* watcher thread */
    watcher_stop = 0;
    if (pthread_create(&watcher_thread, NULL, watcher_thread_proc, NULL) != 0) {
        printf("[proctrack] ERROR: watcher pthread_create failed: %s\n",
               strerror(errno));
        inode_pid_stop = 1;
        pthread_join(inode_pid_thread, NULL);
        inode_pid_started = 0;
        return 0;
    }
    watcher_started = 1;
    printf("[proctrack] file watcher started (monitoring '%s').\n",
           whitelist_file_path);
    return 1;
}

void proctrack_stop_watcher_thread(void)
{
    watcher_stop = 1;
    inode_pid_stop = 1;
    if (watcher_started)  { pthread_join(watcher_thread,  NULL); watcher_started = 0; }
    if (inode_pid_started){ pthread_join(inode_pid_thread, NULL); inode_pid_started = 0; }
}

void proctrack_stats(int *total, int *targets)
{
    int tot = 0, tgt = 0;
    proc_record_t *rec, *tmp;
    pthread_mutex_lock(&proc_lock);
    HASH_ITER(hh, proc_map, rec, tmp) {
        tot++;
        if (rec->is_target) tgt++;
    }
    pthread_mutex_unlock(&proc_lock);
    if (total)   *total   = tot;
    if (targets) *targets = tgt;
}

void proctrack_free(void)
{
    proctrack_stop_watcher_thread();
    proc_map_clear();

    pthread_rwlock_wrlock(&wl_lock);
    wl_list_t old = wl_cur;
    wl_cur = (wl_list_t){0};
    pthread_rwlock_unlock(&wl_lock);
    wl_free(&old);

    /* inode→PID cache temizle */
    ino_pid_t *rec, *tmp;
    HASH_ITER(hh, ino_map, rec, tmp) { HASH_DEL(ino_map, rec); free(rec); }
    ino_map = NULL;

    sockdiag_close();
}
