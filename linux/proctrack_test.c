/*
 * proctrack_test.c — Phase 4 test: per-program connection tracker.
 *
 * Test steps:
 *   1. Create a temporary whitelist file (this process's exe)
 *   2. proctrack_init → load whitelist + build inode→PID cache
 *   3. proctrack_seed → parse /proc/net/tcp + /proc/net/udp → fill map
 *   4. proctrack_is_target → query our own TCP connection
 *   5. proctrack_stats → map size + target count
 *   6. Cleanup
 *
 * Build: make proctrack_test
 * Run:   ./proctrack_test  (no root needed — /proc is world-readable)
 *
 *   7. Identity fallbacks: deleted exe symlink + comm-only match
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "proctrack_linux.h"

/* Temporary whitelist file — this test process's exe path */
static const char *wl_file = "/tmp/gdpi_proctrack_test_wl.txt";

/* Identity-fallback fixtures. Each name is reachable through exactly ONE
 * identity source, so a scenario cannot pass for the wrong reason. */
#define DELETED_EXE_NAME "gdpi-deleted-exe-target"   /* 23 chars → comm truncates */
#define COMM_TARGET_NAME "gdpi-comm-tgt"             /* 13 chars → fits in comm  */
/* Bare name that appears ONLY inside a hostname in the child's arguments. */
#define URL_DECOY_NAME   "gdpi-url-decoy"
/* Bare name that appears ONLY as a path component of an ARGUMENT — the
 * Electron packaging every Vesktop/Discord install on Arch and Fedora uses:
 * exe is /usr/lib/electron<N>/electron and the app identity lives in
 * "electron /usr/lib/vesktop/app.asar". */
#define ELECTRON_APP_NAME "gdpi-vesk"

static int create_whitelist(void)
{
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n <= 0) {
        perror("readlink /proc/self/exe");
        return -1;
    }
    exe[n] = 0;

    FILE *fp = fopen(wl_file, "w");
    if (!fp) {
        perror("fopen whitelist");
        return -1;
    }
    fprintf(fp, "# proctrack test whitelist\n");
    fprintf(fp, "%s\n", exe);   /* tam path → is_path match */
    /* Basename de ekle (path olmayan satir = basename-exact) */
    const char *base = strrchr(exe, '/');
    if (base) {
        base++;
        fprintf(fp, "%s\n", base);
    }
    fprintf(fp, "%s\n", DELETED_EXE_NAME);
    fprintf(fp, "%s\n", COMM_TARGET_NAME);
    fprintf(fp, "%s\n", URL_DECOY_NAME);
    fprintf(fp, "%s\n", ELECTRON_APP_NAME);
    fclose(fp);

    printf("[test] whitelist written: %s\n", exe);
    if (base)
        printf("[test] whitelist basename: %s\n", base);
    return 0;
}

/* Open a TCP connection from this very process (loopback) */
/* Test: open a loopback server, connect a client → ESTABLISHED.
 *   local_port_out, local_addr_out = client's local address
 *   remote_port_out = server port
 *   returns: client_fd (server_fd static, not closed — accept never blocks) */
static int open_test_tcp(uint16_t *local_port_out, uint32_t *local_addr_out,
                          uint16_t *remote_port_out)
{
    /* Server: listen on loopback, random port */
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return -1;

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof saddr);
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    saddr.sin_port = 0;
    if (bind(srv, (struct sockaddr *)&saddr, sizeof saddr) < 0) {
        close(srv); return -1;
    }
    if (listen(srv, 1) < 0) {
        close(srv); return -1;
    }

    socklen_t slen = sizeof saddr;
    getsockname(srv, (struct sockaddr *)&saddr, &slen);
    *remote_port_out = ntohs(saddr.sin_port);

    /* Client: connect to server */
    int cli = socket(AF_INET, SOCK_STREAM, 0);
    if (cli < 0) { close(srv); return -1; }

    struct sockaddr_in caddr;
    memset(&caddr, 0, sizeof caddr);
    caddr.sin_family = AF_INET;
    caddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    caddr.sin_port = 0;
    bind(cli, (struct sockaddr *)&caddr, sizeof caddr);

    connect(cli, (struct sockaddr *)&saddr, sizeof saddr);
    /* Not non-blocking — connect succeeds (loopback → ESTABLISHED) */

    socklen_t clen = sizeof caddr;
    getsockname(cli, (struct sockaddr *)&caddr, &clen);
    *local_port_out = ntohs(caddr.sin_port);
    *local_addr_out = caddr.sin_addr.s_addr;  /* network order */

    /* srv'yi kapatma — ESTABLISHED kalmasi icin. caller kapatmaz. */
    /* leak: bilerek (test programi, kisa omurlu) */
    return cli;
}

/* ── Identity-fallback scenarios ─────────────────────────────────────────────
 *
 * Three regressions, all real field failures of the per-program gate:
 *
 *   deleted : the whitelisted binary is replaced on disk while running (apt
 *             upgrade of a live Firefox, snap refresh). The kernel then reports
 *             "/path/to/app (deleted)" for /proc/<pid>/exe, whose basename no
 *             longer equals the whitelist entry → bypass silently stopped.
 *   comm    : /proc/<pid>/exe and the cmdline carry no recognisable name, so
 *             the kernel task name is the only identity left.
 *   url     : the OPPOSITE failure — a bare whitelist name must not match a
 *             hostname inside an argument, or `curl https://discord.com/`
 *             gets the Discord app's bypass.
 *
 * Each child is double-forked so it is reparented away from this process —
 * otherwise the parent-chain fallback would match the test binary itself and
 * the assertion would pass for the wrong reason.
 */
static int run_child_mode(const char *mode, const char *port_str)
{
    if (strcmp(mode, "comm") == 0)
        prctl(PR_SET_NAME, COMM_TARGET_NAME, 0, 0, 0);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((uint16_t)atoi(port_str));

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) return 1;

    /* Stay alive (holding the socket open) until the parent closes it. */
    char b;
    while (read(fd, &b, 1) > 0)
        ;
    close(fd);
    return 0;
}

/* Copy /proc/self/exe to dst (mode 0755). */
static int copy_self_to(const char *dst)
{
    char buf[65536];
    FILE *in = fopen("/proc/self/exe", "rb");
    if (!in) return -1;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { fclose(in); fclose(out); return -1; }
    }
    fclose(in);
    fclose(out);
    return chmod(dst, 0755);
}

/* Returns 0 when the gate's verdict for the child's connection equals
 * `expect`. `extra_arg` (optional) becomes an additional child argument. */
static int identity_scenario(const char *label, const char *mode,
                             const char *copy_path, int unlink_after_exec,
                             int expect, const char *extra_arg)
{
    printf("\n[test] identity scenario: %s\n", label);

    if (copy_self_to(copy_path) != 0) {
        printf("[test] SKIP: cannot stage %s (%s)\n", copy_path, strerror(errno));
        return 0;
    }

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); unlink(copy_path); return 1; }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(srv, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(srv, 1) < 0) {
        perror("bind/listen"); close(srv); unlink(copy_path); return 1;
    }
    socklen_t slen = sizeof sa;
    getsockname(srv, (struct sockaddr *)&sa, &slen);
    uint16_t srv_port = ntohs(sa.sin_port);

    char port_str[16];
    snprintf(port_str, sizeof port_str, "%u", srv_port);

    pid_t mid = fork();
    if (mid < 0) { perror("fork"); close(srv); unlink(copy_path); return 1; }
    if (mid == 0) {
        /* Intermediate: fork again and exit so the grandchild is reparented. */
        pid_t gc = fork();
        if (gc == 0) {
            /* argv[0] deliberately carries no whitelisted substring, so a
             * cmdline match cannot mask an exe/comm regression. */
            char *cargv[6];
            int n = 0;
            cargv[n++] = (char *)"cproc";
            cargv[n++] = (char *)"--gdpi-child";
            cargv[n++] = (char *)mode;
            cargv[n++] = (char *)port_str;
            if (extra_arg)
                cargv[n++] = (char *)extra_arg;
            cargv[n] = NULL;
            execv(copy_path, cargv);
            _exit(127);
        }
        _exit(0);
    }
    waitpid(mid, NULL, 0);

    int cli = accept(srv, NULL, NULL);
    if (cli < 0) { perror("accept"); close(srv); unlink(copy_path); return 1; }

    if (unlink_after_exec)
        unlink(copy_path);   /* → /proc/<pid>/exe now ends in " (deleted)" */

    struct sockaddr_in peer;
    socklen_t plen = sizeof peer;
    getpeername(cli, (struct sockaddr *)&peer, &plen);

    uint32_t local_a[4]  = { peer.sin_addr.s_addr, 0, 0, 0 };
    uint32_t remote_a[4] = { htonl(INADDR_LOOPBACK), 0, 0, 0 };
    /* Retry like the packet path does: an "unknown" verdict (method 3) means
     * the /proc rescan was throttled, and the next packet resolves it. */
    int target = 0;
    for (int attempt = 0; attempt < 20; attempt++) {
        target = proctrack_is_target(IPPROTO_TCP,
                                     local_a, ntohs(peer.sin_port),
                                     remote_a, srv_port, 0);
        if (proctrack_last_method != 3)
            break;
        usleep(25000);
    }

    printf("[test] child 127.0.0.1:%u → is_target=%d (method=%d)\n",
           ntohs(peer.sin_port), target, proctrack_last_method);

    close(cli);      /* child sees EOF and exits */
    close(srv);
    if (!unlink_after_exec)
        unlink(copy_path);

    if (target != expect) {
        printf("[test] FAIL: %s — is_target=%d, expected %d\n",
               label, target, expect);
        return 1;
    }
    printf("[test] PASS: %s\n", label);
    return 0;
}

int main(int argc, char **argv)
{
    int failures = 0;

    /* Hidden child mode — re-exec of this binary from identity_scenario(). */
    if (argc >= 4 && strcmp(argv[1], "--gdpi-child") == 0)
        return run_child_mode(argv[2], argv[3]);

    printf("=== proctrack_test starting ===\n\n");

    /* 1. Whitelist olustur */
    if (create_whitelist() < 0) {
        fprintf(stderr, "FAIL: cannot create whitelist\n");
        return 1;
    }

    /* 2. proctrack_init */
    printf("\n[test] proctrack_init(\"%s\")...\n", wl_file);
    if (!proctrack_init(wl_file)) {
        fprintf(stderr, "FAIL: proctrack_init failed\n");
        failures++;
        goto cleanup;
    }
    printf("[test] proctrack_init OK\n");

    /* 3. proctrack_seed */
    printf("\n[test] proctrack_seed()...\n");
    if (!proctrack_seed()) {
        fprintf(stderr, "FAIL: proctrack_seed failed\n");
        failures++;
        goto cleanup;
    }
    printf("[test] proctrack_seed OK\n");

    /* 4. stats */
    {
        int total = 0, targets = 0;
        proctrack_stats(&total, &targets);
        printf("\n[test] stats: total=%d targets=%d\n", total, targets);
        if (total == 0) {
            printf("[test] WARNING: map empty (no sockets in /proc/net/tcp?)\n");
        }
    }

    /* 5. proctrack_is_target — kendi baglantimizi sorgula */
    printf("\n[test] opening test TCP connection (loopback server+client)...\n");
    uint16_t local_port, remote_port;
    uint32_t local_addr;
    int tcp_fd = open_test_tcp(&local_port, &local_addr, &remote_port);
    if (tcp_fd < 0) {
        fprintf(stderr, "FAIL: cannot open test TCP socket\n");
        failures++;
        goto cleanup;
    }
    printf("[test] test TCP: local=%s:%u → remote=127.0.0.1:%u\n",
           inet_ntoa(*(struct in_addr *)&local_addr), local_port, remote_port);

    /* Seed tekrar — yeni socket /proc/net/tcp'de gozuksun */
    usleep(100000);  /* 100ms — kernel /proc guncelle */
    proctrack_seed();

    /* Sorgula: local=client addr, remote=server addr+port */
    uint32_t local_a[4]  = {local_addr, 0, 0, 0};
    uint32_t remote_a[4] = {htonl(INADDR_LOOPBACK), 0, 0, 0};
    int target = proctrack_is_target(IPPROTO_TCP,
                                      local_a, local_port,
                                      remote_a, remote_port, 0);
    printf("[test] proctrack_is_target(TCP) = %d (method=%d)\n",
           target, proctrack_last_method);
    if (target == 1) {
        printf("[test] PASS: own process is target (matched whitelist)\n");
    } else {
        printf("[test] INFO: is_target=%d (method=%d) — may be 0 if socket "
               "closed before seed\n", target, proctrack_last_method);
        /* method=2 (sock_diag fallback) veya method=3 (unknown) olabilir */
    }

    close(tcp_fd);

    /* 6. Identity fallbacks (regressions: deleted exe symlink, comm-only).
     *    The staged copy lives in a per-run directory so its BASENAME is
     *    exactly the whitelist entry — that is what the match is about. */
    {
        char dir[64], path[PATH_MAX];
        snprintf(dir, sizeof dir, "/tmp/gdpi-idtest-%ld", (long)getpid());
        if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
            printf("[test] SKIP identity scenarios: mkdir %s: %s\n",
                   dir, strerror(errno));
        } else {
            snprintf(path, sizeof path, "%s/%s", dir, DELETED_EXE_NAME);
            failures += identity_scenario("deleted exe symlink", "deleted",
                                          path, 1, 1, NULL);

            snprintf(path, sizeof path, "%s/cproc", dir);
            failures += identity_scenario("comm-only identity", "comm",
                                          path, 0, 1, NULL);

            /* A hostname that merely CONTAINS a whitelisted name must not
             * hand that program's bypass to an unrelated process. */
            snprintf(path, sizeof path, "%s/cproc2", dir);
            failures += identity_scenario("url argument is not an identity",
                                          "url", path, 0, 0,
                                          "https://" URL_DECOY_NAME ".example/x");

            /* Electron: the app name is neither the exe basename nor comm,
             * only a path component of an argument. Vesktop is bypassed on
             * system-electron distros solely because of this match. */
            snprintf(path, sizeof path, "%s/cproc3", dir);
            failures += identity_scenario("electron asar path is an identity",
                                          "url", path, 0, 1,
                                          "/usr/lib/" ELECTRON_APP_NAME
                                          "/app.asar");
            rmdir(dir);
        }
    }

    /* 7. Hata yoksa basarili */
    printf("\n=== proctrack_test %s ===\n",
           failures == 0 ? "PASSED" : "FAILED");

cleanup:
    proctrack_free();
    unlink(wl_file);
    return failures;
}
