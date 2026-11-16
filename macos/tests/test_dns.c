/* Unit tests for byedpi/dns_resolver.c (parser, timeout, cache). No real network. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include "dns_resolver.h"

static int passed, failed;
static void check(const char *what, int ok)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    ok ? passed++ : failed++;
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Builds a response: the query for (id, name) plus raw answer bytes. */
static size_t make_resp(uint8_t *out, uint16_t id, const char *name, int flags2,
        int rcode, int ancount, const uint8_t *ans, size_t anlen)
{
    int ql = dns_build_query(out, 512, id, name);
    out[2] = (uint8_t)(0x80 | 0x01 | flags2);
    out[3] = (uint8_t)(0x80 | rcode);
    out[6] = (uint8_t)(ancount >> 8); out[7] = (uint8_t)ancount;
    memcpy(out + ql, ans, anlen);
    return (size_t)ql + anlen;
}

/* RR with a compression pointer (0xC00C) to the question name. */
#define PTR_Q 0xC0, 0x0C
#define TTL(n) 0, 0, (n) >> 8, (n) & 0xff

static void test_parser(void)
{
    uint8_t b[512];
    struct in_addr ip; uint32_t ttl = 0;
    char s[32];

    const uint8_t plain[] = { PTR_Q, 0,1, 0,1, TTL(300), 0,4, 1,2,3,4 };
    size_t n = make_resp(b, 0x1234, "example.com", 0, 0, 1, plain, sizeof plain);
    check("parser: plain A", dns_parse_response(b, n, 0x1234, "example.com", &ip, &ttl) == DNS_PARSE_OK
            && inet_ntop(AF_INET, &ip, s, sizeof s) && !strcmp(s, "1.2.3.4") && ttl == 300);

    /* www.example.com CNAME -> edge.example.com (name via pointer to "example.com"
       at offset 12+4 = 16), then edge.example.com A 9.8.7.6. */
    const uint8_t chain[] = {
        PTR_Q, 0,5, 0,1, TTL(60), 0,7, 4,'e','d','g','e', 0xC0,0x10,
        4,'E','D','G','E', 0xC0,0x10, 0,1, 0,1, TTL(120), 0,4, 9,8,7,6 };
    n = make_resp(b, 7, "www.example.com", 0, 0, 2, chain, sizeof chain);
    check("parser: CNAME -> A, compressed names, min TTL",
            dns_parse_response(b, n, 7, "www.example.com", &ip, &ttl) == DNS_PARSE_OK
            && inet_ntop(AF_INET, &ip, s, sizeof s) && !strcmp(s, "9.8.7.6") && ttl == 60);

    /* A record belonging to an unrelated name must not be accepted. */
    const uint8_t other[] = { 5,'o','t','h','e','r', 0, 0,1, 0,1, TTL(300), 0,4, 6,6,6,6 };
    n = make_resp(b, 7, "example.com", 0, 0, 1, other, sizeof other);
    check("parser: unrelated A rejected",
            dns_parse_response(b, n, 7, "example.com", &ip, &ttl) == DNS_PARSE_NOANSWER);

    n = make_resp(b, 0x1234, "example.com", 0, 0, 1, plain, sizeof plain);
    check("parser: wrong ID rejected",
            dns_parse_response(b, n, 0x1235, "example.com", &ip, &ttl) == DNS_PARSE_BAD);
    check("parser: wrong question rejected",
            dns_parse_response(b, n, 0x1234, "example.org", &ip, &ttl) == DNS_PARSE_BAD);
    check("parser: truncated packet rejected",
            dns_parse_response(b, n - 3, 0x1234, "example.com", &ip, &ttl) == DNS_PARSE_BAD);

    n = make_resp(b, 9, "example.com", 0x02, 0, 0, plain, 0);
    check("parser: TC bit", dns_parse_response(b, n, 9, "example.com", &ip, &ttl) == DNS_PARSE_TRUNC);

    n = make_resp(b, 9, "nope.example", 0, 3, 0, plain, 0);
    check("parser: NXDOMAIN", dns_parse_response(b, n, 9, "nope.example", &ip, &ttl) == DNS_PARSE_NOANSWER);

    /* Compression pointer loop must not hang or crash. */
    const uint8_t loop[] = { 0xC0, 12 + 17, 0,1, 0,1, TTL(1), 0,4, 1,1,1,1 };
    uint8_t lp[512];
    n = make_resp(lp, 3, "example.com", 0, 0, 1, loop, sizeof loop);
    lp[12 + 17] = 0xC0; lp[12 + 18] = 12 + 17;   /* points at itself */
    check("parser: pointer loop is bounded",
            dns_parse_response(lp, n, 3, "example.com", &ip, &ttl) != DNS_PARSE_OK);
}

static int bind_udp(struct sockaddr_in *a)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(fd, (struct sockaddr *)a, sizeof *a);
    socklen_t l = sizeof *a;
    getsockname(fd, (struct sockaddr *)a, &l);
    return fd;
}

static void test_timeout(void)
{
    struct sockaddr_in a; char list[64]; struct in_addr ip;
    int fd = bind_udp(&a);   /* bound but never answers */
    snprintf(list, sizeof list, "127.0.0.1:%d", ntohs(a.sin_port));
    dns_set_servers(list);
    dns_cache_clear();
    double t0 = now_s();
    int r = dns_resolve("silent.example.com", &ip);
    double dt = now_s() - t0;
    printf("  silent server: rc=%d, %.2f s\n", r, dt);
    check("timeout: silent server fails in ~3 x 1 s, not 30 s", r == -1 && dt > 2.5 && dt < 4.5);
    t0 = now_s();
    r = dns_resolve("silent.example.com", &ip);
    check("negative cache: repeat fails instantly", r == -1 && now_s() - t0 < 0.2);
    close(fd);
}

static void test_cache_and_end_to_end(void)
{
    struct sockaddr_in a; char list[64]; struct in_addr ip; char s[32];
    int fd = bind_udp(&a);
    snprintf(list, sizeof list, "127.0.0.1:%d", ntohs(a.sin_port));
    pid_t pid = fork();
    if (pid == 0) {   /* fake server: answers exactly one query with CNAME + A */
        uint8_t q[512], r[512];
        struct sockaddr_in from; socklen_t fl = sizeof from;
        ssize_t n = recvfrom(fd, q, sizeof q, 0, (struct sockaddr *)&from, &fl);
        /* CNAME -> "t.example.org", then A for that name */
        const uint8_t cn[] = { 0xC0,0x0C, 0,5, 0,1, TTL(10), 0,15,
                1,'t',7,'e','x','a','m','p','l','e',3,'o','r','g',0 };
        const uint8_t aa[] = { 1,'t',7,'e','x','a','m','p','l','e',3,'o','r','g',0,
                0,1, 0,1, TTL(40), 0,4, 10,20,30,40 };
        memcpy(r, q, n);
        r[2] = 0x81; r[3] = 0x80; r[6] = 0; r[7] = 2;
        memcpy(r + n, cn, sizeof cn);
        memcpy(r + n + sizeof cn, aa, sizeof aa);
        sendto(fd, r, n + sizeof cn + sizeof aa, 0, (struct sockaddr *)&from, fl);
        _exit(0);
    }
    close(fd);
    dns_set_servers(list);
    dns_cache_clear();
    int r = dns_resolve("Alias.Example.COM", &ip);
    check("end to end: CNAME chain via fake server", r == 0
            && inet_ntop(AF_INET, &ip, s, sizeof s) && !strcmp(s, "10.20.30.40"));
    int st; waitpid(pid, &st, 0);   /* server is gone now */
    double t0 = now_s();
    r = dns_resolve("alias.example.com", &ip);
    check("cache: second lookup served without server (TTL clamped to >= 30 s)",
            r == 0 && now_s() - t0 < 0.2 && ip.s_addr == inet_addr("10.20.30.40"));
}

int main(void)
{
    test_parser();
    test_timeout();
    test_cache_and_end_to_end();
    printf("DNS SUMMARY: %d passed, %d failed\n", passed, failed);
    return failed != 0;
}
