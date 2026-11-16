/* DPIGate: bounded IPv4 resolver, see dns_resolver.h. */
#include "dns_resolver.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MAX_SERVERS   4
#define ATTEMPTS      3
#define TIMEOUT_MS    1000
#define TCP_TIMEOUT_MS 2000
#define CACHE_MAX     1024
#define TTL_MIN       30
#define TTL_MAX       3600
#define NEG_TTL       5
#define NAME_MAX_LEN  253

/* ---- wire format ---------------------------------------------------------- */

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static int valid_name(const char *name, size_t *len)
{
    size_t n = strlen(name), label = 0;
    if (n > 0 && name[n - 1] == '.') n--;
    if (n == 0 || n > NAME_MAX_LEN) return 0;
    for (size_t i = 0; i < n; i++) {
        if (name[i] == '.') {
            if (label == 0) return 0;
            label = 0;
        } else if (++label > 63) {
            return 0;
        }
    }
    if (label == 0) return 0;
    *len = n;
    return 1;
}

int dns_build_query(uint8_t *buf, size_t cap, uint16_t id, const char *name)
{
    size_t n;
    if (!valid_name(name, &n) || cap < 12 + n + 2 + 4) return -1;
    memset(buf, 0, 12);
    buf[0] = id >> 8; buf[1] = id & 0xff;
    buf[2] = 0x01;          /* RD */
    buf[5] = 1;             /* QDCOUNT */
    size_t o = 12, start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || name[i] == '.') {
            buf[o++] = (uint8_t)(i - start);
            memcpy(buf + o, name + start, i - start);
            o += i - start;
            start = i + 1;
        }
    }
    buf[o++] = 0;
    buf[o++] = 0; buf[o++] = 1;   /* QTYPE A */
    buf[o++] = 0; buf[o++] = 1;   /* QCLASS IN */
    return (int)o;
}

/*
 * Decodes a (possibly compressed) name at *pos into out (lowercase, dotted,
 * NUL-terminated) and advances *pos past the name as it appears in place.
 */
static int read_name(const uint8_t *b, size_t len, size_t *pos, char *out, size_t cap)
{
    size_t p = *pos, o = 0, jumps = 0;
    int jumped = 0;
    for (;;) {
        if (p >= len) return -1;
        uint8_t c = b[p];
        if ((c & 0xC0) == 0xC0) {
            if (p + 1 >= len) return -1;
            size_t target = ((c & 0x3F) << 8) | b[p + 1];
            if (!jumped) *pos = p + 2;
            jumped = 1;
            if (target >= len || ++jumps > 16) return -1;
            p = target;
        } else if (c & 0xC0) {
            return -1;
        } else if (c == 0) {
            if (!jumped) *pos = p + 1;
            if (o >= cap) return -1;
            if (o > 0 && out[o - 1] == '.') o--;
            out[o] = 0;
            return 0;
        } else {
            if (p + 1 + c > len || o + c + 1 >= cap) return -1;
            for (size_t i = 0; i < c; i++)
                out[o++] = (char)tolower(b[p + 1 + i]);
            out[o++] = '.';
            p += 1 + c;
        }
    }
}

static void lower_copy(char *dst, const char *src, size_t cap)
{
    size_t i = 0;
    for (; src[i] && i + 1 < cap; i++) dst[i] = (char)tolower((unsigned char)src[i]);
    if (i > 0 && dst[i - 1] == '.') i--;
    dst[i] = 0;
}

int dns_parse_response(const uint8_t *b, size_t len, uint16_t id,
        const char *name, struct in_addr *ip, uint32_t *ttl)
{
    char qname[NAME_MAX_LEN + 2], cur[NAME_MAX_LEN + 2], tmp[NAME_MAX_LEN + 2];
    size_t pos;
    if (len < 12 || rd16(b) != id) return DNS_PARSE_BAD;
    if (!(b[2] & 0x80)) return DNS_PARSE_BAD;               /* not a response */
    if (rd16(b + 4) != 1) return DNS_PARSE_BAD;             /* one question */
    pos = 12;
    if (read_name(b, len, &pos, tmp, sizeof tmp) || pos + 4 > len) return DNS_PARSE_BAD;
    lower_copy(qname, name, sizeof qname);
    if (strcmp(tmp, qname) != 0 || rd16(b + pos) != 1 || rd16(b + pos + 2) != 1)
        return DNS_PARSE_BAD;                               /* question mismatch */
    pos += 4;
    if (b[2] & 0x02) return DNS_PARSE_TRUNC;
    if ((b[3] & 0x0F) != 0) return DNS_PARSE_NOANSWER;

    unsigned an = rd16(b + 6);
    size_t first = pos;
    strcpy(cur, qname);
    uint32_t min_ttl = 0xFFFFFFFFu;
    for (int hop = 0; hop < 10; hop++) {
        int progressed = 0;
        pos = first;
        for (unsigned i = 0; i < an; i++) {
            char rn[NAME_MAX_LEN + 2];
            if (read_name(b, len, &pos, rn, sizeof rn) || pos + 10 > len) return DNS_PARSE_BAD;
            unsigned type = rd16(b + pos), cls = rd16(b + pos + 2);
            uint32_t t = rd32(b + pos + 4);
            size_t rdlen = rd16(b + pos + 8), rd = pos + 10;
            if (rd + rdlen > len) return DNS_PARSE_BAD;
            pos = rd + rdlen;
            if (cls != 1 || strcmp(rn, cur) != 0) continue;
            if (type == 1 && rdlen == 4) {
                memcpy(&ip->s_addr, b + rd, 4);
                if (t < min_ttl) min_ttl = t;
                *ttl = min_ttl;
                return DNS_PARSE_OK;
            }
            if (type == 5) {
                size_t p2 = rd;
                if (read_name(b, len, &p2, tmp, sizeof tmp)) return DNS_PARSE_BAD;
                strcpy(cur, tmp);
                if (t < min_ttl) min_ttl = t;
                progressed = 1;
                break;
            }
        }
        if (!progressed) break;
    }
    return DNS_PARSE_NOANSWER;
}

/* ---- servers -------------------------------------------------------------- */

static struct sockaddr_in servers[MAX_SERVERS];
static int nservers;

int dns_set_servers(const char *list)
{
    struct sockaddr_in tmp[MAX_SERVERS];
    int n = 0;
    char buf[256];
    if (!list || strlen(list) >= sizeof buf) return -1;
    strcpy(buf, list);
    for (char *tok = strtok(buf, " ,\t"); tok; tok = strtok(NULL, " ,\t")) {
        if (n >= MAX_SERVERS) break;
        int port = 53;
        char *colon = strchr(tok, ':');
        if (colon) {
            *colon = 0;
            port = atoi(colon + 1);
            if (port <= 0 || port > 65535) return -1;
        }
        memset(&tmp[n], 0, sizeof tmp[n]);
        tmp[n].sin_family = AF_INET;
        tmp[n].sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, tok, &tmp[n].sin_addr) != 1) return -1;
        n++;
    }
    if (n == 0) return -1;
    memcpy(servers, tmp, sizeof tmp);
    nservers = n;
    return 0;
}

static void init_servers(void)
{
    if (nservers) return;
    const char *env = getenv("DPIGATE_DNS");
    if (env && *env && dns_set_servers(env) == 0) return;
    dns_set_servers("1.1.1.1 1.0.0.1");
}

/* ---- transport ------------------------------------------------------------ */

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)(ts.tv_sec * 1000L + ts.tv_nsec / 1000000L);
}

static int udp_query(const struct sockaddr_in *srv, const uint8_t *q, int qlen,
        uint16_t id, const char *name, struct in_addr *ip, uint32_t *ttl)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return DNS_PARSE_BAD;
    int rc = DNS_PARSE_BAD;
    if (connect(fd, (const struct sockaddr *)srv, sizeof *srv) == 0 && send(fd, q, qlen, 0) == qlen) {
        long deadline = now_ms() + TIMEOUT_MS;
        for (;;) {
            long left = deadline - now_ms();
            if (left <= 0) break;
            struct pollfd p = { .fd = fd, .events = POLLIN };
            int r = poll(&p, 1, (int)left);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) break;
            uint8_t resp[1500];
            ssize_t n = recv(fd, resp, sizeof resp, 0);
            if (n < 0) break;   /* e.g. ECONNREFUSED: give up on this server */
            rc = dns_parse_response(resp, (size_t)n, id, name, ip, ttl);
            if (rc != DNS_PARSE_BAD) break;   /* wrong ID/question: keep waiting */
        }
    }
    close(fd);
    return rc;
}

static int wait_fd(int fd, short ev, long deadline)
{
    for (;;) {
        long left = deadline - now_ms();
        if (left <= 0) return -1;
        struct pollfd p = { .fd = fd, .events = ev };
        int r = poll(&p, 1, (int)left);
        if (r < 0 && errno == EINTR) continue;
        return r > 0 ? 0 : -1;
    }
}

static int tcp_query(const struct sockaddr_in *srv, const uint8_t *q, int qlen,
        uint16_t id, const char *name, struct in_addr *ip, uint32_t *ttl)
{
    int rc = DNS_PARSE_BAD;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return rc;
    long deadline = now_ms() + TCP_TIMEOUT_MS;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    if (connect(fd, (const struct sockaddr *)srv, sizeof *srv) < 0) {
        int soerr = 0; socklen_t sl = sizeof soerr;
        if (errno != EINPROGRESS || wait_fd(fd, POLLOUT, deadline) ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) || soerr) goto out;
    }
    uint8_t msg[2 + 512];
    if (qlen > 512) goto out;
    msg[0] = (uint8_t)(qlen >> 8); msg[1] = (uint8_t)qlen;
    memcpy(msg + 2, q, qlen);
    for (size_t off = 0; off < (size_t)qlen + 2; ) {
        if (wait_fd(fd, POLLOUT, deadline)) goto out;
        ssize_t n = send(fd, msg + off, qlen + 2 - off, 0);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (n <= 0) goto out;
        off += (size_t)n;
    }
    uint8_t lenb[2];
    static uint8_t resp[65535];
    size_t got = 0, want = 2;
    uint8_t *dst = lenb;
    int stage = 0;
    for (;;) {
        while (got < want) {
            if (wait_fd(fd, POLLIN, deadline)) goto out;
            ssize_t n = recv(fd, dst + got, want - got, 0);
            if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            if (n <= 0) goto out;
            got += (size_t)n;
        }
        if (stage == 0) {
            want = rd16(lenb);
            if (want < 12) goto out;
            dst = resp; got = 0; stage = 1;
        } else break;
    }
    rc = dns_parse_response(resp, want, id, name, ip, ttl);
out:
    close(fd);
    return rc;
}

/* ---- cache ---------------------------------------------------------------- */

struct entry {
    char name[NAME_MAX_LEN + 2];
    struct in_addr ip;
    int neg;
    long expires;      /* ms, monotonic */
    unsigned long used;
    int live;
};
static struct entry cache[CACHE_MAX];
static unsigned long tick;

void dns_cache_clear(void) { memset(cache, 0, sizeof cache); }

static struct entry *cache_find(const char *name)
{
    long t = now_ms();
    for (int i = 0; i < CACHE_MAX; i++) {
        if (cache[i].live && strcmp(cache[i].name, name) == 0) {
            if (cache[i].expires <= t) { cache[i].live = 0; return NULL; }
            cache[i].used = ++tick;
            return &cache[i];
        }
    }
    return NULL;
}

static void cache_put(const char *name, const struct in_addr *ip, int neg, uint32_t ttl)
{
    struct entry *e = NULL;
    long t = now_ms();
    for (int i = 0; i < CACHE_MAX; i++) {
        if (cache[i].live && strcmp(cache[i].name, name) == 0) { e = &cache[i]; break; }
    }
    if (!e) {
        for (int i = 0; i < CACHE_MAX; i++) {
            if (!cache[i].live || cache[i].expires <= t) { e = &cache[i]; break; }
            if (!e || cache[i].used < e->used) e = &cache[i];
        }
    }
    snprintf(e->name, sizeof e->name, "%s", name);
    e->neg = neg;
    if (ip) e->ip = *ip;
    e->expires = t + (long)ttl * 1000L;
    e->used = ++tick;
    e->live = 1;
}

/* ---- public --------------------------------------------------------------- */

int dns_resolve(const char *name, struct in_addr *ip)
{
    char key[NAME_MAX_LEN + 2];
    size_t n;
    if (!valid_name(name, &n)) return -1;
    lower_copy(key, name, sizeof key);

    struct entry *e = cache_find(key);
    if (e) {
        if (e->neg) return -1;
        *ip = e->ip;
        return 0;
    }
    init_servers();

    uint8_t q[300];
    uint32_t ttl = 0;
    for (int a = 0; a < ATTEMPTS; a++) {
        const struct sockaddr_in *srv = &servers[a % nservers];
        uint16_t id = (uint16_t)arc4random();
        int ql = dns_build_query(q, sizeof q, id, key);
        if (ql < 0) return -1;
        int rc = udp_query(srv, q, ql, id, key, ip, &ttl);
        if (rc == DNS_PARSE_TRUNC) {
            id = (uint16_t)arc4random();
            ql = dns_build_query(q, sizeof q, id, key);
            rc = tcp_query(srv, q, ql, id, key, ip, &ttl);
        }
        if (rc == DNS_PARSE_OK) {
            if (ttl < TTL_MIN) ttl = TTL_MIN;
            if (ttl > TTL_MAX) ttl = TTL_MAX;
            cache_put(key, ip, 0, ttl);
            return 0;
        }
        if (rc == DNS_PARSE_NOANSWER) break;   /* authoritative-ish: do not retry */
    }
    cache_put(key, NULL, 1, NEG_TTL);
    return -1;
}
