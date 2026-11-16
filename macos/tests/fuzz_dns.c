/* Mutation fuzzer for dns_resolver.c parse paths. Build with ASan+UBSan.
 * usage: fuzz_dns <iterations> <seed> [crashdir] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "dns_resolver.h"

static uint64_t s;
static uint32_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return (uint32_t)s; }

static const char *NAMES[] = { "a.example.com", "discord.com", "x", "WWW.Example.COM.",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.c" };

static size_t put16(uint8_t *b, size_t o, unsigned v) { b[o] = v >> 8; b[o + 1] = v & 0xff; return o + 2; }
static size_t put32(uint8_t *b, size_t o, uint32_t v) { o = put16(b, o, v >> 16); return put16(b, o, v & 0xffff); }

/* seed k: valid-looking responses for (id, name) */
static size_t seed(uint8_t *b, size_t cap, int k, uint16_t id, const char *name)
{
    int ql = dns_build_query(b, cap, id, name);
    if (ql < 0) return 0;
    size_t o = (size_t)ql;
    b[2] |= 0x80;                 /* QR */
    if (k == 0) {                 /* one A, name via pointer to question */
        b[7] = 1;
        o = put16(b, o, 0xC00C); o = put16(b, o, 1); o = put16(b, o, 1); o = put32(b, o, 300);
        o = put16(b, o, 4); b[o++] = 1; b[o++] = 2; b[o++] = 3; b[o++] = 4;
    } else if (k == 1) {          /* CNAME -> c.d, then A for c.d */
        b[7] = 2;
        o = put16(b, o, 0xC00C); o = put16(b, o, 5); o = put16(b, o, 1); o = put32(b, o, 60);
        size_t tgt = o + 2;
        o = put16(b, o, 5); b[o++] = 1; b[o++] = 'c'; b[o++] = 1; b[o++] = 'd'; b[o++] = 0;
        o = put16(b, o, 0xC000 | (unsigned)tgt); o = put16(b, o, 1); o = put16(b, o, 1); o = put32(b, o, 30);
        o = put16(b, o, 4); b[o++] = 9; b[o++] = 9; b[o++] = 9; b[o++] = 9;
    } else if (k == 2) {          /* pointer loop in answer name */
        b[7] = 1;
        size_t here = o;
        o = put16(b, o, 0xC000 | (unsigned)here); o = put16(b, o, 1); o = put16(b, o, 1); o = put32(b, o, 1);
        o = put16(b, o, 4); o = put32(b, o, 0x7f000001);
    } else if (k == 3) {          /* truncated flag */
        b[2] |= 0x02;
    } else {                      /* many CNAME hops to self */
        b[7] = 12;
        for (int i = 0; i < 12 && o + 16 < cap; i++) {
            o = put16(b, o, 0xC00C); o = put16(b, o, 5); o = put16(b, o, 1); o = put32(b, o, 5);
            o = put16(b, o, 2); o = put16(b, o, 0xC00C);
        }
    }
    return o;
}

static size_t mutate(uint8_t *b, size_t len, size_t cap, size_t qend)
{
    int n = 1 + rnd() % 8;
    for (int i = 0; i < n; i++) {
        /* bias most mutations past the question so the parser gets deep */
        size_t lo = (rnd() % 4) ? qend : 0;
        if (len <= lo) lo = 0;
        size_t at = len ? lo + rnd() % (len - lo) : 0;
        switch (rnd() % 9) {
        case 0: if (len) b[at] ^= 1u << (rnd() % 8); break;
        case 1: if (len) b[at] = (uint8_t)rnd(); break;
        case 2: if (len) b[at] = 0xC0 | (rnd() % 4); if (at + 1 < len) b[at + 1] = (uint8_t)rnd(); break;
        case 3: if (len && len < cap) { memmove(b + at + 1, b + at, len - at); b[at] = (uint8_t)rnd(); len++; } break;
        case 4: if (len) { memmove(b + at, b + at + 1, len - at - 1); len--; } break;
        case 5: if (len) len = rnd() % (len + 1); break;                     /* truncate */
        case 6: if (len) b[at] = (uint8_t)(rnd() % 70); break;              /* label len */
        case 7: if (len >= 2 && at + 1 < len) { b[at] = 0xFF; b[at + 1] = 0xFF; } break; /* huge rdlen/count */
        case 8: if (len > 7) { b[6] = rnd() & 1 ? 0xFF : 0; b[7] = (uint8_t)rnd(); } break; /* ANCOUNT */
        }
    }
    return len;
}

int main(int argc, char **argv)
{
    long iters = argc > 1 ? atol(argv[1]) : 1000000;
    s = argc > 2 ? strtoull(argv[2], 0, 10) : 88172645463325252ull;
    if (!s) s = 1;
    uint8_t work[1600];
    long ok = 0, bad = 0, trunc = 0, noans = 0;
    for (long it = 0; it < iters; it++) {
        const char *name = NAMES[rnd() % 5];
        uint16_t id = (uint16_t)rnd();
        size_t len = seed(work, sizeof work, rnd() % 5, id, name);
        size_t qend = 12;
        if (len) {
            uint8_t q[600]; int ql = dns_build_query(q, sizeof q, id, name);
            qend = ql > 0 ? (size_t)ql : 12;
        }
        if (rnd() % 10 == 0) { len = rnd() % 600; for (size_t i = 0; i < len; i++) work[i] = (uint8_t)rnd(); }
        else len = mutate(work, len, sizeof work - 1, qend);
        /* exact-size heap copy: ASan flags any over-read, even by one byte */
        uint8_t *buf = malloc(len ? len : 1);
        memcpy(buf, work, len);
        struct in_addr ip; uint32_t ttl;
        int rc = dns_parse_response(buf, len, id, name, &ip, &ttl);
        free(buf);
        if (rc == DNS_PARSE_OK) ok++; else if (rc == DNS_PARSE_BAD) bad++;
        else if (rc == DNS_PARSE_TRUNC) trunc++; else noans++;

        /* also: random names into build_query and server lists into set_servers */
        if ((it & 15) == 0) {
            char nm[400]; size_t nl = rnd() % sizeof nm;
            for (size_t i = 0; i < nl; i++) { uint32_t r = rnd() % 4; nm[i] = r == 0 ? '.' : (char)(r == 1 ? 'a' : (rnd() & 0xff) | 1); }
            nm[nl] = 0;
            uint8_t q[300]; dns_build_query(q, sizeof q, 1, nm);
            char sv[300]; size_t sl = rnd() % sizeof sv;
            for (size_t i = 0; i < sl; i++) { const char *al = "0123456789.:, \t"; sv[i] = (rnd() % 8) ? al[rnd() % 15] : (char)((rnd() & 0xff) | 1); }
            sv[sl] = 0;
            dns_set_servers(sv);
        }
    }
    printf("iters=%ld ok=%ld bad=%ld trunc=%ld noanswer=%ld\n", iters, ok, bad, trunc, noans);
    return 0;
}
