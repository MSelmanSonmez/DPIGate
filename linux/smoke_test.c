/*
 * smoke_test.c — Phase 1 smoke test: NFQUEUE passthrough.
 *
 * 1. nftables rule: tcp dport 80 → NFQUEUE num 200
 * 2. This program: pio_init(200) → pio_recv → pio_send(PASS)
 * 3. curl http://example.com works → packets passed through → test PASS
 *
 * Usage:
 *   sudo nft add table inet gdpitest
 *   sudo nft 'add chain inet gdpitest output { type filter hook output priority mangle\; }'
 *   sudo nft 'add rule inet gdpitest output tcp dport 80 queue num 200 bypass'
 *   sudo ./smoke_test
 *   # other terminal: curl -s http://example.com | head -1
 *   # smoke_test: "packet N: len=X mark=0 → PASS" should appear
 *   # Exit: Ctrl-C
 *   sudo nft delete table inet gdpitest
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "packet_io.h"

static volatile int running = 1;

static void sighandler(int sig)
{
    (void)sig;
    running = 0;
}

int main(int argc, char *argv[])
{
    int qnum = 200;
    if (argc > 1) qnum = atoi(argv[1]);

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    printf("smoke_test: pio_init(qnum=%d)...\n", qnum);
    if (pio_init(qnum) < 0) {
        fprintf(stderr, "smoke_test: pio_init failed\n");
        return 1;
    }
    printf("smoke_test: NFQUEUE ready. Waiting for packets... (Ctrl-C to stop)\n");

    int count = 0;
    while (running) {
        packet_ctx_t ctx;

        if (pio_recv(&ctx) < 0) {
            if (!running) break;
            fprintf(stderr, "smoke_test: pio_recv error\n");
            break;
        }

        /* Parse IP header for basic info */
        char src[INET6_ADDRSTRLEN] = {0};
        char dst[INET6_ADDRSTRLEN] = {0};
        uint8_t proto = 0;

        if (ctx.len >= 1) {
            uint8_t version = (ctx.data[0] >> 4) & 0xf;
            if (version == 4 && ctx.len >= sizeof(struct iphdr)) {
                struct iphdr *iph = (struct iphdr *)ctx.data;
                proto = iph->protocol;
                inet_ntop(AF_INET, &iph->saddr, src, sizeof(src));
                inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));
            }
        }

        count++;
        printf("packet %d: len=%zu mark=0x%x proto=%d %s → %s → PASS\n",
               count, ctx.len, ctx.fwmark, proto, src, dst);

        if (pio_send(&ctx, VERDICT_PASS) < 0) {
            fprintf(stderr, "smoke_test: pio_send failed\n");
            break;
        }
    }

    printf("\nsmoke_test: %d packet(s) processed. Shutting down...\n", count);
    pio_deinit();
    return 0;
}
