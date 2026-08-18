/*
 * rawsend_test.c — Phase 3 test: raw socket fake packet injection.
 *
 * 1. Build a minimal IPv4/TCP SYN packet (with checksum.c)
 * 2. Send it via rawsend_v4 (fwmark = DPI_DESYNC_FWMARK_DEFAULT)
 * 3. Confirm with tcpdump that the packet shows up
 *
 * Usage:
 *   # Terminal 1: listen with tcpdump
 *   sudo tcpdump -ni <iface> 'src host 1.2.3.4 and dst host 10.0.0.1' -c 3
 *   # Terminal 2: run the test
 *   sudo ./rawsend_test
 *
 * Build: make rawsend_test
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "rawsend_linux.h"
#include "checksum.h"
#include "packet_io.h"   /* DPI_DESYNC_FWMARK_DEFAULT */

int main(void)
{
    /* Minimal IPv4/TCP SYN packet: 20 IP + 20 TCP = 40 bytes */
    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));

    struct iphdr *iph = (struct iphdr *)pkt;
    iph->ihl     = 5;
    iph->version = 4;
    iph->tos     = 0;
    iph->tot_len = htons(sizeof(pkt));
    iph->id      = htons(0x1234);
    iph->frag_off = 0;
    iph->ttl     = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr   = inet_addr("1.2.3.4");    /* spoofed src */
    iph->daddr   = inet_addr("10.0.0.1");  /* dst */

    struct tcphdr *tcph = (struct tcphdr *)(pkt + 20);
    tcph->source = htons(54321);
    tcph->dest   = htons(443);
    tcph->doff   = 5;
    tcph->seq    = htonl(0xdeadbeef);
    tcph->ack_seq = 0;
    tcph->syn    = 1;
    tcph->window = htons(65535);

    /* Compute checksums */
    calc_checksums(pkt, sizeof(pkt));

    printf("rawsend_test: packet built (40 bytes)\n");
    printf("  src=1.2.3.4 dst=10.0.0.1 proto=TCP SYN\n");
    printf("  ip.check=0x%04x tcp.check=0x%04x\n",
           ntohs(iph->check), ntohs(tcph->check));

    /* rawsend_init */
    if (rawsend_init() < 0) {
        fprintf(stderr, "rawsend_test: rawsend_init failed (need root?)\n");
        return 1;
    }
    printf("rawsend_test: raw sockets initialized\n");

    /* Send 3 packets */
    struct in_addr dst;
    dst.s_addr = inet_addr("10.0.0.1");

    for (int i = 0; i < 3; i++) {
        /* Change seq on every send */
        tcph->seq = htonl(0xdeadbeef + i * 100);
        calc_checksums(pkt, sizeof(pkt));

        int ret = rawsend_v4(&dst, DPI_DESYNC_FWMARK_DEFAULT, pkt, sizeof(pkt));
        if (ret < 0) {
            fprintf(stderr, "rawsend_test: send %d failed\n", i);
            rawsend_deinit();
            return 1;
        }
        printf("rawsend_test: packet %d sent (fwmark=0x%08x)\n",
               i + 1, DPI_DESYNC_FWMARK_DEFAULT);
    }

    printf("\nrawsend_test: 3 packets sent. Verify with tcpdump:\n");
    printf("  sudo tcpdump -ni any 'src 1.2.3.4 and dst 10.0.0.1' -c 3\n");

    rawsend_deinit();
    return 0;
}
