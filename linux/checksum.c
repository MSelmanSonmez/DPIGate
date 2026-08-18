/*
 * checksum.c — IP/TCP/UDP checksum + packet parser (Linux port).
 *
 * Equivalent of WinDivertHelperCalcChecksums + WinDivertHelperParsePacket.
 * Pattern from docs/linux-port-notes.md Section 10.
 */
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "checksum.h"

/* --- RFC 1071 generic internet checksum --- */

uint16_t inet_checksum(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        uint16_t w = ((uint16_t)p[0] << 8) | p[1];
        sum += w;
        p   += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += (uint16_t)p[0] << 8;
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

/* --- IPv4 header checksum --- */

uint16_t ipv4_header_checksum(struct iphdr *hdr)
{
    hdr->check = 0;
    size_t hdr_len = (size_t)hdr->ihl * 4;
    return inet_checksum(hdr, hdr_len);
}

/* --- Helper: checksum over pseudo-header + segment --- */

static uint16_t pseudo_checksum(const void *pseudo, size_t pseudo_len,
                                 const void *seg, size_t seg_len)
{
    size_t total = pseudo_len + seg_len;
    uint8_t *buf = malloc(total);
    if (!buf) return 0;

    memcpy(buf, pseudo, pseudo_len);
    memcpy(buf + pseudo_len, seg, seg_len);
    uint16_t csum = inet_checksum(buf, total);
    free(buf);
    return csum;
}

/* --- TCP checksum (IPv4) --- */

uint16_t tcp_checksum_v4(const struct iphdr *iph,
                          const struct tcphdr *tcph, size_t tcp_len)
{
    struct __attribute__((packed)) {
        uint32_t src;
        uint32_t dst;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t tcp_len;
    } pseudo = {
        iph->saddr, iph->daddr, 0, IPPROTO_TCP,
        htons((uint16_t)tcp_len)
    };

    return pseudo_checksum(&pseudo, sizeof(pseudo), tcph, tcp_len);
}

/* --- TCP checksum (IPv6) --- */

uint16_t tcp_checksum_v6(const struct ipv6hdr *ip6,
                          const struct tcphdr *tcph, size_t tcp_len)
{
    struct __attribute__((packed)) {
        uint8_t  src[16];
        uint8_t  dst[16];
        uint32_t tcp_len;      /* 32-bit length in IPv6 */
        uint8_t  zero[3];
        uint8_t  next_header;  /* IPPROTO_TCP */
    } pseudo;

    memcpy(pseudo.src, &ip6->saddr, 16);
    memcpy(pseudo.dst, &ip6->daddr, 16);
    pseudo.tcp_len     = htonl((uint32_t)tcp_len);
    pseudo.zero[0]    = 0;
    pseudo.zero[1]    = 0;
    pseudo.zero[2]    = 0;
    pseudo.next_header = IPPROTO_TCP;

    return pseudo_checksum(&pseudo, sizeof(pseudo), tcph, tcp_len);
}

/* --- UDP checksum (IPv4) --- */

uint16_t udp_checksum_v4(const struct iphdr *iph,
                          const struct udphdr *udph, size_t udp_len)
{
    struct __attribute__((packed)) {
        uint32_t src;
        uint32_t dst;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t udp_len;
    } pseudo = {
        iph->saddr, iph->daddr, 0, IPPROTO_UDP,
        htons((uint16_t)udp_len)
    };

    uint16_t csum = pseudo_checksum(&pseudo, sizeof(pseudo), udph, udp_len);
    return csum == 0 ? 0xFFFF : csum;   /* 0 -> 0xFFFF (no checksum) */
}

/* --- UDP checksum (IPv6) --- */

uint16_t udp_checksum_v6(const struct ipv6hdr *ip6,
                          const struct udphdr *udph, size_t udp_len)
{
    struct __attribute__((packed)) {
        uint8_t  src[16];
        uint8_t  dst[16];
        uint32_t udp_len;
        uint8_t  zero[3];
        uint8_t  next_header;
    } pseudo;

    memcpy(pseudo.src, &ip6->saddr, 16);
    memcpy(pseudo.dst, &ip6->daddr, 16);
    pseudo.udp_len     = htonl((uint32_t)udp_len);
    pseudo.zero[0]     = 0;
    pseudo.zero[1]     = 0;
    pseudo.zero[2]     = 0;
    pseudo.next_header = IPPROTO_UDP;

    uint16_t csum = pseudo_checksum(&pseudo, sizeof(pseudo), udph, udp_len);
    return csum == 0 ? 0xFFFF : csum;   /* MANDATORY in IPv6 */
}

/* --- calc_checksums — equivalent of WinDivertHelperCalcChecksums --- */

void calc_checksums(uint8_t *pkt, size_t len)
{
    if (len < 1) return;

    uint8_t version = (pkt[0] >> 4) & 0xf;

    if (version == 4) {
        if (len < sizeof(struct iphdr)) return;
        struct iphdr *iph = (struct iphdr *)pkt;
        size_t ip_hdr_len = (size_t)iph->ihl * 4;
        if (len < ip_hdr_len) return;
    if (ip_hdr_len < sizeof(struct iphdr)) return;

        /* IPv4 header checksum */
        iph->check = 0;
        iph->check = htons(ipv4_header_checksum(iph));

        uint8_t proto = iph->protocol;
        size_t l4_len = (size_t)ntohs(iph->tot_len) - ip_hdr_len;
        if (l4_len > len - ip_hdr_len) l4_len = len - ip_hdr_len;

        if (proto == IPPROTO_TCP && l4_len >= sizeof(struct tcphdr)) {
            struct tcphdr *tcph = (struct tcphdr *)(pkt + ip_hdr_len);
            tcph->check = 0;
            tcph->check = htons(tcp_checksum_v4(iph, tcph, l4_len));
        } else if (proto == IPPROTO_UDP && l4_len >= sizeof(struct udphdr)) {
            struct udphdr *udph = (struct udphdr *)(pkt + ip_hdr_len);
            udph->check = 0;
            udph->check = htons(udp_checksum_v4(iph, udph, l4_len));
        }
    } else if (version == 6) {
        if (len < sizeof(struct ipv6hdr)) return;
        struct ipv6hdr *ip6 = (struct ipv6hdr *)pkt;
        size_t ip6_hdr_len = sizeof(struct ipv6hdr);  /* fixed 40 bytes */
        if (len < ip6_hdr_len) return;

        /* IPv6 headers have NO checksum */
        uint8_t proto = ip6->nexthdr;
        size_t l4_len = (size_t)ntohs(ip6->payload_len);
        if (l4_len > len - ip6_hdr_len) l4_len = len - ip6_hdr_len;

        if (proto == IPPROTO_TCP && l4_len >= sizeof(struct tcphdr)) {
            struct tcphdr *tcph = (struct tcphdr *)(pkt + ip6_hdr_len);
            tcph->check = 0;
            tcph->check = htons(tcp_checksum_v6(ip6, tcph, l4_len));
        } else if (proto == IPPROTO_UDP && l4_len >= sizeof(struct udphdr)) {
            struct udphdr *udph = (struct udphdr *)(pkt + ip6_hdr_len);
            udph->check = 0;
            udph->check = htons(udp_checksum_v6(ip6, udph, l4_len));
        }
    }
}

/* --- parse_packet — equivalent of WinDivertHelperParsePacket --- */

int parse_packet(uint8_t *pkt, size_t len,
                  struct iphdr **out_ip4, struct ipv6hdr **out_ip6,
                  uint8_t *out_proto, struct tcphdr **out_tcp,
                  struct udphdr **out_udp,
                  uint8_t **out_payload, size_t *out_payload_len)
{
    /* Defaults */
    if (out_ip4)       *out_ip4 = NULL;
    if (out_ip6)       *out_ip6 = NULL;
    if (out_proto)     *out_proto = 0;
    if (out_tcp)       *out_tcp = NULL;
    if (out_udp)       *out_udp = NULL;
    if (out_payload)   *out_payload = NULL;
    if (out_payload_len) *out_payload_len = 0;

    if (len < 1) return -1;

    uint8_t version = (pkt[0] >> 4) & 0xf;
    size_t ip_hdr_len;
    uint8_t proto;

    if (version == 4) {
        if (len < sizeof(struct iphdr)) return -1;
        struct iphdr *iph = (struct iphdr *)pkt;
        ip_hdr_len = (size_t)iph->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || len < ip_hdr_len) return -1;
        proto = iph->protocol;

        if (out_ip4) *out_ip4 = iph;
    } else if (version == 6) {
        if (len < sizeof(struct ipv6hdr)) return -1;
        struct ipv6hdr *ip6 = (struct ipv6hdr *)pkt;
        ip_hdr_len = sizeof(struct ipv6hdr);  /* 40 */
        proto = ip6->nexthdr;

        if (out_ip6) *out_ip6 = ip6;
        /* Extension headers are not followed (same as WinDivert) */
    } else {
        return -1;
    }

    if (out_proto) *out_proto = proto;

    size_t l4_offset = ip_hdr_len;
    size_t l4_len = len - ip_hdr_len;

    if (proto == IPPROTO_TCP) {
        if (l4_len < sizeof(struct tcphdr)) return -1;
        struct tcphdr *tcph = (struct tcphdr *)(pkt + l4_offset);
        if (out_tcp) *out_tcp = tcph;

        size_t tcp_hdr_len = (size_t)tcph->doff * 4;
        if (tcp_hdr_len < sizeof(struct tcphdr) || l4_len < tcp_hdr_len)
            tcp_hdr_len = l4_len;
        if (l4_len > tcp_hdr_len) {
            if (out_payload) *out_payload = pkt + l4_offset + tcp_hdr_len;
            if (out_payload_len) *out_payload_len = l4_len - tcp_hdr_len;
        }
    } else if (proto == IPPROTO_UDP) {
        if (l4_len < sizeof(struct udphdr)) return -1;
        struct udphdr *udph = (struct udphdr *)(pkt + l4_offset);
        if (out_udp) *out_udp = udph;

        if (l4_len > sizeof(struct udphdr)) {
            if (out_payload) *out_payload = pkt + l4_offset + sizeof(struct udphdr);
            if (out_payload_len) *out_payload_len = l4_len - sizeof(struct udphdr);
        }
    }

    return 0;
}
