/*
 * checksum.h — IP/TCP/UDP checksum + packet parser for Linux port.
 *
 * Equivalent of WinDivertHelperCalcChecksums + WinDivertHelperParsePacket.
 * linux/ only.
 */
#ifndef _CHECKSUM_H
#define _CHECKSUM_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>       /* struct ipv6hdr — kernel UAPI */
#include <netinet/tcp.h>
#include <netinet/udp.h>

/*
 * inet_checksum — RFC 1071 generic internet checksum.
 * data: buffer to checksum
 * len: length in bytes
 * returns: 16-bit checksum (to be written in network byte order)
 */
uint16_t inet_checksum(const void *data, size_t len);

/*
 * ipv4_header_checksum — compute + store the IPv4 header checksum.
 * Zeroes hdr->check first, then writes the result back.
 * returns: the computed checksum
 */
uint16_t ipv4_header_checksum(struct iphdr *hdr);

/*
 * tcp_checksum_v4 — TCP checksum (IPv4 pseudo-header).
 * iph: IPv4 header (for src/dst)
 * tcph: start of the TCP header + data
 * tcp_len: total TCP segment length (header + data)
 * returns: 16-bit checksum
 */
uint16_t tcp_checksum_v4(const struct iphdr *iph,
                          const struct tcphdr *tcph, size_t tcp_len);

/*
 * tcp_checksum_v6 — TCP checksum (IPv6 pseudo-header).
 * ip6: IPv6 header (for src/dst)
 * tcph: start of the TCP header + data
 * tcp_len: total TCP segment length
 * returns: 16-bit checksum
 */
uint16_t tcp_checksum_v6(const struct ipv6hdr *ip6,
                          const struct tcphdr *tcph, size_t tcp_len);

/*
 * udp_checksum_v4 — UDP checksum (IPv4 pseudo-header).
 * If the result is 0, send 0xFFFF instead (0 means "no checksum" in IPv4).
 * iph: IPv4 header
 * udph: start of the UDP header + data
 * udp_len: total UDP segment length
 * returns: 16-bit checksum (0 -> 0xFFFF)
 */
uint16_t udp_checksum_v4(const struct iphdr *iph,
                          const struct udphdr *udph, size_t udp_len);

/*
 * udp_checksum_v6 — UDP checksum (IPv6 pseudo-header).
 * The UDP checksum is MANDATORY in IPv6 — if it comes out 0, send 0xFFFF.
 * ip6: IPv6 header
 * udph: start of the UDP header + data
 * udp_len: total UDP segment length
 * returns: 16-bit checksum (0 -> 0xFFFF)
 */
uint16_t udp_checksum_v6(const struct ipv6hdr *ip6,
                          const struct udphdr *udph, size_t udp_len);

/*
 * calc_checksums — equivalent of WinDivertHelperCalcChecksums.
 * Recompute + store every checksum in the packet:
 *   - IPv4 header checksum
 *   - TCP/UDP checksum (with pseudo-header)
 *   - NO IPv6 header checksum (there is none to compute)
 * pkt: complete IP packet (IP header included)
 * len: packet length
 */
void calc_checksums(uint8_t *pkt, size_t len);

/*
 * parse_packet — equivalent of WinDivertHelperParsePacket.
 * Parse an IP packet and return pointers to its headers.
 *
 * pkt: complete IP packet
 * len: packet length
 * out_ip4: IPv4 header pointer (NULL if IPv6)
 * out_ip6: IPv6 header pointer (NULL if IPv4)
 * out_proto: L4 protocol (IPPROTO_TCP / IPPROTO_UDP / ...)
 * out_tcp: TCP header pointer (NULL if not TCP)
 * out_udp: UDP header pointer (NULL if not UDP)
 * out_payload: start of the L7 payload (NULL if none)
 * out_payload_len: payload length
 *
 * returns: 0 = success, -1 = error (short packet, unknown version)
 *
 * Note: extension headers are not followed (same behaviour as WinDivert).
 */
int parse_packet(uint8_t *pkt, size_t len,
                  struct iphdr **out_ip4, struct ipv6hdr **out_ip6,
                  uint8_t *out_proto, struct tcphdr **out_tcp,
                  struct udphdr **out_udp,
                  uint8_t **out_payload, size_t *out_payload_len);

#endif /* _CHECKSUM_H */
