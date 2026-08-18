/*
 * rawsend_linux.h — Raw socket fake packet injection (Linux port).
 *
 * Equivalent of WinDivertSend (fake packet injection).
 * SOCK_RAW + IPPROTO_RAW → IP_HDRINCL implied.
 * fwmark via SO_MARK → fake packets do not re-enter NFQUEUE.
 *
 * linux/ only.
 */
#ifndef _RAWSEND_LINUX_H
#define _RAWSEND_LINUX_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>

/*
 * rawsend_init — preinit the raw sockets (needs root).
 *   Called from pio_init, BEFORE the privilege drop.
 *   returns: 0 = success, -1 = error
 */
int  rawsend_init(void);

/* rawsend_deinit — close the raw sockets */
void rawsend_deinit(void);

/*
 * rawsend — send a fake IP packet (raw socket, IP_HDRINCL).
 *   dst: destination address (struct sockaddr_in* or struct sockaddr_in6*)
 *   salen: size of dst (sizeof(struct sockaddr_in) or sockaddr_in6)
 *   fwmark: fake packet fwmark (via SO_MARK, 0 = no mark)
 *   data: complete IP packet (IP header included)
 *   len: packet length
 *   returns: 0 = success, -1 = error
 */
int  rawsend(const struct sockaddr *dst, socklen_t salen,
              uint32_t fwmark, const void *data, size_t len);

/*
 * rawsend_v4 — IPv4 shorthand (struct in_addr → rawsend).
 *   dst_ip: destination IPv4 (struct in_addr*)
 *   fwmark: fake packet fwmark
 *   data: complete IP packet
 *   len: packet length
 */
int  rawsend_v4(const struct in_addr *dst_ip, uint32_t fwmark,
                 const void *data, size_t len);

/*
 * rawsend_v6 — IPv6 shorthand (struct in6_addr → rawsend).
 *   dst_ip: destination IPv6 (struct in6_addr*)
 *   fwmark: fake packet fwmark
 *   data: complete IPv6 packet
 *   len: packet length
 */
int  rawsend_v6(const struct in6_addr *dst_ip, uint32_t fwmark,
                 const void *data, size_t len);

#endif /* _RAWSEND_LINUX_H */
