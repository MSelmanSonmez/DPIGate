/*
 * rawsend_linux.c — Raw socket fake packet injection (Linux port).
 *
 * Derived from the zapret darkmagic.c pattern (docs/linux-port-notes.md Section 7).
 *
 * SOCK_RAW + IPPROTO_RAW → IP_HDRINCL implied (data is a complete IP packet).
 * SO_MARK → fwmark (fake packets do not re-enter NFQUEUE).
 * IP_NODEFRAG → prevent kernel defragmentation.
 * IP_FREEBIND → allow binding to a spoofed src IP.
 * SO_PRIORITY=6 → high priority for fake packets.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "rawsend_linux.h"
#include "packet_io.h"   /* DPI_DESYNC_FWMARK_DEFAULT */

static int raw_sock4 = -1;
static int raw_sock6 = -1;

static int rawsend_socket(sa_family_t family)
{
    int *sock = (family == AF_INET) ? &raw_sock4 : &raw_sock6;
    if (*sock == -1) {
        int yes = 1, pri = 6;

        /* SOCK_RAW + IPPROTO_RAW → IP_HDRINCL implied */
        *sock = socket(family, SOCK_RAW, IPPROTO_RAW);
        if (*sock == -1) {
            fprintf(stderr, "rawsend_socket: socket(%d) failed: %s\n",
                    family, strerror(errno));
            return -1;
        }

        setsockopt(*sock, SOL_SOCKET, SO_PRIORITY, &pri, sizeof(pri));

        if (family == AF_INET) {
            /* PREVENT kernel defragmentation */
            setsockopt(*sock, IPPROTO_IP, IP_NODEFRAG, &yes, sizeof(yes));
            /* Allow binding to a non-existent src IP (spoofed src) */
            setsockopt(*sock, IPPROTO_IP, IP_FREEBIND, &yes, sizeof(yes));
        }
        if (family == AF_INET6) {
            /* IPv6 freebind (kernel 4.15+) — may be unsupported, ignore silently */
#ifdef IPV6_FREEBIND
            setsockopt(*sock, IPPROTO_IPV6, IPV6_FREEBIND, &yes, sizeof(yes));
#endif
        }
    }
    return *sock;
}

static int set_socket_fwmark(int sock, uint32_t fwmark)
{
    if (fwmark == 0) return 1;  /* no mark — skip */
    return setsockopt(sock, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark)) != -1;
}

int rawsend_init(void)
{
    if (rawsend_socket(AF_INET) == -1) return -1;
    if (rawsend_socket(AF_INET6) == -1) {
        /* IPv6 is optional — carry on even if it fails */
        fprintf(stderr, "rawsend_init: IPv6 raw socket failed (non-fatal)\n");
    }
    return 0;
}

void rawsend_deinit(void)
{
    if (raw_sock4 != -1) { close(raw_sock4); raw_sock4 = -1; }
    if (raw_sock6 != -1) { close(raw_sock6); raw_sock6 = -1; }
}

int rawsend(const struct sockaddr *dst, socklen_t salen,
             uint32_t fwmark, const void *data, size_t len)
{
    sa_family_t family = dst->sa_family;
    int sock = rawsend_socket(family);
    if (sock == -1) return -1;
    if (!set_socket_fwmark(sock, fwmark)) {
        fprintf(stderr, "rawsend: SO_MARK failed: %s\n", strerror(errno));
        return -1;
    }

    /* sin6_port = 0 is required for IPv6 (avoids EINVAL on Linux) */
    struct sockaddr_storage dst2;
    memcpy(&dst2, dst, salen);
    if (family == AF_INET6)
        ((struct sockaddr_in6 *)&dst2)->sin6_port = 0;

    ssize_t bytes = sendto(sock, data, len, 0,
                           (struct sockaddr *)&dst2, salen);
    if (bytes == -1) {
        fprintf(stderr, "rawsend: sendto failed: %s\n", strerror(errno));
        return -1;
    }
    return bytes == (ssize_t)len ? 0 : -1;
}

int rawsend_v4(const struct in_addr *dst_ip, uint32_t fwmark,
                const void *data, size_t len)
{
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr = *dst_ip;

    return rawsend((struct sockaddr *)&dst, sizeof(dst), fwmark, data, len);
}

int rawsend_v6(const struct in6_addr *dst_ip, uint32_t fwmark,
                const void *data, size_t len)
{
    struct sockaddr_in6 dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin6_family = AF_INET6;
    dst.sin6_addr = *dst_ip;

    return rawsend((struct sockaddr *)&dst, sizeof(dst), fwmark, data, len);
}
