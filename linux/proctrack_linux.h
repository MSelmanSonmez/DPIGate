/*
 * proctrack_linux.h — Per-program connection tracker (Linux port).
 *
 * Port of the Windows proctrack.h.
 * WinDivert FLOW layer → sock_diag + inode→PID cache.
 * GetExtendedTcpTable → /proc/net/tcp + /proc/net/tcp6.
 * GetExtendedUdpTable → /proc/net/udp + /proc/net/udp6.
 *
 * linux/ only.
 */
#ifndef _PROCTRACK_LINUX_H
#define _PROCTRACK_LINUX_H

#include <stdint.h>

/*
 * Per-program connection tracker.
 *
 * Maps each network 5-tuple (proto, local addr, local port, remote addr,
 * remote port) to a boolean "is_target" flag, indicating whether the owning
 * process is on the bypass whitelist.
 *
 * The map is populated two ways:
 *   1. proctrack_seed()  — snapshot of already-open TCP/UDP sockets at startup
 *      (/proc/net/tcp + /proc/net/udp parse → inode → PID cache).
 *   2. Lazy OS fallback  — on cache miss, sock_diag (or /proc/net/tcp) resolves
 *      the socket inode → PID → exe path → whitelist match.
 *
 * proctrack_is_target() is queried from the main NFQUEUE loop. Safe default is
 * FALSE: packets whose 5-tuple is unknown are NOT bypassed (left untouched).
 *
 * NOTE: all port arguments are in HOST byte order. Callers must convert packet
 * header ports (network order) with ntohs() before calling proctrack_is_target.
 */

int  proctrack_init(const char *whitelist_file);
void proctrack_free(void);
int  proctrack_seed(void);
int  proctrack_start_watcher_thread(void);
void proctrack_stop_watcher_thread(void);

/* No FLOW thread on Linux — no-op. pio_flow_start/stop are no-ops too. */
/* proctrack_start_flow_thread / proctrack_stop_flow_thread REMOVED */

void proctrack_stats(int *total, int *targets);

int  proctrack_is_target(uint8_t proto,
                         const void *local_addr,  uint16_t local_port,
                         const void *remote_addr, uint16_t remote_port,
                         int is_ipv6);

/* Debug: records how the most recent proctrack_is_target() call resolved.
 * Values: 0=map-hit, 1=udp-local-fallback, 2=os-tcp-fallback, 3=unknown.
 * Read only from the main NETWORK thread (single-threaded). */
extern int proctrack_last_method;

#endif /* _PROCTRACK_LINUX_H */
