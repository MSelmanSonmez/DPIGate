/*
 * packet_io.h — Packet I/O abstraction for Linux port (NFQUEUE backend).
 *
 * The goodbyedpi.c main loop uses this API. NFQUEUE details stay
 * hidden inside packet_io_linux.c.
 *
 * linux/ only — the Windows tree (windows/) uses WinDivert.
 */
#ifndef _PACKET_IO_H
#define _PACKET_IO_H

#include <stdint.h>
#include <stddef.h>

/* Packet direction (as reported by the kernel) */
typedef enum { PKT_OUTBOUND, PKT_INBOUND } pkt_dir_t;

/* Verdict — used by pio_send */
typedef enum { VERDICT_PASS, VERDICT_MODIFY, VERDICT_DROP } pkt_verdict_t;

/* Fake packet fwmark — the nftables rule bypasses packets carrying this mark */
#define DPI_DESYNC_FWMARK_DEFAULT 0x40000000

/* Packet context — filled in by pio_recv, consumed by pio_send */
typedef struct {
    uint8_t      *data;        /* IP packet (modifiable in place) */
    size_t        len;         /* packet length */
    size_t        cap;         /* buffer capacity */
    pkt_dir_t     dir;         /* outbound / inbound */
    uint32_t      fwmark;      /* current fwmark (fake detection) */
    uint32_t      packet_id;   /* NFQUEUE: required for the verdict */
    void         *backend_data;/* platform-specific opaque (nfq_handle*) */
} packet_ctx_t;

/*
 * pio_init — create the NFQUEUE queue + preinit the raw socket.
 *   qnum: NFQUEUE queue number (must match nftables)
 *   returns: 0 = success, -1 = error
 */
int  pio_init(int qnum);

/* pio_deinit — close the queue + raw socket */
void pio_deinit(void);

/*
 * pio_recv — blocking; wait for the next packet.
 *   ctx: filled in (data, len, dir, fwmark, packet_id)
 *   returns: 0 = packet received, -1 = error / socket closed
 */
int  pio_recv(packet_ctx_t *ctx);

/*
 * pio_send — issue a verdict + hand the packet back to the kernel.
 *   ctx: packet_id + (data+len for MODIFY) are used
 *   v: VERDICT_PASS / VERDICT_MODIFY / VERDICT_DROP
 *   returns: 0 = success, -1 = error
 */
int  pio_send(packet_ctx_t *ctx, pkt_verdict_t v);

/*
 * pio_send_raw — send a fake packet (raw socket, outside the kernel TCP stack).
 *   pkt: complete IP packet (IP header included, IP_HDRINCL)
 *   len: packet length
 *   dst_ip: destination IP (struct in_addr* or struct in6_addr*)
 *   is_ipv6: 1 = IPv6, 0 = IPv4
 *   fwmark: fake packet fwmark (applied via SO_MARK)
 *   returns: 0 = success, -1 = error
 */
int  pio_send_raw(const void *pkt, size_t len,
                   const void *dst_ip, int is_ipv6, uint32_t fwmark);

/*
 * pio_flow_start / pio_flow_stop — FLOW layer.
 *   No-op on Linux (no FLOW layer; proctrack resolves lazily instead).
 */
int  pio_flow_start(void);
void pio_flow_stop(void);

#endif /* _PACKET_IO_H */
