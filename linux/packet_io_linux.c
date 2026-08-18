/*
 * packet_io_linux.c — NFQUEUE backend for packet_io.h.
 *
 * WinDivert NETWORK layer -> NFQUEUE (libnetfilter_queue).
 * WinDivert fake packet inject -> raw socket (SOCK_RAW, IP_HDRINCL).
 *
 * Pattern lifted from zapret's nfqws.c (Section 6, docs/linux-port-notes.md).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
#include <linux/netfilter.h>               /* NF_ACCEPT, NF_DROP */

#include "packet_io.h"

/* --- NFQUEUE state --- */

static struct nfq_handle   *nfq_h   = NULL;
static struct nfq_q_handle  *nfq_qh  = NULL;
static int                   nfq_fd_val = -1;

/* Recv buffer — nfq_handle_packet requires alignment.
 * MUST hold the largest message the kernel can send us: the copy range
 * requested in pio_init (0xffff) plus netlink + nfnetlink + attribute
 * overhead. A smaller buffer silently truncates jumbo/GSO packets. */
static uint8_t  recv_buf[69632] __attribute__((aligned(8)));

/* Recv buffer for pio_recv — copied from kernel (nfq_get_payload points
 * into kernel buffer, but we copy to give caller a stable buffer). */
static uint8_t  pkt_buf[65536] __attribute__((aligned(8)));


/* Current packet context (filled by callback, consumed by pio_recv) */
static packet_ctx_t  cur_ctx;
static int            cur_ready = 0;    /* 1 = packet waiting in cur_ctx */
static int            cur_ret   = 0;    /* return value for pio_recv */

/*
 * NFQUEUE callback — invoked from inside nfq_handle_packet.
 * It hands us a pointer into the kernel buffer; we copy it and deliver to pio_recv.
 */
static int nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                  struct nfq_data *nfa, void *cookie)
{
    (void)nfmsg; (void)cookie;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ph ? ntohl(ph->packet_id) : 0;
    uint32_t mark = nfq_get_nfmark(nfa);

    uint8_t *data;
    int ilen = nfq_get_payload(nfa, &data);

    if (ilen < 0) {
        /* No payload — passthrough */
        nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, NULL);
        return 0;
    }

    /* Copy — the caller may modify in place without touching the kernel buffer */
    if ((size_t)ilen > sizeof(pkt_buf))
        ilen = sizeof(pkt_buf);
    memcpy(pkt_buf, data, (size_t)ilen);

    /* Fill in ctx */
    cur_ctx.data       = pkt_buf;
    cur_ctx.len        = (size_t)ilen;
    cur_ctx.cap        = sizeof(pkt_buf);
    cur_ctx.fwmark     = mark;
    cur_ctx.packet_id  = id;
    cur_ctx.backend_data = qh;
    /* dir: NFQUEUE INPUT hook (indev>0) = inbound; OUTPUT hook = outbound */
    cur_ctx.dir = (nfq_get_indev(nfa) > 0) ? PKT_INBOUND : PKT_OUTBOUND;

    cur_ready = 1;
    cur_ret   = 0;

    /* Return to nfq_handle_packet — pio_recv will do the one-shot */
    /* Strictly speaking the verdict belongs inside the callback, because
     * nfq_handle_packet holds the buffer until the callback returns. BUT in
     * the pio_* model we treat the callback purely as a "packet arrived"
     * signal and issue the verdict from pio_send.
     *
     * Problem: the nfq_handle_packet callback blocks and then returns.
     * If we do not issue a verdict here the kernel drops the packet (timeout).
     *
     * Workaround: the callback returns a NULL verdict (NF_ACCEPT) and lets the
     * packet through. pio_recv stores the packet in ctx. pio_send then cannot
     * make a separate nfq_set_verdict2 call (packet_id is needed, callback over).
     *
     * So the SIMPLEST APPROACH is: call processPacketData inside the callback
     * and issue the verdict immediately, instead of a pio_recv/pio_send model.
     *
     * BUT the docs/linux-port-notes.md plan specifies pio_recv/pio_send — i.e. the callback
     * only stores the packet in ctx and pio_send issues the verdict.
     *
     * Practical angle: the nfq_handle_packet callback is not BLOCKING —
     * the callback copies the packet and lets it through with NF_ACCEPT, but for
     * a modify pio_send cannot push an already-accepted packet back into the queue.
     *
     * REAL QUESTION: CAN nfq_set_verdict2 be called outside the callback?
     * NO — nfq_set_verdict2 wants qh + packet_id, and qh lives in the callback.
     *
     * CONCLUSION: the pio_recv/pio_send model is awkward with NFQUEUE.
     * Instead: pio_recv blocks (it calls nfq_handle_packet), the callback
     * stores the packet in ctx and returns WITHOUT issuing a verdict.
     * nfq_handle_packet returns. pio_recv returns the packet.
     * When pio_send is called it invokes nfq_set_verdict2.
     *
     * And nfq_set_verdict2 needs qh, which is still valid (nfq_qh is global).
     * packet_id is in ctx too. So pio_send does:
     *   nfq_set_verdict2(nfq_qh, ctx->packet_id, verdict, mark, len, data)
     *
     * IT WORKS — qh is global, packet_id is in ctx, and the callback returning 0 is fine.
     * nfq_handle_packet returns once the callback finishes; no verdict is expected.
     *
     * Check: does nfq_set_verdict2 work outside the callback?
     * Yes — nfq_set_verdict2 only needs qh + packet_id, so outside the callback is fine.
     */

    /* The verdict is issued in pio_send — the callback only delivers the packet */
    return 0;
}

/* --- Raw socket (in rawsend_linux.c) --- */

#include "rawsend_linux.h"

/* --- Public API --- */

int pio_init(int qnum)
{
    nfq_h = nfq_open();
    if (!nfq_h) {
        fprintf(stderr, "pio_init: nfq_open failed: %s\n", strerror(errno));
        return -1;
    }

    if (nfq_bind_pf(nfq_h, AF_INET) < 0) {
        fprintf(stderr, "pio_init: nfq_bind_pf AF_INET failed: %s\n", strerror(errno));
        goto err;
    }

    /* IPv6 bind (optional — carry on even if it fails) */
    nfq_bind_pf(nfq_h, AF_INET6);

    nfq_qh = nfq_create_queue(nfq_h, qnum, &nfq_cb, NULL);
    if (!nfq_qh) {
        fprintf(stderr, "pio_init: nfq_create_queue(%d) failed: %s\n", qnum, strerror(errno));
        goto err;
    }

    if (nfq_set_mode(nfq_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "pio_init: nfq_set_mode failed: %s\n", strerror(errno));
        goto err;
    }
    nfq_set_queue_maxlen(nfq_qh, 4986);

    /* FAIL_OPEN: packets are not dropped if the userspace program crashes */
    nfq_set_queue_flags(nfq_qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN);

    /* 1MB rcv buffer */
    nfnl_rcvbufsiz(nfq_nfnlh(nfq_h), 1024 * 1024);

    /* Suppress ENOBUFS */
    {
        int yes = 1;
#ifdef SOL_NETLINK
#ifdef NETLINK_NO_ENOBUFS
        setsockopt(nfq_fd(nfq_h), SOL_NETLINK, NETLINK_NO_ENOBUFS, &yes, sizeof(yes));
#endif
#endif
    }

    nfq_fd_val = nfq_fd(nfq_h);

    /* Raw socket preinit (needs root) — rawsend_linux.c */
    if (rawsend_init() < 0) {
        fprintf(stderr, "pio_init: rawsend_init failed: %s\n", strerror(errno));
        goto err;
    }

    return 0;

err:
    pio_deinit();
    return -1;
}

void pio_deinit(void)
{
    if (nfq_qh) {
        nfq_destroy_queue(nfq_qh);
        nfq_qh = NULL;
    }
    if (nfq_h) {
        nfq_close(nfq_h);
        nfq_h = NULL;
    }
    nfq_fd_val = -1;

    rawsend_deinit();
}

int pio_recv(packet_ctx_t *ctx)
{
    ssize_t rd;
    cur_ready = 0;

    do {
        rd = recv(nfq_fd_val, recv_buf, sizeof(recv_buf), 0);
        if (rd < 0) {
            if (errno == ENOBUFS) continue;   /* buffer overrun → retry */
            if (errno == EINTR)  continue;   /* signal → retry */
            return -1;                         /* real error */
        }
        if (rd > 0) {
            nfq_handle_packet(nfq_h, (char *)recv_buf, (int)rd);
        }
    } while (!cur_ready);

    *ctx = cur_ctx;
    return cur_ret;
}

int pio_send(packet_ctx_t *ctx, pkt_verdict_t v)
{
    uint32_t verdict;

    switch (v) {
    case VERDICT_MODIFY:
        verdict = NF_ACCEPT;
        return nfq_set_verdict2(nfq_qh, ctx->packet_id, verdict,
                               ctx->fwmark, (uint32_t)ctx->len, ctx->data) < 0 ? -1 : 0;

    case VERDICT_DROP:
        verdict = NF_DROP;
        return nfq_set_verdict2(nfq_qh, ctx->packet_id, verdict,
                               ctx->fwmark, 0, NULL) < 0 ? -1 : 0;

    case VERDICT_PASS:
    default:
        verdict = NF_ACCEPT;
        return nfq_set_verdict2(nfq_qh, ctx->packet_id, verdict,
                               ctx->fwmark, 0, NULL) < 0 ? -1 : 0;
    }
}

int pio_send_raw(const void *pkt, size_t len,
                  const void *dst_ip, int is_ipv6, uint32_t fwmark)
{
    if (is_ipv6) {
        return rawsend_v6((const struct in6_addr *)dst_ip, fwmark, pkt, len);
    } else {
        return rawsend_v4((const struct in_addr *)dst_ip, fwmark, pkt, len);
    }
}

int  pio_flow_start(void)  { return 0; }   /* no-op — no FLOW layer on Linux */
void pio_flow_stop(void)   {               /* no-op */ }
