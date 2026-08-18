/**
 * TCP (TTL) Connection Tracker for GoodbyeDPI
 *
 * Monitors SYN/ACK only, to extract the TTL value of the remote server.
 *
 */

#include <windows.h>
#include <time.h>
#include <stdio.h>
#include <math.h>
#include "goodbyedpi.h"
#include "ttltrack.h"
#include "utils/uthash.h"


/* key ('4' for IPv4 or '6' for IPv6 + srcip[16] + dstip[16] + srcport[2] + dstport[2]) */
#define TCP_CONNRECORD_KEY_LEN 37

#define TCP_CLEANUP_INTERVAL_SEC 30

/* Hard ceiling on tracked handshakes - a SECOND bound, independent of the 30
 * second age-out above, which stays exactly as it was.
 *
 * Why it is needed: the firewall rules queue ALL inbound TCP with source port
 * 80/443 (goodbyedpi.nft "tcp sport { 80, 443 } queue"), so every inbound
 * SYN+ACK reaches tcp_handle_incoming - no handshake, no established
 * connection and no reply required. An off-path attacker spraying spoofed
 * SYN+ACKs therefore inserts one record per packet, and until this ceiling
 * the 30 second sweep was the only thing reclaiming them: at 100k pps that is
 * millions of live records, hundreds of MB, inside a single sweep interval,
 * in a process holding CAP_NET_ADMIN.
 *
 * Why 16384: a record is ~112 bytes, plus allocator and hash-bucket overhead,
 * so ~160 bytes each - a ceiling of ~2.6 MB. That is a rounding error for a
 * desktop process and a hard stop for the flood. A record only lives from the
 * SYN+ACK until that connection's first outbound data segment (one RTT,
 * typically 10-100 ms), so the legitimate live set is normally tens of
 * entries; even a cold browser start opening a few hundred connections at
 * once stays orders of magnitude below this. Legitimately holding 16384 live
 * records would take >500 new TCP connections per second sustained across the
 * whole 30 second window - a router's workload, not a desktop's.
 */
#define TCP_CONNRECORD_MAX  16384
/* Low-water mark for a bulk evict. Leaving a quarter of the table free means
 * the O(n) sweep runs once per 4096 inserts instead of on every insert once
 * the table is full. */
#define TCP_CONNRECORD_KEEP (TCP_CONNRECORD_MAX - TCP_CONNRECORD_MAX / 4)

/* HACK!
 * uthash uses strlen() for HASH_FIND_STR.
 * We have null bytes in our key, so we can't use strlen()
 * And since it's always TCP_CONNRECORD_KEY_LEN bytes long,
 * we don't need to use any string function to determine length.
 */
#undef uthash_strlen
#define uthash_strlen(s) TCP_CONNRECORD_KEY_LEN

typedef struct tcp_connrecord {
    /* key ('4' for IPv4 or '6' for IPv6 + srcip[16] + dstip[16] + srcport[2] + dstport[2]) */
    char key[TCP_CONNRECORD_KEY_LEN];
    time_t time;         /* time when this record was added */
    uint16_t ttl;
    UT_hash_handle hh;   /* makes this structure hashable */
} tcp_connrecord_t;

static time_t last_cleanup = 0;
static tcp_connrecord_t *conntrack = NULL;

inline static void fill_key_data(char *key, const uint8_t is_ipv6, const uint32_t srcip[4],
                    const uint32_t dstip[4], const uint16_t srcport, const uint16_t dstport)
{
    unsigned int offset = 0;

    if (is_ipv6) {
        *(uint8_t*)(key) = '6';
        offset += sizeof(uint8_t);
        ipv6_copy_addr((uint32_t*)(key + offset), srcip);
        offset += sizeof(uint32_t) * 4;
        ipv6_copy_addr((uint32_t*)(key + offset), dstip);
        offset += sizeof(uint32_t) * 4;
    }
    else {
        *(uint8_t*)(key) = '4';
        offset += sizeof(uint8_t);
        ipv4_copy_addr((uint32_t*)(key + offset), srcip);
        offset += sizeof(uint32_t) * 4;
        ipv4_copy_addr((uint32_t*)(key + offset), dstip);
        offset += sizeof(uint32_t) * 4;
    }

    *(uint16_t*)(key + offset) = srcport;
    offset += sizeof(srcport);
    *(uint16_t*)(key + offset) = dstport;
    offset += sizeof(dstport);
}

inline static void fill_data_from_key(uint8_t *is_ipv6, uint32_t srcip[4], uint32_t dstip[4],
                                     uint16_t *srcport, uint16_t *dstport, const char *key)
{
    unsigned int offset = 0;

    if (key[0] == '6') {
        *is_ipv6 = 1;
        offset += sizeof(uint8_t);
        ipv6_copy_addr(srcip, (uint32_t*)(key + offset));
        offset += sizeof(uint32_t) * 4;
        ipv6_copy_addr(dstip, (uint32_t*)(key + offset));
        offset += sizeof(uint32_t) * 4;
    }
    else {
        *is_ipv6 = 0;
        offset += sizeof(uint8_t);
        ipv4_copy_addr(srcip, (uint32_t*)(key + offset));
        offset += sizeof(uint32_t) * 4;
        ipv4_copy_addr(dstip, (uint32_t*)(key + offset));
        offset += sizeof(uint32_t) * 4;
    }
    *srcport = *(uint16_t*)(key + offset);
    offset += sizeof(*srcport);
    *dstport = *(uint16_t*)(key + offset);
    offset += sizeof(*dstport);
}

inline static void construct_key(const uint32_t srcip[4], const uint32_t dstip[4],
                                 const uint16_t srcport, const uint16_t dstport,
                                 char *key, const uint8_t is_ipv6)
{
    debug("Construct key enter\n");
    if (key) {
        debug("Constructing key\n");
        fill_key_data(key, is_ipv6, srcip, dstip, srcport, dstport);
    }
    debug("Construct key end\n");
}

inline static void deconstruct_key(const char *key, const tcp_connrecord_t *connrecord,
                                   tcp_conntrack_info_t *conn_info)
{
    debug("Deconstruct key enter\n");
    if (key && conn_info) {
        debug("Deconstructing key\n");
        fill_data_from_key(&conn_info->is_ipv6,
                           conn_info->srcip, conn_info->dstip,
                           &conn_info->srcport, &conn_info->dstport,
                           key);

        conn_info->ttl = connrecord->ttl;
    }
    debug("Deconstruct key end\n");
}

static int check_get_tcp_conntrack_key(const char *key, tcp_connrecord_t **connrecord) {
    tcp_connrecord_t *tmp_connrecord = NULL;
    if (!conntrack) return FALSE;

    HASH_FIND_STR(conntrack, key, tmp_connrecord);
    if (tmp_connrecord) {
        if (connrecord)
            *connrecord = tmp_connrecord;
        debug("check_get_tcp_conntrack_key found key\n");
        return TRUE;
    }
    debug("check_get_tcp_conntrack_key key not found\n");
    return FALSE;
}

/* Bring the table back under TCP_CONNRECORD_MAX. Follows the two-phase shape
 * of proc_map_evict_locked() in proctrack_linux.c: drop what has expired
 * first, then force the count down if that was not enough.
 *
 * Phase 2 deliberately differs from proctrack's. proctrack empties its map
 * wholesale because every live flow simply re-resolves on its next packet; a
 * ttltrack record cannot be rebuilt, because the TTL it carries was observed
 * once, in a SYN+ACK that will never be sent again. Dropping a live record
 * silently disables auto-ttl for that connection for the rest of its life, so
 * this evicts the OLDEST records rather than all of them.
 *
 * Oldest-first is the right end to cut from: uthash appends on insert
 * (HASH_APPEND_LIST) and HASH_ITER walks hh.next, so iteration is in
 * insertion order, and a legitimate record is consumed by tcp_handle_outgoing
 * roughly one RTT after it is inserted. The oldest entries are therefore
 * overwhelmingly ones that were never claimed - attacker junk, or handshakes
 * whose data segment never came. Evicting newest-first would destroy exactly
 * the fresh records that are about to be used. For a legitimate record to be
 * lost here a flood would have to push TCP_CONNRECORD_MAX/4 entries inside
 * that one RTT, and even then only the oldest quarter goes.
 *
 * No locking, by design: conntrack is reached only from the single-threaded
 * main packet loop in goodbyedpi.c (proctrack's worker threads never call
 * into this file), so there is no lock to take and no lock ordering to get
 * wrong. Called only from add_tcp_conntrack, where no caller holds a record
 * pointer - tcp_handle_outgoing has already finished with, and freed, its
 * record before any insert can follow.
 */
static void tcp_evict_over_limit() {
    tcp_connrecord_t *tmp_connrecord, *tmp_connrecord2 = NULL;
    time_t now = time(NULL);

    /* Phase 1: anything already past its lifetime, at no cost to live flows. */
    HASH_ITER(hh, conntrack, tmp_connrecord, tmp_connrecord2) {
        if (difftime(now, tmp_connrecord->time) >= TCP_CLEANUP_INTERVAL_SEC) {
            HASH_DEL(conntrack, tmp_connrecord);
            free(tmp_connrecord);
        }
    }

    /* Phase 2: still full, so drop oldest-first down to the low-water mark.
     * The count is re-tested BEFORE each delete, so the loop leaves exactly
     * TCP_CONNRECORD_KEEP entries and can never run past it; HASH_COUNT
     * strictly decreases every pass, so it always terminates. */
    HASH_ITER(hh, conntrack, tmp_connrecord, tmp_connrecord2) {
        if (HASH_COUNT(conntrack) <= TCP_CONNRECORD_KEEP)
            break;
        HASH_DEL(conntrack, tmp_connrecord);
        free(tmp_connrecord);
    }
}

static int add_tcp_conntrack(const uint32_t srcip[4], const uint32_t dstip[4],
                             const uint16_t srcport, const uint16_t dstport,
                             const uint8_t is_ipv6, const uint8_t ttl
                            )
{
    if (!(srcip && srcport && dstip && dstport))
        return FALSE;

    /* Second bound, on top of tcp_cleanup()'s 30 second age-out: that sweep is
     * rate limited to once per interval, so a flood fills the table long
     * before it next runs. */
    if (HASH_COUNT(conntrack) >= TCP_CONNRECORD_MAX)
        tcp_evict_over_limit();

    tcp_connrecord_t *tmp_connrecord = malloc(sizeof(tcp_connrecord_t));
        if (!tmp_connrecord) return FALSE;
    construct_key(srcip, dstip, srcport, dstport, tmp_connrecord->key, is_ipv6);

    if (!check_get_tcp_conntrack_key(tmp_connrecord->key, NULL)) {
        tmp_connrecord->time = time(NULL);
        tmp_connrecord->ttl = ttl;
        HASH_ADD_STR(conntrack, key, tmp_connrecord);
        debug("Added TCP conntrack %u:%hu - %u:%hu\n", srcip[0], ntohs(srcport), dstip[0], ntohs(dstport));
        return TRUE;
    }
    debug("Not added TCP conntrack %u:%hu - %u:%hu\n", srcip[0], ntohs(srcport), dstip[0], ntohs(dstport));
    free(tmp_connrecord);
    return FALSE;
}

static void tcp_cleanup() {
    tcp_connrecord_t *tmp_connrecord, *tmp_connrecord2 = NULL;

    if (last_cleanup == 0) {
        last_cleanup = time(NULL);
        return;
    }

    if (difftime(time(NULL), last_cleanup) >= TCP_CLEANUP_INTERVAL_SEC) {
        last_cleanup = time(NULL);

        HASH_ITER(hh, conntrack, tmp_connrecord, tmp_connrecord2) {
            if (difftime(last_cleanup, tmp_connrecord->time) >= TCP_CLEANUP_INTERVAL_SEC) {
                HASH_DEL(conntrack, tmp_connrecord);
                free(tmp_connrecord);
            }
        }
    }
}

int tcp_handle_incoming(uint32_t srcip[4], uint32_t dstip[4],
                        uint16_t srcport, uint16_t dstport,
                        uint8_t is_ipv6, uint8_t ttl)
{
    tcp_cleanup();

    debug("trying to add TCP srcport = %hu, dstport = %hu\n", ntohs(srcport), ntohs(dstport));
    return add_tcp_conntrack(srcip, dstip, srcport, dstport, is_ipv6, ttl);

    debug("____tcp_handle_incoming FALSE: srcport = %hu, dstport = %hu\n", ntohs(srcport), ntohs(dstport));
    return FALSE;
}

int tcp_handle_outgoing(uint32_t srcip[4], uint32_t dstip[4],
                        uint16_t srcport, uint16_t dstport,
                        tcp_conntrack_info_t *conn_info,
                        uint8_t is_ipv6)
{
    char key[TCP_CONNRECORD_KEY_LEN];
    tcp_connrecord_t *tmp_connrecord = NULL;

    if (!conn_info)
        return FALSE;

    tcp_cleanup();
    construct_key(dstip, srcip, dstport, srcport, key, is_ipv6);
    if (check_get_tcp_conntrack_key(key, &tmp_connrecord) && tmp_connrecord) {
        /* Connection exists in conntrack, moving on */
        deconstruct_key(key, tmp_connrecord, conn_info);
        HASH_DEL(conntrack, tmp_connrecord);
        free(tmp_connrecord);
        debug("____tcp_handle_outgoing TRUE: srcport = %hu\n", ntohs(srcport));
        return TRUE;
    }

    debug("____tcp_handle_outgoing FALSE: srcport = %hu\n", ntohs(srcport));
    return FALSE;
}

int tcp_get_auto_ttl(const uint8_t ttl, const uint8_t autottl1,
                     const uint8_t autottl2, const uint8_t minhops,
                     const uint8_t maxttl) {
    uint8_t nhops = 0;
    uint8_t ttl_of_fake_packet = 0;

    if (ttl > 98 && ttl < 128) {
        nhops = 128 - ttl;
    }
    else if (ttl > 34 && ttl < 64) {
        nhops = 64 - ttl;
    }
    else {
        return 0;
    }

    if (nhops <= autottl1 || nhops < minhops) {
        return 0;
    }

    ttl_of_fake_packet = nhops - autottl2;
    if (ttl_of_fake_packet < autottl2 && nhops <= 9) {
        ttl_of_fake_packet = nhops - autottl1 - trunc((autottl2 - autottl1) * ((float)nhops/10));
    }

    if (maxttl && ttl_of_fake_packet > maxttl) {
        ttl_of_fake_packet = maxttl;
    }

    return ttl_of_fake_packet;
}
