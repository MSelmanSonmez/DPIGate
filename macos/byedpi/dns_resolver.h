/*
 * DPIGate: self-contained, bounded IPv4 name resolver for the macOS proxy.
 * Replaces the blocking getaddrinfo() call, which can stall the single-threaded
 * event loop for 30 s. UDP A queries with a short timeout, TCP retry on
 * truncation, small TTL-aware cache. IPv6 is out of scope (A records only).
 */
#ifndef DPIGATE_DNS_RESOLVER_H
#define DPIGATE_DNS_RESOLVER_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#define DNS_PARSE_OK        0
#define DNS_PARSE_BAD      -1   /* malformed, wrong ID/question, not a response */
#define DNS_PARSE_TRUNC     1   /* TC bit set: retry over TCP */
#define DNS_PARSE_NOANSWER  2   /* well-formed, but no usable A record (incl. NXDOMAIN) */

/* Builds a recursive A/IN query. Returns the packet length, or -1. */
int dns_build_query(uint8_t *buf, size_t cap, uint16_t id, const char *name);

/*
 * Parses a response to the query (id, name). Follows the CNAME chain to an A
 * record. On DNS_PARSE_OK stores the address and the smallest TTL on the chain.
 */
int dns_parse_response(const uint8_t *buf, size_t len, uint16_t id,
        const char *name, struct in_addr *ip, uint32_t *ttl);

/* Servers: "1.1.1.1 1.0.0.1" or "ip[:port]" separated by spaces/commas. */
int dns_set_servers(const char *list);
/* Resolves a name (cache first). 0 on success, -1 on failure. Bounded in time. */
int dns_resolve(const char *name, struct in_addr *ip);
/* Drops all cached entries. */
void dns_cache_clear(void);

#endif
