/*
 * bypass_test.c — Unit tests for bypass modules (Phase 5).
 *
 * Tests:
 *   1. blackwhitelist: file load + hostname check
 *   2. dnsredir: outgoing/incoming DNS conntrack
 *   3. ttltrack: TCP SYN/ACK tracking + auto TTL
 *   4. fakepackets: load_from_hex, load_from_sni, load_random
 *
 * No network needed — only function logic is tested.
 * Sending fake packets (send_fake_data) needs the network; not tested here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "goodbyedpi.h"
#include "blackwhitelist.h"
#include "dnsredir.h"
#include "ttltrack.h"
#include "fakepackets.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name, cond) do { \
    tests_run++; \
    if (cond) { tests_passed++; } \
    else { printf("FAIL: %s (line %d)\n", name, __LINE__); } \
} while(0)

/* === blackwhitelist tests === */
static void test_blackwhitelist(void) {
    printf("=== blackwhitelist ===\n");

    /* temp blacklist file */
    FILE *fp = fopen("/tmp/gdpi_test_blacklist.txt", "w");
    fputs("example.com\n", fp);
    fputs("blocked.org\n", fp);
    fputs(".partial.com\n", fp);
    fclose(fp);

    int ret = blackwhitelist_load_list("/tmp/gdpi_test_blacklist.txt");
    TEST("blackwhitelist_load_list returns TRUE", ret == TRUE);

    /* exact match */
    TEST("blackwhitelist check example.com",
         blackwhitelist_check_hostname("example.com", strlen("example.com")) == TRUE);

    /* non-blacklisted */
    TEST("blackwhitelist check clean.com is FALSE",
         blackwhitelist_check_hostname("clean.com", strlen("clean.com")) == FALSE);

    /* subdomain match via tokenization */
    TEST("blackwhitelist check sub.blocked.org (tokenized)",
         blackwhitelist_check_hostname("sub.blocked.org", strlen("sub.blocked.org")) == TRUE);

    /* too long host */
    TEST("blackwhitelist too-long host is FALSE",
         blackwhitelist_check_hostname("x", HOST_MAXLEN + 10) == FALSE);

    unlink("/tmp/gdpi_test_blacklist.txt");
}

/* === dnsredir tests === */
static void test_dnsredir(void) {
    printf("=== dnsredir ===\n");

    uint32_t srcip[4] = {0};
    uint32_t dstip[4] = {0};
    uint16_t srcport = htons(12345);
    uint16_t dstport = htons(53);

    /* srcip = 192.168.1.100 (network order) */
    srcip[0] = inet_addr("192.168.1.100");
    /* dstip = 8.8.8.8 */
    dstip[0] = inet_addr("8.8.8.8");

    /* minimal DNS query: transaction ID + flags + QDCOUNT=1 */
    uint8_t dns_query[] = {
        0x12, 0x34,    /* transaction ID */
        0x01, 0x00,    /* flags: standard query, recursion desired */
        0x00, 0x01,    /* QDCOUNT = 1 */
        0x00, 0x00,    /* ANCOUNT = 0 */
        0x00, 0x00,    /* NSCOUNT = 0 */
        0x00, 0x00,    /* ARCOUNT = 0 */
        /* question: example.com A */
        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m', 0x00,
        0x00, 0x01,    /* type A */
        0x00, 0x01     /* class IN */
    };
    size_t dns_query_len = sizeof(dns_query);

    /* is_dns_packet check */
    TEST("dns_is_dns_packet outgoing=TRUE",
         dns_is_dns_packet(dns_query, dns_query_len, 1) == TRUE);

    /* handle outgoing — should add to conntrack */
    int ret = dns_handle_outgoing(srcip, srcport, dstip, dstport,
                                  dns_query, dns_query_len, 0);
    TEST("dns_handle_outgoing returns TRUE", ret == TRUE);

    /* handle incoming — should find and remove from conntrack */
    uint8_t dns_response[] = {
        0x12, 0x34,    /* same transaction ID */
        0x81, 0x80,    /* flags: response, recursion desired/available */
        0x00, 0x01,    /* QDCOUNT = 1 */
        0x00, 0x01,    /* ANCOUNT = 1 */
        0x00, 0x00,    /* NSCOUNT = 0 */
        0x00, 0x00,    /* ARCOUNT = 0 */
        /* question: example.com A */
        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m', 0x00,
        0x00, 0x01,
        0x00, 0x01,
        /* answer (abbreviated) */
        0xc0, 0x0c,   /* name pointer */
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x04,
        0x01, 0x02, 0x03, 0x04  /* 1.2.3.4 */
    };
    size_t dns_response_len = sizeof(dns_response);

    conntrack_info_t conn_info;
    memset(&conn_info, 0, sizeof(conn_info));

    /* dns_is_dns_packet for response */
    TEST("dns_is_dns_packet incoming=TRUE",
         dns_is_dns_packet(dns_response, dns_response_len, 0) == TRUE);

    /* swap src/dst for incoming — incoming packet dst = client = outgoing src
     * dns_handle_incoming key = client (outgoing src), not DNS server */
    ret = dns_handle_incoming(srcip, srcport,
                              dns_response, dns_response_len,
                              &conn_info, 0);
    TEST("dns_handle_incoming returns TRUE", ret == TRUE);
    TEST("dns_handle_incoming conn_info.srcport matches",
         conn_info.srcport == srcport);
    TEST("dns_handle_incoming conn_info.dstport matches",
         conn_info.dstport == dstport);
    TEST("dns_handle_incoming conn_info.srcip matches",
         conn_info.srcip[0] == srcip[0]);
    TEST("dns_handle_incoming conn_info.dstip matches",
         conn_info.dstip[0] == dstip[0]);

    /* second incoming — should fail (already consumed) */
    memset(&conn_info, 0, sizeof(conn_info));
    ret = dns_handle_incoming(srcip, srcport,
                              dns_response, dns_response_len,
                              &conn_info, 0);
    TEST("dns_handle_incoming second time returns FALSE", ret == FALSE);
}

/* === ttltrack tests === */
static void test_ttltrack(void) {
    printf("=== ttltrack ===\n");

    uint32_t srcip[4] = {0};
    uint32_t dstip[4] = {0};
    srcip[0] = inet_addr("1.2.3.4");
    dstip[0] = inet_addr("10.0.0.1");
    uint16_t srcport = htons(80);
    uint16_t dstport = htons(54321);

    /* handle incoming SYN/ACK — records TTL=64 */
    int ret = tcp_handle_incoming(srcip, dstip, srcport, dstport, 0, 64);
    TEST("tcp_handle_incoming returns TRUE", ret == TRUE);

    /* handle outgoing — should find and extract TTL */
    tcp_conntrack_info_t conn_info;
    memset(&conn_info, 0, sizeof(conn_info));
    ret = tcp_handle_outgoing(dstip, srcip, dstport, srcport, &conn_info, 0);
    TEST("tcp_handle_outgoing returns TRUE", ret == TRUE);
    TEST("tcp_handle_outgoing ttl=64", conn_info.ttl == 64);
    TEST("tcp_handle_outgoing srcip matches", conn_info.srcip[0] == srcip[0]);
    TEST("tcp_handle_outgoing dstip matches", conn_info.dstip[0] == dstip[0]);

    /* second outgoing — should fail (consumed) */
    memset(&conn_info, 0, sizeof(conn_info));
    ret = tcp_handle_outgoing(dstip, srcip, dstport, srcport, &conn_info, 0);
    TEST("tcp_handle_outgoing second time returns FALSE", ret == FALSE);

    /* auto TTL tests */
    /* TTL=64 -> nhops = 64-50 = 14, autottl1=3, autottl2=10, minhops=1, maxttl=0
     * 14 > 3, 14 >= 1 -> ttl_of_fake = 14-10 = 4 */
    uint8_t auto_ttl = tcp_get_auto_ttl(50, 3, 10, 1, 0);
    TEST("tcp_get_auto_ttl(50,3,10,1,0) = 4", auto_ttl == 4);
    /* TTL=120 -> nhops=8, 8 > 3 -> ttl_of_fake = 8-10 = uint8_t underflow -> 254
     * 254 < autottl2(10)? NO (254 > 10). nhops <= 9 but first check fails.
     * So returns 254. */
    auto_ttl = tcp_get_auto_ttl(120, 3, 10, 1, 0);
    TEST("tcp_get_auto_ttl(120,3,10,1,0) = 254 (uint8 underflow)", auto_ttl == 254);

    /* TTL too low (< minhops) -> return 0 */
    auto_ttl = tcp_get_auto_ttl(63, 3, 10, 5, 0);
    /* nhops=1, 1 < 5 -> return 0 */
    TEST("tcp_get_auto_ttl(63,3,10,5,0) = 0 (minhops)", auto_ttl == 0);

    /* TTL out of range -> return 0 */
    auto_ttl = tcp_get_auto_ttl(200, 3, 10, 1, 0);
    TEST("tcp_get_auto_ttl(200,...) = 0 (out of range)", auto_ttl == 0);

    /* maxttl cap */
    auto_ttl = tcp_get_auto_ttl(50, 1, 1, 1, 5);
    /* nhops=14, 14 > 1 -> ttl_of_fake = 14-1 = 13, but maxttl=5 -> 5 */
    TEST("tcp_get_auto_ttl(50,1,1,1,5) = 5 (maxttl cap)", auto_ttl == 5);
}

/* === fakepackets tests === */
static void test_fakepackets(void) {
    printf("=== fakepackets ===\n");

    /* load from hex */
    fakes_count = 0;
    int ret = fake_load_from_hex("48656c6c6f");  /* "Hello" */
    TEST("fake_load_from_hex valid hex returns 0", ret == 0);
    TEST("fakes_count == 1 after hex load", fakes_count == 1);
    TEST("fakes[0]->size == 5", fakes[0] != NULL && fakes[0]->size == 5);
    TEST("fakes[0]->data == 'Hello'",
         fakes[0] != NULL && memcmp(fakes[0]->data, "Hello", 5) == 0);

    /* invalid hex — even length but contains non-hex char */
    ret = fake_load_from_hex("xyzz");
    TEST("fake_load_from_hex invalid char returns 2", ret == 2);

    ret = fake_load_from_hex("4");  /* odd length */
    TEST("fake_load_from_hex odd length returns 1", ret == 1);

    /* load from SNI */
    ret = fake_load_from_sni("test.example.com");
    TEST("fake_load_from_sni returns 0", ret == 0);
    TEST("fakes_count == 2 after SNI load", fakes_count == 2);

    /* check SNI domain is embedded */
    struct fake_t *sni_fake = fakes[1];
    TEST("SNI fake contains domain",
         sni_fake != NULL && memmem(sni_fake->data, sni_fake->size,
             "test.example.com", strlen("test.example.com")) != NULL);

    /* load random */
    ret = fake_load_random(3, 100);
    TEST("fake_load_random(3,100) returns 0", ret == 0);
    TEST("fakes_count == 5 after random load", fakes_count == 5);

    /* check random fakes have correct sizes */
    int valid = 1;
    for (int i = 2; i < 5; i++) {
        if (!fakes[i] || fakes[i]->size < 8 || fakes[i]->size > 107)
            valid = 0;
    }
    TEST("random fakes sizes in [8, 107]", valid);

    /* too many */
    ret = fake_load_random(100, 100);
    TEST("fake_load_random too many returns 1 or 2", ret == 1 || ret == 2);

    /* NULL domain */
    ret = fake_load_from_sni(NULL);
    TEST("fake_load_from_sni(NULL) returns 1", ret == 1);
}

int main(void) {
    printf("bypass_test — Phase 5 unit tests\n");
    printf("================================\n\n");

    test_blackwhitelist();
    printf("\n");
    test_dnsredir();
    printf("\n");
    test_ttltrack();
    printf("\n");
    test_fakepackets();

    printf("\n================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    if (tests_passed == tests_run) {
        printf("gtest: ok\n");
        return 0;
    }
    return 1;
}
