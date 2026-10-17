/*
 * goodbyedpi.c — Linux port main loop.
 *
 * WinDivert → NFQUEUE + sock_diag.
 * Filter strings removed (nftables handles packet filtering).
 * --port / --ip-id become no-ops with warning (need nftables rule).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <arpa/inet.h>      /* inet_pton, ntohs, htons */
#include <netinet/in.h>     /* struct in_addr, in6_addr, IPPROTO_TCP/UDP */
#include <netinet/ip.h>     /* struct iphdr */
#include <linux/ipv6.h>     /* struct ipv6hdr */

#include "goodbyedpi.h"
#include "packet_io.h"
#include "checksum.h"
#include "fakepackets.h"
#include "dnsredir.h"
#include "ttltrack.h"
#include "blackwhitelist.h"
#include "proctrack_linux.h"

/* Upstream GoodbyeDPI release this fork is derived from. Left untouched so a
 * bug report still says which upstream base the engine came from. */
#define GOODBYEDPI_VERSION "v0.2.3rc3"

/* This fork's own version. Bump it here and in windows/setup.iss (AppVersion,
 * VersionInfoVersion, OutputBaseFilename) together — those are the only two
 * places a release version is declared. */
#define DPIGATE_VERSION "3.0.0"

#define die() do { exit(EXIT_FAILURE); } while (0)

#define SET_HTTP_FRAGMENT_SIZE_OPTION(fragment_size) do { \
    if (!http_fragment_size) { \
        http_fragment_size = (unsigned int)fragment_size; \
    } \
    else if (http_fragment_size != (unsigned int)fragment_size) { \
        printf( \
            "WARNING: HTTP fragment size is already set to %u, not changing.\n", \
            http_fragment_size \
        ); \
    } \
} while (0)

/*
 * TCP_HANDLE_OUTGOING_TTL_PARSE_PACKET_IF
 * Uses pre-computed src4[4]/dst4[4] arrays (set after parse_packet).
 * Ports stay in NETWORK byte order (ttltrack expects network order).
 */
#define TCP_HANDLE_OUTGOING_TTL_PARSE_PACKET_IF() \
    if ((packet_v4 && tcp_handle_outgoing(src4, dst4, \
                        ppTcpHdr->source, ppTcpHdr->dest, \
                        &tcp_conn_info, 0)) \
        || \
        (packet_v6 && tcp_handle_outgoing(src4, dst4, \
                        ppTcpHdr->source, ppTcpHdr->dest, \
                        &tcp_conn_info, 1)))

/*
 * TCP_HANDLE_OUTGOING_FAKE_PACKET
 * Linux: no handle/addr params. Fake packet funcs take (pkt, len, is_ipv6, ttl, chksum, seq).
 */
#define TCP_HANDLE_OUTGOING_FAKE_PACKET(func) do { \
    should_send_fake = 1; \
    if (do_auto_ttl || ttl_min_nhops) { \
        TCP_HANDLE_OUTGOING_TTL_PARSE_PACKET_IF() { \
            if (do_auto_ttl) { \
                ttl_of_fake_packet = tcp_get_auto_ttl(tcp_conn_info.ttl, auto_ttl_1, auto_ttl_2, \
                                                      ttl_min_nhops, auto_ttl_max); \
                if (do_tcp_verb) { \
                    printf("Connection TTL = %d, Fake TTL = %d\n", tcp_conn_info.ttl, ttl_of_fake_packet); \
                } \
            } \
            else if (ttl_min_nhops) { \
                if (!tcp_get_auto_ttl(tcp_conn_info.ttl, 0, 0, ttl_min_nhops, 0)) { \
                    should_send_fake = 0; \
                } \
            } \
        } \
    } \
    if (should_send_fake) \
        func(packet, packetLen, packet_v6, \
             ttl_of_fake_packet, do_wrong_chksum, do_wrong_seq); \
} while (0)

enum ERROR_CODE {
    ERROR_DEFAULT = 1,
    ERROR_PORT_BOUNDS,
    ERROR_DNS_V4_ADDR,
    ERROR_DNS_V6_ADDR,
    ERROR_DNS_V4_PORT,
    ERROR_DNS_V6_PORT,
    ERROR_BLACKLIST_LOAD,
    ERROR_AUTOTTL,
    ERROR_ATOUSI,
    ERROR_AUTOB
};

static const char http10_redirect_302[] = "HTTP/1.0 302 ";
static const char http11_redirect_302[] = "HTTP/1.1 302 ";
static const char http_host_find[] = "\r\nHost: ";
static const char http_host_replace[] = "\r\nhoSt: ";
static const char http_useragent_find[] = "\r\nUser-Agent: ";
static const char location_http[] = "\r\nLocation: http://";
static const char connection_close[] = "\r\nConnection: close";
static const char *http_methods[] = {
    "GET ",
    "HEAD ",
    "POST ",
    "PUT ",
    "DELETE ",
    "CONNECT ",
    "OPTIONS ",
};

static struct option long_options[] = {
    {"port",        required_argument, 0,  'z' },
    {"dns-addr",    required_argument, 0,  'd' },
    {"dns-port",    required_argument, 0,  'g' },
    {"dnsv6-addr",  required_argument, 0,  '!' },
    {"dnsv6-port",  required_argument, 0,  '@' },
    {"dns-verb",    no_argument,       0,  'v' },
    {"blacklist",   required_argument, 0,  'b' },
    {"allow-no-sni",no_argument,       0,  ']' },
    {"frag-by-sni", no_argument,       0,  '>' },
    {"ip-id",       required_argument, 0,  'i' },
    {"set-ttl",     required_argument, 0,  '$' },
    {"min-ttl",     required_argument, 0,  '[' },
    {"auto-ttl",    optional_argument, 0,  '+' },
    {"wrong-chksum",no_argument,       0,  '%' },
    {"wrong-seq",   no_argument,       0,  ')' },
    {"native-frag", no_argument,       0,  '*' },
    {"reverse-frag",no_argument,       0,  '(' },
    {"max-payload", optional_argument, 0,  '|' },
    {"fake-from-hex", required_argument, 0,  'u' },
    {"fake-with-sni", required_argument, 0,  '}' },
    {"fake-gen",    required_argument, 0,  'j' },
    {"fake-resend", required_argument, 0,  't' },
    {"only-programs",required_argument, 0,  'o' },
    {"debug-proc",   optional_argument, 0,  'O' },
    {"debug-exit",  optional_argument, 0,  'x' },
    {"queue",       required_argument, 0,  'Q' },
    {0,             0,                 0,   0  }
};

/* --- helpers --- */

static char* dumb_memmem(const char* haystack, unsigned int hlen,
                         const char* needle, unsigned int nlen)
{
    if (nlen > hlen) return NULL;
    unsigned int i;
    for (i = 0; i < hlen - nlen + 1; i++) {
        if (memcmp(haystack + i, needle, nlen) == 0) {
            return (char*)(haystack + i);
        }
    }
    return NULL;
}

unsigned short int atousi(const char *str, const char *msg) {
    char *endptr = NULL;
    long unsigned int res = strtoul(str, &endptr, 10u);
    if (endptr == str || *endptr != '\0') {
        puts(msg);
        exit(ERROR_ATOUSI);
    }
    if (res > 0xFFFFu) {
        puts(msg);
        exit(ERROR_ATOUSI);
    }
    return (unsigned short int)res;
}

uint8_t atoub(const char *str, const char *msg) {
    char *endptr = NULL;
    long unsigned int res = strtoul(str, &endptr, 10u);
    if (endptr == str || *endptr != '\0') {
        puts(msg);
        exit(ERROR_AUTOB);
    }
    if (res > 0xFFu) {
        puts(msg);
        exit(ERROR_AUTOB);
    }
    return (uint8_t)res;
}

static void mix_case(char *pktdata, unsigned int pktlen) {
    unsigned int i;
    if (pktlen <= 0) return;
    for (i = 0; i < pktlen; i++) {
        if (i % 2) {
            pktdata[i] = (char) toupper((unsigned char)pktdata[i]);
        }
    }
}

static int is_passivedpi_redirect(const char *pktdata, unsigned int pktlen) {
    if (memcmp(pktdata, http11_redirect_302, sizeof(http11_redirect_302) - 1) == 0 ||
        memcmp(pktdata, http10_redirect_302, sizeof(http10_redirect_302) - 1) == 0)
    {
        if (dumb_memmem(pktdata, pktlen, location_http, sizeof(location_http) - 1) &&
            dumb_memmem(pktdata, pktlen, connection_close, sizeof(connection_close) - 1)) {
            return TRUE;
        }
    }
    return FALSE;
}

static int find_header_and_get_info(const char *pktdata, unsigned int pktlen,
                const char *hdrname,
                char **hdrnameaddr,
                char **hdrvalueaddr, unsigned int *hdrvaluelen) {
    char *data_addr_rn;
    char *hdr_begin;

    *hdrvaluelen = 0u;
    *hdrnameaddr = NULL;
    *hdrvalueaddr = NULL;

    hdr_begin = dumb_memmem(pktdata, pktlen, hdrname, (unsigned int)strlen(hdrname));
    if (!hdr_begin) return FALSE;
    if (pktdata > hdr_begin) return FALSE;

    *hdrnameaddr = hdr_begin;
    *hdrvalueaddr = hdr_begin + strlen(hdrname);

    data_addr_rn = dumb_memmem(*hdrvalueaddr,
                        pktlen - (unsigned int)(*hdrvalueaddr - pktdata),
                        "\r\n", 2);
    if (data_addr_rn) {
        *hdrvaluelen = (unsigned int)(data_addr_rn - *hdrvalueaddr);
        if (*hdrvaluelen >= 3 && *hdrvaluelen <= HOST_MAXLEN)
            return TRUE;
    }
    return FALSE;
}

static int extract_sni(const char *pktdata, unsigned int pktlen,
                    char **hostnameaddr, unsigned int *hostnamelen) {
    unsigned int ptr = 0;
    const unsigned char *d = (const unsigned char *)pktdata;
    const unsigned char *hnaddr = 0;
    int hnlen = 0;

    while (ptr + 8 < pktlen) {
        if (d[ptr] == '\0' && d[ptr+1] == '\0' && d[ptr+2] == '\0' &&
            d[ptr+4] == '\0' && d[ptr+6] == '\0' && d[ptr+7] == '\0' &&
            d[ptr+3] - d[ptr+5] == 2 && d[ptr+5] - d[ptr+8] == 3)
        {
            if (ptr + 9 + d[ptr+8] > pktlen) {
                return FALSE;
            }
            hnaddr = &d[ptr+9];
            hnlen = d[ptr+8];
            if (hnlen < 3 || hnlen > HOST_MAXLEN) {
                return FALSE;
            }
            for (int i = 0; i < hnlen; i++) {
                if (!((hnaddr[i] >= '0' && hnaddr[i] <= '9') ||
                     (hnaddr[i] >= 'a' && hnaddr[i] <= 'z') ||
                     hnaddr[i] == '.' || hnaddr[i] == '-'))
                {
                    return FALSE;
                }
            }
            *hostnameaddr = (char*)hnaddr;
            *hostnamelen = (unsigned int)hnlen;
            return TRUE;
        }
        ptr++;
    }
    return FALSE;
}

static inline void change_window_size(struct tcphdr *ppTcpHdr, unsigned int size) {
    if (size >= 1 && size <= 0xFFFFu) {
        ppTcpHdr->window = htons((uint16_t)size);
    }
}

static char *find_http_method_end(const char *pkt, unsigned int http_frag, int *is_fragmented) {
    unsigned int i;
    for (i = 0; i < (sizeof(http_methods) / sizeof(*http_methods)); i++) {
        if (memcmp(pkt, http_methods[i], strlen(http_methods[i])) == 0) {
            if (is_fragmented)
                *is_fragmented = 0;
            return (char*)pkt + strlen(http_methods[i]) - 1;
        }
        if ((http_frag == 1 || http_frag == 2) &&
            memcmp(pkt, http_methods[i] + http_frag,
                   strlen(http_methods[i]) - http_frag) == 0)
        {
            if (is_fragmented)
                *is_fragmented = 1;
            return (char*)pkt + strlen(http_methods[i]) - http_frag - 1;
        }
    }
    return NULL;
}

/*
 * send_native_fragment — fragment and send via raw socket.
 *
 * step 0: cut off end (keep first fragment_size bytes of data)
 * step 1: cut off beginning (remove first fragment_size bytes, advance SeqNum)
 *
 * Sent via pio_send_raw with DPI_DESYNC_FWMARK_DEFAULT.
 * Original packet restored from backup after send.
 */
static void send_native_fragment(uint8_t *packet, size_t packetLen,
                        uint8_t *packet_data, size_t packet_dataLen,
                        int packet_v4, int packet_v6,
                        struct iphdr *ppIpHdr, struct ipv6hdr *ppIpV6Hdr,
                        struct tcphdr *ppTcpHdr,
                        unsigned int fragment_size, int step)
{
    uint8_t packet_bak[MAX_PACKET_SIZE];
    if (packetLen > MAX_PACKET_SIZE)
        return;
    memcpy(packet_bak, packet, packetLen);
    size_t orig_packetLen = packetLen;

    if (fragment_size >= packet_dataLen) {
        if (step == 1)
            fragment_size = 0;
        else
            return;
    }

    if (step == 0) {
        if (packet_v4)
            ppIpHdr->tot_len = htons(
                ntohs(ppIpHdr->tot_len) -
                (uint16_t)packet_dataLen + (uint16_t)fragment_size
            );
        else if (packet_v6)
            ppIpV6Hdr->payload_len = htons(
                ntohs(ppIpV6Hdr->payload_len) -
                (uint16_t)packet_dataLen + (uint16_t)fragment_size
            );
        packetLen = packetLen - packet_dataLen + fragment_size;
    }
    else if (step == 1) {
        if (packet_v4)
            ppIpHdr->tot_len = htons(
                ntohs(ppIpHdr->tot_len) - (uint16_t)fragment_size
            );
        else if (packet_v6)
            ppIpV6Hdr->payload_len = htons(
                ntohs(ppIpV6Hdr->payload_len) - (uint16_t)fragment_size
            );
        memmove(packet_data,
                packet_data + fragment_size,
                packet_dataLen - fragment_size);
        packetLen -= fragment_size;
        ppTcpHdr->seq = htonl(ntohl(ppTcpHdr->seq) + fragment_size);
    }

    calc_checksums(packet, packetLen);

    /* Send fragment via raw socket with fwmark */
    if (packet_v4) {
        struct in_addr dst;
        dst.s_addr = ppIpHdr->daddr;
        pio_send_raw(packet, packetLen, &dst, 0, DPI_DESYNC_FWMARK_DEFAULT);
    }
    else if (packet_v6) {
        pio_send_raw(packet, packetLen, &ppIpV6Hdr->daddr, 1,
                     DPI_DESYNC_FWMARK_DEFAULT);
    }

    memcpy(packet, packet_bak, orig_packetLen);
}


/* --- signal handler --- */

static void sig_handler(int sig) {
    (void)sig;
    _exit(EXIT_SUCCESS);
}

/* --- main --- */

int main(int argc, char *argv[]) {
    enum packet_type_e {
        unknown,
        ipv4_tcp, ipv4_tcp_data, ipv4_udp_data,
        ipv6_tcp, ipv6_tcp_data, ipv6_udp_data
    } packet_type;
    bool debug_exit = false;
    int i, should_reinject, should_recalc_checksum = 0;
    int sni_ok = 0;
    int opt;
    int packet_v4, packet_v6;
    int queue_num = 0;
    packet_ctx_t ctx;
    conntrack_info_t dns_conn_info;
    tcp_conntrack_info_t tcp_conn_info;

    int do_passivedpi = 0, do_block_quic = 0,
        do_fragment_http = 0,
        do_fragment_http_persistent = 0,
        do_fragment_http_persistent_nowait = 0,
        do_fragment_https = 0, do_host = 0,
        do_host_removespace = 0, do_additional_space = 0,
        do_http_allports = 0,
        do_host_mixedcase = 0,
        do_dnsv4_redirect = 0, do_dnsv6_redirect = 0,
        do_dns_verb = 0, do_tcp_verb = 0, do_blacklist = 0,
        do_allow_no_sni = 0,
        do_fragment_by_sni = 0,
        do_fake_packet = 0,
        do_auto_ttl = 0,
        do_wrong_chksum = 0,
        do_wrong_seq = 0,
        do_native_frag = 0, do_reverse_frag = 0;
    int do_only_programs = 0;
    int do_debug_proc = 0;
    unsigned int proc_debug_limit = 300;
    unsigned int proc_debug_count = 0;
    unsigned int http_fragment_size = 0;
    unsigned int https_fragment_size = 0;
    unsigned int current_fragment_size = 0;
    unsigned short max_payload_size = 0;
    uint8_t should_send_fake = 0;
    uint8_t ttl_of_fake_packet = 0;
    uint8_t ttl_min_nhops = 0;
    uint8_t auto_ttl_1 = 0;
    uint8_t auto_ttl_2 = 0;
    uint8_t auto_ttl_max = 0;
    uint32_t dnsv4_addr = 0;
    struct in6_addr dnsv6_addr;
    struct in6_addr dns_temp_addr;
    memset(&dnsv6_addr, 0, sizeof(dnsv6_addr));
    memset(&dns_temp_addr, 0, sizeof(dns_temp_addr));
    uint16_t dnsv4_port = htons(53);
    uint16_t dnsv6_port = htons(53);
    char *host_addr, *useragent_addr, *method_addr;
    unsigned int host_len, useragent_len;
    int http_req_fragmented;

    char *hdr_name_addr = NULL, *hdr_value_addr = NULL;
    unsigned int hdr_value_len;

    printf(
        "DPIGate " DPIGATE_VERSION " (linux)"
        " (engine: GoodbyeDPI " GOODBYEDPI_VERSION ")\n"
        "Passive DPI blocker and Active DPI circumvention utility\n"
        "https://github.com/ValdikSS/GoodbyeDPI\n\n"
    );

    if (argc == 1) {
        /* enable mode -9 by default */
        do_fragment_http = do_fragment_https = 1;
        do_reverse_frag = do_native_frag = 1;
        http_fragment_size = https_fragment_size = 2;
        do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
        do_fake_packet = 1;
        do_wrong_chksum = 1;
        do_wrong_seq = 1;
        do_block_quic = 1;
        max_payload_size = 1200;
    }

    while ((opt = getopt_long(argc, argv, "123456789pqrsaf:e:mwk:nQ:", long_options, NULL)) != -1) {
        switch (opt) {
            case '1':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_http = do_fragment_https \
                = do_fragment_http_persistent \
                = do_fragment_http_persistent_nowait = 1;
                break;
            case '2':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_http = do_fragment_https \
                = do_fragment_http_persistent \
                = do_fragment_http_persistent_nowait = 1;
                https_fragment_size = 40u;
                break;
            case '3':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_https = 1;
                https_fragment_size = 40u;
                break;
            case '4':
                do_passivedpi = do_host = do_host_removespace = 1;
                break;
            case '5':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_auto_ttl = 1;
                max_payload_size = 1200;
                break;
            case '6':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_wrong_seq = 1;
                max_payload_size = 1200;
                break;
            case '9':
                do_block_quic = 1;
                /* fall through */
            case '8':
                do_wrong_seq = 1;
                /* fall through */
            case '7':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_wrong_chksum = 1;
                max_payload_size = 1200;
                break;
            case 'p':
                do_passivedpi = 1;
                break;
            case 'q':
                do_block_quic = 1;
                break;
            case 'r':
                do_host = 1;
                break;
            case 's':
                do_host_removespace = 1;
                break;
            case 'a':
                do_additional_space = 1;
                do_host_removespace = 1;
                break;
            case 'm':
                do_host_mixedcase = 1;
                break;
            case 'f':
                do_fragment_http = 1;
                SET_HTTP_FRAGMENT_SIZE_OPTION(atousi(optarg, "Fragment size should be in range [0 - 0xFFFF]\n"));
                break;
            case 'k':
                do_fragment_http_persistent = 1;
                do_native_frag = 1;
                SET_HTTP_FRAGMENT_SIZE_OPTION(atousi(optarg, "Fragment size should be in range [0 - 0xFFFF]\n"));
                break;
            case 'n':
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                do_native_frag = 1;
                break;
            case 'e':
                do_fragment_https = 1;
                https_fragment_size = atousi(optarg, "Fragment size should be in range [0 - 65535]\n");
                break;
            case 'w':
                do_http_allports = 1;
                break;
            case 'Q':
                queue_num = atoi(optarg);
                if (queue_num < 0 || queue_num > 65535) {
                    printf("Queue number parameter error!\n");
                    exit(ERROR_DEFAULT);
                }
                break;
            case 'z':
                i = atoi(optarg);
                if (i <= 0 || i > 65535) {
                    printf("Port parameter error!\n");
                    exit(ERROR_PORT_BOUNDS);
                }
                if (i != 80 && i != 443)
                    printf("WARNING: --port %d: configure nftables rule for this port.\n", i);
                i = 0;
                break;
            case 'i':
                atousi(optarg, "IP ID parameter error!\n");
                printf("WARNING: --ip-id: not supported on Linux (nftables handles IP ID filtering).\n");
                break;
            case 'd':
                if (inet_pton(AF_INET, optarg, dns_temp_addr.s6_addr) == 1) {
                    if (!do_dnsv4_redirect) {
                        do_dnsv4_redirect = 1;
                        if (inet_pton(AF_INET, optarg, &dnsv4_addr) != 1) {
                            puts("DNS address parameter error!");
                            exit(ERROR_DNS_V4_ADDR);
                        }
                        flush_dns_cache();
                    } else {
                        printf("WARN: DNSv4 redirect already set, ignoring\n");
                    }
                    break;
                }
                puts("DNS address parameter error!");
                exit(ERROR_DNS_V4_ADDR);
                break;
            case '!':
                if (inet_pton(AF_INET6, optarg, dns_temp_addr.s6_addr) == 1) {
                    if (!do_dnsv6_redirect) {
                        do_dnsv6_redirect = 1;
                        if (inet_pton(AF_INET6, optarg, dnsv6_addr.s6_addr) != 1) {
                            puts("DNS address parameter error!");
                            exit(ERROR_DNS_V6_ADDR);
                        }
                        flush_dns_cache();
                    } else {
                        printf("WARN: DNSv6 redirect already set, ignoring\n");
                    }
                    break;
                }
                puts("DNS address parameter error!");
                exit(ERROR_DNS_V6_ADDR);
                break;
            case 'g':
                if (!do_dnsv4_redirect) {
                    puts("--dns-port should be used with --dns-addr!\n"
                        "Make sure you use --dns-addr and pass it before "
                        "--dns-port");
                    exit(ERROR_DNS_V4_PORT);
                }
                dnsv4_port = atousi(optarg, "DNS port parameter error!");
                dnsv4_port = htons(dnsv4_port);
                break;
            case '@':
                if (!do_dnsv6_redirect) {
                    puts("--dnsv6-port should be used with --dnsv6-addr!\n"
                        "Make sure you use --dnsv6-addr and pass it before "
                        "--dnsv6-port");
                    exit(ERROR_DNS_V6_PORT);
                }
                dnsv6_port = atousi(optarg, "DNS port parameter error!");
                dnsv6_port = htons(dnsv6_port);
                break;
            case 'v':
                do_dns_verb = 1;
                do_tcp_verb = 1;
                break;
            case 'b':
                do_blacklist = 1;
                if (!blackwhitelist_load_list(optarg)) {
                    printf("Can't load blacklist from file!\n");
                    exit(ERROR_BLACKLIST_LOAD);
                }
                break;
            case ']':
                do_allow_no_sni = 1;
                break;
            case '>':
                do_fragment_by_sni = 1;
                break;
            case '$':
                do_auto_ttl = auto_ttl_1 = auto_ttl_2 = auto_ttl_max = 0;
                do_fake_packet = 1;
                ttl_of_fake_packet = atoub(optarg, "Set TTL parameter error!");
                break;
            case '[':
                do_fake_packet = 1;
                ttl_min_nhops = atoub(optarg, "Set Minimum TTL number of hops parameter error!");
                break;
            case '+':
                do_fake_packet = 1;
                do_auto_ttl = 1;

                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];

                if (optarg) {
                    char *autottl_copy = strdup(optarg);
    if (!autottl_copy) { puts("Set Auto TTL parameter error!"); exit(EXIT_FAILURE); }
                    if (strchr(autottl_copy, '-')) {
                        char *autottl_current = strtok(autottl_copy, "-");
                        auto_ttl_1 = atoub(autottl_current, "Set Auto TTL parameter error!");
                        autottl_current = strtok(NULL, "-");
                        if (!autottl_current) {
                            puts("Set Auto TTL parameter error!");
                            exit(ERROR_AUTOTTL);
                        }
                        auto_ttl_2 = atoub(autottl_current, "Set Auto TTL parameter error!");
                        autottl_current = strtok(NULL, "-");
                        if (!autottl_current) {
                            puts("Set Auto TTL parameter error!");
                            exit(ERROR_AUTOTTL);
                        }
                        auto_ttl_max = atoub(autottl_current, "Set Auto TTL parameter error!");
                    }
                    else {
                        auto_ttl_2 = atoub(optarg, "Set Auto TTL parameter error!");
                        auto_ttl_1 = auto_ttl_2;
                    }
                    free(autottl_copy);
                }
                break;
            case '%':
                do_fake_packet = 1;
                do_wrong_chksum = 1;
                break;
            case ')':
                do_fake_packet = 1;
                do_wrong_seq = 1;
                break;
            case '*':
                do_native_frag = 1;
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                break;
            case '(':
                do_reverse_frag = 1;
                do_native_frag = 1;
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                break;
            case '|':
                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];
                if (optarg)
                    max_payload_size = atousi(optarg, "Max payload size parameter error!");
                else
                    max_payload_size = 1200;
                break;
            case 'u':
                if (fake_load_from_hex(optarg)) {
                    printf("WARNING: bad fake HEX value %s\n", optarg);
                }
                break;
            case '}':
                if (fake_load_from_sni(optarg)) {
                    printf("WARNING: bad domain name for SNI: %s\n", optarg);
                }
                break;
            case 'j':
                if (fake_load_random(atoub(optarg, "Fake generator parameter error!"), 200)) {
                    puts("WARNING: fake generator has failed!");
                }
                break;
            case 't':
                fakes_resend = atoub(optarg, "Fake resend parameter error!");
                if (fakes_resend == 1)
                    puts("WARNING: fake-resend is 1, no resending is in place!");
                else if (!fakes_resend)
                    puts("WARNING: fake-resend is 0, fake packet mode is disabled!");
                else if (fakes_resend > 100)
                    puts("WARNING: fake-resend value is a little too high, don't you think?");
                break;
            case 'o':
                do_only_programs = 1;
                if (!proctrack_init(optarg)) {
                    printf("ERROR: can't load programs list '%s'\n", optarg);
                    die();
                }
                break;
            case 'O':
                do_debug_proc = 1;
                if (optarg && optarg[0]) {
                    long v = strtol(optarg, NULL, 10);
                    if (v > 0)
                        proc_debug_limit = (unsigned int)v;
                }
                break;
            case 'x':
                debug_exit = true;
                break;
            default:
                puts("Usage: goodbyedpi [OPTION...]\n"
                " -p          block passive DPI\n"
                " -q          block QUIC/HTTP3\n"
                " -r          replace Host with hoSt\n"
                " -s          remove space between host header and its value\n"
                " -a          additional space between Method and Request-URI (enables -s, may break sites)\n"
                " -m          mix Host header case (test.com -> tEsT.cOm)\n"
                " -f <value>  set HTTP fragmentation to value\n"
                " -k <value>  enable HTTP persistent (keep-alive) fragmentation and set it to value\n"
                " -n          do not wait for first segment ACK when -k is enabled\n"
                " -e <value>  set HTTPS fragmentation to value\n"
                " -w          try to find and parse HTTP traffic on all processed ports (not only on port 80)\n"
                " --queue      <value>    NFQUEUE queue number (default 0)\n"
                " --port        <value>    additional TCP port (requires nftables rule)\n"
                " --ip-id       <value>    not supported on Linux (nftables handles)\n"
                " --dns-addr    <value>    redirect UDPv4 DNS requests to the supplied IPv4 address\n"
                " --dns-port    <value>    redirect UDPv4 DNS requests to the supplied port (53 by default)\n"
                " --dnsv6-addr  <value>    redirect UDPv6 DNS requests to the supplied IPv6 address\n"
                " --dnsv6-port  <value>    redirect UDPv6 DNS requests to the supplied port (53 by default)\n"
                " --dns-verb               print verbose DNS redirection messages\n"
                " --blacklist   <txtfile>  perform circumvention tricks only to host names and subdomains\n"
                " --allow-no-sni           perform circumvention if TLS SNI can't be detected with --blacklist\n"
                " --frag-by-sni            fragment the packet right before SNI value\n"
                " --set-ttl     <value>    activate Fake Request Mode and send it with supplied TTL value.\n"
                " --auto-ttl    [a1-a2-m]  activate Fake Request Mode, automatically detect TTL\n"
                " --min-ttl     <value>    minimum TTL distance for Fake Request\n"
                " --wrong-chksum           activate Fake Request Mode with incorrect TCP checksum\n"
                " --wrong-seq              activate Fake Request Mode with TCP SEQ/ACK in the past\n"
                " --native-frag            fragment packets by sending them in smaller packets\n"
                " --reverse-frag           fragment packets in reversed order\n"
                " --fake-from-hex <value>  load fake packets from HEX values\n"
                " --fake-with-sni <value>  generate fake packets with given SNI domain name\n"
                " --fake-gen <value>       generate random-filled fake packets\n"
                " --fake-resend <value>    send each fake packet N times\n"
                " --max-payload [value]    skip packets with TCP payload larger than value\n"
                " --only-programs <txtfile> apply tricks ONLY to traffic of listed programs\n"
                " --debug-proc [N]         print per-program gate decisions (first N packets, default 300)\n"
                "\n"
                "LEGACY modesets:\n"
                " -1          -p -r -s -f 2 -k 2 -n -e 2\n"
                " -2          -p -r -s -f 2 -k 2 -n -e 40\n"
                " -3          -p -r -s -e 40\n"
                " -4          -p -r -s\n"
                "Modern modesets:\n"
                " -5          -f 2 -e 2 --auto-ttl --reverse-frag --max-payload\n"
                " -6          -f 2 -e 2 --wrong-seq --reverse-frag --max-payload\n"
                " -7          -f 2 -e 2 --wrong-chksum --reverse-frag --max-payload\n"
                " -8          -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload\n"
                " -9          -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload -q (default)\n\n"
                );
                exit(ERROR_DEFAULT);
        }
    }

    if (!http_fragment_size)
        http_fragment_size = 2;
    if (!https_fragment_size)
        https_fragment_size = 2;
    if (!auto_ttl_1)
        auto_ttl_1 = 1;
    if (!auto_ttl_2)
        auto_ttl_2 = 4;
    if (do_auto_ttl) {
        if (!ttl_min_nhops)
            ttl_min_nhops = 3;
        if (!auto_ttl_max)
            auto_ttl_max = 10;
    }

    printf("Block passive: %d\n"
           "Block QUIC/HTTP3: %d\n"
           "Fragment HTTP: %u\n"
           "Fragment persistent HTTP: %u\n"
           "Fragment HTTPS: %u\n"
           "Fragment by SNI: %u\n"
           "Native fragmentation (splitting): %d\n"
           "Fragments sending in reverse: %d\n"
           "hoSt: %d\n"
           "Host no space: %d\n"
           "Additional space: %d\n"
           "Mix Host: %d\n"
           "HTTP AllPorts: %d\n"
           "HTTP Persistent Nowait: %d\n"
           "DNS redirect: %d\n"
           "DNSv6 redirect: %d\n"
           "Allow missing SNI: %d\n"
           "Fake requests, TTL: %s (fixed: %hu, auto: %hu-%hu-%hu, min distance: %hu)\n"
           "Fake requests, wrong checksum: %d\n"
           "Fake requests, wrong SEQ/ACK: %d\n"
           "Fake requests, custom payloads: %d\n"
           "Fake requests, resend: %d\n"
           "Max payload size: %hu\n"
           "NFQUEUE queue: %d\n",
           do_passivedpi, do_block_quic,
           (do_fragment_http ? http_fragment_size : 0),
           (do_fragment_http_persistent ? http_fragment_size : 0),
           (do_fragment_https ? https_fragment_size : 0),
           do_fragment_by_sni,
           do_native_frag,
           do_reverse_frag,
           do_host,
           do_host_removespace,
           do_additional_space,
           do_host_mixedcase,
           do_http_allports,
           do_fragment_http_persistent_nowait,
           do_dnsv4_redirect,
           do_dnsv6_redirect,
           do_allow_no_sni,
           do_auto_ttl ? "auto" : (do_fake_packet ? "fixed" : "disabled"),
               ttl_of_fake_packet, do_auto_ttl ? auto_ttl_1 : 0, do_auto_ttl ? auto_ttl_2 : 0,
               do_auto_ttl ? auto_ttl_max : 0, ttl_min_nhops,
           do_wrong_chksum,
           do_wrong_seq,
           fakes_count,
           fakes_resend,
           max_payload_size,
           queue_num
          );

    if (do_fragment_http && http_fragment_size > 2 && !do_native_frag) {
        puts("\nWARNING: HTTP fragmentation values > 2 are not fully compatible "
             "with other options. Please use values <= 2 or disable HTTP fragmentation "
             "completely.");
    }

    if (do_native_frag && !(do_fragment_http || do_fragment_https)) {
        puts("\nERROR: Native fragmentation is enabled but fragment sizes are not set.\n"
             "Fragmentation has no effect.");
        die();
    }

    puts("\nOpening NFQUEUE");
    if (pio_init(queue_num) < 0) {
        die();
    }

    if (debug_exit) {
        printf("Debug Exit\n");
        pio_deinit();
        exit(EXIT_SUCCESS);
    }
    printf("NFQUEUE queue %d activated, GoodbyeDPI is now running!\n", queue_num);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (do_only_programs) {
        printf("Per-program mode: seeding existing connections...\n");
        proctrack_seed();
        proctrack_start_watcher_thread();
    }
    fflush(stdout);

    while (1) {
        if (pio_recv(&ctx) != 0) {
            printf("Error receiving packet!\n");
            break;
        }

        uint8_t *packet = ctx.data;
        size_t packetLen = ctx.len;
        int is_outbound = (ctx.dir == PKT_OUTBOUND);

        /* GSO/TSO super-segments (routine on VM NICs, which defer segmentation)
         * can be far larger than MAX_PACKET_SIZE, while every mangling path
         * below copies the packet into a MAX_PACKET_SIZE stack buffer. Pass
         * them through untouched instead of smashing the stack. Nothing is
         * lost: the DPI-relevant packets (TLS ClientHello, first HTTP request,
         * inbound RST, QUIC Initial) are all far below this bound. */
        if (packetLen > MAX_PACKET_SIZE) {
            debug("Oversized packet (len=%zu > %d), passing through\n",
                  packetLen, MAX_PACKET_SIZE);
            pio_send(&ctx, VERDICT_PASS);
            continue;
        }
        should_reinject = 1;
        should_recalc_checksum = 0;
        sni_ok = 0;

        struct iphdr *ppIpHdr = NULL;
        struct ipv6hdr *ppIpV6Hdr = NULL;
        struct tcphdr *ppTcpHdr = NULL;
        struct udphdr *ppUdpHdr = NULL;
        uint8_t *packet_data = NULL;
        size_t packet_dataLen = 0;
        uint8_t proto = 0;
        packet_v4 = packet_v6 = 0;
        packet_type = unknown;

        debug("Got %s packet, len=%zu!\n", is_outbound ? "outbound" : "inbound",
              packetLen);

        if (parse_packet(packet, packetLen, &ppIpHdr, &ppIpV6Hdr, &proto,
                         &ppTcpHdr, &ppUdpHdr, &packet_data, &packet_dataLen) == 0)
        {
            if (ppIpHdr) {
                packet_v4 = 1;
                if (ppTcpHdr) {
                    packet_type = ipv4_tcp;
                    if (packet_data) {
                        packet_type = ipv4_tcp_data;
                    }
                }
                else if (ppUdpHdr && packet_data) {
                    packet_type = ipv4_udp_data;
                }
            }
            else if (ppIpV6Hdr) {
                packet_v6 = 1;
                if (ppTcpHdr) {
                    packet_type = ipv6_tcp;
                    if (packet_data) {
                        packet_type = ipv6_tcp_data;
                    }
                }
                else if (ppUdpHdr && packet_data) {
                    packet_type = ipv6_udp_data;
                }
            }
        }

        /* Pre-compute src4[4]/dst4[4] for dnsredir/ttltrack calls */
        uint32_t src4[4] = {0, 0, 0, 0};
        uint32_t dst4[4] = {0, 0, 0, 0};
        if (packet_v4) {
            src4[0] = ppIpHdr->saddr;
            dst4[0] = ppIpHdr->daddr;
        }
        else if (packet_v6) {
            memcpy(src4, &ppIpV6Hdr->saddr, 16);
            memcpy(dst4, &ppIpV6Hdr->daddr, 16);
        }

        /* 1. Passive DPI: drop inbound RST from port 80/443
         *    (was WinDivert filter with DROP flag) */
        if (do_passivedpi && !is_outbound &&
            (packet_type == ipv4_tcp || packet_type == ipv6_tcp) &&
            ppTcpHdr->rst &&
            (ppTcpHdr->source == htons(80) || ppTcpHdr->source == htons(443))) {
            pio_send(&ctx, VERDICT_DROP);
            continue;
        }

        /* 2. QUIC block: outbound UDP/443 Initial (long header, >=1200 bytes).
         *    Any non-zero version counts — matching only v1 let QUIC v2
         *    (0x6b3343cf) and draft versions through with a plaintext SNI.
         *    Version 0 is Version Negotiation, which is server->client only. */
        if (do_block_quic && is_outbound &&
            (packet_type == ipv4_udp_data || packet_type == ipv6_udp_data) &&
            ppUdpHdr->dest == htons(443) && packet_dataLen >= 1200 &&
            packet_data[0] >= 0xC0 &&
            (packet_data[1] | packet_data[2] | packet_data[3] | packet_data[4]) != 0) {
            /* Backstop only: the firewall rejects outbound QUIC with an ICMP
             * port-unreachable (see goodbyedpi.nft / plat_fw_load) so clients
             * fall back to TCP immediately instead of waiting out a black
             * hole. Anything that still reaches the queue is dropped here. */
            pio_send(&ctx, VERDICT_DROP);
            continue;
        }

        /* 3. max_payload_size: skip large non-exempt TCP payloads */
        if (max_payload_size &&
            (packet_type == ipv4_tcp_data || packet_type == ipv6_tcp_data) &&
            packet_dataLen >= max_payload_size) {
            int exempt = 0;
            if (packet_dataLen >= 4) {
                if (memcmp(packet_data, "GET ", 4) == 0 ||
                    memcmp(packet_data, "POST", 4) == 0)
                    exempt = 1;
            }
            if (!exempt && packet_dataLen >= 3 &&
                packet_data[0] == 0x16 && packet_data[1] == 0x03 && packet_data[2] <= 0x03)
                exempt = 1;
            if (!exempt) {
                pio_send(&ctx, VERDICT_PASS);
                continue;
            }
        }

        /* 4. Proctrack gate: when --only-programs is active, apply bypass
         *    tricks only to traffic owned by a whitelisted process.
         *    DNS redirect is EXEMPT (must work globally). */
        if (do_only_programs && (ppTcpHdr || ppUdpHdr) &&
            !(ppUdpHdr && (do_dnsv4_redirect || do_dnsv6_redirect)))
        {
            uint8_t  pt_proto = ppTcpHdr ? IPPROTO_TCP : IPPROTO_UDP;
            uint16_t pt_lport, pt_rport;
            const void *pt_laddr, *pt_raddr;

            if (is_outbound) {
                pt_laddr = packet_v4 ? (const void *)&ppIpHdr->saddr
                                     : (const void *)&ppIpV6Hdr->saddr;
                pt_raddr = packet_v4 ? (const void *)&ppIpHdr->daddr
                                     : (const void *)&ppIpV6Hdr->daddr;
                pt_lport = ppTcpHdr ? ppTcpHdr->source : ppUdpHdr->source;
                pt_rport = ppTcpHdr ? ppTcpHdr->dest : ppUdpHdr->dest;
            } else {
                pt_laddr = packet_v4 ? (const void *)&ppIpHdr->daddr
                                     : (const void *)&ppIpV6Hdr->daddr;
                pt_raddr = packet_v4 ? (const void *)&ppIpHdr->saddr
                                     : (const void *)&ppIpV6Hdr->saddr;
                pt_lport = ppTcpHdr ? ppTcpHdr->dest : ppUdpHdr->dest;
                pt_rport = ppTcpHdr ? ppTcpHdr->source : ppUdpHdr->source;
            }

            if (!proctrack_is_target(pt_proto, pt_laddr, ntohs(pt_lport),
                                     pt_raddr, ntohs(pt_rport), packet_v6)) {
                if (do_debug_proc && proc_debug_count < proc_debug_limit) {
                    proc_debug_count++;
                    const char *mname = "UNKNOWN";
                    switch (proctrack_last_method) {
                        case 0: mname = "map"; break;
                        case 1: mname = "udp-loc"; break;
                        case 2: mname = "os-fallback"; break;
                    }
                    if (packet_v4) {
                        uint32_t la = *(const uint32_t *)pt_laddr;
                        uint32_t ra = *(const uint32_t *)pt_raddr;
                        printf("[GATE] %s %s %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u BLOCK method=%s\n",
                               pt_proto == IPPROTO_TCP ? "TCP" : "UDP",
                               is_outbound ? "out" : "in",
                               la & 0xFF, (la>>8)&0xFF, (la>>16)&0xFF, (la>>24)&0xFF, ntohs(pt_lport),
                               ra & 0xFF, (ra>>8)&0xFF, (ra>>16)&0xFF, (ra>>24)&0xFF, ntohs(pt_rport),
                               mname);
                    } else {
                        printf("[GATE] %s %s [v6]:%u -> [v6]:%u BLOCK method=%s\n",
                               pt_proto == IPPROTO_TCP ? "TCP" : "UDP",
                               is_outbound ? "out" : "in",
                               ntohs(pt_lport), ntohs(pt_rport), mname);
                    }
                    fflush(stdout);
                }
                pio_send(&ctx, VERDICT_PASS);
                continue;
            } else if (do_debug_proc && proc_debug_count < proc_debug_limit) {
                proc_debug_count++;
                const char *mname = "UNKNOWN";
                switch (proctrack_last_method) {
                    case 0: mname = "map"; break;
                    case 1: mname = "udp-loc"; break;
                    case 2: mname = "os-fallback"; break;
                }
                if (packet_v4) {
                    uint32_t la = *(const uint32_t *)pt_laddr;
                    uint32_t ra = *(const uint32_t *)pt_raddr;
                    printf("[GATE] %s %s %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u PASS method=%s\n",
                           pt_proto == IPPROTO_TCP ? "TCP" : "UDP",
                           is_outbound ? "out" : "in",
                           la & 0xFF, (la>>8)&0xFF, (la>>16)&0xFF, (la>>24)&0xFF, ntohs(pt_lport),
                           ra & 0xFF, (ra>>8)&0xFF, (ra>>16)&0xFF, (ra>>24)&0xFF, ntohs(pt_rport),
                           mname);
                } else {
                    printf("[GATE] %s %s [v6]:%u -> [v6]:%u PASS method=%s\n",
                           pt_proto == IPPROTO_TCP ? "TCP" : "UDP",
                           is_outbound ? "out" : "in",
                           ntohs(pt_lport), ntohs(pt_rport), mname);
                }
                fflush(stdout);
            }
        }

        debug("packet_type: %d, packet_v4: %d, packet_v6: %d\n", packet_type, packet_v4, packet_v6);

        /* 5. Packet type handling */
        if (packet_type == ipv4_tcp_data || packet_type == ipv6_tcp_data) {
            /* Got a TCP packet WITH DATA */

            /* Handle INBOUND packet with data: check for HTTP redirect */
            if (!is_outbound && packet_dataLen > 16) {
                if (do_passivedpi && is_passivedpi_redirect((const char *)packet_data, (unsigned int)packet_dataLen)) {
                    if (packet_v4) {
                        should_reinject = 0;
                    }
                    else if (packet_v6) {
                        uint32_t flow_label = ((uint32_t)(ppIpV6Hdr->flow_lbl[0] & 0x0F) << 16) |
                                              ((uint32_t)ppIpV6Hdr->flow_lbl[1] << 8) |
                                              (uint32_t)ppIpV6Hdr->flow_lbl[2];
                        if (flow_label == 0x0) {
                            should_reinject = 0;
                        }
                    }
                }
            }
            /* Handle OUTBOUND packet on port 443: TLS fake request */
            else if (is_outbound &&
                    ((do_fragment_https ? packet_dataLen == https_fragment_size : 0) ||
                     packet_dataLen > 16) &&
                     ppTcpHdr->dest != htons(80) &&
                     (do_fake_packet || do_native_frag))
            {
                if ((packet_dataLen == 2 && memcmp(packet_data, "\x16\x03", 2) == 0) ||
                    (packet_dataLen >= 3 && (memcmp(packet_data, "\x16\x03\x01", 3) == 0 ||
                                             memcmp(packet_data, "\x16\x03\x03", 3) == 0)))
                {
                    /* NOTE: the ClientHello is NEVER rewritten here. Deleting
                     * bytes from an in-flight TCP segment (the old ECH-strip
                     * hack) desynchronises the byte stream — the peer receives
                     * fewer bytes than the sender accounted for — and breaks
                     * the TLS 1.3 transcript hash, so the handshake dies.
                     * ECH already hides the real SNI from the DPI, so there
                     * is nothing to circumvent on such connections. */
                    if (do_blacklist || do_fragment_by_sni) {
                        sni_ok = extract_sni((const char *)packet_data, (unsigned int)packet_dataLen,
                                    &host_addr, &host_len);
                    }
                    if (
                         (do_blacklist && sni_ok &&
                          blackwhitelist_check_hostname(host_addr, host_len)
                         ) ||
                         (do_blacklist && !sni_ok && do_allow_no_sni) ||
                         (!do_blacklist)
                       )
                    {
                        if (do_fake_packet) {
                            TCP_HANDLE_OUTGOING_FAKE_PACKET(send_fake_https_request);
                        }
                        if (do_native_frag) {
                            should_recalc_checksum = 1;
                        }
                    }
                }
            }
            /* Handle OUTBOUND packet on port 80: HTTP Host header tricks */
            else if (is_outbound &&
                    packet_dataLen > 16 &&
                    (do_http_allports ? 1 : (ppTcpHdr->dest == htons(80))) &&
                    find_http_method_end((const char *)packet_data,
                                         (do_fragment_http ? http_fragment_size : 0u),
                                         &http_req_fragmented) &&
                    (do_host || do_host_removespace ||
                    do_host_mixedcase || do_fragment_http_persistent ||
                    do_fake_packet))
            {
                if (find_header_and_get_info((const char *)packet_data, (unsigned int)packet_dataLen,
                    http_host_find, &hdr_name_addr, &hdr_value_addr, &hdr_value_len) &&
                    hdr_value_len > 0 && hdr_value_len <= HOST_MAXLEN &&
                    (do_blacklist ? blackwhitelist_check_hostname(hdr_value_addr, hdr_value_len) : 1))
                {
                    host_addr = hdr_value_addr;
                    host_len = hdr_value_len;

                    if (do_native_frag) {
                        should_recalc_checksum = 1;
                    }

                    if (do_fake_packet) {
                        TCP_HANDLE_OUTGOING_FAKE_PACKET(send_fake_http_request);
                    }

                    if (do_host_mixedcase) {
                        mix_case(host_addr, host_len);
                        should_recalc_checksum = 1;
                    }

                    if (do_host) {
                        memcpy(hdr_name_addr, http_host_replace, strlen(http_host_replace));
                        should_recalc_checksum = 1;
                    }

                    if (do_additional_space && do_host_removespace) {
                        method_addr = find_http_method_end((const char *)packet_data,
                                                        (do_fragment_http ? http_fragment_size : 0),
                                                        NULL);
                        if (method_addr) {
                            memmove(method_addr + 1, method_addr,
                                    (size_t)(host_addr - method_addr - 1));
                            should_recalc_checksum = 1;
                        }
                    }
                    else if (do_host_removespace) {
                        if (find_header_and_get_info((const char *)packet_data, (unsigned int)packet_dataLen,
                                                    http_useragent_find, &hdr_name_addr,
                                                     &hdr_value_addr, &hdr_value_len))
                        {
                            useragent_addr = hdr_value_addr;
                            useragent_len = hdr_value_len;

                            if (useragent_addr && useragent_len > 0) {
                                if (useragent_addr > host_addr) {
                                    memmove(host_addr - 1, host_addr,
                                            (size_t)(useragent_addr + useragent_len - host_addr));
                                    host_addr -= 1;
                                    *(char*)((unsigned char*)useragent_addr + useragent_len - 1) = ' ';
                                    should_recalc_checksum = 1;
                                }
                                else {
                                    memmove(useragent_addr + useragent_len + 1,
                                            useragent_addr + useragent_len,
                                            (size_t)(host_addr - 1 - (useragent_addr + useragent_len)));
                                    *(char*)((unsigned char*)useragent_addr + useragent_len) = ' ';
                                    should_recalc_checksum = 1;
                                }
                            }
                        }
                    }
                }
            }

            /* Native fragmentation: send fragments via raw socket, drop original */
            if (should_reinject && should_recalc_checksum && do_native_frag)
            {
                current_fragment_size = 0;
                if (do_fragment_http && ppTcpHdr->dest == htons(80)) {
                    current_fragment_size = http_fragment_size;
                }
                else if (do_fragment_https && ppTcpHdr->dest != htons(80)) {
                    if (do_fragment_by_sni && sni_ok) {
                        current_fragment_size = (unsigned int)((char*)host_addr - (char*)packet_data);
                    } else {
                        current_fragment_size = https_fragment_size;
                    }
                }

                if (current_fragment_size) {
                    send_native_fragment(packet, packetLen, packet_data, packet_dataLen,
                                        packet_v4, packet_v6,
                                        ppIpHdr, ppIpV6Hdr, ppTcpHdr,
                                        current_fragment_size, do_reverse_frag);
                    send_native_fragment(packet, packetLen, packet_data, packet_dataLen,
                                        packet_v4, packet_v6,
                                        ppIpHdr, ppIpV6Hdr, ppTcpHdr,
                                        current_fragment_size, !do_reverse_frag);
                    pio_send(&ctx, VERDICT_DROP);
                    continue;
                }
            }
        } /* Handle TCP packet with data */

        /* Else if we got TCP packet without data (SYN, SYN+ACK, etc.) */
        else if (packet_type == ipv4_tcp || packet_type == ipv6_tcp) {
            if (!is_outbound &&
                ppTcpHdr->syn == 1 && ppTcpHdr->ack == 1) {
                /* INBOUND SYN+ACK: track TTL for auto-ttl, change window size */

                if (do_fake_packet && (do_auto_ttl || ttl_min_nhops)) {
                    if (!((packet_v4 && tcp_handle_incoming(src4, dst4,
                                    ppTcpHdr->source, ppTcpHdr->dest,
                                    0, ppIpHdr->ttl))
                        ||
                        (packet_v6 && tcp_handle_incoming(src4, dst4,
                                    ppTcpHdr->source, ppTcpHdr->dest,
                                    1, ppIpV6Hdr->hop_limit))))
                    {
                        if (do_tcp_verb)
                            puts("[TCP WARN] Can't add TCP connection record.");
                    }
                }

                if (!do_native_frag) {
                    if (do_fragment_http && ppTcpHdr->source == htons(80)) {
                        change_window_size(ppTcpHdr, http_fragment_size);
                        should_recalc_checksum = 1;
                    }
                    else if (do_fragment_https && ppTcpHdr->source != htons(80)) {
                        change_window_size(ppTcpHdr, https_fragment_size);
                        should_recalc_checksum = 1;
                    }
                }
            }
        }

        /* Else if we got UDP packet with data (DNS redirect) */
        else if ((do_dnsv4_redirect && (packet_type == ipv4_udp_data)) ||
                 (do_dnsv6_redirect && (packet_type == ipv6_udp_data)))
        {
            if (!is_outbound) {
                /* INBOUND DNS response: restore original source IP/port */
                if ((packet_v4 && dns_handle_incoming(dst4, ppUdpHdr->dest,
                                    packet_data, packet_dataLen,
                                    &dns_conn_info, 0))
                    ||
                    (packet_v6 && dns_handle_incoming(dst4, ppUdpHdr->dest,
                                    packet_data, packet_dataLen,
                                    &dns_conn_info, 1)))
                {
                    if (packet_v4)
                        ppIpHdr->saddr = dns_conn_info.dstip[0];
                    else if (packet_v6)
                        ipv6_copy_addr((uint32_t*)&ppIpV6Hdr->saddr, dns_conn_info.dstip);
                    ppUdpHdr->dest = dns_conn_info.srcport;
                    ppUdpHdr->source = dns_conn_info.dstport;
                    should_recalc_checksum = 1;
                }
                else {
                    if (dns_is_dns_packet(packet_data, packet_dataLen, 0))
                        should_reinject = 0;

                    if (do_dns_verb && !should_reinject) {
                        printf("[DNS] Error handling incoming packet: srcport = %hu, dstport = %hu\n",
                           ntohs(ppUdpHdr->source), ntohs(ppUdpHdr->dest));
                    }
                }
            }

            else if (is_outbound) {
                /* OUTBOUND DNS request: redirect to configured DNS server */
                if ((packet_v4 && dns_handle_outgoing(src4, ppUdpHdr->source,
                                    dst4, ppUdpHdr->dest,
                                    packet_data, packet_dataLen, 0))
                    ||
                    (packet_v6 && dns_handle_outgoing(src4, ppUdpHdr->source,
                                    dst4, ppUdpHdr->dest,
                                    packet_data, packet_dataLen, 1)))
                {
                    if (packet_v4) {
                        ppIpHdr->daddr = dnsv4_addr;
                        ppUdpHdr->dest = dnsv4_port;
                    }
                    else if (packet_v6) {
                        ipv6_copy_addr((uint32_t*)&ppIpV6Hdr->daddr,
                                       (const uint32_t*)&dnsv6_addr);
                        ppUdpHdr->dest = dnsv6_port;
                    }
                    should_recalc_checksum = 1;
                }
                else {
                    if (dns_is_dns_packet(packet_data, packet_dataLen, 1))
                        should_reinject = 0;

                    if (do_dns_verb && !should_reinject) {
                        printf("[DNS] Error handling outgoing packet: srcport = %hu, dstport = %hu\n",
                           ntohs(ppUdpHdr->source), ntohs(ppUdpHdr->dest));
                    }
                }
            }
        }

        /* 6. Reinject / drop */
        if (should_reinject) {
            if (should_recalc_checksum) {
                calc_checksums(packet, packetLen);
        ctx.len = packetLen;
                pio_send(&ctx, VERDICT_MODIFY);
            } else {
                pio_send(&ctx, VERDICT_PASS);
            }
        } else {
            pio_send(&ctx, VERDICT_DROP);
        }
    }

    pio_deinit();
    proctrack_free();
    return 0;
}
