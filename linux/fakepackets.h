#ifndef _FAKEPACKETS_H
#define _FAKEPACKETS_H

#include <stdint.h>
#include <stddef.h>

#define FAKES_MAX 30

struct fake_t {
    const unsigned char* data;
    size_t size;
};

extern struct fake_t *fakes[FAKES_MAX];
extern int fakes_count;
extern int fakes_resend;

int send_fake_http_request(const uint8_t *pkt, size_t packetLen,
                           int is_ipv6,
                           uint8_t set_ttl, uint8_t set_checksum, uint8_t set_seq);

int send_fake_https_request(const uint8_t *pkt, size_t packetLen,
                            int is_ipv6,
                            uint8_t set_ttl, uint8_t set_checksum, uint8_t set_seq);

int fake_load_from_hex(const char *data);
int fake_load_from_sni(const char *domain_name);
int fake_load_random(unsigned int count, unsigned int maxsize);

#endif /* _FAKEPACKETS_H */
