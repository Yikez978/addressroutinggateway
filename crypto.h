#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>

#define HMAC_SIZE 20
#define HMAC_BLOCK_SIZE 64

#define ARG_IV "argisayarg"

int hmac_sha1(const uint8_t *key, unsigned int klen, const uint8_t *data, unsigned int dlen, uint8_t *out);
uint32_t hotp(const uint8_t *key, unsigned int klen, unsigned long count);
uint32_t totp(const uint8_t *key, unsigned int klen, unsigned long step, unsigned long time);

void get_random_bytes(void *buf, int nbytes);

#endif
