#ifndef HMAC_H
#define HMAC_H

#include "utility.h"

#define HMAC_SIZE 40
#define HMAC_BLOCK_SIZE 64

int hmac_sha1(const uchar *key, size_t klen, const uchar *data, size_t dlen, uchar *out);
uint32_t hotp(const uchar *key, size_t klen, unsigned long count);
uint32_t totp(uchar *key, size_t klen, unsigned long step, unsigned long time);

#endif

