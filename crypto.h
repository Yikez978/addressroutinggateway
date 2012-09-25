#ifndef HMAC_H
#define HMAC_H

#include "utility.h"

#define HMAC_SIZE 20
#define HMAC_BLOCK_SIZE 64

#define ARG_IV "argisayarg"

int hmac_sha1(const uchar *key, size_t klen, const uchar *data, size_t dlen, uchar *out);
uint32_t hotp(const uchar *key, size_t klen, unsigned long count);
uint32_t totp(const uchar *key, size_t klen, unsigned long step, unsigned long time);

#endif

