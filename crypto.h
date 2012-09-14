#ifndef HMAC_H
#define HMAC_H

#include "utility.h"

#define HMAC_SIZE 5

int hmac_sha1(const uchar *key, size_t klen, const uchar *data, size_t dlen, uchar *out);

#endif

