#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>

#include "polarssl/config.h"	
#include "polarssl/rsa.h"
#include "polarssl/sha1.h"

#define HMAC_SIZE 20
#define HMAC_BLOCK_SIZE 64

// Generates a Hash-based One-Time Password value. See RFC4226
uint32_t hotp(const uint8_t *key, unsigned int klen, unsigned long count);

// Uses hotp to create a Time-Based One-Time Password. See RFC6238
uint32_t totp(const uint8_t *key, unsigned int klen, unsigned long step, unsigned long time);

void get_random_bytes(void *buf, int nbytes);

#endif

