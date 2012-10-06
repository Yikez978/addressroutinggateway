#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "crypto.h"
#include "settings.h"

uint32_t hotp(const uint8_t *key, unsigned int klen, unsigned long count)
{
	int offset = 0;
	uint32_t result = 0;
	uint8_t hmac_result[HMAC_SIZE] = {0};
	
	sha1_hmac(key, klen, (uint8_t*)&count, sizeof(count), hmac_result);

	// Truncate, code directly from HOTP RFC
	offset =  hmac_result[HMAC_SIZE - 1] & 0xf;
    result = (hmac_result[offset] & 0x7f) << 24
			| (hmac_result[offset+1] & 0xff) << 16
			| (hmac_result[offset+2] & 0xff) <<  8
			| (hmac_result[offset+3] & 0xff);

	// We skip the "string to number" step of the full HOTP algorithm
	// The security analysis in the RFC seems to indicate that this is perfectly
	// acceptable. In fact, this removes the (negligble) bias introduced by that step

	return result;
}

uint32_t totp(const uint8_t *key, unsigned int klen, unsigned long step, unsigned long time)
{
	// Protect us from ourselves
	if(step == 0)
		step = 1;

	return hotp(key, klen, time / step);	
}

void get_random_bytes(void *buf, int nbytes)
{
	static int randomData = 0;
	int n = 0;

	if(randomData == 0)
		randomData = open("/dev/urandom", O_RDONLY);
	
	do
	{
		n += read(randomData, (uint8_t*)buf + n, nbytes - n);
	} while(n < nbytes);
}

