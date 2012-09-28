#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "crypto.h"
#include "sha1.h"
#include "settings.h"

int hmac_sha1(const uint8_t *key, unsigned int klen, const uint8_t *data, unsigned int dlen, uint8_t *out)
{
	int i = 0;
	uint8_t *scratchSpace = NULL;
	SHA1Context sha;
	int maxLen = HMAC_BLOCK_SIZE + (HMAC_SIZE < dlen ? dlen : HMAC_SIZE);

	// Safety check
	if(klen > HMAC_BLOCK_SIZE)
	{
		printf("ARG: Key must be shorter than HMAC_BLOCK_SIZE (%i)\n", HMAC_BLOCK_SIZE);
		return 0;
	}
	
	// Allocate enough space for the max we need, which is
	// the key padded to block size + either the data length or the hash length
	scratchSpace = calloc(maxLen, 1);
	if(scratchSpace == NULL)
	{
		printf("ARG: Unable to allocate scratch space for HMAC\n");
		return 0;
	}

	// Steps refer to the steps under the HMAC RFC's "Definition of HMAC" section
	// (1) Pad key. TBD this could always come in padded to allow 
	// the copy to be skipped
	memmove(scratchSpace, key, klen);
	
	// (2) XOR padded key with ipad (0x36 repeated, from RFC2104)
	for(i = 0; i < HMAC_BLOCK_SIZE; i++)
		scratchSpace[i] ^= 0x36;

	// (3) Append data
	memmove(scratchSpace + HMAC_BLOCK_SIZE, data, dlen);

	// (4) Hash that mess
	SHA1Reset(&sha);
	SHA1Input(&sha, scratchSpace, HMAC_BLOCK_SIZE + dlen);
	if(!SHA1Result(&sha))
	{
		printf("ARG: HMAC unable to create inner SHA\n");
		return 0;
	}

	// (pre-5) Redo the key padding
	memset(scratchSpace, 0, HMAC_BLOCK_SIZE);
	memmove(scratchSpace, key, klen);
	
	// (5) XOR padded key with opad (0x5C repeated, from RFC2104)
	for(i = 0; i < HMAC_BLOCK_SIZE; i++)
		scratchSpace[i] ^= 0x5C;

	// (6) Append first hash
	memmove(scratchSpace, sha.Message_Digest, HMAC_SIZE);
	
	// (7) And hash again
	SHA1Reset(&sha);
	SHA1Input(&sha, scratchSpace, HMAC_BLOCK_SIZE + HMAC_SIZE);
	if(!SHA1Result(&sha))
	{
		printf("ARG: HMAC unable to create outer SHA\n");
		return 0;
	}

	// Save off
	memmove(out, sha.Message_Digest, HMAC_SIZE);

	// All done!
	free(scratchSpace);

	return 1;
}

uint32_t hotp(const uint8_t *key, unsigned int klen, unsigned long count)
{
	int offset = 0;
	uint32_t result = 0;
	uint8_t hmac_result[HMAC_SIZE] = {0};
	
	if(!hmac_sha1(key, klen, (uint8_t*)&count, sizeof(count), hmac_result))
	{
		printf("ARG: Unable to perform HOTP\n");
		return 0;
	}

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

void aes_encrypt(const uint8_t *key, int klen, const uint8_t *data, int dlen, uint8_t *out, int *outlen)
{
	// TBD encrypt
	/*struct cryto_cipher *tfm;

	tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
	if(IS_ERR(tfm))
	{
		printf("ARG: Unable to allocate cipher for AES encryption\n");
		return;
	}

	crypto_cipher_setkey(tfm, key, klen);

	crypto_cipher_encrypt_one(tfm, b, b_0);
 

	crypto_free_cipher(tfm);*/
}

void aes_decrypt(uint8_t *data, int dlen, uint8_t *out, int *outlen)
{
	// TBD decrypt
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

