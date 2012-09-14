#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "crypto.h"
#include "sha1.h"
#include "settings.h"

int hmac_sha1(const uchar *key, size_t klen, const uchar *data, size_t dlen, uchar *out)
{
	int i = 0;
	uchar *scratchSpace = NULL;
	SHA1Context sha;
	int maxLen = HMAC_BLOCK_SIZE + (HMAC_SIZE < dlen ? dlen : HMAC_SIZE);

	// Allocate enough space for the max we need, which is
	// the key padded to block size + either the data length or the hash length
	scratchSpace = kcalloc(maxLen, 1, GFP_KERNEL);
	if(scratchSpace == NULL)
	{
		printk(KERN_ALERT "ARG: Unable to allocate scratch space for HMAC\n");
		return 1;
	}

	// Pad key. TBD this could always come in padded to allow 
	// the copy to be skipped
	memmove(scratchSpace, key, klen);
	
	// XOR padded key with ipad (0x36 repeated, from RFC2104)
	for(i = 0; i < HMAC_BLOCK_SIZE; i++)
		scratchSpace[i] ^= 0x36;

	// Append data
	memmove(scratchSpace + HMAC_BLOCK_SIZE, data, dlen);

	// Hash that mess
	SHA1Reset(&sha);
	SHA1Input(&sha, scratchSpace, HMAC_BLOCK_SIZE + dlen);
	if(!SHA1Result(&sha))
	{
		printk(KERN_ALERT "ARG: Unable to create SHA\n");
		return 0;
	}

	// Redo the key padding
	memset(scratchSpace, 0, HMAC_BLOCK_SIZE);
	memmove(scratchSpace, key, klen);
	
	// XOR padded key with opad (0x5C repeated, from RFC2104)
	for(i = 0; i < HMAC_BLOCK_SIZE; i++)
		scratchSpace[i] ^= 0x5C;

	// Append first hash
	memmove(scratchSpace, sha.Message_Digest, HMAC_SIZE);
	
	// And hash again
	SHA1Reset(&sha);
	SHA1Input(&sha, scratchSpace, HMAC_BLOCK_SIZE + HMAC_SIZE);
	if(!SHA1Result(&sha))
	{
		printk(KERN_ALERT "ARG: Unable to create SHA\n");
		return 0;
	}

	// Save off
	memmove(out, sha.Message_Digest, HMAC_SIZE);

	// All done!
	kfree(scratchSpace);

	return 0;
}

