#ifndef NAT_H
#define NAT_H

#include <linux/skbuff.h>
#include <linux/types.h>

#include "utility.h"
#include "uthash.h"
#include "net_info.h"

// Struct of an entry in the NAT table
struct nat_entry_bucket;

typedef struct nat_entry {
	// Host inside of ARG
	uchar intIP[ADDR_SIZE];
	__be16 intPort;
	
	// Gateway IP at the time the connection was established
	uchar gateIP[ADDR_SIZE];
	__be16 gatePort;

	// Walltime of the last time this connection was actively used
	int lastUsed;

	// Other entries in this NAT list
	struct nat_entry *next;
} nat_entry;

typedef struct nat_entry_bucket {
	// Hash key
	int key;
	
	// Host outside of ARG that is being connected to
	uchar extIP[ADDR_SIZE];
	__be16 extPort;

	// Connections in this bucket
	struct nat_entry *first;

	// Allows this struct to be used by uthash
	UT_hash_handle hh;
} nat_entry_bucket;

// Initializes anything needed by NAT
void init_nat(void);

// Re-writes the given packet based on data in
// the NAT table and returns true. If it is unable
// to (i.e., there is no coresponding entry), false is returned.
char do_nat_inbound_rewrite(struct sk_buff *skb);

// Re-writes the given packet based on data in
// the NAT table and returns true. If needed, a new
// entry is created in the table based on the current IP
// If it is unable to rewrite, false is returned.
char do_nat_outbound_rewrite(struct sk_buff *skb);

// Clears the NAT table of old functions
void clean_nat_table(void);

#endif

