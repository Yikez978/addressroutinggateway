#ifndef NAT_H
#define NAT_H

#include <linux/skbuff.h>
#include <linux/types.h>

#include "utility.h"
#include "uthash.h"
#include "net_info.h"

// Number of seconds between full checks of the NAT table for expired connections
#define NAT_CLEAN_TIME 30

// Number of seconds before an inactive connection is removed
#define NAT_OLD_CONN_TIME 120

// Struct of an entry in the NAT table
struct nat_entry_bucket;

typedef struct nat_entry {
	// Host inside of ARG
	uchar intIP[ADDR_SIZE];
	__be16 intPort;
	
	// Gateway IP at the time the connection was established
	uchar gateIP[ADDR_SIZE];
	__be16 gatePort;

	// Protocol of the connection
	int proto;

	// Walltime of the last time this connection was actively used
	__kernel_time_t lastUsed;

	// Traversal info for list
	struct nat_entry_bucket *bucket;
	struct nat_entry *next;
	struct nat_entry *prev;
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
void init_nat_locks(void);
char init_nat(void);
void uninit_nat(void);

// Re-writes the given packet based on data in
// the NAT table and returns true. If it is unable
// to (i.e., there is no coresponding entry), false is returned.
char do_nat_inbound_rewrite(struct sk_buff *skb);

// Re-writes the given packet based on data in
// the NAT table and returns true. If needed, a new
// entry is created in the table based on the current IP
// If it is unable to rewrite, false is returned.
char do_nat_outbound_rewrite(struct sk_buff *skb);

// Displays all the data in the NAT table
void print_nat_table(void);

// Helpers to display NAT data
void print_nat_bucket(const struct nat_entry_bucket *bucket);
void print_nat_entry(const struct nat_entry *entry);

// Helpers to create NAT data
struct nat_entry_bucket *create_nat_bucket(const struct sk_buff *skb, const int key);
struct nat_entry *create_nat_entry(const struct sk_buff *skb, struct nat_entry_bucket *bucket);

void update_nat_entry_time(struct nat_entry *e);

// Build bucket key based on the given IP and port (must be given directly,
// not as an sk_buff because incoming/outgoing use different parts)
int create_nat_bucket_key(const void *ip, const __be16 port); 

// Helpers to remove NAT entries. Return references to the next element, where applicable
// NOT synchronized. Callers MUST ensure they have the write lock
struct nat_entry_bucket *remove_nat_bucket(struct nat_entry_bucket *bucket);
struct nat_entry *remove_nat_entry(struct nat_entry *e);

// Clears the NAT table of old functions/provides
// callback for timed cleanup. All functions work with the lock to ensure synchronization
void empty_nat_table(void);
void nat_timed_cleanup(unsigned long data);
void clean_nat_table(void);

#endif

