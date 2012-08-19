#include "nat.h"

/**********************
NAT table data
**********************/

char do_nat_inbound_rewrite(struct sk_buff *skb)
{
	// TBD Find entry in table

	// Change destination addr and port

	// Re-checksum

	return 1;
}

char do_nat_outbound_rewrite(struct sk_buff *skb)
{
	// TBD Find entry in table
	// If not, create one

	// Change destination addr and port

	// Re-checksum

	return 1;
}


