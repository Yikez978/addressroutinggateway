#ifndef NAT_H
#define NAT_H

#include <linux/skbuff.h>

// Re-writes the given packet based on data in
// the NAT table and returns true. If it is unable
// to (i.e., there is no coresponding entry), false is returned.
char do_nat_inbound_rewrite(struct sk_buff *skb);

// Re-writes the given packet based on data in
// the NAT table and returns true. If needed, a new
// entry is created in the table based on the current IP
// If it is unable to rewrite, false is returned.
char do_nat_outbound_rewrite(struct sk_buff *skb);

#endif

