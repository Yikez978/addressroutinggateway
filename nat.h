#ifndef NAT_H
#define NAT_H

#include <linux/skbuff.h>

// Re-writes the given packet based on data in
// the NAT table and returns true. If it is unable
// to (i.e., there is no coresponding entry), false is returned.
char do_nat_rewrite(struct sk_buff *skb);

#endif

