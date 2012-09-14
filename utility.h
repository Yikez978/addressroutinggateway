#ifndef UTILITY_H
#define UTILITY_H

#include <linux/types.h>
#include <linux/skbuff.h>

typedef unsigned char uchar;

void printRaw(int len, const void *buf);
void printAscii(int len, const void *buf);
void printIP(int len, const void *buf);
void printPacket(const struct sk_buff *skb);
void printPacketInfo(const struct sk_buff *skb);

__be16 get_source_port(const struct sk_buff *skb);
__be16 get_dest_port(const struct sk_buff *skb);
void set_source_port(const struct sk_buff *skb, const __be16 port);
void set_dest_port(const struct sk_buff *skb, const __be16 port);

// Ensures that the offset for transport_header is correct
void fix_transport_header(struct sk_buff *skb);

// Returns true if the given packet uses a connection-oriented protocol
char is_conn_oriented(const struct sk_buff *skb);

// Mask an arbitrarilly long number of bytes. Eh, whatever. It's a hack
// orig, mask, and result must all be the same length
void mask_array(int len, void *orig, void *mask, void *result);

// Compares two arrays (left and right) based on the mask given
// If equal, 0 is returned. Otherwise, non-0 (undefined beyond that)
char mask_array_cmp(int len, void *mask, void *left, void *right);

#endif

