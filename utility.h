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

// Returns true if the given packet uses a connection-oriented protocol
char is_conn_oriented(const struct sk_buff *skb);

#endif

