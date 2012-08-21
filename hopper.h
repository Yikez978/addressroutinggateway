#ifndef HOPPER_H
#define HOPPER_H

#include <linux/skbuff.h>
#include <linux/ip.h>

#include "utility.h"
#include "net_info.h"

void init_hopper(void);

// Returns the current IP address for the gateway
// NOTE: the previous IP is also valid for receiving,
// so checks from that perspective should use is_current_ip(uchar *ip);
uchar const *current_ip(void);

// Returns true if the given IP is valid, false otherwise
char is_current_ip(uchar const *ip);

// Checks if the given packet is an administrative 
// packet or not. Returns true if it is, false otherwise
char is_admin_packet(struct sk_buff const *skb);

// Checks if the given packet is signed correctly.
// Returns true if it is, false otherwise
char is_signature_valid(struct sk_buff const *skb);

// Wraps the given packet for the appropriate ARG network
// and signs it. The new packet is left in skb
// Returns false if the packet is not destined for a known
// ARG network or another error occurs during processing
char do_arg_wrap(struct sk_buff *skb);

// Unwraps the given packet, leaving the inner packet in skb.
// Returns false if the signature fails to match or another error
// occurs during processing
char do_arg_unwrap(struct sk_buff *skb);

// Returns the ID of the associated ARG network of the given
// the IP. If 0, indicates the IP belongs to THIS network
// A negative value is returned if the IP is not found
int get_arg_id(uchar const *ip);

// Returns true if the given IP is an ARG network
char is_arg_ip(uchar const *ip);

#endif

