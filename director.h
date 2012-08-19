#ifndef DIRECTOR_H
#define DIRECTOR_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>

unsigned int direct_inbound(struct sk_buff *skb);
unsigned int direct_outbound(struct sk_buff *skb);

#endif

