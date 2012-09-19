#ifndef DIRECTOR_H
#define DIRECTOR_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>

char init_director(void);
char uninit_director(void);

unsigned int direct_inbound(unsigned int hooknum, struct sk_buff *skb, 
							const struct net_device *in,
							const struct net_device *out, 
							int (*okfn)(struct sk_buff *));
unsigned int direct_outbound(unsigned int hooknum, struct sk_buff *skb, 
							const struct net_device *in,
							const struct net_device *out,
							int (*okfn)(struct sk_buff *));

char is_local_traffic(const struct sk_buff *skb);
char is_control_traffic(const struct net_device *dev);
char is_supported_proto(const struct sk_buff *skb);

#endif

