#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>

/* After promisc drops, checksum checks. */
#define NF_IP_PRE_ROUTING       0
/* If the packet is destined for this box. */
#define NF_IP_LOCAL_IN          1
/* If the packet is destined for another interface. */
#define NF_IP_FORWARD           2
/* Packets coming from a local process. */
#define NF_IP_LOCAL_OUT         3
/* Packets about to hit the wire. */
#define NF_IP_POST_ROUTING      4
#define NF_IP_NUMHOOKS          5

#include "nat.h"
#include "director.h"
#include "hopper.h"
#include "utility.h"

/***************************
Netfilter hooking variables
***************************/
static struct nf_hook_ops *incomingTrafficHook = NULL;
static struct nf_hook_ops *outgoingTrafficHook = NULL;

char init_director(void)
{
	printk("ARG: Director init\n");

	// Hook the inboud traffic
	incomingTrafficHook = (struct nf_hook_ops*)kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
	if(incomingTrafficHook == NULL)
	{
		printk(KERN_ALERT "ARG: Unable to create hook for incoming traffic\n");
		return 0;
	}
	
	incomingTrafficHook->hook = direct_inbound;                       
	incomingTrafficHook->hooknum = NF_IP_PRE_ROUTING;
	incomingTrafficHook->pf = PF_INET;
	incomingTrafficHook->priority = NF_IP_PRI_FIRST;

	// Hook the outbound local traffic
	outgoingTrafficHook = (struct nf_hook_ops*)kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
	if(outgoingTrafficHook == NULL)
	{
		printk(KERN_ALERT "ARG: Unable to create hook for outgoing traffic\n");

		// Free the incoming hook
		kfree(incomingTrafficHook);
		incomingTrafficHook = NULL;

		return 0;
	}

	outgoingTrafficHook->hook = direct_outbound;               
	outgoingTrafficHook->hooknum = NF_IP_LOCAL_OUT; // TBD IP_FORWARD later
	outgoingTrafficHook->pf = PF_INET;
	outgoingTrafficHook->priority = NF_IP_PRI_FIRST;

	// Register hooks
	nf_register_hook(incomingTrafficHook);
	nf_register_hook(outgoingTrafficHook);

	printk("ARG: Director initialized\n");

	return 1;
}

char uninit_director(void)
{
	printk("ARG: Director uninit\n");

	if(incomingTrafficHook != NULL)
	{
		nf_unregister_hook(incomingTrafficHook);
		kfree(incomingTrafficHook);
		incomingTrafficHook = NULL;
	}
	
	if(outgoingTrafficHook != NULL)
	{
		nf_unregister_hook(outgoingTrafficHook);
		kfree(outgoingTrafficHook);
		outgoingTrafficHook = NULL;
	}

	printk("ARG: Director finished\n");

	return 1;
}

unsigned int direct_inbound(unsigned int hooknum, struct sk_buff *skb, 
							const struct net_device *in,
							const struct net_device *out,
							int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);

	// Ensure everything is working as intended
	fix_transport_header(skb);

	// Ignore all local traffic (accept it)
	if(is_local_traffic(skb))
		return NF_ACCEPT;

	// We only support a few protocols
	if(!is_supported_proto(skb))
	{
		printk("ARG: Unsupported protocol (%i) seen\n", iph->protocol);
		return NF_DROP;
	}

	printk("ARG: destination IP: ");
	printIP(ADDR_SIZE, &iph->daddr);
	printk("\n");

	// Is it an admin packet? (could be coming from a
	// not yet associated ARG network, hence we must check
	// before the IP check)
	if(is_admin_packet(skb))
	{
		// Pass off to admin handler
		printk("ARG: Inbound Accept: Admin packet!\n");
	}
	else if(is_arg_ip(&iph->saddr))
	{
		// From an ARG network
		// Is it to the correct IP?
		if(is_current_ip((uchar*)&iph->daddr))
		{
			// Correct IP. Is it signed correctly?
			if(is_signature_valid(skb))
			{
				if(do_arg_unwrap(skb))
				{
					printk("ARG: Inbound Accept: Unwrap\n");
					return NF_ACCEPT;
				}
				else
				{
					printk("ARG: Inbound Reject: Unable to unwrap\n");
					return NF_DROP;
				}
			}
			else
			{
				printk("ARG: Inbound Reject: Signature\n");
				return NF_DROP;
			}
		}
		else
		{
			// Incorrect IP. Reject!
			printk("ARG: Inbound Reject: IP\n");
			//return NF_DROP; // TBD uncomment
		}
		
		printRaw(ADDR_SIZE, &iph->daddr);
	}
	else
	{
		// From a non-ARG IP
		// Pass off to the NAT handler
		if(do_nat_inbound_rewrite(skb))
		{
			printk("ARG: Inbound Accept: Rewrite\n");
			return NF_ACCEPT;
		}
		else
		{
			printk("ARG: Inbound Reject: NAT\n");
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

unsigned int direct_outbound(unsigned int hooknum, struct sk_buff *skb, 
							const struct net_device *in,
							const struct net_device *out,
							int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);
	
	// Ensure everything is working as intended
	fix_transport_header(skb);
	
	// Ignore all local traffic (accept it)
	if(is_local_traffic(skb))
		return NF_ACCEPT;
	
	// We only support a few protocols
	if(!is_supported_proto(skb))
	{
		printk("ARG: Unsupported protocol (%i) seen\n", iph->protocol);
		return NF_DROP;
	}
	
	// Who should handle it?
	if(is_arg_ip((uchar*)&iph->daddr))
	{
		// Destined for an ARG network
		if(do_arg_wrap(skb))
		{
			printk("ARG: Outbound Accept: Wrap\n");
			return NF_ACCEPT;
		}
		else
		{
			printk("ARG: Outbound Reject: Failed to wrap\n");
			return NF_DROP;
		}
	}
	else
	{
		// Unknown destination. Rewrite via NAT, creating an entry
		// if needed
		if(do_nat_outbound_rewrite(skb))
		{
			printk("ARG: Outbound: Accept: Rewrite\n");
			return NF_ACCEPT;
		}
		else
		{
			printk("ARG: Outbound Reject: NAT\n");
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

char is_local_traffic(const struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	return iph->daddr == htonl(0x7F000001);
}

char is_supported_proto(const struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	if(iph->version == 4)
	{
		return (iph->protocol == TCP_PROTO
			|| iph->protocol == UDP_PROTO
			|| iph->protocol == ICMP_PROTO);
	}
	else
	{
		printk("ARG: Non-ipv4 packet dropped\n");
		return 0;
	}
}

