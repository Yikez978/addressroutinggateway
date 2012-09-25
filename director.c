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
#include "settings.h"
#include "protocol.h"

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
	//outgoingTrafficHook->hooknum = NF_IP_LOCAL_OUT;
	outgoingTrafficHook->hooknum = NF_IP_FORWARD;
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
	struct arg_network_info *gate = NULL;
	uchar *data = NULL;
	int dlen;

	// Ensure everything is working as intended
	fix_transport_header(skb);

	// Ignore traffic not inbound on the EXTERNAL device
	if(strcmp(EXT_DEV_NAME, in->name))	
		return NF_ACCEPT;

	// We only support a few protocols
	if(!is_supported_proto(skb))
	{
		printk("ARG: Unsupported protocol (%i) seen\n", iph->protocol);
		return NF_DROP;
	}

	// Is this an ARG packet?
	gate = get_arg_network(&iph->saddr);
	if(gate != NULL)
	{
		printk("ARG: ARG packet inbound!\n");

		skbuff_to_msg(skb, &data, &dlen);

		if(is_admin_msg(data, dlen))
		{
			process_admin_msg(skb, gate, data, dlen);

			// We never forward admin packets into the network
			return NF_DROP;
		}
		else
		{
			// Unwrap and drop into network, assuming everything checks out
			// TBD, call unwrapper
			return NF_ACCEPT;
		}
	}
	else
	{
		// From a non-ARG IP
		// Pass off to the NAT handler
		if(do_nat_inbound_rewrite(skb))
		{
			#ifdef DISP_RESULTS
			printk("ARG: Inbound Accept: Rewrite\n");
			#endif
			return NF_ACCEPT;
		}
		else
		{
			#ifdef DISP_RESULTS
			printk("ARG: Inbound Reject: NAT\n");
			#endif
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
	struct arg_network_info *gate = NULL;

	// Ensure everything is working as intended
	fix_transport_header(skb);
	
	// Ignoral all traffic not actually leaving by the external device
	if(strcmp(EXT_DEV_NAME, out->name))
		return NF_ACCEPT;
	
	// We only support a few protocols
	if(!is_supported_proto(skb))
	{
		printk(KERN_INFO "ARG: Unsupported protocol (%i) seen\n", iph->protocol);
		return NF_DROP;
	}
	
	// Who should handle it?
	gate = get_arg_network(&iph->daddr);
	if(gate != NULL)
	{
		printk("ARG: ARG packet outbound!\n");

		// Destined for an ARG network
		if(do_arg_wrap(skb, gate))
		{
			#ifdef DISP_RESULTS
			printk("ARG: Outbound Accept: Wrap\n");
			#endif
			return NF_ACCEPT;
		}
		else
		{
			#ifdef DISP_RESULTS
			printk("ARG: Outbound Reject: Failed to wrap\n");
			#endif
			return NF_DROP;
		}
	}
	else
	{
		// Unknown destination. Rewrite via NAT, creating an entry
		// if needed
		if(do_nat_outbound_rewrite(skb))
		{
			#ifdef DISP_RESULTS
			printk("ARG: Outbound: Accept: Rewrite\n");
			#endif
			return NF_ACCEPT;
		}
		else
		{
			#ifdef DISP_RESULTS
			printk("ARG: Outbound Reject: NAT\n");
			#endif
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

char is_control_traffic(const struct net_device *dev)
{
	// eth0 is always our control device for our test network
	return (dev->name[3] == '0');
}

char is_supported_proto(const struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	if(iph->version == 4)
	{
		return (iph->protocol == ARG_PROTO
			|| iph->protocol == TCP_PROTO
			|| iph->protocol == UDP_PROTO
			|| iph->protocol == ICMP_PROTO);
	}
	else
	{
		printk("ARG: Non-ipv4 packet dropped\n");
		return 0;
	}
}

