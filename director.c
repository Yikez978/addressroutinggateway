#include <linux/skbuff.h>
#include <linux/ip.h>

#include "nat.h"
#include "director.h"
#include "hopper.h"
#include "utility.h"

unsigned int direct_inbound(struct sk_buff *skb)
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

unsigned int direct_outbound(struct sk_buff *skb)
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

