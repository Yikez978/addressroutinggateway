#include <linux/skbuff.h>
#include <linux/ip.h>

#include "director.h"
#include "hopper.h"
#include "utility.h"

unsigned int direct_inbound(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	// Is it an admin packet? (could be coming from a
	// not yet associated ARG network, hence we must check
	// before the IP check)
	if(is_admin_packet(skb))
	{
		// Pass off to admin handler
		printk("ARG: admin packet!\n");
	}
	else if(is_arg_ip((uchar*)&iph->saddr))
	{
		// From an ARG network
		// Is it to the correct IP?
		if(is_current_ip((uchar*)&iph->daddr))
		{
			// Correct IP. Is it signed correctly?
			if(is_signature_valid(skb))
			{
				printk("ARG: Accept: Unwrap\n");

				// TBD do unwrap

				return NF_ACCEPT;
			}
			else
			{
				printk("ARG: Reject: Signature\n");
				return NF_DROP;
			}
		}
		else
		{
			// Incorrect IP. Reject!
			printk("ARG: Reject: IP\n");
			//return NF_DROP; // TBD uncomment
		}
		
		printRaw(ADDR_SIZE, &iph->daddr);
	}
	else
	{
		// From a non-ARG IP
		// Pass off to the NAT handler
		printk("ARG: from external\n");
		// TBD
	}

	return NF_ACCEPT;
}

unsigned int direct_outbound(struct sk_buff *skb)
{
	return NF_ACCEPT;
}

