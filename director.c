#include <stdio.h>

#include "director.h"
#include "settings.h"
#include "utility.h"
#include "packet.h"
#include "hopper.h"

/***************************
Receive thread data
***************************/
static struct receive_thread_data intData = {
	.dev = INT_DEV_NAME,
	.handler = direct_outbound,
};
static struct receive_thread_data extData = {
	.dev = EXT_DEV_NAME,
	.handler = direct_inbound,
};

char init_director(void)
{
	printf("ARG: Director init\n");

	// Enter receive loop, which we then pass off to director
	pthread_create(&intData.thread, NULL, receive_thread, (void*)&intData);
	pthread_create(&extData.thread, NULL, receive_thread, (void*)&extData);
	
	printf("ARG: Director initialized\n");
	return 0;
}

char uninit_director(void)
{
	printf("ARG: Director uninit\n");

	pthread_cancel(intData.thread);
	pthread_cancel(extData.thread);
	join_director();

	printf("ARG: Director finished\n");
	return 0;
}

void join_director(void)
{
	pthread_join(extData.thread, NULL);
	pthread_join(intData.thread, NULL);
}

void *receive_thread(void *tData)
{
	struct receive_thread_data *data = (struct receive_thread_data*)tData;

	int linkLayerLen = 0;

	char ebuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	struct packet_data packet;

	// Activate pcap
	pcap_t *pd = pcap_create(data->dev, ebuf);
	if(pd == NULL)
	{
		printf("Unable to initialize create pcap driver on %s: %s\n", data->dev, ebuf);
		return (void*)-1;
	}

	pcap_set_timeout(pd, 250);
	pcap_set_snaplen(pd, MAX_PACKET_SIZE);
	pcap_set_promisc(pd, 1);

	if(pcap_activate(pd))
	{
		printf("Unable to activate pcap on %s: %s\n", data->dev, pcap_geterr(pd));
		return (void*)-2;
	}

	// Cache how far to jump in packets
	if(pcap_datalink(pd) == DLT_EN10MB)
		linkLayerLen = 14;
	else
	{
		linkLayerLen = 0;
		printf("Unable to determine data link type\n");
		return (void*)-3;
	}

	// Receive, parse, and pass on to handler
	printf("Ready to receive packets on %s\n", data->dev);

	for(;;)
	{
		packet.data = (uint8_t*)pcap_next(pd, &header);
		if(packet.data == NULL)
			continue;

		packet.len = header.caplen;
		
		packet.tstamp.tv_sec = header.ts.tv_sec;
		packet.tstamp.tv_nsec = header.ts.tv_usec * 1000;

		if(parse_packet(linkLayerLen, &packet))
			continue;

		if(data->handler != NULL)
			(*data->handler)(&packet);
	}

	pcap_close(pd);
	pd = NULL;

	printf("Done receiving packets on %s\n", data->dev);

	return NULL;
}

void direct_inbound(const struct packet_data *packet)
{
	struct arg_network_info *gate = NULL;
	
	// Is this packet from an ARG network?
	if(packet->arg != NULL)
	{
		printf("ARG: ARG packet inbound!\n");
		gate = get_arg_network(&packet->ipv4->saddr);
		if(gate == NULL)
		{
			#ifdef DISP_RESULTS
			printf("ARG: Inbound Reject: ARG packet from non-ARG ip");
			#endif
			return;
		}

		if(is_admin_msg(packet->arg))
		{
			process_admin_msg(packet, gate);
		}
		else
		{
			// Unwrap and drop into network, assuming everything checks out
			// TBD, call unwrapper
		}
	}
	else
	{
		// From a non-ARG IP
		// Pass off to the NAT handler
		/*if(do_nat_inbound_rewrite(skb))
		{
			#ifdef DISP_RESULTS
			printf("ARG: Inbound Accept: Rewrite\n");
			#endif
		
			// TBD send
		}
		else
		{
			#ifdef DISP_RESULTS
			printf("ARG: Inbound Reject: NAT\n");
			#endif
		}
		*/
	}
	
}

void direct_outbound(const struct packet_data *packet)
{
	printf("Direct outbound!\n");
}

/*
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
		printf("ARG: Unsupported protocol (%i) seen\n", iph->protocol);
		return NF_DROP;
	}

	// Is this an ARG packet?
	gate = get_arg_network(&iph->saddr);
	if(gate != NULL)
	{
		printf("ARG: ARG packet inbound!\n");

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
			printf("ARG: Inbound Accept: Rewrite\n");
			#endif
			return NF_ACCEPT;
		}
		else
		{
			#ifdef DISP_RESULTS
			printf("ARG: Inbound Reject: NAT\n");
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
		printf(KERN_INFO "ARG: Unsupported protocol (%i) seen\n", iph->protocol);
		return NF_DROP;
	}
	
	// Who should handle it?
	gate = get_arg_network(&iph->daddr);
	if(gate != NULL)
	{
		printf("ARG: ARG packet outbound!\n");

		// Destined for an ARG network
		if(do_arg_wrap(skb, gate))
		{
			#ifdef DISP_RESULTS
			printf("ARG: Outbound Accept: Wrap\n");
			#endif
			return NF_ACCEPT;
		}
		else
		{
			#ifdef DISP_RESULTS
			printf("ARG: Outbound Reject: Failed to wrap\n");
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
			printf("ARG: Outbound: Accept: Rewrite\n");
			#endif
			return NF_ACCEPT;
		}
		else
		{
			#ifdef DISP_RESULTS
			printf("ARG: Outbound Reject: NAT\n");
			#endif
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}
*/

