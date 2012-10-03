#include <stdio.h>
#include <arpa/inet.h>

#include "director.h"
#include "settings.h"
#include "utility.h"
#include "packet.h"
#include "hopper.h"
#include "nat.h"

/***************************
Receive thread data
***************************/
static struct receive_thread_data intData = {
	.dev = INT_DEV_NAME,
	.ifaceSide = IFACE_INTERNAL,
	.handler = direct_outbound,
};
static struct receive_thread_data extData = {
	.dev = EXT_DEV_NAME,
	.ifaceSide = IFACE_EXTERNAL,
	.handler = direct_inbound,
};

char init_director(void)
{
	printf("ARG: Director init\n");

	// Enter receive loop, which we then pass off to director
	pthread_create(&intData.thread, NULL, receive_thread, (void*)&intData); // TBD check returns
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

	char ebuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	int frameHeadLen = 0;
	int frameTailLen = 0;
	
	struct bpf_program fp;
	char filter[MAX_FILTER_LEN];
	char baseIP[INET_ADDRSTRLEN];
	char mask[INET_ADDRSTRLEN];

	uint8_t *wireData = NULL;
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

	// Filter outbound traffic (we only want to get traffic incoming to this card)
	inet_ntop(AF_INET, gate_base_ip(), baseIP, sizeof(baseIP));
	inet_ntop(AF_INET, gate_mask(), mask, sizeof(mask));
	snprintf(filter, sizeof(filter), "not arp and not %s net %s mask %s",
		(data->ifaceSide == IFACE_EXTERNAL ? "src" : "dst"), baseIP, mask);
	
	printf("Using filter: %s\n", filter);
    
	if(pcap_compile(pd, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1)
	{
		printf("Unable to compile filter\n");
		return (void*)-3;
	}

    if(pcap_setfilter(pd, &fp) == -1)
	{
		printf("Unable to set filter\n");
		return (void*)-4;
	}

	// Cache how far to jump in packets
	if(pcap_datalink(pd) == DLT_EN10MB)
	{
		frameHeadLen = LINK_LAYER_SIZE;
		frameTailLen = 0;
	}
	else
	{
		frameHeadLen = 0;
		frameTailLen = 0;
		printf("Unable to determine data link type\n");
		return (void*)-3;
	}

	// Receive, parse, and pass on to handler
	printf("Ready to receive packets on %s\n", data->dev);

	for(;;)
	{
		wireData = (uint8_t*)pcap_next(pd, &header);
		if(wireData == NULL)
			continue;

		// Point packet to skip the 
		packet.linkLayerLen = 0;
		packet.data = wireData + frameHeadLen;
		packet.len = header.caplen - frameHeadLen - frameTailLen;

		packet.tstamp.tv_sec = header.ts.tv_sec;
		packet.tstamp.tv_nsec = header.ts.tv_usec * 1000;

		if(parse_packet(&packet))
			continue;
		
		if(!packet.ipv4)
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
	
	// Is this packet from a connected and authenticated ARG network?
	gate = get_arg_network(&packet->ipv4->saddr);
	if(gate != NULL)
	{
		if(packet->arg == NULL)
		{
			#ifdef DISP_RESULTS
			printf("ARG: Inbound Reject: Bad Protocol\n");
			#endif
			return;
		}

		if(is_admin_msg(packet->arg))
		{
			if(process_admin_msg(packet, gate) == 0)
			{
				#ifdef DISP_RESULTS
				printf("ARG: Inbound Accept: admin\n");
				#endif
			}
			else
			{
				#ifdef DISP_RESULTS
				printf("ARG: Inbound Reject: Invalid admin\n");
				#endif
			}
		}
		else
		{
			// Ensure the IPs were correct
			if(!is_valid_local_ip((uint8_t*)&packet->ipv4->daddr))
			{
				#ifdef DISP_RESULTS
				printf("ARG: Inbound Reject: Dest IP Incorrect\n");
				#endif
				return;
			}
			
			if(!is_valid_ip(gate, (uint8_t*)&packet->ipv4->saddr))
			{
				#ifdef DISP_RESULTS
				printf("ARG: Inbound Reject: Source IP Incorrect\n");
				#endif
				return;
			}

			// Unwrap and drop into network, assuming everything checks out
			if(do_arg_unwrap(packet, gate) == 0)
			{
				#ifdef DISP_RESULTS
				printf("ARG: Inbound Accept: Unwrapped\n");
				#endif
			}
			else
			{
				#ifdef DISP_RESULTS
				printf("ARG: Inbound Reject: Failed to unwrap\n");
				#endif
			}
		}
	}
	else
	{
		// From a non-ARG IP
		// Pass off to the NAT handler
		if(do_nat_inbound_rewrite(packet) == 0)
		{
			#ifdef DISP_RESULTS
			printf("ARG: Inbound Accept: Rewrite\n");
			#endif
		}
		else
		{
			#ifdef DISP_RESULTS
			printf("ARG: Inbound Reject: NAT\n");
			#endif
		}
	}
	
}

void direct_outbound(const struct packet_data *packet)
{
	struct arg_network_info *gate = NULL;

	// Who should handle it?
	gate = get_arg_network(&packet->ipv4->daddr);
	if(gate != NULL)
	{
		// Destined for an ARG network
		if(do_arg_wrap(packet, gate) == 0)
		{
			#ifdef DISP_RESULTS
			printf("ARG: Outbound Accept: Wrap\n");
			#endif
		}
		else
		{
			#ifdef DISP_RESULTS
			printf("ARG: Outbound Reject: Failed to wrap\n");
			#endif
		}
	}
	else
	{
		// Unknown destination. Rewrite via NAT, creating an entry
		// if needed
		if(do_nat_outbound_rewrite(packet) == 0)
		{
			#ifdef DISP_RESULTS
			printf("ARG: Outbound: Accept: Rewrite\n");
			#endif
		}
		else
		{
			#ifdef DISP_RESULTS
			printf("ARG: Outbound Reject: NAT\n");
			#endif
		}
	}
}

