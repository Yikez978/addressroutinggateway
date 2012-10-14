#include <stdio.h>
#include <arpa/inet.h>

#include "director.h"
#include "settings.h"
#include "utility.h"
#include "packet.h"
#include "arg_error.h"
#include "hopper.h"
#include "nat.h"

/***************************
Receive thread data
***************************/
static struct receive_thread_data intData = {
	.dev = "",
	.ifaceSide = IFACE_INTERNAL,
	.handler = direct_outbound,
};
static struct receive_thread_data extData = {
	.dev = "",
	.ifaceSide = IFACE_EXTERNAL,
	.handler = direct_inbound,
};

char init_director(struct config_data *config)
{
	arglog(LOG_DEBUG, "Director init\n");

	strncpy(intData.dev, config->intDev, sizeof(intData.dev));
	strncpy(extData.dev, config->extDev, sizeof(extData.dev));

	// Enter receive loop, which we then pass off to director
	pthread_create(&intData.thread, NULL, receive_thread, (void*)&intData); // TBD check returns
	pthread_create(&extData.thread, NULL, receive_thread, (void*)&extData);
	
	arglog(LOG_DEBUG, "Director initialized\n");
	return 0;
}

char uninit_director(void)
{
	arglog(LOG_DEBUG, "Director uninit\n");

	pthread_cancel(intData.thread);
	pthread_cancel(extData.thread);
	join_director();

	arglog(LOG_DEBUG, "Director finished\n");
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

	int devIndex = 0;
	uint8_t hwaddr[ETH_ALEN];

	uint8_t *wireData = NULL;
	struct packet_data packet;

	// Cache hardware address for ARP
	if(get_mac_addr(data->dev, hwaddr) < 0)
	{
		arglog(LOG_DEBUG, "Unable to get hardware address of %s\n", data->dev);
		return (void*)-1;
	}

	if((devIndex = get_dev_index(data->dev)) < 0)
	{
		arglog(LOG_DEBUG, "Unable to get index of device %s\n", data->dev);
		return (void*)-1;
	}

	// Activate pcap
	pcap_t *pd = pcap_create(data->dev, ebuf);
	if(pd == NULL)
	{
		arglog(LOG_DEBUG, "Unable to initialize create pcap driver on %s: %s\n", data->dev, ebuf);
		return (void*)-1;
	}

	pcap_set_timeout(pd, 250);
	pcap_set_snaplen(pd, MAX_PACKET_SIZE);
	pcap_set_promisc(pd, 1);

	if(pcap_activate(pd))
	{
		arglog(LOG_DEBUG, "Unable to activate pcap on %s: %s\n", data->dev, pcap_geterr(pd));
		return (void*)-2;
	}

	// Filter outbound traffic (we only want to get traffic coming to this card)
	inet_ntop(AF_INET, gate_base_ip(), baseIP, sizeof(baseIP));
	inet_ntop(AF_INET, gate_mask(), mask, sizeof(mask));
	if(data->ifaceSide == IFACE_EXTERNAL)
	{
		snprintf(filter, sizeof(filter), "not arp and dst net %s mask %s", baseIP, mask);
	}
	else
	{
		// For the internal card, we also want to get ARP packets that are for
		// addresses outside our network. We will respond to them with our own MAC
		snprintf(filter, sizeof(filter), "(arp and not dst net %s mask %s) or "
										 "(not arp and src net %s mask %s)",
										baseIP, mask, baseIP, mask);
	}

	arglog(LOG_DEBUG, "Using filter '%s' on %s\n", filter, data->dev);
    
	if(pcap_compile(pd, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1)
	{
		arglog(LOG_DEBUG, "Unable to compile filter: %s\n", pcap_geterr(pd));
		pcap_close(pd);
		return (void*)-3;
	}

    if(pcap_setfilter(pd, &fp) == -1)
	{
		arglog(LOG_DEBUG, "Unable to set filter: %s\n", pcap_geterr(pd));
		pcap_freecode(&fp);
		pcap_close(pd);
		return (void*)-4;
	}
	
	pcap_freecode(&fp);

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
		arglog(LOG_DEBUG, "Unable to determine data link type\n");
		return (void*)-3;
	}

	// Receive, parse, and pass on to handler
	arglog(LOG_DEBUG, "Ready to receive packets on %s\n", data->dev);

	for(;;)
	{
		wireData = (uint8_t*)pcap_next(pd, &header);
		if(wireData == NULL)
			continue;

		packet.linkLayerLen = frameHeadLen;
		packet.data = wireData;
		packet.len = header.caplen - frameTailLen;

		packet.tstamp.tv_sec = header.ts.tv_sec;
		packet.tstamp.tv_nsec = header.ts.tv_usec * 1000;

		if(parse_packet(&packet))
			continue;
		
		if(packet.arp)
		{
			// Send back a reply telling them to send their packets here.
			// The filter ensure we only get ARP packets directed for our
			// other side, so we don't have to perform any checks here
			arglog(LOG_DEBUG, "Preparing to send arp...\n");
			send_arp_reply(&packet, devIndex, hwaddr);
			arglog(LOG_DEBUG, "Send\n");
			continue;
		}

		if(!packet.ipv4)
			continue;

		if(data->handler != NULL)
			(*data->handler)(&packet);
	}

	pcap_close(pd);
	pd = NULL;

	arglog(LOG_DEBUG, "Done receiving packets on %s\n", data->dev);

	return NULL;
}

void direct_inbound(const struct packet_data *packet)
{
	int ret = 0;
	struct arg_network_info *gate = NULL;
	char error[MAX_ERROR_STR_LEN];
	
	// Is this packet from a connected and authenticated ARG network?
	gate = get_arg_network(&packet->ipv4->saddr);
	if(gate != NULL)
	{
		if(packet->arg == NULL)
		{
			arglog_result(packet, NULL, 1, 0, "Admin", "bad protocol");
			return;
		}

		if(is_admin_msg(packet->arg))
		{
			if((ret = process_admin_msg(packet, gate)) < 0)
			{
				arg_strerror_r(ret, error, sizeof(error));
				arglog_result(packet, NULL, 0, 0, "Admin", error);
			}
		}
		else
		{
			// Ensure the IPs were correct
			if(!is_valid_local_ip((uint8_t*)&packet->ipv4->daddr))
			{
				arglog_result(packet, NULL, 1, 0, "Unwrap", "Dest IP Incorrect");
				return;
			}
			
			if(!is_valid_ip(gate, (uint8_t*)&packet->ipv4->saddr))
			{
				arglog_result(packet, NULL, 1, 0, "Unwrap", "Source IP Incorrect");
				return;
			}

			// Unwrap and drop into network, assuming everything checks out
			if((ret = do_arg_unwrap(packet, gate) < 0))
			{
				arg_strerror_r(ret, error, sizeof(error));
				arglog_result(packet, NULL, 0, 0, "Unwrap", error);
			}
		}
	}
	else
	{
		// From a non-ARG IP
		// Pass off to the NAT handler
		if((ret = do_nat_inbound_rewrite(packet)) < 0)
		{
			arg_strerror_r(ret, error, sizeof(error));
			arglog_result(packet, NULL, 1, 0, "NAT", error);
		}
	}
}

void direct_outbound(const struct packet_data *packet)
{
	char error[MAX_ERROR_STR_LEN];
	int ret;
	struct arg_network_info *gate = NULL;

	// Who should handle it?
	gate = get_arg_network(&packet->ipv4->daddr);
	if(gate != NULL)
	{
		// Destined for an ARG network
		if((ret = do_arg_wrap(packet, gate) < 0))
		{
			arg_strerror_r(ret, error, sizeof(error));
			arglog_result(packet, NULL, 0, 0, "Wrap", error);
		}
	}
	else
	{
		// Unknown destination. Rewrite via NAT, creating an entry
		// if needed
		if((ret = do_nat_outbound_rewrite(packet)) < 0)
		{
			arg_strerror_r(ret, error, sizeof(error));
			arglog_result(packet, NULL, 0, 0, "NAT", error);
		}
	}
}

