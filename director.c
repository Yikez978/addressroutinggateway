#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>

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
bool receiveShouldRun = false;

pthread_mutex_t cancelLock;
bool cancelSent = false;

static struct receive_thread_data intData = {
	.pd = NULL,
	.dev = "",
	.ifaceSide = IFACE_INTERNAL,
	.handler = direct_outbound,
};
static struct receive_thread_data extData = {
	.pd = NULL,
	.dev = "",
	.ifaceSide = IFACE_EXTERNAL,
	.handler = direct_inbound,
};

void init_director_locks(void)
{
	pthread_mutex_init(&cancelLock, NULL);
}

int init_director(struct config_data *config)
{
	int ret;
	char baseIP[INET_ADDRSTRLEN];
	char mask[INET_ADDRSTRLEN];

	arglog(LOG_DEBUG, "Director init\n");

	// Initialize data and start pcap stuff
	strncpy(intData.dev, config->intDev, sizeof(intData.dev) - 1);
	strncpy(extData.dev, config->extDev, sizeof(extData.dev) - 1);

	arglog(LOG_ALERT, "Internal device is %s, external is %s\n", intData.dev, extData.dev);

	if((ret = init_pcap_driver(&intData.pd, intData.dev, 1)) < 0)
	{
		arglog(LOG_FATAL, "Unable to initialize the internal device %s\n", intData.dev);
		return ret;
	}
	if((ret = init_pcap_driver(&extData.pd, extData.dev, 0)) < 0)
	{
		arglog(LOG_FATAL, "Unable to initialize the internal device %s\n", intData.dev);
		return ret;
	}

	// TBD internal address (doing the base again right now)
	inet_ntop(AF_INET, gate_base_ip(), baseIP, sizeof(baseIP));
	inet_ntop(AF_INET, gate_mask(), mask, sizeof(mask));	
	arglog(LOG_ALERT, "Internal IP: %s, external IP: %s, external mask: %s\n", baseIP, baseIP, mask);

	// Enter receive loop
	receiveShouldRun = true;
	pthread_create(&intData.thread, NULL, receive_thread, (void*)&intData); // TBD check returns
	pthread_create(&extData.thread, NULL, receive_thread, (void*)&extData);
	
	arglog(LOG_DEBUG, "Director initialized\n");
	return 0;
}

int init_pcap_driver(pcap_t **pd, char *dev, bool is_internal)
{
	char ebuf[PCAP_ERRBUF_SIZE];

	struct bpf_program fp;
	char filter[MAX_FILTER_LEN];
	char baseIP[INET_ADDRSTRLEN];
	char mask[INET_ADDRSTRLEN];

	// Activate pcap
	*pd = pcap_create(dev, ebuf);
	if(*pd == NULL)
	{
		arglog(LOG_FATAL, "Unable to initialize create pcap driver on %s: %s\n", dev, ebuf);
		return -ARG_CONFIG_BAD;
	}

	pcap_set_timeout(*pd, 250);
	pcap_set_snaplen(*pd, MAX_PACKET_SIZE);
	pcap_set_promisc(*pd, 1);

	if(pcap_activate(*pd))
	{
		arglog(LOG_FATAL, "Unable to activate pcap on %s: %s\n", dev, pcap_geterr(*pd));
		return -ARG_CONFIG_BAD;
	}

	// Filter outbound traffic (we only want to get traffic coming to this card)
	inet_ntop(AF_INET, gate_base_ip(), baseIP, sizeof(baseIP));
	inet_ntop(AF_INET, gate_mask(), mask, sizeof(mask));
	if(!is_internal)
	{
		// Get ARP traffic about IPs inside our network that doesn't originate from us
		// and non-ARP traffic that is intended for inside us
		snprintf(filter, sizeof(filter), "(arp and not src net %s mask %s and dst net %s mask %s) or "
										 "(not arp and dst net %s mask %s)",
										 baseIP, mask, baseIP, mask, baseIP, mask);
	}
	else
	{
		// For the internal card, we also want to get ARP packets that are for
		// addresses outside our network. We will respond to them with our own MAC
		snprintf(filter, sizeof(filter), "(arp and not dst net %s mask %s) or "
										 "(not arp and src net %s mask %s)",
										baseIP, mask, baseIP, mask);
	}

	arglog(LOG_DEBUG, "Using filter '%s' on %s\n", filter, dev);
    
	if(pcap_compile(*pd, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1)
	{
		arglog(LOG_FATAL, "Unable to compile filter: %s\n", pcap_geterr(*pd));
		pcap_close(*pd);
		return -ARG_INTERNAL_ERROR;
	}

    if(pcap_setfilter(*pd, &fp) == -1)
	{
		arglog(LOG_FATAL, "Unable to set filter: %s\n", pcap_geterr(*pd));
		pcap_freecode(&fp);
		pcap_close(*pd);
		return -ARG_CONFIG_BAD;
	}
	
	pcap_freecode(&fp);

	return 0;
}

int uninit_director(void)
{
	if(pthread_mutex_trylock(&cancelLock) == EBUSY)
		return 0;
	
	if(!cancelSent)
	{
		cancelSent = true;

		arglog(LOG_DEBUG, "Director uninit\n");

		// Stop threads
		pthread_cancel(intData.thread);
		pthread_cancel(extData.thread);
		receiveShouldRun = false;
		join_director();

		// Kill pcap
		if(intData.pd != NULL)
		{
			pcap_close(intData.pd);
			intData.pd = NULL;
		}
		if(extData.pd != NULL)
		{
			pcap_close(extData.pd);
			extData.pd = NULL;
		}
	
		pthread_mutex_unlock(&cancelLock);
		pthread_mutex_destroy(&cancelLock);
	
		arglog(LOG_DEBUG, "Director finished\n");
	}

	return 0;
}

void join_director(void)
{
	if(extData.thread != 0)
	{
		pthread_join(extData.thread, NULL);
		extData.thread = 0;
	}
	if(intData.thread != 0)
	{
		pthread_join(intData.thread, NULL);
		intData.thread = 0;
	}
}

void *receive_thread(void *tData)
{
	struct receive_thread_data *data = (struct receive_thread_data*)tData;

	struct pcap_pkthdr header;
	int frameHeadLen = 0;
	int frameTailLen = 0;

	int devIndex = 0;
	uint8_t hwaddr[ETH_ALEN];

	uint8_t *wireData = NULL;
	struct packet_data packet;

	// Cache hardware address for ARP
	if(get_mac_addr(data->dev, hwaddr) < 0)
	{
		arglog(LOG_DEBUG, "Unable to get hardware address of %s\n", data->dev);
		return (void*)-ARG_CONFIG_BAD;
	}

	if((devIndex = get_dev_index(data->dev)) < 0)
	{
		arglog(LOG_DEBUG, "Unable to get index of device %s\n", data->dev);
		return (void*)-ARG_CONFIG_BAD;
	}

	// Cache how far to jump in packets
	if(pcap_datalink(data->pd) == DLT_EN10MB)
	{
		frameHeadLen = LINK_LAYER_SIZE;
		frameTailLen = 0;
	}
	else
	{
		frameHeadLen = 0;
		frameTailLen = 0;
		arglog(LOG_DEBUG, "Unable to determine data link type\n");
		return (void*)-ARG_CONFIG_BAD;
	}

	// Receive, parse, and pass on to handler
	arglog(LOG_DEBUG, "Ready to receive packets on %s\n", data->dev);

	while(receiveShouldRun)
	{
		wireData = (uint8_t*)pcap_next(data->pd, &header);
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
			send_arp_reply(&packet, devIndex, hwaddr);
			continue;
		}

		if(!packet.ipv4)
			continue;

		if(data->handler != NULL)
			(*data->handler)(&packet);
	}

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
			arglog(LOG_DEBUG, "IP direction destination\n");
			invalid_local_ip_direction((uint8_t*)&packet->ipv4->daddr);

			char ipStr[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, gate->currIP, ipStr, sizeof(ipStr));
			arglog(LOG_DEBUG, "Remote curr IP is now 1 %s\n", ipStr);

			arglog(LOG_DEBUG, "IP direction source\n");
			invalid_ip_direction(gate, (uint8_t*)&packet->ipv4->saddr);

			// Ensure the IPs were correct
			if(!is_valid_local_ip((uint8_t*)&packet->ipv4->daddr))
			{
				arglog_result(packet, NULL, 1, 0, "Hopper", "Dest IP Incorrect");
				note_bad_ip(gate);
				return;
			}
			
			if(!is_valid_ip(gate, (uint8_t*)&packet->ipv4->saddr))
			{
				inet_ntop(AF_INET, gate->currIP, ipStr, sizeof(ipStr));
				arglog(LOG_DEBUG, "Remote curr IP is now 2 %s\n", ipStr);
				arglog_result(packet, NULL, 1, 0, "Hopper", "Source IP Incorrect");
				note_bad_ip(gate);
				return;
			}

			// IP must be good by this point
			note_good_ip(gate);

			// Unwrap and drop into network, assuming everything checks out
			if((ret = do_arg_unwrap(packet, gate)) < 0)
			{
				arg_strerror_r(ret, error, sizeof(error));
				arglog_result(packet, NULL, 0, 0, "Hopper", error);
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
		if((ret = do_arg_wrap(packet, gate)) < 0)
		{
			arg_strerror_r(ret, error, sizeof(error));
			arglog_result(packet, NULL, 0, 0, "Hopper", error);
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

