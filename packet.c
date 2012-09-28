#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>

#include <arpa/inet.h> // TBD add to configure.ac

#include "packet.h"
#include "protocol.h"

char parse_packet(struct packet_data *packet)
{
	void *transStart = NULL;
	
	packet->eth = NULL;
	packet->ipv4 = NULL;
	packet->udp = NULL;
	packet->tcp = NULL;
	packet->icmp = NULL;
	packet->arg = NULL;

	if(sizeof(ethhdr) == packet->linkLayerLen)
	{
		packet->eth = (struct ethhdr*)packet->data;
		
		if(ntohs(packet->eth->type) == 0x0800)
			packet->ipv4 = (struct iphdr*)(packet->data + packet->linkLayerLen);
		else if(ntohs(packet->eth->type) == 0x86DD)
			printf("IPv6, sad day\n");
	
		// Probably ARP or something else
	}
	else
	{
		// Assume IP
		packet->ipv4 = (struct iphdr*)(packet->data + packet->linkLayerLen);
	}

	// Parse IP packets further
	if(packet->ipv4 != NULL)
	{
		if(packet->ipv4->version != 4)
			return -1;

		transStart = (void*)((uint8_t*)packet->ipv4 + packet->ipv4->ihl*4);

		if(packet->ipv4->protocol == ARG_PROTO)
			packet->arg = (struct arghdr*)transStart;
		else if(packet->ipv4->protocol == TCP_PROTO)
			packet->tcp = (struct tcphdr*)transStart;
		else if(packet->ipv4->protocol == UDP_PROTO)
			packet->udp = (struct udphdr*)transStart;
		else if(packet->ipv4->protocol == ICMP_PROTO)
			packet->icmp = (struct icmphdr*)transStart;
	}

	return 0;
}

struct packet_data *copy_packet(const struct packet_data *packet)
{
	struct packet_data *c = NULL;
	c = (struct packet_data*)malloc(sizeof(struct packet_data));
	if(c == NULL)
	{
		printf("Unable to allocate space to copy packet\n");
		return NULL;
	}

	c->data = (uint8_t*)malloc(packet->len);
	if(c->data == NULL)
	{
		printf("Unable to allocate space to copy packet data\n");
		free(c);
		return NULL;
	}

	c->len = packet->len;
	c->linkLayerLen = packet->linkLayerLen;
	memcpy(c->data, packet->data, c->len);

	parse_packet(c);
	return c;
}

void free_packet(struct packet_data *packet)
{
	if(packet != NULL)
	{
		if(packet->data != NULL)
		{
			free(packet->data);
		}

		free(packet);
	}
}

void compute_packet_checksums(struct packet_data *packet)
{
	// TBD. May not be needed, sendto does it for us	
}

char send_packet(const struct packet_data *packet)
{
	static int sock = 0;
	struct sockaddr_in dest_addr;
	int len = 0;

	if(sock <= 0)
	{
		sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if(sock < 0)
		{
			printf("Unable to create raw socket for sending\n");
			return sock;
		}
	}

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(get_dest_port(packet));
	dest_addr.sin_addr.s_addr = packet->ipv4->daddr;

	if(packet->ipv4)
		len = ntohs(packet->ipv4->tot_len);
	else
		len = packet->len - packet->linkLayerLen;

	if(sendto(sock, (uint8_t*)packet->data + packet->linkLayerLen, len,
		0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0)
	{
		printf("Send failed: %i\n", errno);
		return -1;
	}

	return 0;
}

uint16_t get_source_port(const struct packet_data *packet)
{
	if(packet->tcp)
		return ntohs(packet->tcp->source);
	else if(packet->udp)
		return ntohs(packet->udp->source);
	else
		return 0;
}

uint16_t get_dest_port(const struct packet_data *packet)
{
	if(packet->tcp)
		return ntohs(packet->tcp->dest);
	else if(packet->udp)
		return ntohs(packet->udp->dest);
	else
		return 0;
}

void set_source_port(struct packet_data *packet, const uint16_t port)
{
	if(packet->tcp)
		packet->tcp->source = htons(port);
	else if(packet->udp)
		packet->udp->source = htons(port);
}

void set_dest_port(struct packet_data *packet, const uint16_t port)
{
	// Find port numbers for appropriate protocol
	if(packet->tcp)
		packet->tcp->dest = htons(port);
	else if(packet->udp)
		packet->udp->dest = htons(port);
}

