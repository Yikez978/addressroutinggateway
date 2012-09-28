#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h> // TBD add to configure.ac

#include "packet.h"
#include "protocol.h"

char parse_packet(int linkLayerLen, struct packet_data *packet)
{
	void *transStart = NULL;
	
	packet->udp = NULL;
	packet->tcp = NULL;
	packet->icmp = NULL;
	packet->arg = NULL;
	packet->ipv4 = (struct iphdr*)(packet->data + linkLayerLen);
	
	if(packet->ipv4->version == 4)
	{
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
	else if(packet->ipv4->version == 6)
	{
		packet->ipv4 = NULL;
		printf("IPv6 packet received, not currently parsed\n");
		return -1;
	}
	else
	{
		packet->ipv4 = NULL;
		printf("Unknown, non-IP packet received. Ignoring\n");
		return -1;
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
	memmove(c->data, packet->data, c->len);

	parse_packet(LINK_LAYER_SIZE, c); // TBD I'd like to make link-layer size a struct member
	return c;
}

void free_packet(struct packet_data *packet)
{
	if(packet != NULL)
	{
		if(packet->data != NULL)
			free(packet->data);

		free(packet);
	}
}

void compute_packet_checksums(struct packet_data *packet)
{
	// TBD	
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

