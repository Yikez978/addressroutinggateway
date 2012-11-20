#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>

#include <polarssl/md5.h>

#include "packet.h"
#include "arg_error.h"
#include "protocol.h"

int parse_packet(struct packet_data *packet)
{
	packet->eth = NULL;
	packet->ipv4 = NULL;
	packet->udp = NULL;
	packet->tcp = NULL;
	packet->icmp = NULL;
	packet->arp = NULL;
	packet->arg = NULL;
	
	packet->unknown_data = NULL;
	packet->unknown_len = 0;

	if(sizeof(struct ethhdr) == packet->linkLayerLen)
	{
		packet->eth = (struct ethhdr*)packet->data;
		
		if(ntohs(packet->eth->h_proto) == ETH_P_IP)
		{
			packet->ipv4 = (struct iphdr*)(packet->data + packet->linkLayerLen);
			packet->unknown_data = (void*)((uint8_t*)packet->ipv4 + packet->ipv4->ihl * 4);
		}
		else if(ntohs(packet->eth->h_proto) == ETH_P_ARP)
		{
			packet->arp = (struct ether_arp*)(packet->data + packet->linkLayerLen);
			packet->unknown_data = (void*)((uint8_t*)packet->arp + sizeof(struct ether_arp));
		}
		else if(ntohs(packet->eth->h_proto) == ETH_P_IPV6)
		{
			arglog(LOG_ALERT, "IPv6, sad day. Not handled\n");
		}
	}
	else
	{
		// Assume IP
		packet->ipv4 = (struct iphdr*)(packet->data + packet->linkLayerLen);
		packet->unknown_data = (void*)((uint8_t*)packet->ipv4 + packet->ipv4->ihl * 4);
	}

	// Parse IP packets further
	if(packet->ipv4 != NULL)
	{
		if(packet->ipv4->version != 4)
			return -ARG_PACKET_PARSE_ERROR;

		// Back up the packet length to skip the padding. If there is none/we're just ipv4,
		// this step should have no impact
		packet->len = packet->linkLayerLen + ntohs(packet->ipv4->tot_len);

		void *transStart = (void*)((uint8_t*)packet->ipv4 + packet->ipv4->ihl*4);

		switch(packet->ipv4->protocol)
		{
		case ARG_PROTO:
			packet->arg = (struct arghdr*)transStart;
			packet->unknown_data = (uint8_t*)transStart + sizeof(struct arghdr);
			break;

		case TCP_PROTO:
			packet->tcp = (struct tcphdr*)transStart;
			packet->unknown_data = (uint8_t*)transStart + packet->tcp->doff * 4;
			break;

		case UDP_PROTO:
			packet->udp = (struct udphdr*)transStart;
			packet->unknown_data = (uint8_t*)transStart + sizeof(struct udphdr);
			break;

		case ICMP_PROTO:
			packet->icmp = (struct icmphdr*)transStart;
			packet->unknown_data = (uint8_t*)transStart + sizeof(struct icmphdr);
			break;

		default:
			packet->unknown_data = (uint8_t*)transStart;
		}
	}
	
	// Ensure this length is correct
	packet->unknown_len = packet->len - (packet->unknown_data - packet->data);

	return 0;
}

void create_packet_id(const struct packet_data *packet, char *buf, int buflen)
{
	char sIP[INET_ADDRSTRLEN];
	char dIP[INET_ADDRSTRLEN];

	// Can only work with IPv4 packets
	if(packet->ipv4 == NULL)
	{
		snprintf(buf, buflen, "Unable to generate ID");
		return;
	}

	arglog(LOG_DEBUG, "Hashing");
	printRaw(packet->len, packet->data);

	// Hash whole packet, skipping checksums 
	md5_context ctx;
	uint8_t md5sumRaw[16];

	md5_starts(&ctx);

	if(packet->ipv4)
	{
		// IPv4 header except the checksum
		int sizeToCheck = 10;
		md5_update(&ctx, (uint8_t*)packet->ipv4, sizeToCheck);
		md5_update(&ctx, (uint8_t*)packet->ipv4 + sizeToCheck + sizeof(packet->ipv4->check),
			packet->ipv4->ihl*4 - sizeToCheck - sizeof(packet->ipv4->check));
		
		// Transport layer
		if(packet->tcp)
		{
			sizeToCheck = 16;
			md5_update(&ctx, (uint8_t*)packet->tcp, sizeToCheck);
			md5_update(&ctx, (uint8_t*)packet->tcp + sizeToCheck + sizeof(packet->tcp->check),
				packet->tcp->doff*4 - sizeToCheck - sizeof(packet->tcp->check));
		}
		else if(packet->udp)
		{
			sizeToCheck = 6;
			md5_update(&ctx, (uint8_t*)packet->udp, sizeToCheck);
		}
		else if(packet->icmp)
		{
			sizeToCheck = 2;
			md5_update(&ctx, (uint8_t*)packet->icmp, sizeToCheck);
		}
		else if(packet->arg)
		{
			md5_update(&ctx, (uint8_t*)packet->arg, sizeof(struct arghdr));
		}

		// Remainder
		md5_update(&ctx, packet->unknown_data, packet->unknown_len);
	}
	else
	{
		// Screw it, do the whole packet minus the link layer
		md5_update(&ctx, packet->data + packet->linkLayerLen, packet->len - packet->linkLayerLen);
	}
	
	md5_finish(&ctx, md5sumRaw);
	
	// Convert to hex string
	char md5sum[33] = "";
	for(int i = 0; i < sizeof(md5sumRaw); i++)
		sprintf(md5sum + (2 * i), "%02x", (int)md5sumRaw[i]);
	md5sum[sizeof(md5sum) - 1] = '\0';

	// Add rest of label for the IP packet
	inet_ntop(AF_INET, &packet->ipv4->saddr, sIP, sizeof(sIP));
	inet_ntop(AF_INET, &packet->ipv4->daddr, dIP, sizeof(dIP));
	snprintf(buf, buflen, "p:%i s:%s:%i d:%s:%i hash:%s",
		packet->ipv4->protocol, sIP, get_source_port(packet), dIP, get_dest_port(packet), md5sum);
}

int get_mac_addr(const char *dev, uint8_t *mac)
{
	int ret;
	int sockfd;
	struct ifreq if_mac;

	if((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return -1;

	memset(&if_mac, 0, sizeof(if_mac));
	strncpy(if_mac.ifr_name, dev, sizeof(if_mac.ifr_name) - 1);
	if((ret = ioctl(sockfd, SIOCGIFHWADDR, &if_mac)) < 0)
	{
		close(sockfd);
		return ret;
	}

	memcpy(mac, if_mac.ifr_hwaddr.sa_data, ETH_ALEN);

	close(sockfd);

	return 0;
}

int get_dev_index(char *dev)
{
	int ret;
	int sockfd;
	struct ifreq if_idx;

	if((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return -1;

	memset(&if_idx, 0, sizeof(if_idx));
	strncpy(if_idx.ifr_name, dev, sizeof(if_idx.ifr_name) - 1);
	if((ret = ioctl(sockfd, SIOCGIFINDEX, &if_idx)) < 0)
		return ret;

	close(sockfd);

	return if_idx.ifr_ifindex;
}

struct packet_data *create_packet(int len)
{
	struct packet_data *c = NULL;
	c = (struct packet_data*)malloc(sizeof(struct packet_data));
	if(c == NULL)
	{
		arglog(LOG_DEBUG, "Unable to allocate space for new packet\n");
		return NULL;
	}

	c->len = 0;
	c->linkLayerLen = 0;
	
	if(len > 0)
	{
		c->len = len;
		c->data = (uint8_t*)calloc(len, 1);
		if(c->data == NULL)
		{
			arglog(LOG_DEBUG, "Unable to allocate space for new packet data\n");
			free(c);
			return NULL;
		}
	}

	parse_packet(c);
	return c;
}

struct packet_data *copy_packet(const struct packet_data *packet)
{
	struct packet_data *c = NULL;
	c = (struct packet_data*)malloc(sizeof(struct packet_data));
	if(c == NULL)
	{
		arglog(LOG_DEBUG, "Unable to allocate space to copy packet\n");
		return NULL;
	}

	c->data = (uint8_t*)malloc(packet->len);
	if(c->data == NULL)
	{
		arglog(LOG_DEBUG, "Unable to allocate space to copy packet data\n");
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

int send_packet_on(int dev_index, const struct packet_data *packet)
{
	static int sock = 0;
	struct sockaddr_ll addr;

	if(sock <= 0)
	{
		sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
		if(sock < 0)
		{
			arglog(LOG_DEBUG, "Unable to create raw socket for sending\n");
			return sock;
		}
	}

	if(!packet->eth)
	{
		arglog(LOG_ALERT, "Packtes may only be sent on a specific interface when ethernet header is given\n");
		return -ARG_INTERNAL_ERROR;
	}

	addr.sll_ifindex = dev_index;
	addr.sll_halen = ETH_ALEN;
	memcpy(addr.sll_addr, packet->eth->h_dest, sizeof(addr.sll_addr));

	if(sendto(sock, (uint8_t*)packet->data, packet->len, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		arglog(LOG_DEBUG, "Send failed on dev %i: %i\n", dev_index, errno);
		return -errno;
	}

	return 0;

}

int send_packet(const struct packet_data *packet)
{
	static int sock = 0;
	struct sockaddr_in dest_addr;
	int len = 0;

	//arglog(LOG_DEBUG, "Sending packet:");
	//printRaw(packet->len, packet->data);

	if(sock <= 0)
	{
		sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if(sock < 0)
		{
			arglog(LOG_DEBUG, "Unable to create raw socket for sending\n");
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
		arglog(LOG_DEBUG, "Normal send failed, errno %i. Msg size %i\n", errno, len);
		return -errno;
	}

	return 0;
}

int send_arp_reply(const struct packet_data *packet, int devIndex, const uint8_t *hwaddr)
{
	int ret;
	struct packet_data *reply = NULL;
	char ip[INET_ADDRSTRLEN];

	if(!packet->arp || ntohs(packet->arp->ea_hdr.ar_op) != ARPOP_REQUEST)
		return -1;

	reply = create_packet(sizeof(struct ethhdr) + sizeof(struct ether_arp));
	if(reply == NULL)
	{
		arglog(LOG_DEBUG, "Unable to create ARP reply\n");
		return -ENOMEM;
	}

	// Build reply
	reply->linkLayerLen = sizeof(struct ethhdr);
	reply->eth = (struct ethhdr*)reply->data;
	reply->eth->h_proto = htons(ETH_P_ARP);
	memcpy(reply->eth->h_dest, packet->arp->arp_sha, sizeof(reply->eth->h_dest));
	memcpy(reply->eth->h_source, hwaddr, sizeof(reply->eth->h_source));
	
	parse_packet(reply);
	reply->arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER); // Ethernet
	reply->arp->ea_hdr.ar_pro = htons(ETH_P_IP); // IP 
	reply->arp->ea_hdr.ar_hln = sizeof(packet->arp->arp_sha); // 6-byte MACs 
	reply->arp->ea_hdr.ar_pln = ADDR_SIZE; // IP address size
	reply->arp->ea_hdr.ar_op = htons(ARPOP_REPLY); // ARP Reply

	memcpy(reply->arp->arp_sha, hwaddr, sizeof(reply->arp->arp_sha)); // Our MAC
	memcpy(reply->arp->arp_spa, packet->arp->arp_tpa, sizeof(reply->arp->arp_spa)); // We're whatever IP they asked for
	memcpy(reply->arp->arp_tha, packet->arp->arp_sha, sizeof(reply->arp->arp_tha)); // To the sender of the request
	memcpy(reply->arp->arp_tpa, packet->arp->arp_spa, sizeof(reply->arp->arp_tpa));

	// Whew, that was a lot of work
	if((ret = send_packet_on(devIndex, reply)) >= 0)
	{
		inet_ntop(AF_INET, packet->arp->arp_tpa, ip, sizeof(ip));
		arglog(LOG_DEBUG, "Sent ARP reply for %s\n", ip);
	}
	else
		arglog(LOG_DEBUG, "ARP reply failed to send\n");

	free_packet(reply);

	return ret;
}

void tcp_csum(struct packet_data *packet)
{
	#ifdef COMPUTE_CHECKSUMS
	csum_with_psuedo(packet);
	#endif
}

void udp_csum(struct packet_data *packet)
{
	if(!packet->udp)
		return;
	
	#ifdef COMPUTE_CHECKSUMS
	csum_with_psuedo(packet);
	#else
	packet->udp->check = 0;
	#endif
}

void csum_with_psuedo(struct packet_data *packet)
{
	if(!packet->ipv4 || (!packet->tcp && !packet->udp))
		return;

	// Because we need to include the psuedo header and packets may be fairly long,
	// manually add up each part, rather than consolidating down. May help memory usage
	// and speed for large packets
	uint32_t sum = 0;
	
	// Transport layer itself
	uint16_t *curr = NULL;
	int i = 0;
	uint32_t len = 0;
	if(packet->tcp)
	{
		packet->tcp->check = 0;
		curr = (uint16_t*)packet->tcp;
		len = ntohs(packet->ipv4->tot_len) - packet->ipv4->ihl * 4;
	}
	else
	{
		packet->udp->check = 0;
		curr = (uint16_t*)packet->udp;
		len = ntohs(packet->udp->len);
	}

	i = len;
	while(i > 1)
	{
		sum += (uint32_t)ntohs(*curr);
		i -= 2;
		curr++;
	}

	if(i == 1)
		sum += (uint32_t)ntohs(*curr) & 0xFF00;
	
	// IPs
	sum += ntohs((packet->ipv4->saddr >> 16) & 0xFFFF);
	sum += ntohs(packet->ipv4->saddr & 0xFFFF);
	
	sum += ntohs((packet->ipv4->daddr >> 16) & 0xFFFF);
	sum += ntohs(packet->ipv4->daddr & 0xFFFF);

	// Protocol and length
	sum += (uint32_t)packet->ipv4->protocol;
	sum += (uint32_t)len;

	// Finalize sum and complement. First two steps carry in any overflow
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum = (sum >> 16) + (sum & 0xFFFF);

	if(packet->tcp)
		packet->tcp->check = ~((uint16_t)htons(sum));
	else
		packet->udp->check = ~((uint16_t)htons(sum));
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

