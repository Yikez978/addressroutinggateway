#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

#include <time.h>

#define ICMP_PROTO 0x01
#define TCP_PROTO 0x06
#define UDP_PROTO 0x11

#define LINK_LAYER_SIZE 14

// Size of IPv4 addresses (bytes)
#define ADDR_SIZE sizeof(__be32)

struct arghdr;

// Taken from the #if 0'd out part of ethhdr
// It's removed there because it can be variable sized... we're not handling that case
typedef struct arp_data {
	uint8_t ar_sha[ETH_ALEN];
	uint8_t ar_sip[ADDR_SIZE];
	uint8_t ar_tha[ETH_ALEN];
	uint8_t ar_tip[ADDR_SIZE];
} arp_data;

typedef struct packet_data
{
	unsigned long len;
	int linkLayerLen;

	struct timespec tstamp;

	struct ethhdr *eth;
	struct iphdr *ipv4;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct icmphdr *icmp;
	struct ether_arp *arp;
	struct arghdr *arg;

	uint8_t *unknown_data; // Pointer to first part of data we didn't parse

	uint8_t *data;
} packet_data;

char parse_packet(struct packet_data *packet);

// Creates a string to "uniquely" (hopefully) ID a packet
void create_packet_id(const struct packet_data *packet, char *buf, int buflen);

struct packet_data *create_packet(int len);
struct packet_data *copy_packet(const struct packet_data *packet);
void free_packet(struct packet_data *packet);

char send_packet(const struct packet_data *packet);

char send_arp_reply(const struct packet_data *packet, const uint8_t *hwaddr);

char get_mac_addr(const char *dev, uint8_t *mac);

uint16_t get_source_port(const struct packet_data *packet);
uint16_t get_dest_port(const struct packet_data *packet);
void set_source_port(struct packet_data *packet, const uint16_t port);
void set_dest_port(struct packet_data *packet, const uint16_t port);

#endif

