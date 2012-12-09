#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stdbool.h>

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

// The basic packet used throughout ARG. Pointers point into the main data section,
// allowing easy parsing of all parts
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
	unsigned long unknown_len; // Length of unparsed data

	uint8_t *data;
} packet_data;

// Initializes a packet structure, ensuring the pointers are in the correct
// locations based on the data there. IE, if an IP packet has protocol 6, tcp
// points to the start of the TCP header after this function completes
int parse_packet(struct packet_data *packet);

// Creates a string to "unique" (hopefully) ID a packet
void create_packet_id(const struct packet_data *packet, char *buf, int buflen);

// Create or copy new packets
struct packet_data *create_packet(int len);
struct packet_data *copy_packet(const struct packet_data *packet);
void free_packet(struct packet_data *packet);

// Sends a packet into the network
int send_packet(const struct packet_data *packet);
int send_packet_on(int dev_index, const struct packet_data *packet);

// To be transparent we need to know how to respond to ethernet ARP requests.
// This actually answers them
int send_arp_reply(const struct packet_data *packet, int devIndex, const uint8_t *hwaddr);

// Returns the MAC address of the given card (by device name)
int get_mac_addr(const char *dev, uint8_t *mac);

// Returns the device index of the given card
int get_dev_index(char *dev);

// Checksums for packets
void tcp_csum(struct packet_data *packet);
void udp_csum(struct packet_data *packet);
void csum_with_psuedo(struct packet_data *packet);

// Get and set port numbers transparently, whether we have a TCP or UDP packet
uint16_t get_source_port(const struct packet_data *packet);
uint16_t get_dest_port(const struct packet_data *packet);
void set_source_port(struct packet_data *packet, const uint16_t port);
void set_dest_port(struct packet_data *packet, const uint16_t port);

#endif

