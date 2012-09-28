#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#include <time.h>

#define ICMP_PROTO 0x01
#define TCP_PROTO 0x06
#define UDP_PROTO 0x11

#define LINK_LAYER_SIZE 14

// Size of IPv4 addresses (bytes)
#define ADDR_SIZE sizeof(__be32)

struct arghdr;

typedef struct packet_data
{
	unsigned long len;
	int linkLayerLen;

	struct timespec tstamp;
	
	struct iphdr *ipv4;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct icmphdr *icmp;
	struct arghdr *arg;
	
	uint8_t *data;
} packet_data;

char parse_packet(struct packet_data *packet);

struct packet_data *create_packet(void);
struct packet_data *copy_packet(const struct packet_data *packet);
void free_packet(struct packet_data *packet);

void compute_packet_checksums(struct packet_data *packet);

char send_packet(const struct packet_data *packet);

uint16_t get_source_port(const struct packet_data *packet);
uint16_t get_dest_port(const struct packet_data *packet);
void set_source_port(struct packet_data *packet, const uint16_t port);
void set_dest_port(struct packet_data *packet, const uint16_t port);

#endif

