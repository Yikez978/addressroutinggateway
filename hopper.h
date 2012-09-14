#ifndef HOPPER_H
#define HOPPER_H

#include <linux/skbuff.h>
#include <linux/ip.h>

#include "utility.h"
#include "net_info.h"
#include "uthash.h"

#define MAX_NAME_SIZE 20

#define INT_DEV_NAME "eth1"
#define EXT_DEV_NAME "eth0"

#define RSA_KEY_SIZE 16
#define AES_KEY_SIZE 16
#define HOP_KEY_SIZE 16

// Structure to hold data on associated ARG networks
typedef struct arg_network_info {
	// Connected to this network?
	char connected;

	// Name
	uchar name[MAX_NAME_SIZE];

	// Encryption keys
	uchar privKey[RSA_KEY_SIZE];
	uchar pubKey[RSA_KEY_SIZE];
	uchar symKey[AES_KEY_SIZE];

	// Hopping information
	uchar hopKey[HOP_KEY_SIZE];

	// IP range information
	uchar baseIP[ADDR_SIZE];
	uchar mask[ADDR_SIZE];

	uchar currIP[ADDR_SIZE];
	uchar prevIP[ADDR_SIZE];

	// Linked-list links
	struct arg_network_info *next;
	struct arg_network_info *prev;
} arg_network_info;

// Take care of resources
void init_hopper_locks(void);
char init_hopper(void);
void uninit_hopper(void);

// Retreives and sets known ARG network keys/local gateway keys, etc
char get_hopper_conf(void);

// Enable and disable hopping
void enable_hopping(void);
void disable_hopping(void);

// Perform actual periodic hop
void timed_hop(unsigned long data);

// Manage the list of ARG networks. NOT synchronzied, caller should claim lock!
struct arg_network_info *create_arg_network_info(void);
struct arg_network_info *remove_arg_network(struct arg_network_info *network);
void remove_all_associated_arg_networks(void);

// Adds a network to the table
void add_network(void);

// Ensures the current and previous IPs are correct,
// based on the current time and hop key
void update_ips(void);

// Returns the current IP address for the gateway
// NOTE: the previous IP is also valid for receiving,
// so checks from that perspective should use is_current_ip(uchar *ip);
uchar *current_ip(void);

// Returns true if the given IP is valid, false otherwise
char is_current_ip(uchar const *ip);

// Sets the current external IP address of the physical card and rotates
// the internal addresses
void set_external_ip(uchar *ip);

// Checks if the given packet is an administrative 
// packet or not. Returns true if it is, false otherwise
char is_admin_packet(struct sk_buff const *skb);

// Checks if the given packet is signed correctly.
// Returns true if it is, false otherwise
char is_signature_valid(struct sk_buff const *skb);

// Wraps the given packet for the appropriate ARG network
// and signs it. The new packet is left in skb
// Returns false if the packet is not destined for a known
// ARG network or another error occurs during processing
char do_arg_wrap(struct sk_buff *skb);

// Unwraps the given packet, leaving the inner packet in skb.
// Returns false if the signature fails to match or another error
// occurs during processing
char do_arg_unwrap(struct sk_buff *skb);

// Returns pointer to the ARG network the give IP belongs to
struct arg_network_info *get_arg_network(void const *ip);

// Returns true if the given IP is an ARG network
char is_arg_ip(void const *ip);

#endif

