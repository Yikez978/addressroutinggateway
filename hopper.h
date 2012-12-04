#ifndef HOPPER_H
#define HOPPER_H

#include <stdbool.h>

#include <pthread.h>

#include <polarssl/config.h>
#include <polarssl/rsa.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/cipher.h>
#include <polarssl/md.h>

#include "utility.h"
#include "uthash.h"
#include "crypto.h"
#include "packet.h"
#include "protocol.h"
#include "settings.h"

// Structure to hold data on associated ARG networks
// All times here are given in jiffies for the current system, unless
// otherwise specified
typedef struct arg_network_info {
	// Basic info
	char name[MAX_NAME_SIZE];
	
	// State of gateway connection/things to be done
	bool connected; // True if we have all the data needed to send ARG packets to this gateway

	struct timespec lastDataUpdate;
	struct proto_data proto;

	// Lock
	pthread_mutex_t lock;

	// Encryption keys and parameters
	uint8_t symKey[AES_KEY_SIZE];
	uint8_t iv[AES_BLOCK_SIZE];

	cipher_context_t cipher;
	md_context_t md;

	rsa_context rsa;
	entropy_context entropy;
	ctr_drbg_context ctr_drbg;

	// Hopping information
	uint8_t hopKey[HOP_KEY_SIZE];
	struct timespec timeBase;
	uint32_t hopInterval;

	// IP range information
	uint8_t baseIP[ADDR_SIZE];
	uint8_t mask[ADDR_SIZE];

	uint8_t currIP[ADDR_SIZE];
	uint8_t prevIP[ADDR_SIZE];
	struct timespec ipCacheExpiration;

	// Linked-list links
	struct arg_network_info *next;
	struct arg_network_info *prev;
} arg_network_info;

// Take care of resources
void init_hopper_locks(void);
int init_hopper(const struct config_data *config);
void init_hopper_finish(void);
void uninit_hopper(void);

// Retreives and sets known ARG network keys/local gateway keys, etc
int get_hopper_conf(const struct config_data *config);

// Does the initial connect to all of the gateways we know of
void *hopper_admin_thread(void *data);

// Manage the list of ARG networks. NOT synchronzied, caller should claim lock!
struct arg_network_info *create_arg_network_info(void);
struct arg_network_info *remove_arg_network(struct arg_network_info *network);
void remove_all_associated_arg_networks(void);

void print_associated_networks(void);
void print_network(const struct arg_network_info *network);

// Adds a network to the table
void add_network(void);

// Returns the current IP address for the gateway
// NOTE: the previous IP is also valid for receiving,
// so checks from that perspective should use is_valid_local_ip()
uint8_t *current_ip(void);

// Returns true if the given IP is valid, false otherwise
bool is_valid_local_ip(const uint8_t *ip);
bool is_valid_ip(struct arg_network_info *gate, const uint8_t *ip);

// Determines how "wrong" an IP was. Returns 0 if the ip is current,
// -1 if it was one hop in the past, -2 for two hops, etc. Limited to
// +/-5 hops. MAX_INT returned if beyond that
int invalid_ip_direction(const uint8_t *ip);

void note_bad_ip(struct arg_network_info *gate);
void note_good_ip(struct arg_network_info *gate);

// Returns configuration information
const uint8_t *gate_base_ip(void);
const uint8_t *gate_mask(void);

// Processes incoming admin messages by handing them off to the correct protocol handler
int process_admin_msg(const struct packet_data *packet, struct arg_network_info *srcGate);

// Generates the IP address for a given gate, based on the mask, hop key, and time
void update_ips(struct arg_network_info *gate);

// Generates the current IP for the given gate, based on the current time plus
// a given correction factor. Correction may be positive (in the future) or negative.
void generate_ip_corrected(struct arg_network_info *gate, int correction, uint8_t *ip);

// Wraps the given packet for the appropriate ARG network
// and signs it.
// Returns false if the packet is not destined for a known
// ARG network or another error occurs during processing
int do_arg_wrap(const struct packet_data *packet, struct arg_network_info *destGate);

// Unwraps the given packet.
// Returns false if the signature fails to match or another error
// occurs during processing
int do_arg_unwrap(const struct packet_data *packet, struct arg_network_info *srcGate);

// Returns pointer to the ARG network the give IP belongs to
struct arg_network_info *get_arg_network(void const *ip);

// Returns true if the given IP is an ARG network
bool is_arg_ip(void const *ip);

#endif

