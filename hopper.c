#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <errno.h>

#include <pthread.h>

#include "settings.h"
#include "hopper.h"
#include "arg_error.h"
#include "utility.h"
#include "crypto.h"

/**************************
IP Hopping data
**************************/
static arg_network_info *gateInfo = NULL;
static pthread_mutex_t networksLock;

static pthread_mutex_t ipLock;

static pthread_t connectThread;

void init_hopper_locks(void)
{
	pthread_mutex_init(&ipLock, NULL);
	pthread_mutex_init(&networksLock, NULL);
}

int init_hopper(const struct config_data *config)
{
	int ret;

	arglog(LOG_DEBUG, "Hopper init\n");

	pthread_mutex_lock(&networksLock);
	pthread_mutex_lock(&ipLock);
	
	// "Read in" settings
	if(get_hopper_conf(config))
	{
		arglog(LOG_DEBUG, "Unable to configure hopper\n");
		
		pthread_mutex_unlock(&ipLock);
		pthread_mutex_unlock(&networksLock);
		uninit_hopper();

		return -ARG_CONFIG_BAD;
	}

	entropy_init(&gateInfo->entropy);
	if((ret = ctr_drbg_init( &gateInfo->ctr_drbg, entropy_func, &gateInfo->entropy, NULL, 0)) != 0)
	{
		arglog(LOG_DEBUG,  "Unable to initialize entropy pool, error %d\n", ret);
		
		pthread_mutex_unlock(&ipLock);
		pthread_mutex_unlock(&networksLock);
		uninit_hopper();

		return -ARG_INTERNAL_ERROR;
	}

	pthread_mutex_unlock(&ipLock);
	pthread_mutex_unlock(&networksLock);
	
	arglog(LOG_DEBUG, "Hopper initialized\n");

	return 0;
}

void init_hopper_finish(void)
{
	arglog(LOG_DEBUG, "Starting connection/gateway auth thread\n");
	pthread_create(&connectThread, NULL, hopper_admin_thread, NULL); // TBD check return
}

void uninit_hopper(void)
{
	arglog(LOG_DEBUG, "Hopper uninit\n");

	// No more need to hop and connect
	if(connectThread != 0)
	{
		pthread_cancel(connectThread);
		pthread_join(connectThread, NULL);
		connectThread = 0;
	}
	
	pthread_mutex_lock(&networksLock);
	pthread_mutex_lock(&ipLock);
	
	// Remove our own information
	if(gateInfo != NULL)
	{
		remove_all_associated_arg_networks();

		free(gateInfo);
		gateInfo = NULL;
	}
	
	pthread_mutex_unlock(&ipLock);
	pthread_mutex_unlock(&networksLock);
	
	pthread_mutex_destroy(&ipLock);
	pthread_mutex_destroy(&networksLock);

	arglog(LOG_DEBUG, "Hopper finished\n");
}

int get_hopper_conf(const struct config_data *config)
{
	struct gate_list *currGateName = NULL;

	struct arg_network_info *currNet = NULL;
	struct arg_network_info *prevNet = NULL;

	// Read in each gate config
	currGateName = config->gate;
	while(currGateName)
	{
		// New node!
		prevNet = currNet;
		currNet = create_arg_network_info();
		if(currNet == NULL)
		{
			arglog(LOG_DEBUG, "Unable to create arg network info during configuration\n");
			return -ENOMEM;
		}
		
		// First gate is "us" for now, we rearrange later
		if(gateInfo == NULL)
			gateInfo = currNet;

		// Connect new node to list
		if(prevNet != NULL)
		{
			prevNet->next = currNet;
			currNet->prev = prevNet;
		}

		// Get public data for this node. If it's us, we'll get the private key
		// and IP address/mask in a bit
		strncpy(currNet->name, currGateName->name, sizeof(currNet->name) - 1);
		read_public_key(config, currNet);
		mask_array(sizeof(currNet->baseIP), currNet->baseIP, currNet->mask, currNet->baseIP);

		currGateName = currGateName->next;
	}

	// Which one is our head? Find it, move to beginning, and rearrange
	// all relevant pointers.
	arglog(LOG_DEBUG, "Locating configuration for %s\n", config->ourGateName);

	currNet = gateInfo;
	while(currNet != NULL)
	{
		if(strncmp(config->ourGateName, currNet->name, sizeof(currNet->name)) == 0)
		{
			// Found, make currNet the head of list (if not already)
			if(currNet != gateInfo)
			{
				arglog(LOG_DEBUG, "Rearranging ARG network list\n");

				if(currNet->next != NULL)
					currNet->next->prev = currNet->prev;
				if(currNet->prev != NULL)
					currNet->prev->next = currNet->next;
			
				if(gateInfo != NULL)
					gateInfo->prev = currNet;

				currNet->prev = NULL;
				currNet->next = gateInfo;

				gateInfo = currNet;
			}

			break;
		}

		currNet = currNet->next;
	}

	if(currNet == NULL)
	{
		// Didn't find a match
		arglog(LOG_DEBUG, "Misconfiguration, unable to find which gate we are\n");
		return -ARG_CONFIG_BAD;
	}

	arglog(LOG_DEBUG, "Configured as %s\n", gateInfo->name);

	// Private key
	if(read_private_key(config, gateInfo))
	{
		arglog(LOG_FATAL, "Private key check failed\n");
		return -ARG_CONFIG_BAD;
	}

	// Hop and symmetric key
	arglog(LOG_DEBUG, "Generating hop and symmetric encryption keys\n");
	get_random_bytes(gateInfo->iv, sizeof(gateInfo->iv));
	get_random_bytes(gateInfo->hopKey, sizeof(gateInfo->hopKey));
	get_random_bytes(gateInfo->symKey, sizeof(gateInfo->symKey));

	cipher_setkey(&gateInfo->cipher, gateInfo->symKey, sizeof(gateInfo->symKey) * 8, POLARSSL_DECRYPT);
	md_hmac_starts(&gateInfo->md, gateInfo->symKey, sizeof(gateInfo->symKey));
	
	if(cipher_get_block_size(&gateInfo->cipher) != AES_BLOCK_SIZE)
	{
		arglog(LOG_DEBUG, "WARNING!!! Cipher block size (%i) is not the same as compiled AES_BLOCK_SIZE (%i)\n",
			cipher_get_block_size(&gateInfo->cipher), AES_BLOCK_SIZE);
	}

	// Rest of hop data
	current_time(&gateInfo->timeBase);
	gateInfo->hopInterval = config->hopRate;
	arglog(LOG_DEBUG, "Hop rate set to %lums\n", gateInfo->hopInterval);

	// Set IP based on configuration
	arglog(LOG_DEBUG, "Setting initial IP\n");
	update_ips(gateInfo);

	return 0;
}

void *hopper_admin_thread(void *data)
{
	struct arg_network_info *gate = NULL;

	arglog(LOG_DEBUG, "Connect thread running\n");

	sleep(INITIAL_CONNECT_WAIT);

	for(;;)
	{
		struct timespec curr;
		current_time(&curr);

		gate = gateInfo->next;
		while(gate != NULL)
		{
			long int offset = 0;
			offset = time_offset(&gate->lastDataUpdate, &curr);

			if(gate->connected && offset > MAX_UPDATE_TIME * 1000)
			{
				// We haven't heard from this gate in a while
				arglog(LOG_DEBUG, "No update from %s in %li seconds, disconnecting\n", gate->name, offset / 1000);
				gate->connected = 0;
			}
			
			if(offset > CONNECT_WAIT_TIME * 1000)
			{
				// Start new connection/send current data to the other gate so we know we're current
				start_connection(gateInfo, gate);
			}

			offset = time_offset(&gate->proto.pingSentTime, &curr);
			if(gate->connected && offset > MIN_PING_TIME * 1000 && gate->proto.badIPCount != 0)
			{
				// It's been at least a bit since we sent a ping, but we only need to worry
				// about it if we're seeing a lot of bad IP packets coming in, relative
				// to the number of good ones
				int prop = gate->proto.goodIPCount / gate->proto.badIPCount;
				arglog(LOG_DEBUG, "IP rejection proportion currently at %i (%i / %i) with %s\n",
					prop, gate->proto.goodIPCount, gate->proto.badIPCount, gate->name);
				if(MIN_VALID_IP_PROP > prop)
				{
					arglog(LOG_DEBUG, "High proportion (%i) of packets being rejected by IP with %s, starting time sync\n",
						prop, gate->name);
					start_time_sync(gateInfo, gate);

					gate->proto.goodIPCount = 0;
					gate->proto.badIPCount = 0;
				}
			}
			
			// Next
			gate = gate->next;
		}

		print_associated_networks();
		sleep(MIN_PING_TIME);
	}
	
	arglog(LOG_DEBUG, "Connect thread dying\n");

	return 0;
}

struct arg_network_info *create_arg_network_info(void)
{
	struct arg_network_info *newInfo = NULL;

	newInfo = (struct arg_network_info*)malloc(sizeof(struct arg_network_info));
	if(newInfo == NULL)
	{
		arglog(LOG_DEBUG, "Unable to allocate space for ARG network info\n");
		return NULL;
	}

	// Clear it all out
	memset(newInfo, 0, sizeof(struct arg_network_info));

	// Init things that need it
	pthread_mutex_init(&newInfo->lock, NULL);
	rsa_init(&newInfo->rsa, RSA_PKCS_V15, 0);

	cipher_init_ctx(&newInfo->cipher, cipher_info_from_string(SYMMETRIC_ALGO));
	md_init_ctx(&newInfo->md, md_info_from_string(HASH_ALGO));

	newInfo->hopInterval = UINT32_MAX;
	newInfo->proto.outSeqNum = 1;
	newInfo->proto.inSeqNum = 0;

	return newInfo;
}

struct arg_network_info *remove_arg_network(struct arg_network_info *network)
{
	struct arg_network_info *next = network->next;

	// Hook up the pointers to the networks on either side of us
	if(network->next != NULL)
		network->next->prev = network->prev;
	
	if(network->prev != NULL)
		network->prev->next = network->next;

	pthread_mutex_destroy(&network->lock);

	rsa_free(&network->rsa);
	md_free_ctx(&network->md);
	cipher_free_ctx(&network->cipher);

	// Free us
	free(network);

	return next;
}

void remove_all_associated_arg_networks(void)
{
	arglog(LOG_DEBUG, "Removing all associated ARG networks\n");

	if(gateInfo == NULL)
	{
		arglog(LOG_DEBUG, "Attempt to remove associated networks when hopper not initialized\n");
		return;
	}

	// Just keep removing our next network until there are no more
	// Note that we don't remove ourselves
	while(gateInfo->next != NULL)
		remove_arg_network(gateInfo->next);
}

void print_associated_networks(void)
{
	struct arg_network_info *curr = gateInfo;
	
	// Skip ourselves
	if(curr)
	{
		curr = curr->next;
		arglog(LOG_INFO, "Associated gateways:\n");
	}
	else
	{
		arglog(LOG_INFO, "No associated gateways\n");
		return;
	}

	while(curr)
	{
		print_network(curr);
		curr = curr->next;
	}
}

void print_network(const struct arg_network_info *network)
{
	char ip[INET_ADDRSTRLEN];
	char mask[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, network->baseIP, ip, sizeof(ip));
	inet_ntop(AF_INET, network->mask, mask, sizeof(mask));

	arglog(LOG_INFO, "  %s (%s, %s): %s\n", network->name, ip, mask, 
		network->connected ? "connected" : "disconnected");
}

uint8_t *current_ip(void)
{
	uint8_t *ipCopy = NULL;

	ipCopy = (uint8_t*)malloc(ADDR_SIZE);
	if(ipCopy == NULL)
	{
		arglog(LOG_DEBUG, "Unable to allocate space for saving off IP address.\n");
		return NULL;
	}

	pthread_mutex_lock(&ipLock);
	memcpy(ipCopy, gateInfo->currIP, ADDR_SIZE);
	pthread_mutex_unlock(&ipLock);

	return ipCopy;
}

bool is_valid_local_ip(const uint8_t *ip)
{
	return is_valid_ip(gateInfo, ip);
}

bool is_valid_ip(struct arg_network_info *gate, const uint8_t *ip)
{
	char ret = 0;

	pthread_mutex_lock(&gate->lock);

	update_ips(gate);

	if(memcmp(ip, gate->currIP, ADDR_SIZE) == 0)
		ret = 1;
	else if(memcmp(ip, gate->prevIP, ADDR_SIZE) == 0)
		ret = 1;
	else
		ret = 0;
	
	pthread_mutex_unlock(&gate->lock);

	return ret;
}

void note_bad_ip(struct arg_network_info *gate)
{
	gate->proto.badIPCount++;
}

void note_good_ip(struct arg_network_info *gate)
{
	gate->proto.goodIPCount++;
}

const uint8_t *gate_base_ip(void)
{
	return gateInfo->baseIP;
}

const uint8_t *gate_mask(void)
{
	return gateInfo->mask;
}

int process_admin_msg(const struct packet_data *packet, struct arg_network_info *srcGate)
{
	switch(get_msg_type(packet->arg))
	{
	case ARG_PING_MSG:
		return process_arg_ping(gateInfo, srcGate, packet);
		break;

	case ARG_PONG_MSG:
		return process_arg_pong(gateInfo, srcGate, packet);
		break;

	case ARG_CONN_DATA_REQ_MSG:
		return process_arg_conn_data_req(gateInfo, srcGate, packet);
		break;

	case ARG_CONN_DATA_RESP_MSG:
		return process_arg_conn_data_resp(gateInfo, srcGate, packet);
		break;

	case ARG_TRUST_DATA_MSG:
		return process_arg_trust(gateInfo, srcGate, packet);
		break;

	default:
		return -ARG_UNHANDLED_TYPE;
	}

	return 0;
}

void update_ips(struct arg_network_info *gate)
{
	int i = 0;
	uint32_t bits = 0;
	uint8_t *bitIndex = (uint8_t*)&bits;
	int minLen = 0;
	uint8_t ip[sizeof(gate->currIP)];

	struct timespec currTime;
	current_time(&currTime);

	// Is the cache out of date? If not, do nothing
	if(time_offset(&gate->ipCacheExpiration, &currTime) < 0)
		return;

	// Copy in top part of address. baseIP has already been masked to
	// ensure it is zeros for the portion that changes, so we only have
	// to copy it in
	memcpy(ip, gate->baseIP, sizeof(gate->baseIP));

	// Apply random bits to remainder of IP. If we have fewer bits than
	// needed for the mask, the extra remain 0. Sorry
	//arglog(LOG_DEBUG, "UPDATE IPS for %s: Hop interval %lu, offset %li, key ", gate->name, gate->hopInterval, time_offset(&gate->timeBase, &currTime));
	//printRaw(sizeof(gate->hopKey), gate->hopKey);

	bits = totp(gate->hopKey, sizeof(gate->hopKey), gate->hopInterval, time_offset(&gate->timeBase, &currTime)); 

	minLen = sizeof(gate->mask) < sizeof(bits) ? sizeof(gate->mask) : sizeof(bits);
	for(i = 0; i < minLen; i++)
	{
		ip[sizeof(gate->baseIP) - i - 1] |=
							~gate->mask[sizeof(gate->mask) - i - 1] &
							bitIndex[sizeof(bits) - i - 1];
	}

	// Is this an actual change? If so, copy the old address back and the new one in
	// If we always blindly rotated, spurious updates would cause us to lose our prevIP
	if(memcmp(ip, gate->currIP, sizeof(gate->currIP)) != 0)
	{
		memcpy(gate->prevIP, gate->currIP, sizeof(gate->currIP));
		memcpy(gate->currIP, ip, sizeof(gate->currIP));

		// Update on exactly when the next hop should occur
		current_time(&gate->ipCacheExpiration);
		time_plus(&gate->ipCacheExpiration,
			gate->hopInterval - time_offset(&gate->timeBase, &gate->ipCacheExpiration) % gate->hopInterval);
	}
}

int do_arg_wrap(const struct packet_data *packet, struct arg_network_info *destGate)
{
	// Ignore requests to ourselves
	if(destGate == gateInfo)
		return 0;

	return send_arg_wrapped(gateInfo, destGate, packet);
}

int do_arg_unwrap(const struct packet_data *packet, struct arg_network_info *srcGate)
{
	return process_arg_wrapped(gateInfo, srcGate, packet);
}

struct arg_network_info *get_arg_network(void const *ip)
{
	struct arg_network_info *curr = gateInfo;

	while(curr != NULL)
	{
		if(mask_array_cmp(sizeof(curr->baseIP), curr->mask, curr->baseIP, ip) == 0)
			return curr;

		curr = curr->next;
	}

	// Not found
	return NULL;
}

bool is_arg_ip(void const *ip)
{
	return get_arg_network(ip) != NULL;
}

