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
#include "utility.h"
#include "crypto.h"

/**************************
IP Hopping data
**************************/
static arg_network_info *gateInfo = NULL;
static pthread_spinlock_t networksLock;

static pthread_spinlock_t ipLock;

static pthread_t connectThread;

void init_hopper_locks(void)
{
	pthread_spin_init(&ipLock, PTHREAD_PROCESS_SHARED);
	pthread_spin_init(&networksLock, PTHREAD_PROCESS_SHARED);
}

char init_hopper(char *conf, char *name)
{
	int ret;

	arglog(LOG_DEBUG, "Hopper init\n");

	pthread_spin_lock(&networksLock);
	pthread_spin_lock(&ipLock);
	
	// "Read in" settings
	if(get_hopper_conf(conf, name))
	{
		arglog(LOG_DEBUG, "Unable to configure hopper\n");
		
		pthread_spin_unlock(&ipLock);
		pthread_spin_unlock(&networksLock);
		uninit_hopper();

		return -1;
	}

	entropy_init(&gateInfo->entropy);
	if((ret = ctr_drbg_init( &gateInfo->ctr_drbg, entropy_func, &gateInfo->entropy, NULL, 0)) != 0)
	{
		arglog(LOG_DEBUG,  "Unable to initialize entropy pool, error %d\n", ret);
		
		pthread_spin_unlock(&ipLock);
		pthread_spin_unlock(&networksLock);
		uninit_hopper();

		return -2;
	}

	pthread_spin_unlock(&ipLock);
	pthread_spin_unlock(&networksLock);
	
	arglog(LOG_DEBUG, "Hopper initialized\n");

	return 0;
}

void init_hopper_finish(void)
{
	arglog(LOG_DEBUG, "Starting connection/gateway auth thread\n");
	pthread_create(&connectThread, NULL, connect_thread, NULL); // TBD check return
}

void uninit_hopper(void)
{
	arglog(LOG_DEBUG, "Hopper uninit\n");

	// No more need to hop and connect
	if(connectThread != 0)
	{
		arglog(LOG_DEBUG, "Asking connect thread to stop...");
		pthread_cancel(connectThread);
		pthread_join(connectThread, NULL);
		connectThread = 0;
		arglog(LOG_DEBUG, "done\n");
	}
	
	pthread_spin_lock(&networksLock);
	pthread_spin_lock(&ipLock);
	
	// Remove our own information
	if(gateInfo != NULL)
	{
		remove_all_associated_arg_networks();

		free(gateInfo);
		gateInfo = NULL;
	}
	
	pthread_spin_unlock(&ipLock);
	pthread_spin_unlock(&networksLock);
	
	pthread_spin_destroy(&ipLock);
	pthread_spin_destroy(&networksLock);

	arglog(LOG_DEBUG, "Hopper finished\n");
}

char get_hopper_conf(char *confPath, char *gateName)
{
	struct gate_list *currGateName = NULL;

	struct arg_network_info *currNet = NULL;
	struct arg_network_info *prevNet = NULL;

	struct config_data conf;

	// Read in main conf
	strncpy(conf.file, confPath, sizeof(conf.file));
	if(read_config(&conf))
	{
		arglog(LOG_ALERT, "Unable to read in main configuration from %s\n", confPath);
		return -1;
	}

	currGateName = conf.gate;
	while(currGateName)
	{
		// New node!
		prevNet = currNet;
		currNet = create_arg_network_info();
		if(currNet == NULL)
		{
			arglog(LOG_DEBUG, "Unable to create arg network info during configuration\n");
			return -2;
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
		strncpy(currNet->name, currGateName->name, sizeof(currNet->name));
		read_public_key(&conf, currNet);

		currGateName = currGateName->next;
	}

	// Which one is our head? Find it, move to beginning, and rearrange
	// all relevant pointers.
	arglog(LOG_DEBUG, "Locating configuration for %s\n", gateName);

	currNet = gateInfo;
	while(currNet != NULL)
	{
		if(strncmp(gateName, currNet->name, sizeof(currNet->name)) == 0)
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
		return -4;
	}

	arglog(LOG_DEBUG, "Configured as %s\n", gateInfo->name);

	// Private key
	read_private_key(&conf, gateInfo);
	mask_array(sizeof(currNet->baseIP), currNet->baseIP, currNet->mask, currNet->baseIP);

	// Hop and symmetric key
	arglog(LOG_DEBUG, "Generating hop and symmetric encryption keys\n");
	get_random_bytes(gateInfo->iv, sizeof(gateInfo->iv));
	get_random_bytes(gateInfo->hopKey, sizeof(gateInfo->hopKey));
	get_random_bytes(gateInfo->symKey, sizeof(gateInfo->symKey));

	cipher_setkey(&gateInfo->cipher, gateInfo->symKey, sizeof(gateInfo->symKey) * 8, POLARSSL_DECRYPT);
	md_hmac_starts(&gateInfo->md, gateInfo->symKey, sizeof(gateInfo->symKey)); // TBD use separate key for hmac?
	
	if(cipher_get_block_size(&gateInfo->cipher) != AES_BLOCK_SIZE)
	{
		arglog(LOG_DEBUG, "WARNING!!! Cipher block size (%i) is not the same as compiled AES_BLOCK_SIZE (%i)\n",
			cipher_get_block_size(&gateInfo->cipher), AES_BLOCK_SIZE);
	}

	// Rest of hop data
	current_time(&gateInfo->timeBase);
	gateInfo->hopInterval = conf.hopRate;
	arglog(LOG_DEBUG, "Hop rate set to %lums\n", gateInfo->hopInterval);

	// Set IP based on configuration
	arglog(LOG_DEBUG, "Setting initial IP\n");
	update_ips(gateInfo);

	// All done with this
	release_config(&conf);

	return 0;
}

void *connect_thread(void *data)
{
	struct arg_network_info *gate = NULL;

	long int offset = 0;

	arglog(LOG_DEBUG, "Connect thread running\n");

	sleep(INITIAL_CONNECT_WAIT);

	for(;;)
	{
		gate = gateInfo->next;
		while(gate != NULL)
		{
			offset = current_time_offset(&gate->lastDataUpdate);
			if(gate->connected && offset > MAX_UPDATE_TIME * 1000)
			{
				arglog(LOG_DEBUG, "No update from %s in %li seconds, disconnecting\n", gate->name, offset / 1000);
				gate->connected = 0;
			}
			
			if(offset > CONNECT_WAIT_TIME * 1000)
				start_connection(gateInfo, gate);
			
			// Next
			gate = gate->next;
		}

		sleep(CONNECT_WAIT_TIME / 4);
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
	pthread_spin_init(&newInfo->lock, PTHREAD_PROCESS_SHARED);
	rsa_init(&newInfo->rsa, RSA_PKCS_V15, 0);

	cipher_init_ctx(&newInfo->cipher, cipher_info_from_string(SYMMETRIC_ALGO));
	md_init_ctx(&newInfo->md, md_info_from_string(HASH_ALGO));

	newInfo->hopInterval = UINT32_MAX;
	newInfo->proto.outSeqNum = 1;

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

	pthread_spin_destroy(&network->lock);

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

uint8_t *current_ip(void)
{
	uint8_t *ipCopy = NULL;

	ipCopy = (uint8_t*)malloc(ADDR_SIZE);
	if(ipCopy == NULL)
	{
		arglog(LOG_DEBUG, "Unable to allocate space for saving off IP address.\n");
		return NULL;
	}

	pthread_spin_lock(&ipLock);
	memcpy(ipCopy, gateInfo->currIP, ADDR_SIZE);
	pthread_spin_unlock(&ipLock);

	return ipCopy;
}

char is_valid_local_ip(const uint8_t *ip)
{
	return is_valid_ip(gateInfo, ip);
}

char is_valid_ip(struct arg_network_info *gate, const uint8_t *ip)
{
	char ret = 0;

	pthread_spin_lock(&gate->lock);

	update_ips(gate);

	/*arglog(LOG_DEBUG, "Request: ");
	printIP(4, ip);
	arglog(LOG_DEBUG, " Could be ");
	printIP(4, gate->currIP);
	arglog(LOG_DEBUG, " or ");
	printIP(4, gate->prevIP);
	arglog(LOG_DEBUG, "\n");*/

	if(memcmp(ip, gate->currIP, ADDR_SIZE) == 0)
		ret = 1;
	else if(memcmp(ip, gate->prevIP, ADDR_SIZE) == 0)
		ret = 1;
	else
		ret = 0;
	
	pthread_spin_unlock(&gate->lock);

	return ret;
}


const uint8_t *gate_base_ip(void)
{
	return gateInfo->baseIP;
}

const uint8_t *gate_mask(void)
{
	return gateInfo->mask;
}

char process_admin_msg(const struct packet_data *packet, struct arg_network_info *srcGate)
{
	switch(get_msg_type(packet->arg))
	{
	case ARG_PING_MSG:
		process_arg_ping(gateInfo, srcGate, packet);
		break;

	case ARG_PONG_MSG:
		process_arg_pong(gateInfo, srcGate, packet);
		break;

	case ARG_CONN_DATA_REQ_MSG:
		process_arg_conn_data_req(gateInfo, srcGate, packet);
		break;

	case ARG_CONN_DATA_RESP_MSG:
		process_arg_conn_data_resp(gateInfo, srcGate, packet);
		break;
	
	default:
		arglog(LOG_DEBUG, "Unhandled message type seen (%i)\n", get_msg_type(packet->arg));
		return -1;	
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
		printf("Next update for %s occurs on %lu\n", gate->name, gate->ipCacheExpiration.tv_sec);
	}
}

void set_external_ip(uint8_t *addr)
{
	// Code mostly from http://www.lainoox.com/set-ip-address-c-linux/
	int sockfd;
	struct ifreq ifr;
	struct sockaddr_in sin;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd == -1)
	{
		arglog(LOG_DEBUG, "Unable to create socket to set external IP address\n");
		return;
	}
 
	// Get flags
	strncpy(ifr.ifr_name, EXT_DEV_NAME, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0)
	{
		arglog(LOG_DEBUG, "Unable to get flags to set external IP address\n");
		return;
	}
	
	#ifdef ifr_flags
	# define IRFFLAGS       ifr_flags
	#else   /* Present on kFreeBSD */
	# define IRFFLAGS       ifr_flagshigh
	#endif
 
	// If interface is down, bring it up
	if (ifr.IRFFLAGS | ~(IFF_UP))
	{
		ifr.IRFFLAGS |= IFF_UP;
		if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0)
		{
			arglog(LOG_DEBUG, "External interface down, unable to set IP: %i\n", errno);
			return;
		}
	}
 
	sin.sin_family = AF_INET;
 
	memcpy(&sin.sin_addr.s_addr, addr, sizeof(sin.sin_addr.s_addr));
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));	
 
	// Set interface address
	if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0)
	{
		arglog(LOG_DEBUG, "Unable to set IP address on external interface\n");
		return;
	}	
	#undef IRFFLAGS		
}

char do_arg_wrap(const struct packet_data *packet, struct arg_network_info *destGate)
{
	return send_arg_wrapped(gateInfo, destGate, packet);
}

char do_arg_unwrap(const struct packet_data *packet, struct arg_network_info *srcGate)
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

char is_arg_ip(void const *ip)
{
	return get_arg_network(ip) != NULL;
}

