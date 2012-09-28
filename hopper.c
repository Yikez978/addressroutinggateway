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

static char hoppingEnabled = 0;

static pthread_spinlock_t ipLock;

static pthread_t connectThread;
static pthread_t hopThread;

void init_hopper_locks(void)
{
	pthread_spin_init(&ipLock, PTHREAD_PROCESS_SHARED);
	pthread_spin_init(&networksLock, PTHREAD_PROCESS_SHARED);
}

char init_hopper(char *conf, char *name)
{
	printf("ARG: Hopper init\n");

	pthread_spin_lock(&networksLock);
	pthread_spin_lock(&ipLock);
	
	// "Read in" settings
	if(get_hopper_conf(conf, name))
	{
		printf("ARG: Unable to configure hopper\n");
		
		pthread_spin_unlock(&ipLock);
		pthread_spin_unlock(&networksLock);
		uninit_hopper();

		return -1;
	}

	pthread_spin_unlock(&ipLock);
	pthread_spin_unlock(&networksLock);
	
	// Allow hopping now
	printf("ARG: Starting hop thread\n");
	pthread_create(&hopThread, NULL, timed_hop_thread, NULL); // TBD check return
	enable_hopping();
	
	printf("ARG: Hopper initialized\n");

	return 0;
}

void init_hopper_finish(void)
{
	printf("ARG: Starting connection/gateway auth thread\n");
	pthread_create(&connectThread, NULL, connect_thread, NULL); // TBD check return
}

void uninit_hopper(void)
{
	printf("ARG: Hopper uninit\n");

	// Disable hopping
	disable_hopping();
	
	// No more need to hop and connect
	// TBD isnt't there a possibility of something bad happening if we del_timer while in
	// the timer? IE, it will reregister and then everything will die
	if(hopThread != 0)
	{
		printf("ARG: Asking hop thread to stop...");
		pthread_cancel(hopThread);
		pthread_join(hopThread, NULL);
		hopThread = 0;
		printf("done\n");
	}
	if(connectThread != 0)
	{
		printf("ARG: Asking connect thread to stop...");
		pthread_cancel(connectThread);
		pthread_join(connectThread, NULL);
		connectThread = 0;
		printf("done\n");
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

	printf("ARG: Hopper finished\n");
}

char get_hopper_conf(char *confPath, char *gateName)
{
	FILE *confFile = NULL;
	char line[MAX_CONF_LINE+1];

	struct arg_network_info *currNet = NULL;
	struct arg_network_info *prevNet = NULL;

	confFile = fopen(confPath, "r");
	if(confFile == NULL)
	{
		printf("Unable to open config file at %s\n", confPath);
		return -1;
	}

	while(!feof(confFile))
	{
		prevNet = currNet;
		currNet = create_arg_network_info();
		if(currNet == NULL)
		{
			printf("Unable to create arg network info during configuration\n");
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

		// Conf file format is:
		// name
		// base ip in dot-notation
		// mask in dot-notation
		// repeat for next gate
		if(get_next_line(confFile, line, MAX_CONF_LINE))
		{
			remove_arg_network(currNet);
			break;
		}
		strncpy(currNet->name, line, sizeof(currNet->name));
		
		if(get_next_line(confFile, line, MAX_CONF_LINE))
		{
			printf("Problem reading in base IP from conf for %s\n", currNet->name);
			remove_arg_network(currNet);
			break;
		}
		inet_pton(AF_INET, line, currNet->baseIP);
		
		if(get_next_line(confFile, line, MAX_CONF_LINE))
		{
			printf("Problem reading in mask from conf for %s\n", currNet->name);
			remove_arg_network(currNet);
			break;
		}
		inet_pton(AF_INET, line, currNet->mask);

		// Fix base ip by masking (just in case)
		mask_array(sizeof(currNet->baseIP), currNet->baseIP, currNet->mask, currNet->baseIP);
	}

	fclose(confFile);

	// Which one is our head? Find it, move to beginning, and rearrange
	// all relevant pointers.
	printf("Locating configuration for %s\n", gateName);

	currNet = gateInfo;
	while(currNet != NULL)
	{
		if(strncmp(gateName, currNet->name, sizeof(currNet->name)) == 0)
		{
			// Found, make currNet the head of list (if not already)
			if(currNet != gateInfo)
			{
				printf("ARG: Rearranging ARG network list\n");

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
		printf("ARG: Misconfiguration, unable to find which gate we are\n");
		return -4;
	}

	printf("ARG: Configured as %s\n", gateInfo->name);

	// Hop and symmetric key
	printf("ARG: Generating hop and symmetric encryption keys\n");
	get_random_bytes(gateInfo->hopKey, sizeof(gateInfo->hopKey));
	get_random_bytes(gateInfo->symKey, sizeof(gateInfo->symKey));

	// Rest of hop data
	current_time(&gateInfo->timeBase);
	gateInfo->hopInterval = HOP_TIME;

	// Set IP based on configuration
	printf("ARG: Setting initial IP\n");
	update_ips(gateInfo);

	return 0;
}

void enable_hopping(void)
{
	printf("ARG: Hopping enabled\n");
	hoppingEnabled = 1;
}

void disable_hopping(void)
{
	printf("ARG: Hopping disabled\n");
	hoppingEnabled = 0;
}

void *connect_thread(void *data)
{
	struct arg_network_info *gate = NULL;

	printf("ARG: Connect thread running\n");

	for(;;)
	{
		gate = gateInfo->next;
		while(gate != NULL)
		{
			if(!gate->connected)
			{
				printf("ARG: Attempting to connect to gateway at ");
				printIP(sizeof(gate->baseIP), gate->baseIP);
				printf("\n");

				start_connection(gateInfo, gate);
			}	

			// Next
			gate = gate->next;
		}

		sleep(CONNECT_WAIT_TIME);
	}
	
	printf("ARG: Connect thread dying\n");

	return 0;
}

void *timed_hop_thread(void *data)
{
	printf("ARG: Hop thread running\n");

	for(;;)
	{
		if(hoppingEnabled)
		{
			printf("ARG: Updating local IPs\n");

			
			pthread_spin_lock(&gateInfo->lock);
			update_ips(gateInfo);
			pthread_spin_unlock(&gateInfo->lock);
		
			// Apply to the network card
			//set_external_ip(gateInfo->currIP);
		}
		
		usleep(1000 * gateInfo->hopInterval);
	}
	
	printf("ARG: Hop thread dying\n");

	return 0;
}

struct arg_network_info *create_arg_network_info(void)
{
	struct arg_network_info *newInfo = NULL;

	newInfo = (struct arg_network_info*)malloc(sizeof(struct arg_network_info));
	if(newInfo == NULL)
	{
		printf("ARG: Unable to allocate space for ARG network info\n");
		return NULL;
	}

	// Clear it all out
	memset(newInfo, 0, sizeof(struct arg_network_info));
	
	// Init lock
	pthread_spin_init(&newInfo->lock, PTHREAD_PROCESS_SHARED);
	
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

	// Free us
	free(network);

	return next;
}

void remove_all_associated_arg_networks(void)
{
	printf("ARG: Removing all associated ARG networks\n");

	if(gateInfo == NULL)
	{
		printf("ARG: Attempt to remove associated networks when hopper not initialized\n");
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
		printf("ARG: Unable to allocate space for saving off IP address.\n");
		return NULL;
	}

	pthread_spin_lock(&ipLock);
	memcpy(ipCopy, gateInfo->currIP, ADDR_SIZE);
	pthread_spin_unlock(&ipLock);

	return ipCopy;
}

char is_current_ip(uint8_t const *ip)
{
	char ret = 0;

	pthread_spin_lock(&gateInfo->lock);
	
	if(memcmp(ip, gateInfo->currIP, ADDR_SIZE) == 0)
		ret = 1;
	else if(memcmp(ip, gateInfo->prevIP, ADDR_SIZE) == 0)
		ret = 1;
	else
		ret = 0;
	
	pthread_spin_unlock(&gateInfo->lock);

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
	
	case ARG_CONN_REQ_MSG:
		process_arg_conn_req(gateInfo, srcGate, packet);
		break;

	case ARG_CONN_RESP_MSG:
		process_arg_conn_resp(gateInfo, srcGate, packet);
		break;

	default:
		printf("ARG: Unhandled message type seen (%i)\n", get_msg_type(packet->arg));
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

	// Is the cache out of date? If not, do nothing
	if(current_time_offset(&gate->ipCacheExpiration) < gate->hopInterval)
		return;

	// Copy in top part of address. baseIP has already been masked to
	// ensure it is zeros for the portion that changes, so we only have
	// to copy it in
	memcpy(ip, gate->baseIP, sizeof(gate->baseIP));

	// Apply random bits to remainder of IP. If we have fewer bits than
	// needed for the mask, the extra remain 0. Sorry
	bits = totp(gate->hopKey, sizeof(gate->hopKey), gate->hopInterval, current_time_offset(&gate->timeBase)); 

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

		// Update cache time. TBD this should probably technically be moved to update on a precise
		// time, not just hopInterval in the future
		current_time(&gate->ipCacheExpiration);
		time_plus(&gate->ipCacheExpiration, gate->hopInterval);
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
		printf("Unable to create socket to set external IP address\n");
		return;
	}
 
	// Get flags
	strncpy(ifr.ifr_name, EXT_DEV_NAME, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0)
	{
		printf("Unable to get flags to set external IP address\n");
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
			printf("External interface down, unable to set IP: %i\n", errno);
			return;
		}
	}
 
	sin.sin_family = AF_INET;
 
	memcpy(&sin.sin_addr.s_addr, addr, sizeof(sin.sin_addr.s_addr));
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));	
 
	// Set interface address
	if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0)
	{
		printf("Unable to set IP address on external interface\n");
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

