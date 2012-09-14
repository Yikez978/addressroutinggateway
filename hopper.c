#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/crypto.h>

#include "settings.h"
#include "hopper.h"
#include "utility.h"
#include "crypto.h"

/**************************
IP Hopping data
**************************/
static rwlock_t networksLock;
static arg_network_info *gateInfo = NULL; 

// In a full implementation, we would use public and private keys for authentication
// and initial connection to other gateways. For the test implementation, we used a
// globally shared key for HMACs, rather than digital signatures
static const uchar argGlobalKey[AES_KEY_SIZE] = {25, -18, -127, -10,
												 67, 30, 7, -49,
												 68, -70, 19, 106,
												 -100, -11, 72, 18};

static char hoppingEnabled = 0;

static rwlock_t ipLock;

static struct net_device *intDev = NULL;
static struct net_device *extDev = NULL;

static struct timer_list hopTimer;

void init_hopper_locks(void)
{
	ipLock = __RW_LOCK_UNLOCKED(ipLock);
	networksLock = __RW_LOCK_UNLOCKED(networksLock);
}

char init_hopper(void)
{
	printk("ARG: Hopper init\n");
	
	write_lock(&networksLock);
	write_lock(&ipLock);
	
	// "Read in" settings
	if(!get_hopper_conf())
	{
		printk(KERN_ALERT "ARG: Unable to configure hopper\n");
		
		write_unlock(&ipLock);
		write_unlock(&networksLock);
		uninit_hopper();

		return 0;
	}

	printk("ARG: External IP: ");
	printIP(ADDR_SIZE, gateInfo->currIP);
	printk("\n");

	// Enable promisc and/or forwarding?
	printk("ARG: Enabling promiscuous mode\n");
	rtnl_lock();
	dev_set_promiscuity(extDev, 1);
	rtnl_unlock();
	
	write_unlock(&ipLock);
	write_unlock(&networksLock);
	
	// And allow hopping now
	timed_hop(0);
	enable_hopping();
	
	printk("ARG: Hopper initialized\n");

	return 1;
}

void uninit_hopper(void)
{
	printk("ARG: Hopper uninit\n");

	// Disable hopping
	disable_hopping();
	
	write_lock(&networksLock);
	write_lock(&ipLock);
	
	// Turn off promiscuity
	if(extDev != NULL)
	{
		printk("ARG: Dropping promiscuous mode\n");
		rtnl_lock();
		dev_set_promiscuity(extDev, -1);
		rtnl_unlock();
	}

	// Remove references to devices
	if(extDev != NULL)
	{
		dev_put(extDev);
		extDev = NULL;
	}
	if(intDev != NULL)
	{
		dev_put(intDev);
		intDev = NULL;
	}

	// Remove our own information
	if(gateInfo != NULL)
	{
		remove_all_associated_arg_networks();

		kfree(gateInfo);
		gateInfo = NULL;
	}
	
	write_unlock(&ipLock);
	write_unlock(&networksLock);

	printk("ARG: Hopper finished\n");
}

char get_hopper_conf(void)
{
	struct arg_network_info *currNet = NULL;
	struct arg_network_info *prevNet = NULL;

	// TBD this is all hardcoded. Ideally this comes from a conf file or something
	// Create ARG gateway info for each gateway in the network, then select
	// the correct one to be the head for the current gateway
	// Gate A
	currNet = create_arg_network_info();
	gateInfo = currNet;
	if(currNet == NULL)
		return 0;

	strncpy(currNet->name, "GateA", sizeof(currNet->name));
	currNet->baseIP[0] = 10;
	currNet->baseIP[1] = 2;
	currNet->baseIP[2] = 0;
	currNet->baseIP[3] = 0;
	currNet->mask[0] = 0xFF;
	currNet->mask[1] = 0xFF;
	currNet->mask[2] = 0xFF;
	currNet->mask[3] = 0x00;

	// Gate B
	prevNet = currNet;
	currNet = create_arg_network_info();
	if(currNet == NULL)
		return 0;

	strncpy(currNet->name, "GateB", sizeof(currNet->name));
	currNet->baseIP[0] = 10;
	currNet->baseIP[1] = 1;
	currNet->baseIP[2] = 0;
	currNet->baseIP[3] = 0;
	currNet->mask[0] = 0xFF;
	currNet->mask[1] = 0xFF;
	currNet->mask[2] = 0xFF;
	currNet->mask[3] = 0x00;

	prevNet->next = currNet;
	currNet->prev = prevNet;

	// Grab devices 
	extDev = dev_get_by_name(&init_net, EXT_DEV_NAME);
	if(extDev == NULL)
	{
		printk(KERN_ALERT "ARG: Unable to find external network device %s\n", EXT_DEV_NAME);
		return 0;
	}

	intDev = dev_get_by_name(&init_net, INT_DEV_NAME);
	if(intDev == NULL)
	{
		printk(KERN_ALERT "ARG: Unable to find internal network device %s\n", INT_DEV_NAME);
		return 0;
	}

	// Which one is our head? Find it, move to beginning, and rearrange
	// all relevant pointers. We find based on which masked IP in the list matches
	// our masked external IP
	currNet = gateInfo;
	while(currNet != NULL)
	{
		printk("ARG: Checking if %s (base IP ", currNet->name);
		printIP(sizeof(currNet->baseIP), currNet->baseIP);
		printk(")\n");
	
		if(mask_array_cmp(ADDR_SIZE, currNet->mask,
			currNet->baseIP,
			&extDev->ip_ptr->ifa_list->ifa_address) == 0)
		{
			printk("ARG: We are %s!\n", currNet->name);
			
			// Found, make currNet the head of list (if not already)
			if(currNet != gateInfo)
			{
				printk("ARG: Rearranging ARG network list\n");

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
		printk(KERN_ALERT "ARG: Misconfiguration, unable to find which gate we are\n");
		return 0;
	}

	printk("ARG: Configured as %s\n", gateInfo->name);

	// Hop and symmetric key
	printk("ARG: Generating hop and symmetric encryption keys\n");
	get_random_bytes(gateInfo->hopKey, sizeof(gateInfo->hopKey));
	get_random_bytes(gateInfo->symKey, sizeof(gateInfo->symKey));
	
	// Set IP based on configuration
	printk("ARG: Setting initial IP\n");
	memmove(gateInfo->mask, &extDev->ip_ptr->ifa_list->ifa_mask, sizeof(gateInfo->mask));
	update_ips();

	return 1;
}

void enable_hopping(void)
{
	printk("ARG: Hopping enabled\n");
	hoppingEnabled = 1;
}

void disable_hopping(void)
{
	printk("ARG: Hopping disabled\n");
	hoppingEnabled = 0;
}

void timed_hop(unsigned long data)
{
	if(hoppingEnabled)
	{
		update_ips();
	}

	// Regardless, reset timer. We choose to always have the hop timer running
	// to eliminate the overhead of having it happen from being a difference in
	// hopping verses not. TBD: Maybe that's a bad choice.
	init_timer(&hopTimer);
	hopTimer.expires = jiffies + HOP_TIME * HZ / 1000;
	hopTimer.function = &timed_hop;
	add_timer(&hopTimer);
}

struct arg_network_info *create_arg_network_info(void)
{
	struct arg_network_info *newInfo = NULL;

	newInfo = (struct arg_network_info*)kmalloc(sizeof(struct arg_network_info), GFP_KERNEL);
	if(newInfo == NULL)
	{
		printk("ARG: Unable to allocate space for ARG network info\n");
		return NULL;
	}

	// Clear it all out
	memset(newInfo, 0, sizeof(struct arg_network_info));
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
	kfree(network);

	return next;
}

void remove_all_associated_arg_networks(void)
{
	printk("ARG: Removing all associated ARG networks\n");

	if(gateInfo == NULL)
	{
		printk("ARG: Attempt to remove associated networks when hopper not initialized\n");
		return;
	}

	// Just keep removing our next network until there are no more
	// Note that we don't remove ourselves
	while(gateInfo->next != NULL)
		remove_arg_network(gateInfo->next);
}

void update_ips(void)
{
	char hmac[HMAC_SIZE];
	char pass[] = "22";
	char key[] = "passphrase";

	// Backup old address and generate a new one
	memmove(gateInfo->prevIP, gateInfo->currIP, sizeof(gateInfo->prevIP));
	
	printk("ARG: generating new address\n");
	hmac_sha1(key, strlen(key), pass, strlen(pass), hmac);

	// Apply to the network card
	memmove(&extDev->ip_ptr->ifa_list->ifa_address, gateInfo->currIP, sizeof(gateInfo->currIP));
}

uchar *current_ip(void)
{
	uchar *ipCopy = NULL;

	ipCopy = (uchar*)kmalloc(ADDR_SIZE, GFP_ATOMIC);
	if(ipCopy == NULL)
	{
		printk("ARG: Unable to allocate space for saving off IP address.\n");
		return NULL;
	}

	read_lock(&ipLock);
	memmove(ipCopy, gateInfo->currIP, ADDR_SIZE);
	read_unlock(&ipLock);

	return ipCopy;
}

char is_current_ip(uchar const *ip)
{
	char ret = 0;

	read_lock(&ipLock);
	
	if(memcmp(ip, gateInfo->currIP, ADDR_SIZE) == 0)
		ret = 1;
	else if(memcmp(ip, gateInfo->prevIP, ADDR_SIZE) == 0)
		ret = 1;
	else
		ret = 0;
	
	read_unlock(&ipLock);

	return ret;
}

void set_external_ip(uchar *addr)
{
	struct in_ifaddr *ifa = extDev->ip_ptr->ifa_list;
	
	// Rotate internal IPs
	write_lock(&ipLock);
	memmove(gateInfo->prevIP, gateInfo->currIP, ADDR_SIZE);
	memmove(gateInfo->currIP, addr, ADDR_SIZE);
	write_unlock(&ipLock);

	// Set physical card
	rtnl_lock();
	memmove(&ifa->ifa_address, addr, ADDR_SIZE);
	ifa->ifa_local = ifa->ifa_address;
	rtnl_unlock();
}

char is_admin_packet(struct sk_buff const *skb)
{
	return 0;
}

char is_signature_valid(struct sk_buff const *skb)
{
	return 1;
}

char do_arg_wrap(struct sk_buff *skb)
{
	return 1;
}

char do_arg_unwrap(struct sk_buff *skb)
{
	return 1;
}

struct arg_network_info *get_arg_network(void const *ip)
{
	return 0;
}

char is_arg_ip(void const *ip)
{
	return get_arg_network(ip) != NULL;
}

