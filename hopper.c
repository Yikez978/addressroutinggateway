#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>

#include "settings.h"
#include "hopper.h"
#include "utility.h"
#include "crypto.h"

/**************************
IP Hopping data
**************************/
static arg_network_info *gateInfo = NULL;
static rwlock_t networksLock;

static char hoppingEnabled = 0;

static rwlock_t ipLock;

static struct net_device *intDev = NULL;
static struct net_device *extDev = NULL;

static struct task_struct *connectThread = NULL;
static struct task_struct *hopThread = NULL;

void init_hopper_locks(void)
{
	ipLock = __RW_LOCK_UNLOCKED(ipLock);
	networksLock = __RW_LOCK_UNLOCKED(networksLock);
}

char init_hopper(void)
{
	printk("ARG: Hopper init\n");

	printk("ARG: Current jiffies: %li, jiffies/second: %i\n", jiffies, HZ);

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

	// Enable promisc and/or forwarding?
	printk("ARG: Enabling promiscuous mode\n");
	rtnl_lock();
	dev_set_promiscuity(extDev, 1);
	rtnl_unlock();
	
	write_unlock(&ipLock);
	write_unlock(&networksLock);
	
	// Allow hopping now
	printk("ARG: Starting hop thread\n");
	hopThread = kthread_run(timed_hop_thread, NULL, "hop thread");
	enable_hopping();
	
	printk("ARG: Hopper initialized\n");

	return 1;
}

void init_hopper_finish(void)
{
	printk("ARG: Starting connection/gateway auth thread\n");
	connectThread = kthread_run(connect_thread, NULL, "connect thread");
}

void uninit_hopper(void)
{
	printk("ARG: Hopper uninit\n");

	// Disable hopping
	disable_hopping();
	
	// No more need to hop and connect
	// TBD isnt't there a possibility of something bad happening if we del_timer while in
	// the timer? IE, it will reregister and then everything will die
	if(hopThread != NULL)
	{
		printk("ARG: Asking hop thread to stop...");
		kthread_stop(hopThread);
		hopThread = NULL;
		printk("done\n");
	}
	if(connectThread != NULL)
	{
		printk("ARG: Asking connect thread to stop...");
		kthread_stop(connectThread);
		connectThread = NULL;
		printk("done\n");
	}
	
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
	currNet->baseIP[0] = 172;
	currNet->baseIP[1] = 1;
	currNet->baseIP[2] = 0;
	currNet->baseIP[3] = 1;
	currNet->mask[0] = 0xFF;
	currNet->mask[1] = 0xFF;
	currNet->mask[2] = 0x00;
	currNet->mask[3] = 0x00;

	// Gate B
	prevNet = currNet;
	currNet = create_arg_network_info();
	if(currNet == NULL)
		return 0;

	strncpy(currNet->name, "GateB", sizeof(currNet->name));
	currNet->baseIP[0] = 172;
	currNet->baseIP[1] = 2;
	currNet->baseIP[2] = 0;
	currNet->baseIP[3] = 1;
	currNet->mask[0] = 0xFF;
	currNet->mask[1] = 0xFF;
	currNet->mask[2] = 0x00;
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

	// Rest of hop data
	gateInfo->timeBase = jiffies;
	gateInfo->hopInterval = (HOP_TIME * HZ) / 1000;

	// Set IP based on configuration
	printk("ARG: Setting initial IP\n");
	update_ips(gateInfo);

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

int connect_thread(void *data)
{
	struct arg_network_info *gate = NULL;

	printk("ARG: Connect thread running\n");

	while(!kthread_should_stop())
	{
		gate = gateInfo->next;
		while(gate != NULL)
		{
			if(!gate->connected)
			{
				printk("ARG: Attempting to connect to gateway at ");
				printIP(sizeof(gate->baseIP), gate->baseIP);
				printk("\n");

				start_connection(gateInfo, gate);
			}	

			// Next
			gate = gate->next;
		}

		schedule_timeout_interruptible(CONNECT_WAIT_TIME * HZ);
	}
	
	printk("ARG: Connect thread dying\n");

	return 0;
}

int timed_hop_thread(void *data)
{
	printk("ARG: Hop thread running\n");

	while(!kthread_should_stop())
	{
		if(hoppingEnabled)
		{
			printk("ARG: Updating local IPs\n");

			write_lock(&gateInfo->lock);
			update_ips(gateInfo);
			write_unlock(&gateInfo->lock);
		
			// Apply to the network card
			set_external_ip(gateInfo->currIP);
		}
		
		schedule_timeout_interruptible(gateInfo->hopInterval);
	}
	
	printk("ARG: Hop thread dying\n");

	return 0;
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
	
	// Init lock
	newInfo->lock = __RW_LOCK_UNLOCKED(newInfo->lock);
	
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

	read_lock(&gateInfo->lock);
	
	if(memcmp(ip, gateInfo->currIP, ADDR_SIZE) == 0)
		ret = 1;
	else if(memcmp(ip, gateInfo->prevIP, ADDR_SIZE) == 0)
		ret = 1;
	else
		ret = 0;
	
	read_unlock(&gateInfo->lock);

	return ret;
}

char process_admin_msg(struct sk_buff *skb, struct arg_network_info *srcGate, uchar *data, int dlen)
{
	switch(get_msg_type(data, dlen))
	{
	case ARG_PING_MSG:
		process_arg_ping(gateInfo, srcGate, data, dlen);
		break;

	case ARG_PONG_MSG:
		process_arg_pong(gateInfo, srcGate, data, dlen);
		break;
	
	case ARG_CONN_REQ_MSG:
		process_arg_conn_req(gateInfo, srcGate, data, dlen);
		break;

	case ARG_CONN_RESP_MSG:
		process_arg_conn_resp(gateInfo, data, dlen);
		break;
	
	case ARG_TIME_REQ_MSG:
		process_arg_time_req(gateInfo, srcGate, data, dlen);
		break;

	case ARG_TIME_RESP_MSG:
		process_arg_time_resp(gateInfo, data, dlen);
		break;

	default:
		printk(KERN_ALERT "ARG: Unhandled message type seen (%i)\n", get_msg_type(data, dlen));
		return 0;	
	}

	return 1;
}

void update_ips(struct arg_network_info *gate)
{
	int i = 0;
	uint32_t bits = 0;
	uchar *bitIndex = (uchar*)&bits;
	int minLen = 0;
	uchar ip[sizeof(gate->currIP)];

	// Is the cache out of date? If not, do nothing
	if(gate->ipCacheExpiration > jiffies)
		return;

	// Copy in top part of address. baseIP has already been masked to
	// ensure it is zeros for the portion that changes, so we only have
	// to copy it in
	memmove(ip, gate->baseIP, sizeof(gate->baseIP));

	// Apply random bits to remainder of IP. If we have fewer bits than
	// needed for the mask, the extra remain 0. Sorry
	bits = totp(gate->hopKey, sizeof(gate->hopKey), gate->hopInterval, jiffies - gate->timeBase); 

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
		memmove(gate->prevIP, gate->currIP, sizeof(gate->currIP));
		memmove(gate->currIP, ip, sizeof(gate->currIP));

		// Update cache time. TBD this should probably technically be moved to update on a precise
		// time, not just hopInterval in the future
		gate->ipCacheExpiration = jiffies + gate->hopInterval;
	}
}

void set_external_ip(uchar *addr)
{
	struct in_ifaddr *ifa = extDev->ip_ptr->ifa_list;

	// Set physical card
	rtnl_lock();
	memmove(&ifa->ifa_address, addr, ADDR_SIZE);
	ifa->ifa_local = ifa->ifa_address;
	rtnl_unlock();
}

char is_signature_valid(struct sk_buff const *skb)
{
	return 1;
}

char do_arg_wrap(struct sk_buff *skb, struct arg_network_info *gate)
{
	printk("ARG: Wrapping packet for transmission\n");

	printRaw(skb->data_len, skb->data);

	//send_arg_packet(gateInfo, gate, ARG_WRAPPED_MSG, skb->data, skb->data_len);

	return 1;
}

char do_arg_unwrap(const struct sk_buff *skb, struct arghdr *argh)
{
	return 1;
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

