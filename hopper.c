#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/spinlock.h>

#include "hopper.h"
#include "utility.h"

/**************************
IP Hopping data
**************************/
static rwlock_t ipLock;

static char hoppingEnabled = 0;

static uchar ipPrefixLen = 0;
static uchar ipMask[ADDR_SIZE];
static uchar currIP[ADDR_SIZE];
static uchar prevIP[ADDR_SIZE];

static struct net_device *intDev = NULL;
static struct net_device *extDev = NULL;

void init_hopper_locks(void)
{
	ipLock = __RW_LOCK_UNLOCKED(ipLock);
}

char init_hopper(void)
{
	printk("ARG: Hopper init\n");
	
	write_lock(&ipLock);

	// No matter what happens, make sure these are valid
	memset(currIP, 0, ADDR_SIZE);
	memset(prevIP, 0, ADDR_SIZE);

	// Grab devices 
	extDev = dev_get_by_name(&init_net, EXT_DEV_NAME);
	if(extDev == NULL)
	{
		printk(KERN_ALERT "ARG: Unable to find external network device %s\n", EXT_DEV_NAME);
		
		write_unlock(&ipLock);
		uninit_hopper();

		return 0;
	}

	intDev = dev_get_by_name(&init_net, INT_DEV_NAME);
	if(intDev == NULL)
	{
		printk(KERN_ALERT "ARG: Unable to find internal network device %s\n", INT_DEV_NAME);
		
		write_unlock(&ipLock);
		uninit_hopper();

		return 0;
	}

	// Pull data off external card (don't really care about the internal device)
	memmove(currIP, &extDev->ip_ptr->ifa_list->ifa_address, ADDR_SIZE);
	memmove(prevIP, currIP, ADDR_SIZE);
	memmove(ipMask, &extDev->ip_ptr->ifa_list->ifa_mask, ADDR_SIZE);
	ipPrefixLen = extDev->ip_ptr->ifa_list->ifa_prefixlen;

	printk("ARG: External IP: ");
	printIP(ADDR_SIZE, currIP);
	printk("/%i\n", ipPrefixLen);

	// Enable promisc and/or forwarding?
	printk("ARG: Enabling promiscuous mode\n");
	rtnl_lock();
	dev_set_promiscuity(extDev, 1);
	rtnl_unlock();

	write_unlock(&ipLock);
	
	// And allow hopping now
	enable_hopping();

	printk("ARG: Hopper initialized\n");

	return 1;
}

void uninit_hopper(void)
{
	printk("ARG: Hopper uninit\n");

	// Disable hopping
	disable_hopping();
	
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

	write_unlock(&ipLock);

	printk("ARG: Hopper finished\n");
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
	memmove(ipCopy, currIP, ADDR_SIZE);
	read_unlock(&ipLock);

	return ipCopy;
}

char is_current_ip(uchar const *ip)
{
	char ret = 0;

	read_lock(&ipLock);
	
	if(memcmp(ip, currIP, ADDR_SIZE) == 0)
		ret = 1;
	else if(memcmp(ip, prevIP, ADDR_SIZE) == 0)
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
	memmove(prevIP, currIP, ADDR_SIZE);
	memmove(currIP, addr, ADDR_SIZE);
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

int get_arg_id(void const *ip)
{
	return -1;
}

char is_arg_ip(void const *ip)
{
	return get_arg_id(ip) >= 0;
}

