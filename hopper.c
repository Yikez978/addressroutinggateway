#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>

#include "hopper.h"
#include "utility.h"

/**************************
IP Hopping data
**************************/
static char hoppingEnabled = 0;

static uchar currIP[ADDR_SIZE];
static uchar prevIP[ADDR_SIZE];

static struct net_device *intDev = NULL;
static struct net_device *extDev = NULL;

char init_hopper(void)
{
	printk("ARG: hopper init");

	// Grab devices 
	extDev = dev_get_by_name(&init_net, EXT_DEV_NAME);
	if(extDev == NULL)
	{
		uninit_hopper();

		printk(KERN_ALERT "ARG: Unable to find external network device %s\n", EXT_DEV_NAME);
		return 0;
	}

	intDev = dev_get_by_name(&init_net, INT_DEV_NAME);
	if(intDev == NULL)
	{
		uninit_hopper();

		printk(KERN_ALERT "ARG: Unable to find internal network device %s\n", INT_DEV_NAME);
		return 0;
	}

	
	memmove(currIP, "abcd", ADDR_SIZE);
	memmove(prevIP, "\xC0\xA8\x01\x83", ADDR_SIZE);
	
	// And allow hopping now
	enable_hopping();

	return 1;
}

void uninit_hopper(void)
{
	// Disable hopping
	disable_hopping();

	// Remove references to devices
	if(extDev != NULL)
		dev_put(extDev);
	if(intDev != NULL)
		dev_put(intDev);
	extDev = NULL;
	intDev = NULL;
}

void enable_hopping(void)
{
	hoppingEnabled = 1;
}

void disable_hopping(void)
{
	hoppingEnabled = 0;
}

uchar const *current_ip(void)
{
	return currIP;
}

char is_current_ip(uchar const *ip)
{
	if(memcmp(ip, currIP, ADDR_SIZE) == 0)
		return 1;
	else if(memcmp(ip, prevIP, ADDR_SIZE) == 0)
		return 1;
	else
		return 0;
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

int get_arg_id(uchar const *ip)
{
	return -1;
}

char is_arg_ip(uchar const *ip)
{
	return get_arg_id(ip) >= 0;
}

