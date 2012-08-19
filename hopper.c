#include <linux/kernel.h>
#include <linux/module.h>

#include "hopper.h"
#include "utility.h"

/**************************
IP Hopping data
**************************/
static uchar currIP[ADDR_SIZE];
static uchar prevIP[ADDR_SIZE];

void init_hopper(void)
{
	printk("ARG: hopper init");
	
	memmove(currIP, "abcd", ADDR_SIZE);
	memmove(prevIP, "\xC0\xA8\x01\x83", ADDR_SIZE);
	
	printRaw(ADDR_SIZE, currIP);
	printRaw(ADDR_SIZE, prevIP);
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

int get_arg_id(uchar const *ip)
{
	// Pretend it's always someone
	return 1;
}

char is_arg_ip(uchar const *ip)
{
	return get_arg_id(ip) >= 0;
}

