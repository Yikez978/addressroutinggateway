#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/spinlock.h>

#include "nat.h"
#include "hopper.h"
#include "uthash.h"

/**********************
NAT table data
**********************/
static struct nat_entry_bucket *natTable = NULL;
static rwlock_t natTableLock;

void init_nat(void)
{
	natTableLock = __RW_LOCK_UNLOCKED(natTableLock);
}

char do_nat_inbound_rewrite(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	
	struct nat_entry_bucket *bucket = NULL;
	struct nat_entry *e = NULL;
	int key = 0;
	
	// Safety check. For now we're only going ipv4
	if(iph->version != 4)
	{
		printk("ARG: IPv6 packet found, not allowed current\n");
		return 0;
	}

	// Read lock!
	read_lock(&natTableLock);

	// Find entry in table by finding the bucket then
	// searching through the associated list
	key = iph->saddr;
	HASH_FIND_INT(natTable, &key, bucket);

	if(bucket == NULL)
	{
		read_unlock(&natTableLock);
		return 0;
	}

	// Have the correct bucket, now find the entry in the attached list 
	// that has the correct gateway IP address
	e = bucket->first;
	while(e != NULL && memcmp((void*)&iph->daddr, e->gateIP, ADDR_SIZE) != 0)
	{
		e = e->next;
	}

	if(e == NULL)
	{
		read_unlock(&natTableLock);
		return 0;
	}

	// Change destination addr to the correct internal IP and port
	memcpy((void*)&iph->daddr, e->intIP, ADDR_SIZE);

	// Re-checksum
	ip_send_check(iph);

	// Note that the entry has been used
	//e->lastUsed = time();

	// Unlock
	read_unlock(&natTableLock);

	return 1;
}

char do_nat_outbound_rewrite(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	
	struct nat_entry_bucket *bucket = NULL;
	struct nat_entry *oldHead = NULL;
	struct nat_entry *e = NULL;
	int key = 0;

	// Safety check. For now we're only going ipv4
	if(iph->version != 4)
	{
		printk("ARG: IPv6 packet found, not allowed current\n");
		return 0;
	}

	// Write lock for now, just to be fully safe.
	// TBD it may be possible to read lock and only write lock
	// when creating new entries. Just have to ensure all readers
	// are out of that bucket/entry list. However, straight reader
	// locks won't work for this, you can't aquire the writer lock from
	// a reader
	write_lock(&natTableLock);
	
	// Find entry in table by finding the bucket then
	// searching through the associated list
	key = iph->daddr;
	HASH_FIND_INT(natTable, &key, bucket);

	if(bucket == NULL)
	{
		printk("ARG: creating new bucket for key %i\n", key);
		
		// Create new bucket
		bucket = (nat_entry_bucket*)kmalloc(sizeof(struct nat_entry_bucket), GFP_KERNEL);
		if(bucket == NULL)
		{
			printk("ARG: Unable to allocate space for new NAT bucket\n");
			write_unlock(&natTableLock);
			return 0;
		}

		bucket->key = key;
		memcpy(bucket->extIP, (void*)&iph->daddr, ADDR_SIZE);
		bucket->first = NULL;

		// Find port numbers for appropriate protocol
		switch(iph->protocol)
		{
		case ICMP_PROTO:
			break;
		
		case TCP_PROTO:
			tcph = tcp_hdr(skb);
			bucket->extPort = (tcph->dest);
			break;

		case UDP_PROTO:
			udph = udp_hdr(skb);
			bucket->extPort = (udph->dest);
			break;

		default:
			printk("ARG: Unsupported protocol (%i) seen outgoing\n", iph->protocol);
			write_unlock(&natTableLock);
			return 0;
		}

		// Add new bucket
		HASH_ADD_INT(natTable, key, bucket);
	}

	// Have the correct bucket, now find the entry in the attached list 
	// that has the correct internal IP address
	e = bucket->first;
	while(e != NULL && memcmp((void*)&iph->saddr, e->intIP, ADDR_SIZE) != 0)
	{
		e = e->next;
	}

	if(e == NULL)
	{
		// Create new entry
		printk("ARG: creating new entry\n");
		
		e = (struct nat_entry*)kmalloc(sizeof(struct nat_entry), GFP_KERNEL);
		if(e == NULL)
		{
			printk("ARG: Unable to allocate space for new NAT entry\n");
			write_unlock(&natTableLock);
			return 0;
		}

		// Fill in data
		memcpy(e->intIP, (void*)&iph->saddr, ADDR_SIZE);
		memcpy(e->gateIP, (void*)&iph->saddr, ADDR_SIZE); // TBD real gateway IP

		// Find port numbers for appropriate protocol
		switch(iph->protocol)
		{
		case ICMP_PROTO:
			break;
		
		case TCP_PROTO:
			tcph = tcp_hdr(skb);
			e->intPort = (tcph->source);
			e->gatePort = (tcph->source); 
			break;

		case UDP_PROTO:
			udph = udp_hdr(skb);
			e->intPort = (udph->source);
			e->gatePort = (udph->source); 
			break;

		default:
			printk("ARG: Unsupported protocol (%i) seen outgoing\n", iph->protocol);
			write_unlock(&natTableLock);
			return 0;
		}

		// Insert as head of bucket, pointing to the old head
		oldHead = bucket->first;
		bucket->first = e;
		e->next = oldHead;
	}

	// Change source addr to the correct external IP and port
	memcpy((void*)&iph->saddr, e->gateIP, ADDR_SIZE);

	switch(iph->protocol)
	{
	case ICMP_PROTO:
		break;

	case TCP_PROTO:
		tcph = tcp_hdr(skb);
		tcph->source = e->gatePort;
		break;

	case UDP_PROTO:
		udph = udp_hdr(skb);
		udph->source = e->gatePort;
		break;

	default:
		printk("ARG: Unsupported protocol (%i) seen outgoing\n", iph->protocol);
		write_unlock(&natTableLock);
		return 0;
	}

	// Re-checksum
	ip_send_check(iph);

	// Note that the entry has been used

	// Unlock
	write_unlock(&natTableLock);

	return 1;
}

void clean_nat_table(void)
{
	// Find entries older than X and remove
}

