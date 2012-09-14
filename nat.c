#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/delay.h>

#include "nat.h"
#include "hopper.h"
#include "uthash.h"

/**********************
NAT table data
**********************/
static struct nat_entry_bucket *natTable = NULL;
static rwlock_t natTableLock;

static struct timer_list natCleanupTimer;

void init_nat_locks(void)
{
	natTableLock = __RW_LOCK_UNLOCKED(natTableLock);
}

char init_nat(void)
{
	printk("ARG: NAT init\n");

	// Ensure the NAT table is empty and allow it to start its
	// periodic cleanup timer
	nat_timed_cleanup(0);

	printk("ARG: NAT initialized\n");

	return 1;
}

void uninit_nat(void)
{
	printk("ARG: NAT uninit\n");

	del_timer(&natCleanupTimer);

	empty_nat_table();
	
	printk("ARG: NAT finished\n");
}

char do_nat_inbound_rewrite(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	__be16 port = 0;
	
	struct nat_entry_bucket *bucket = NULL;
	struct nat_entry *e = NULL;
	int key = 0;

	//printk("ARG: inbound\n");
	
	if((void*)iph == (void*)tcp_hdr(skb))
		printk("ARG: BROKEN indeed\n");

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
	key = create_nat_bucket_key(&iph->saddr, get_source_port(skb));
	HASH_FIND_INT(natTable, &key, bucket);

	if(bucket == NULL)
	{
		read_unlock(&natTableLock);
		return 0;
	}

	// Have the correct bucket, now find the entry in the attached list 
	// that has the correct gateway IP address
	port = get_dest_port(skb);
	e = bucket->first;
	while(e != NULL
		&& (iph->protocol != e->proto
		|| port != e->gatePort
		|| memcmp((void*)&iph->daddr, e->gateIP, ADDR_SIZE) != 0))
	{
		e = e->next;
	}

	if(e == NULL)
	{
		read_unlock(&natTableLock);
		return 0;
	}

	// Sanity check
	if(e->gatePort != get_dest_port(skb))
	{
		printk("ARG: DEST PORT DOES NOT MATCH\n");
	}
	if(e->proto != iph->protocol)
	{
		printk("ARG: PROTOCOL DOES NOT MATCH\n");
	}
	if(memcmp((void*)&iph->daddr, e->gateIP, ADDR_SIZE) != 0)
	{
		printk("ARG: ADDR DOES NOT MATCH\n");
	}
	
	// Change destination addr to the correct internal IP and port
	memcpy((void*)&iph->daddr, e->intIP, ADDR_SIZE);
	set_dest_port(skb, e->intPort);

	// Re-checksum
	ip_send_check(iph);

	// Note that the entry has been used
	update_nat_entry_time(e);

	// Unlock
	read_unlock(&natTableLock);

	return 1;
}

char do_nat_outbound_rewrite(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	__be16 port = 0;

	struct nat_entry_bucket *bucket = NULL;
	struct nat_entry *e = NULL;
	int key = 0;

	//printk("ARG: outbound\n");

	// Safety check. For now we're only going ipv4
	if(iph->version != 4)
	{
		printk("ARG: IPv6 packet found, not allowed currently\n");
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
	key = create_nat_bucket_key(&iph->daddr, get_dest_port(skb));
	HASH_FIND_INT(natTable, &key, bucket);

	if(bucket == NULL)
	{
		bucket = create_nat_bucket(skb, key);
		if(bucket == NULL)
		{
			write_unlock(&natTableLock);
			return 0;
		}
	}

	// Have the correct bucket, now find the entry in the attached list 
	// that has the correct internal IP address
	port = get_source_port(skb);
	e = bucket->first;
	while(e != NULL
		&& (iph->protocol != e->proto
		|| port != e->intPort
		|| memcmp((void*)&iph->saddr, e->intIP, ADDR_SIZE) != 0))
	{
		e = e->next;
	}

	if(e == NULL)
	{
		e = create_nat_entry(skb, bucket);
		if(e == NULL)
		{
			write_unlock(&natTableLock);
			return 0;
		}
	}
	
	// Sanity check
	if(e->intPort != get_source_port(skb))
	{
		printk("ARG: SOURCE PORT DOES NOT MATCH\n");
	}
	if(e->proto != iph->protocol)
	{
		printk("ARG: PROTOCOL DOES NOT MATCH\n");
	}
	if(memcmp((void*)&iph->saddr, e->intIP, ADDR_SIZE) != 0)
	{
		printk("ARG: ADDR DOES NOT MATCH\n");
	}
	
	// Change source addr to the correct external IP and port
	memcpy((void*)&iph->saddr, e->gateIP, ADDR_SIZE);
	set_source_port(skb, e->gatePort);

	// Re-checksum
	ip_send_check(iph);

	// Note that the entry has been used
	update_nat_entry_time(e);

	// Unlock
	write_unlock(&natTableLock);

	return 1;
}

void print_nat_table(void)
{
	struct nat_entry_bucket *b = natTable;
	struct nat_entry *e = NULL;

	printk("ARG: NAT Table:\n");
	while(b != NULL)
	{
		printk("ARG:  Bucket: ");
		print_nat_bucket(b);
		printk("\n");

		e = b->first;
		while(e != NULL)
		{
			printk("ARG:   Entry: ");
			print_nat_entry(e);
			printk("\n");

			e = e->next;
		}
		
		b = (struct nat_entry_bucket*)(b->hh.next);
	}
}

void print_nat_bucket(const struct nat_entry_bucket *bucket)
{
	printk("k:%i e:", bucket->key);
	printIP(ADDR_SIZE, bucket->extIP);
	printk(":%i", bucket->extPort);
}

void print_nat_entry(const struct nat_entry *entry)
{
	printk("i:");
	printIP(ADDR_SIZE, entry->intIP);
	printk(":%i g:", entry->intPort);
	printIP(ADDR_SIZE, entry->gateIP);
	printk(":%i (lu %li)", entry->gatePort, (long)entry->lastUsed);
}

struct nat_entry_bucket *create_nat_bucket(const struct sk_buff *skb, const int key)
{
	struct iphdr *iph = ip_hdr(skb);
	struct nat_entry_bucket *bucket = NULL;

	// Create new bucket
	bucket = (nat_entry_bucket*)kmalloc(sizeof(struct nat_entry_bucket), GFP_KERNEL);
	if(bucket == NULL)
	{
		printk("ARG: Unable to allocate space for new NAT bucket\n");
		return NULL;
	}

	bucket->key = key;
	memcpy(bucket->extIP, (void*)&iph->daddr, ADDR_SIZE);
	bucket->first = NULL;
	bucket->extPort = get_dest_port(skb);

	// Add new bucket
	HASH_ADD_INT(natTable, key, bucket);

	return bucket;
}

struct nat_entry *create_nat_entry(const struct sk_buff *skb, struct nat_entry_bucket *bucket)
{
	struct iphdr *iph = ip_hdr(skb);
	struct nat_entry *e = NULL;
	struct nat_entry *oldHead = NULL;

	uchar *currIP = NULL;

	e = (struct nat_entry*)kmalloc(sizeof(struct nat_entry), GFP_KERNEL);
	if(e == NULL)
	{
		printk("ARG: Unable to allocate space for new NAT entry\n");
		return NULL;
	}

	// Fill in data
	memcpy(e->intIP, &iph->saddr, ADDR_SIZE);

	currIP = current_ip();
	if(currIP == NULL)
	{
		printk("ARG: Unable to complete creation of new NAT entry, out of memory\n");
		kfree(e);
		return NULL;
	}
	memcpy(e->gateIP, currIP, ADDR_SIZE);
	kfree(currIP);

	e->intPort = get_source_port(skb);
	e->gatePort = e->intPort; // TBD random port
	e->proto = iph->protocol;

	// Insert as head of bucket, pointing to the old head
	oldHead = bucket->first;
	bucket->first = e;
	e->next = oldHead;

	if(oldHead != NULL)
		oldHead->prev = e;
	
	e->bucket = bucket;
	e->prev = NULL;

	return e;
}

void update_nat_entry_time(struct nat_entry *e)
{
	struct timespec ts;
	getnstimeofday(&ts);
	e->lastUsed = ts.tv_sec;
}

int create_nat_bucket_key(const void *ip, const __be16 port)
{
	int key;
	memcpy(&key, ip, ADDR_SIZE);
	key ^= port;
	
	return key;
}

void empty_nat_table(void)
{
	struct nat_entry_bucket *b = natTable;
	
	write_lock(&natTableLock);
	
	while(b != NULL)
		b = remove_nat_bucket(b);
	
	write_unlock(&natTableLock);
}

struct nat_entry_bucket *remove_nat_bucket(struct nat_entry_bucket *bucket)
{
	// Save next bucket
	struct nat_entry_bucket *next = (struct nat_entry_bucket*)bucket->hh.next;

	struct nat_entry *e = NULL;

	// Remove all entries in bucket first
	e = bucket->first;
	while(e != NULL)
		e = remove_nat_entry(e);

	// And kill the bucket
	HASH_DEL(natTable, bucket);
	kfree(bucket);

	return next;
}

struct nat_entry *remove_nat_entry(struct nat_entry *e)
{
	// Save our next spot
	struct nat_entry *next = e->next;

	// Hook the entries on either side of us together
	if(e->prev != NULL)
		e->prev->next = e->next;
	if(e->next != NULL)
		e->next->prev = e->prev;

	// Ensure there isn't a bucket pointing to us
	if(e->bucket != NULL && e->bucket->first == e)
	{
		if(e->next != NULL)
			e->bucket->first = e->next;
		else
			e->bucket->first = NULL;
	}
	
	// And kill us off
	kfree(e);

	return next;
}

void nat_timed_cleanup(unsigned long data)
{
	clean_nat_table();
	
	read_lock(&natTableLock);
	print_nat_table();
	read_unlock(&natTableLock);

	// Put ourselves back in the queue
	init_timer(&natCleanupTimer);
	natCleanupTimer.expires = jiffies + NAT_CLEAN_TIME * HZ;
	natCleanupTimer.function = &nat_timed_cleanup;
	add_timer(&natCleanupTimer);
}

void clean_nat_table(void)
{
	struct timespec ts;

	struct nat_entry_bucket *b = natTable;
	struct nat_entry *e = NULL;

	// Get current time and give connections 120 seconds with no activity
	getnstimeofday(&ts);
	ts.tv_sec -= NAT_OLD_CONN_TIME;

	write_lock(&natTableLock);

	while(b != NULL)
	{
		e = b->first;
		while(e != NULL)
		{
			// Is this connection too old?
			if(e->lastUsed < ts.tv_sec)
				e = remove_nat_entry(e);
			else
				e = e->next;
		}
	
		// We could remove empty buckets here, but I doubt it matters
		// (empty buckets have b->first == NULL
		if(b->first == NULL)
			b = remove_nat_bucket(b);
		else
			b = (struct nat_entry_bucket*)b->hh.next;
	}

	write_unlock(&natTableLock);
}

