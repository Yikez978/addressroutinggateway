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
	__be16 port = 0;

	struct nat_entry_bucket *bucket = NULL;
	struct nat_entry *e = NULL;
	int key = 0;

	printk("ARG: inbound\n");
	
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
	printk("ARG: i dest port %i, src port %i\n", get_dest_port(skb), get_source_port(skb));
	key = create_nat_bucket_key(&iph->saddr, get_source_port(skb));
	HASH_FIND_INT(natTable, &key, bucket);

	if(bucket == NULL)
	{
		printk("ARG: Bucket reject: ");
		printPacketInfo(skb);
		printk("\n");

		printPacket(skb);

		print_nat_table();

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
		printk("ARG: Entry reject: ");
		printPacketInfo(skb);
		printk("\n");
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
	//e->lastUsed = time();

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

	printk("ARG: outbound\n");

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
	printk("ARG: dest port %i, src port %i\n", get_dest_port(skb), get_source_port(skb));
	key = create_nat_bucket_key(&iph->daddr, get_dest_port(skb));
	HASH_FIND_INT(natTable, &key, bucket);

	if(bucket == NULL)
	{
		bucket = create_nat_bucket(skb, key);
		printPacketInfo(skb);
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
	printk(":%i", entry->gatePort);
}

struct nat_entry_bucket *create_nat_bucket(const struct sk_buff *skb, const int key)
{
	struct iphdr *iph = ip_hdr(skb);
	struct nat_entry_bucket *bucket = NULL;

	printk("ARG: creating new bucket for key %i: ", key);
	
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

	// Are we getting the wrong port number?
	printk("ARG: NEW BUCKET DATA (port num %i):\n", bucket->extPort);
	printPacket(skb);

	// Debug data
	print_nat_bucket(bucket);
	printk("\n");

	// Add new bucket
	HASH_ADD_INT(natTable, key, bucket);

	return bucket;
}

struct nat_entry *create_nat_entry(const struct sk_buff *skb, struct nat_entry_bucket *bucket)
{
	struct iphdr *iph = ip_hdr(skb);
	struct nat_entry *e = NULL;
	struct nat_entry *oldHead = NULL;

	// Create new entry
	printk("ARG: creating new entry: ");
	
	e = (struct nat_entry*)kmalloc(sizeof(struct nat_entry), GFP_KERNEL);
	if(e == NULL)
	{
		printk("ARG: Unable to allocate space for new NAT entry\n");
		return NULL;
	}

	// Fill in data
	memcpy(e->intIP, (void*)&iph->saddr, ADDR_SIZE);
	memcpy(e->gateIP, (void*)&iph->saddr, ADDR_SIZE); // TBD real gateway IP
	e->intPort = get_source_port(skb);
	e->gatePort = e->intPort; // TBD random port
	e->proto = iph->protocol;

	// Debug data
	print_nat_entry(e);
	printk("\n");

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

int create_nat_bucket_key(const void *ip, const __be16 port)
{
	int key;
	memcpy(&key, ip, ADDR_SIZE);
	key ^= port;
	
	printk("ARG: making key from ip:");
	printIP(ADDR_SIZE, ip);
	printk(" port:%i = %i\n", port, key);

	return key;
}

void clean_nat_table(void)
{
	// Find entries older than X and remove
}

