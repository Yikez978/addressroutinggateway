#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <pthread.h>

#include "nat.h"
#include "hopper.h"
#include "uthash.h"

/**********************
NAT table data
**********************/
static struct nat_entry_bucket *natTable = NULL;
static pthread_spinlock_t natTableLock;

static pthread_t natCleanupThread;

void init_nat_locks(void)
{
	pthread_spin_init(&natTableLock, 0);
}

char init_nat(void)
{
	printf("ARG: NAT init\n");

	pthread_create(&natCleanupThread, NULL, nat_cleanup_thread, NULL);

	printf("ARG: NAT initialized\n");

	return 1;
}

void uninit_nat(void)
{
	printf("ARG: NAT uninit\n");
	
	if(natCleanupThread != 0)
	{
		printf("ARG: Asking NAT cleanup thread to stop...");
		pthread_cancel(natCleanupThread);
		pthread_join(natCleanupThread, NULL);
		natCleanupThread = 0;
		printf("done\n");
	}

	empty_nat_table();

	pthread_spin_destroy(&natTableLock);

	printf("ARG: NAT finished\n");
}

char do_nat_inbound_rewrite(const struct packet_data *packet)
{
	struct packet_data *newPacket = NULL;
	const struct iphdr *iph = packet->ipv4;
	
	uint16_t port = 0;
	
	struct nat_entry_bucket *bucket = NULL;
	struct nat_entry *e = NULL;
	int key = 0;

	// Read lock!
	pthread_spin_lock(&natTableLock);

	// Find entry in table by finding the bucket then
	// searching through the associated list
	key = create_nat_bucket_key(&iph->saddr, get_source_port(packet));
	HASH_FIND_INT(natTable, &key, bucket);

	if(bucket == NULL)
	{
		pthread_spin_unlock(&natTableLock);
		return -1;
	}

	// Have the correct bucket, now find the entry in the attached list 
	// that has the correct gateway IP address
	port = get_dest_port(packet);
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
		pthread_spin_unlock(&natTableLock);
		return -2;
	}
	
	// Note that the entry has been used
	update_nat_entry_time(e);

	pthread_spin_unlock(&natTableLock);

	// Change destination addr to the correct internal IP and port
	newPacket = copy_packet(packet);
	if(newPacket == NULL)
	{
		printf("Unable to rewrite packet\n");
		return -3;
	}

	memcpy((void*)&newPacket->ipv4->daddr, e->intIP, ADDR_SIZE);
	set_dest_port(newPacket, e->intPort);

	compute_packet_checksums(newPacket);

	// Send

	return 0;
}

char do_nat_outbound_rewrite(const struct packet_data *packet)
{
	struct packet_data *newPacket = NULL;
	const struct iphdr *iph = packet->ipv4;
	
	uint16_t port = 0;

	struct nat_entry_bucket *bucket = NULL;
	struct nat_entry *e = NULL;
	int key = 0;

	pthread_spin_lock(&natTableLock);
	
	// Find entry in table by finding the bucket then
	// searching through the associated list
	key = create_nat_bucket_key(&iph->daddr, get_dest_port(packet));
	HASH_FIND_INT(natTable, &key, bucket);

	if(bucket == NULL)
	{
		bucket = create_nat_bucket(packet, key);
		if(bucket == NULL)
		{
			pthread_spin_unlock(&natTableLock);
			return -1;
		}
	}

	// Have the correct bucket, now find the entry in the attached list 
	// that has the correct internal IP address
	port = get_source_port(packet);
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
		e = create_nat_entry(packet, bucket);
		if(e == NULL)
		{
			pthread_spin_unlock(&natTableLock);
			return -2;
		}
	}

	// Note that the entry has been used
	update_nat_entry_time(e);

	pthread_spin_unlock(&natTableLock);
	
	// Change source addr to the correct external IP and port
	newPacket = copy_packet(packet);
	if(newPacket == NULL)
	{
		printf("Unable to rewrite packet\n");
		return -3;
	}
	
	memcpy((void*)&newPacket->ipv4->saddr, e->gateIP, ADDR_SIZE);
	set_source_port(newPacket, e->gatePort);

	// Re-checksum
	compute_packet_checksums(newPacket);

	return 0;
}

void print_nat_table(void)
{
	struct nat_entry_bucket *b = natTable;
	struct nat_entry *e = NULL;

	printf("ARG: NAT Table:\n");
	while(b != NULL)
	{
		printf("ARG:  Bucket: ");
		print_nat_bucket(b);
		printf("\n");

		e = b->first;
		while(e != NULL)
		{
			printf("ARG:   Entry: ");
			print_nat_entry(e);
			printf("\n");

			e = e->next;
		}
		
		b = (struct nat_entry_bucket*)(b->hh.next);
	}
}

void print_nat_bucket(const struct nat_entry_bucket *bucket)
{
	printf("k:%i e:", bucket->key);
	printIP(ADDR_SIZE, bucket->extIP);
	printf(":%i", bucket->extPort);
}

void print_nat_entry(const struct nat_entry *entry)
{
	printf("i:");
	printIP(ADDR_SIZE, entry->intIP);
	printf(":%i g:", entry->intPort);
	printIP(ADDR_SIZE, entry->gateIP);
	printf(":%i (lu %li ms ago)", entry->gatePort, current_time_offset(&entry->lastUsed));
}

struct nat_entry_bucket *create_nat_bucket(const struct packet_data *packet, const int key)
{
	const struct iphdr *iph = packet->ipv4;
	struct nat_entry_bucket *bucket = NULL;

	// Create new bucket
	bucket = (nat_entry_bucket*)malloc(sizeof(struct nat_entry_bucket));
	if(bucket == NULL)
	{
		printf("ARG: Unable to allocate space for new NAT bucket\n");
		return NULL;
	}

	bucket->key = key;
	memcpy(bucket->extIP, (void*)&iph->daddr, ADDR_SIZE);
	bucket->first = NULL;
	bucket->extPort = get_dest_port(packet);

	// Add new bucket
	HASH_ADD_INT(natTable, key, bucket);

	return bucket;
}

struct nat_entry *create_nat_entry(const struct packet_data *packet, struct nat_entry_bucket *bucket)
{
	const struct iphdr *iph = packet->ipv4;
	struct nat_entry *e = NULL;
	struct nat_entry *oldHead = NULL;

	uint8_t *currIP = NULL;

	e = (struct nat_entry*)malloc(sizeof(struct nat_entry));
	if(e == NULL)
	{
		printf("ARG: Unable to allocate space for new NAT entry\n");
		return NULL;
	}

	// Fill in data
	memcpy(e->intIP, &iph->saddr, ADDR_SIZE);

	currIP = current_ip();
	if(currIP == NULL)
	{
		printf("ARG: Unable to complete creation of new NAT entry, out of memory\n");
		free(e);
		return NULL;
	}
	memcpy(e->gateIP, currIP, ADDR_SIZE);
	free(currIP);

	e->intPort = get_source_port(packet);
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
	current_time(&e->lastUsed);
}

int create_nat_bucket_key(const void *ip, const uint16_t port)
{
	int key;
	memcpy(&key, ip, ADDR_SIZE);
	key ^= port;
	
	return key;
}

void empty_nat_table(void)
{
	struct nat_entry_bucket *b = natTable;
	
	pthread_spin_lock(&natTableLock);
	
	while(b != NULL)
		b = remove_nat_bucket(b);
	
	pthread_spin_unlock(&natTableLock);
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
	free(bucket);

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
	free(e);

	return next;
}

void *nat_cleanup_thread(void *data)
{
	printf("ARG: NAT cleanup thread running\n");

	for(;;)
	{
		clean_nat_table();
	
		pthread_spin_lock(&natTableLock);
		print_nat_table();
		pthread_spin_unlock(&natTableLock);
	
		sleep(NAT_CLEAN_TIME);
	}

	printf("ARG: NAT cleanup thread dying\n");

	return 0;
}

void clean_nat_table(void)
{
	struct timespec now;

	struct nat_entry_bucket *b = natTable;
	struct nat_entry *e = NULL;

	current_time(&now);

	pthread_spin_lock(&natTableLock);

	while(b != NULL)
	{
		e = b->first;
		while(e != NULL)
		{
			// Is this connection too old?
			if(time_offset(&now, &e->lastUsed) > NAT_CLEAN_TIME * 1000)
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

	pthread_spin_unlock(&natTableLock);
}

