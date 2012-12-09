#ifndef DIRECTOR_H
#define DIRECTOR_H

#include <pcap.h>
#include <pthread.h>

#include "protocol.h"

#define MAX_FILTER_LEN 150

#define IFACE_EXTERNAL 0
#define IFACE_INTERNAL 1

struct packet_data;

// Structure for passing data to newly created threads
typedef struct receive_thread_data
{
	pcap_t *pd;
	char dev[10];
	void (*handler)(const struct packet_data*);
	char ifaceSide;
	pthread_t thread;
} receive_thread_data;

// Initialization functions
void init_director_locks(void);
int init_director(struct config_data *config);
int init_pcap_driver(pcap_t **pd, char *dev, bool is_internal);

int uninit_director(void);

// Wait for all children to finish (receivers, hopper, nat)
void join_director(void);

// Receive data from a given interface
void *receive_thread(void *tData);

// Take traffic received on the external interface and process
void direct_inbound(const struct packet_data *packet);

// Take traffic received on the internal interface and process
void direct_outbound(const struct packet_data *packet);

#endif

