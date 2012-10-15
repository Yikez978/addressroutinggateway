#ifndef DIRECTOR_H
#define DIRECTOR_H

#include <pcap.h>
#include <pthread.h>

#include "protocol.h"

#define MAX_FILTER_LEN 150

#define IFACE_EXTERNAL 0
#define IFACE_INTERNAL 1

struct packet_data;

typedef struct receive_thread_data
{
	char dev[10];
	void (*handler)(const struct packet_data*);
	char ifaceSide;
	pthread_t thread;
} receive_thread_data;

int init_director(struct config_data *config);
int uninit_director(void);

void join_director(void);

void *receive_thread(void *tData);

void direct_inbound(const struct packet_data *packet);
void direct_outbound(const struct packet_data *packet);

#endif

