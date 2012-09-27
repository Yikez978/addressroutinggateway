#ifndef DIRECTOR_H
#define DIRECTOR_H

#include <pcap.h>
#include <pthread.h>

#include "protocol.h"

struct packet_data;

typedef struct receive_thread_data
{
	char dev[10];
	void (*handler)(const struct packet_data*);
	pthread_t thread;
} receive_thread_data;

char init_director(void);
char uninit_director(void);

void join_director(void);

void *receive_thread(void *tData);

void direct_inbound(const struct packet_data *packet);
void direct_outbound(const struct packet_data *packet);

#endif

