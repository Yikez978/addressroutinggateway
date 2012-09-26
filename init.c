#include <stdio.h>
#include <pthread.h>
#include <pcap.h>

#include "settings.h"


// Called when the module is initialized
static int arg_init(void)
{
	printf("ARG: Starting\n");
/*
	// Take care of locks first so that we know they're ALWAYS safe to use
	init_nat_locks();
	init_hopper_locks();
	init_protocol_locks();

	// Init various components
	if(!init_hopper())
	{
		printf("ARG: Unable to initialize hopper\n");
		
		uninit_hopper();
		
		return 0;
	}

	if(!init_nat())
	{
		printf("ARG: NAT failed to initialize\n");

		uninit_nat();
		uninit_hopper();

		return 0;
	}

	// Hook network communication to listen for instructions
	if(!init_director())
	{
		printf("ARG: Director failed to initialized, disabling subsystems\n");
		
		uninit_director();
		uninit_nat();
		uninit_hopper();
		
		return 0;
	}
*/
	printf("ARG: Running\n");
   
	// Do first attempt to connect to the gateways we know of
	//init_hopper_finish();

	return 0;
}

// Called when the module is unloaded
static void arg_exit(void)
{
	printf("ARG: Shutting down\n");

	// Unregister our network hooks so the system doesn't crash
/*	uninit_director();

	// Cleanup any resources as needed
	uninit_nat();
	uninit_hopper();
*/
	printf("ARG: Finished\n");
}

typedef struct receive_thread_data
{
	char dev[10];
	void (*handler)(struct pcap_pkthdr*, const u_char*);
} receive_thread_data;

static void *receive_thread(void *arg)
{
	struct receive_thread_data *data = (struct receive_thread_data*)arg;

	char ebuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const u_char *packet = NULL;

	// Activate pcap
	pcap_t *pd = pcap_create(data->dev, ebuf);
	if(pd == NULL)
	{
		printf("Unable to initialize create pcap driver on %s\n", data->dev);
		return (void*)-1;
	}

	pcap_set_timeout(pd, 250);
	pcap_set_snaplen(pd, MAX_PACKET_SIZE);
	pcap_set_promisc(pd, 1);

	if(pcap_activate(pd))
	{
		printf("Unable to activate pcap on %s: %s\n", data->dev, pcap_geterr(pd));
		return (void*)-2;
	}

	// Receive packets and send to director
	printf("Ready to receive packets on %s\n", data->dev);

	for(;;)
	{
		packet = pcap_next(pd, &header);
		if(packet == NULL)
			continue;

		printf("packet received on %s\n", data->dev);
		if(data->handler != NULL)
			(*data->handler)(&header, packet);
	}

	pcap_close(pd);
	pd = NULL;

	printf("Done receiving packets on %s\n", data->dev);

	return NULL;
}

int main(int argc, char *argv[])
{
	struct receive_thread_data intData = {
		.dev = INT_DEV_NAME,
		.handler = NULL,
	};
	struct receive_thread_data extData = {
		.dev = EXT_DEV_NAME,
		.handler = NULL,
	};
	pthread_t intThread;
	pthread_t extThread;

	arg_init();

	// Enter receive loop, which we then pass off to director
	pthread_create(&intThread, NULL, receive_thread, (void*)&intData);
	pthread_create(&extThread, NULL, receive_thread, (void*)&extData);
	pthread_join(extThread, NULL);
	pthread_join(intThread, NULL);

	arg_exit();
	
	return 0;
}

