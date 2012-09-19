#ifndef ARG_PROTOCOL_H
#define ARG_PROTOCOL_H

#include "utility.h"
#include "crypto.h"

struct arg_network_info;

#define ARG_WRAPPED_TYPE 1
#define ARG_TIME_TYPE 2

typedef struct arghdr {
	__u8 version:4,
		type:4;
	__be16 len;

	uchar hmac[HMAC_SIZE];
} arghdr;

#define ARG_HDR_LEN sizeof(struct arghdr)

// Creates the ARG header for the given data and sends it
char send_arg_packet(struct arg_network_info *srcGate,
					 struct arg_network_info *destGate,
					 int type, uchar *data, int dlen);

// Creates and sends a packet with the given data. Only works between ARG gateways currently
char send_packet(uchar *srcIP, uchar *destIP, uchar *data, int dlen);

#endif

