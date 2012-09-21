#ifndef ARG_PROTOCOL_H
#define ARG_PROTOCOL_H

#include "utility.h"
#include "crypto.h"

struct arg_network_info;

/*******************************
 * Protocol description:
 *
 * All packets are UDP, port is unimportant. Inside of UDP is:
 * +----------------------------------+
 * | 1 byte  |   1 byte    | 40 bytes |
 * | version | packet type |   HMAC   |
 * +----------------------------------+
 * 
 * Version - for thesis, inconsequential. Would be needed in the real world
 * Type - type of this packet, determines how it will be handled
 * HMAC - HMAC using the sender's symmetric key of everything from
 *		the version on. HMAC bytes are set to 0 for this process
 * 
 * In the following description, local is the current gateway and
 * remote is the gateway with which we are communicating. We assume
 * that local is the initiator, although obviously it goes both ways.
 *
 * Auth process, to verify that a valid gateway is sitting an a give IP range
 * 	- HMACs are all done with global symmetric key (IRL, private key of sender)
 *	1. Local sends AUTH_REQ containing random 4-byte unsigned int and
 *		4 bytes of randomness, all encrypted by the global key. (IRL, would
 *		be encrypted by remote public key)
 *	2. Remote sends AUTH_RESP with same int and different random bytes,
 *		encrypted (IRL, would be encrypted by remote private key)
 *  3. Local ensures received int matches sent int. If so, remote is 
 *		marked as authenticated
 *
 * Lag detection
 * 	- HMACs are all done with global symmetric key (IRL, sign with private key of sender)
 *	1. Local sends PING and records time it sent (no data in packet)
 *	2. Remote sends PONG in response (no data)
 *	3. Local receives and stops the stop watch. Divide by 2 to get
 *		the latency one direction. Record. And probably do again to average
 *
 * Time sync, to ensure both gateways know when they are changing IPs
 * 	- HMACs are all done with global symmetric key (IRL, private key of sender)
 *	1. Ensure auth (do process if needed)
 *	2. Do lag detection (every time)
 *	3. Local sends TIME_REQ containing its time in jiffies (4 bytes) and
 *		its jiffies per second (4 bytes). This packet is _NOT_ encrypted
 *	4. Remote receives packet and does the calculation:
 *			diff = Rj * Rjps - Lj * Ljps 
 *		Where Lj is local jiffies (received), Ljps is local jiffies/sec,
 *		Rj is remote jiffies, and Rjps is remote jiffies/sec. This gives
 *		the difference between the two times in seconds
 *	5. Remote sends TIME_RESP back to local with diff/Ljps (unencrypted)
 *	6. Remote records diff/Rjps 
 *	7. Local receives TIME_RESP and records value
 *
 * Connect process
 * 	- HMACs are all done with global symmetric key (IRL, private key of sender)
 *	1. Ensure auth
 *	2. Ensure time sync
 *	2. Local sends CONN_DATA_REQ containing its hop key, hop interval, and
 *		symmetric key, all encrypted with global key. (Remote MAY save this data,
 *		or it could simply do its own request next.)
 *	3. Remote sends CONN_DATA_RESP acknowledgement back, containing the remote
 *		hop key, hop interval, and symmetric key. Again, encrypted with global key
 *	4. Local saves data and marks gateway as connected
 *
 * Route packet
 *	1. Ensure connect
 *	2. Local takes outbound packet and encrypts with with remote symmetric key
 *	3. Local sends WRAPPED message to remote current IP. HMAC is done using
 *		local symmetric key
 *	4. Remote receives message, ensures the HMAC matches, and extracts the packet
 *	5. Remote sends packet on, into the internal network
 */
#define ARG_ADMIN_PORT 7654
#define ARG_PROTO 253

#define ARG_WRAPPED_MSG 0

#define ARG_PING_MSG 1
#define ARG_PONG_MSG 2

#define ARG_AUTH_REQ_MSG 3
#define ARG_AUTH_RESP_MSG 4

#define ARG_CONN_DATA_REQ_MSG 5
#define ARG_CONN_DATA_MSG 6

#define ARG_TIME_REQ_MSG 7
#define ARG_TIME_RESP_MSG 8

typedef struct arghdr {
	__u8 version;
	__u8 type;
	__be16 len; // Size in bytes from version to end of data

	uchar hmac[HMAC_SIZE];
} arghdr;

#define ARG_HDR_LEN sizeof(struct arghdr)

// Lag detection
char send_arg_ping(struct arg_network_info *srcGate,
				   struct arg_network_info *destGate);
char send_arg_pong(struct arg_network_info *srcGate,
				   struct arg_network_info *destGate);
char process_arg_pong(struct arg_network_info *srcGate);

char send_arg_connect(struct arg_network_info *srcGate,
					  struct arg_network_info *destGate);

// Creates the ARG header for the given data and sends it
char send_arg_packet(struct arg_network_info *srcGate,
					 struct arg_network_info *destGate,
					 int type,
					 uchar *hmacKey,
					 uchar *data, int dlen);

// Creates and sends a packet with the given data. Only works between ARG gateways currently
char send_packet(uchar *srcIP, uchar *destIP, uchar *data, int dlen);

char get_msg_type(uchar *data, int dlen);
char is_wrapped_msg(uchar *data, int dlen);
char is_admin_msg(uchar *data, int dlen);

char skbuff_to_msg(struct sk_buff *skb, uchar **data, int *dlen);

#endif

