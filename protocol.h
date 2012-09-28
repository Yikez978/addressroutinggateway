#ifndef ARG_PROTOCOL_H
#define ARG_PROTOCOL_H

#include <stdint.h>

#include "utility.h"
#include "crypto.h"
#include "packet.h"

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
 *			Also allows round-trip latency detection
 * 	- HMACs are all done with global symmetric key (IRL, private key of sender)
 *	1. Local sends AUTH_REQ containing random 4-byte unsigned int and
 *		4 bytes of randomness, all encrypted by the global key. (IRL, would
 *		be encrypted by remote public key.) Time of send is recorded
 *	2. Remote sends AUTH_RESP with same int and different random bytes,
 *		encrypted (IRL, would be encrypted by remote private key)
 *  3. Local ensures received int matches sent int. If so, remote is 
 *		marked as authenticated. Time for auth is determined and recorded by
 *		dividing the start and end times, giving the one-way latency in jiffies
 *
 * Connect process
 * 	- HMACs are all done with global symmetric key (IRL, private key of sender)
 *	1. Ensure auth
 *	2. Local sends CONN_REQ containing its hop key, hop interval, time offset in ms (curr time - base), and
 *		symmetric key, all encrypted with global key. (Remote MAY save this data,
 *		or it could simply do its own request next.)
 *	3. Remote sends CONN_RESP acknowledgement back, containing the remote
 *		hop key, hop interval, hop point, and symmetric key. Again, encrypted with global key
 *	4. Local saves data and marks gateway as connected. Offset is converted to a
 *		local base time for that gateway via local curr time - offset
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

#define ARG_AUTH_REQ_MSG ARG_PING_MSG
#define ARG_AUTH_RESP_MSG ARG_PONG_MSG

#define ARG_CONN_REQ_MSG 5
#define ARG_CONN_RESP_MSG 6

#define ARG_TIME_REQ_MSG 7
#define ARG_TIME_RESP_MSG 8

typedef struct arghdr {
	uint8_t version;
	uint8_t type;
	uint16_t len; // Size in bytes from version to end of data

	uint8_t hmac[HMAC_SIZE];
} arghdr;

typedef struct argmsg {
	uint16_t len;

	uint8_t *data;
} argmsg;

#define ARG_HDR_LEN sizeof(struct arghdr)

#define ARG_DO_AUTH 0x01
#define ARG_DO_PING ARG_DO_AUTH
#define ARG_DO_TIME 0x04
#define ARG_DO_CONN 0x08

typedef struct proto_data {
	char state; // Records actions that need to occur

	long latency; // One-way latency in jiffies
	
	struct timespec pingSentTime;
	uint32_t pingID;
} proto_data;

void init_protocol_locks(void);

// Protocol flow control
char start_auth(struct arg_network_info *local, struct arg_network_info *remote);
char start_time_sync(struct arg_network_info *local, struct arg_network_info *remote);
char start_connection(struct arg_network_info *local, struct arg_network_info *remote);

char do_next_action(struct arg_network_info *local, struct arg_network_info *remote);

// Lag detection
char send_arg_ping(struct arg_network_info *local,
				   struct arg_network_info *remote);
char process_arg_ping(struct arg_network_info *local,
					  struct arg_network_info *remote,
					  const struct packet_data *packet);
char process_arg_pong(struct arg_network_info *local,
					  struct arg_network_info *remote,
					  const struct packet_data *packet);

// Connect
char send_arg_conn_req(struct arg_network_info *local,
					   struct arg_network_info *remote);
char process_arg_conn_req(struct arg_network_info *local,
						  struct arg_network_info *remote,
						  const struct packet_data *packet);
char process_arg_conn_resp(struct arg_network_info *remote,
						   const struct packet_data *packet);

// Creates the ARG header for the given data and sends it
char send_arg_packet(struct arg_network_info *srcGate,
					 struct arg_network_info *destGate,
					 int type,
					 const uint8_t *hmacKey,
					 const uint8_t *encKey,
					 const struct argmsg *msg);

// Validates the packet data (from ARG header on) and decrypts it.
// New space is allocated and placed into out, which must be freed via free_arg_packet()
char process_arg_packet(const uint8_t *hmacKey, const uint8_t *encKey,
						const struct arghdr *hdr,
						struct argmsg **msg);
struct argmsg *create_arg_msg(uint16_t len);
void free_arg_msg(struct argmsg *msg);

char get_msg_type(const struct arghdr *msg);
char is_wrapped_msg(const struct arghdr *msg);
char is_admin_msg(const struct arghdr *msg);

#endif

