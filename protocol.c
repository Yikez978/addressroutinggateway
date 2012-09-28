#include <stdio.h>

#include <arpa/inet.h>
#include <pthread.h>

#include "protocol.h"
#include "hopper.h"
#include "crypto.h"

// In a full implementation, we would use public and private keys for authentication
// and initial connection to other gateways. For the test implementation, we used a
// globally shared key for HMACs, rather than digital signatures
static const uint8_t argGlobalKey[AES_KEY_SIZE] = {25, -18, -127, -10,
												 67, 30, 7, -49,
												 68, -70, 19, 106,
												 -100, -11, 72, 18};

void init_protocol_locks(void)
{

}

char start_auth(struct arg_network_info *local, struct arg_network_info *remote)
{
	remote->proto.state |= ARG_DO_AUTH;
	return do_next_action(local, remote);
}

char start_time_sync(struct arg_network_info *local, struct arg_network_info *remote)
{
	remote->proto.state |= ARG_DO_AUTH | ARG_DO_TIME;
	return do_next_action(local, remote);
}

char start_connection(struct arg_network_info *local, struct arg_network_info *remote)
{
	remote->proto.state |= ARG_DO_AUTH | ARG_DO_TIME | ARG_DO_CONN;
	return do_next_action(local, remote);
}

char do_next_action(struct arg_network_info *local, struct arg_network_info *remote)
{
	char state = remote->proto.state;
	if(state & ARG_DO_AUTH)
		return send_arg_ping(local, remote);
	else if(state & ARG_DO_CONN)
		return send_arg_conn_req(local, remote);
	else
		return 0;
}

char send_arg_ping(struct arg_network_info *local,
				   struct arg_network_info *remote)
{
	struct argmsg *msg = NULL;
	char r;
	
	printf("ARG: Sending ping to ");
	printIP(sizeof(remote->baseIP), remote->baseIP);
	printf("\n");

	msg = create_arg_msg(sizeof(remote->proto.pingID));
	if(msg == NULL)
	{
		printf("Unable to allocate space to send ping\n");
		return -1;
	}

	pthread_spin_lock(&remote->lock);

	get_random_bytes(&remote->proto.pingID, sizeof(remote->proto.pingID));
	memcpy(msg->data, &remote->proto.pingID, msg->len);

	r = send_arg_packet(local, remote, ARG_PING_MSG, argGlobalKey, argGlobalKey, msg);
	if(r)
		current_time(&remote->proto.pingSentTime);

	pthread_spin_unlock(&remote->lock);
	
	return r;
}

char process_arg_ping(struct arg_network_info *local,
					  struct arg_network_info *remote,
					  const struct packet_data *packet)
{
	char status = 0;
	struct argmsg *msg = NULL;

	printf("ARG: Received ping from %s\n", remote->name);
	
	if(process_arg_packet(argGlobalKey, argGlobalKey, packet, &msg))
	{
		printf("ARG: Stopping pong processing\n");
		return 0;
	}

	if(msg->len == sizeof(remote->proto.pingID))
	{
		// Echo back their data
		status = send_arg_packet(local, remote, ARG_PONG_MSG, argGlobalKey, argGlobalKey, msg);
	}
	else
	{
		printf("ARG: Not sending pong, data not a proper ping ID\n");
		status = 0;
	}
	
	free_arg_msg(msg);
	return status;
}

char process_arg_pong(struct arg_network_info *local,
					  struct arg_network_info *remote,
					  const struct packet_data *packet)
{
	char status = 0;
	struct argmsg *msg = NULL;
	uint32_t *id = 0;
	
	printf("ARG: Received pong from %s\n", remote->name);
	
	if(process_arg_packet(argGlobalKey, argGlobalKey, packet, &msg))
	{
		printf("ARG: Stopping pong processing\n");
		return 0;
	}

	if(msg->data == NULL || msg->len != sizeof(remote->proto.pingID))
	{
		printf("ARG: Not accepting pong, data not a proper ping ID\n");
		free_arg_msg(msg);
		return 0;
	}

	pthread_spin_lock(&remote->lock);

	if(remote->proto.pingID != 0)
	{
		id = (uint32_t*)(msg->data);

		if(remote->proto.pingID == *id)
		{
			remote->proto.latency = current_time_offset(&remote->proto.pingSentTime) / 2;
			remote->authenticated = 1;
			status = 1;
			printf("ARG: Latency to %s: %li ms\n", remote->name, remote->proto.latency);
		}
		else
		{
			// We sent one, but the ID was incorrect. The remote gateway
			// had the wrong ID or it did not have the correct global key
			// Either way, we don't trust them now
			printf("ARG: The ping ID was incorrect, rejecting other gateway (expected %i, got %i)\n", remote->proto.pingID, *id);
			remote->authenticated = 0;
			status = 1;
		}
	}
	else
	{
		printf("ARG: Not accepting pong, no ping sent\n");
		status = 0;
	}
	
	pthread_spin_unlock(&remote->lock);
	
	free_arg_msg(msg);
	
	// All done with a ping/auth
	remote->proto.state &= ~ARG_DO_AUTH;
	do_next_action(local, remote);
	
	return status;
}

// Connect
char send_arg_conn_req(struct arg_network_info *local,
					   struct arg_network_info *remote)
{
	return 0;
}

char process_arg_conn_req(struct arg_network_info *local,
						  struct arg_network_info *remote,
					  	  const struct packet_data *packet)
{
	return 0;
}

char process_arg_conn_resp(struct arg_network_info *remote,
						   const struct packet_data *packet)
{
	return 0;
}

char send_arg_packet(struct arg_network_info *srcGate,
					 struct arg_network_info *destGate,
					 int type,
					 const uint8_t *hmacKey,
					 const uint8_t *encKey,
					 const struct argmsg *msg)
{
	struct packet_data *packet = NULL;
	uint16_t fullLen = 0;
	
	// Create packet we will build within
	fullLen = 20 + ARG_HDR_LEN;
	if(msg != NULL)
		fullLen += msg->len;
	packet = create_packet(fullLen);
	if(packet == NULL)
	{
		printf("Unable to allocate space for ARG packet\n");
		return -1;
	}
	
	// Ensure IPs are up-to-date
	update_ips(srcGate);
	update_ips(destGate);	

	// IP header
	packet->ipv4->version = 4;
	packet->ipv4->ihl = 5;
	packet->ipv4->ttl = 32;
	packet->ipv4->tos = 0;
	packet->ipv4->protocol = ARG_PROTO;
	memcpy(&packet->ipv4->saddr, srcGate->currIP, sizeof(packet->ipv4->saddr));
	memcpy(&packet->ipv4->daddr, destGate->currIP, sizeof(packet->ipv4->daddr));
	packet->ipv4->id = 0;
	packet->ipv4->frag_off = 0;
	packet->ipv4->tot_len = htons(packet->len);
	packet->ipv4->check = 0;

	parse_packet(packet);

	// TBD encrypt
	//if(encKey != NULL)
	//	;

	packet->arg->version = 1;
	packet->arg->type = type;
	if(msg != NULL)
	{
		packet->arg->len = htons(msg->len + ARG_HDR_LEN);
		memcpy((uint8_t*)packet->arg + ARG_HDR_LEN, msg->data, msg->len);
	}
	else
		packet->arg->len = 0;
	
	if(hmacKey != NULL)
		hmac_sha1(hmacKey, AES_KEY_SIZE, (uint8_t*)packet->arg, ntohs(packet->arg->len), packet->arg->hmac);
	
	// Send!
	if(send_packet(packet) < 0)
	{
		printf("Failed to send ARG packet\n");
		return -2;
	}

	free_packet(packet);

	return 0;
}

char process_arg_packet(const uint8_t *hmacKey, const uint8_t *encKey,
						const struct packet_data *packet,
						struct argmsg **msg)
{
	struct packet_data *newPacket = NULL;
	struct argmsg *out = NULL;

	//printf("Processing packet");
	//printRaw(packet->len, packet->data);

	// Duplicate packet so we can remove the hash and check
	newPacket = copy_packet(packet);
	if(newPacket == NULL)
	{
		printf("Unable to duplicate packet for checking\n");
		return -1;
	}
	
	// Check hash
	if(hmacKey != NULL)
	{
		memset(newPacket->arg->hmac, 0, sizeof(newPacket->arg->hmac));
		hmac_sha1(hmacKey, AES_KEY_SIZE, (uint8_t*)newPacket->arg, ntohs(newPacket->arg->len), newPacket->arg->hmac);
		
		if(memcmp(packet->arg->hmac, newPacket->arg->hmac, sizeof(packet->arg->hmac)) != 0)
		{
			printf("ARG: Received packet did not have a matching HMAC\n");
			free_packet(newPacket);
			return -2;
		}
	}
	
	// TBD decrypt
	//if(encKey != NULL)
	//	;
	// else
	
	out = create_arg_msg(ntohs(newPacket->arg->len) - ARG_HDR_LEN);
	if(out == NULL)
	{
		printf("Unable to allocate space to write decrypted message\n");
		free_packet(newPacket);
		return -3;
	}

	memcpy(out->data, (uint8_t*)newPacket->arg + ARG_HDR_LEN, out->len);
	*msg = out;
	
	//printf("msg from packet");
	//printRaw(out->len, out->data);
	
	return 0;
}

struct argmsg *create_arg_msg(uint16_t len)
{
	struct argmsg *out = NULL;

	out = malloc(sizeof(struct argmsg));
	if(out == NULL)
		return NULL;
	
	out->len = len;
	out->data = calloc(len, 1);
	if(out->data == NULL)
	{
		free(out);
		return NULL;
	}

	return out;
}

void free_arg_msg(struct argmsg *msg)
{
	if(msg != NULL)
	{
		if(msg->data != NULL)
			free(msg->data);

		free(msg);
	}
}

char get_msg_type(const struct arghdr *msg)
{
	return msg->type;
}

char is_wrapped_msg(const struct arghdr *msg)
{
	return get_msg_type(msg) == ARG_WRAPPED_MSG;
}

char is_admin_msg(const struct arghdr *msg)
{
	return get_msg_type(msg) != ARG_WRAPPED_MSG;
}

