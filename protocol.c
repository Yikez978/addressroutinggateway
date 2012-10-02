#include <stdio.h>

#include <arpa/inet.h>
#include <pthread.h>

#include "protocol.h"
#include "crypto.h"
#include "hopper.h"

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

char send_arg_hello(struct arg_network_info *local,
				   struct arg_network_info *remote)
{
	struct argmsg *msg = NULL;
	
	printf("ARG: Sending ping to %s\n", remote->name);

	msg = create_arg_msg(sizeof(remote->proto.myID));
	if(msg == NULL)
	{
		printf("Unable to allocate space to send gateway hello\n");
		return -1;
	}

	pthread_spin_lock(&remote->lock);

	// Every gateway we talk to gets a unique identifier from us. (they'll also have a unique incoming one)
	if(remote->proto.myID == 0)
		get_random_bytes(&remote->proto.myID, sizeof(remote->proto.myID));
	memcpy(msg->data, &remote->proto.myID, msg->len);

	if(send_arg_packet(local, remote, ARG_GATE_HELLO_MSG, msg) < 0)
		printf("Failed to send ARG gateway hello\n");

	pthread_spin_unlock(&remote->lock);
	
	free_arg_msg(msg);
	
	return 0;
}

char process_arg_hello(struct arg_network_info *local,
					  struct arg_network_info *remote,
					  const struct packet_data *packet)
{
	char status = 0;
	struct argmsg *inMsg = NULL;
	struct argmsg *outMsg = NULL;
	struct arg_welcome *welcome = NULL;

	printf("ARG: Received gateway hello from %s\n", remote->name);
	
	if(process_arg_packet(local, remote, packet, &inMsg))
	{
		printf("Stopping hello processing\n");
		return -1;
	}

	if(inMsg->len != sizeof(remote->proto.theirID))
	{
		printf("ARG: Not sending welcome, packet not correct length\n");
		free_arg_msg(inMsg);
		return -2;
	}

	// Pull out their ID. We don't accept it yet, they have to verify it with
	// a corresponding verification of OUR id
	remote->proto.theirPendingID = *((uint32_t*)inMsg);
	free_arg_msg(inMsg);
	inMsg = NULL;

	outMsg = create_arg_msg(sizeof(remote->proto.myID));
	if(outMsg == NULL)
	{
		printf("Unable to allocate space to send gateway hello\n");
		return -1;
	}

	// Send back both their and our IDs
	if(remote->proto.myID == 0)
		get_random_bytes(&remote->proto.myID, sizeof(remote->proto.myID));

	welcome = (struct arg_welcome*)outMsg->data;
	welcome->id1 = remote->proto.theirPendingID;
	welcome->id2 = remote->proto.myID;

	if(send_arg_packet(local, remote, ARG_GATE_WELCOME_MSG, outMsg) < 0)
		printf("Failed to send ARG gateway welcome\n");
	
	free_arg_msg(outMsg);
	return status;
}


char process_arg_welcome(struct arg_network_info *local,
					  struct arg_network_info *remote,
					  const struct packet_data *packet)
{
	char status = 0;
	struct argmsg *inMsg = NULL;
	struct argmsg *outMsg = NULL;
	struct arg_welcome *welcome = NULL;

	printf("ARG: Received gateway welcome from %s\n", remote->name);
	
	if(process_arg_packet(local, remote, packet, &inMsg))
	{
		printf("Stopping welcome processing\n");
		return -1;
	}

	if(inMsg->len != sizeof(struct arg_welcome))
	{
		printf("Not sending verification, welcome improperly sized\n");
		free_arg_msg(inMsg);
		return -2;
	}

	welcome = (struct arg_welcome*)inMsg->data;

	free_arg_msg(inMsg);
	return status;
}

char process_arg_verified(struct arg_network_info *local,
					  struct arg_network_info *remote,
					  const struct packet_data *packet)
{
	char status = 0;
	struct argmsg *msg = NULL;
	uint32_t *id = 0;
	
	printf("ARG: Received pong from %s\n", remote->name);
	
	if(process_arg_packet(local, remote, packet, &msg))
	{
		printf("ARG: Stopping pong processing\n");
		return -1;
	}

	if(msg->data == NULL || msg->len != sizeof(remote->proto.pingID))
	{
		printf("ARG: Not accepting pong, data not a proper ping ID\n");
		free_arg_msg(msg);
		return -2;
	}

	pthread_spin_lock(&remote->lock);

	if(remote->proto.pingID != 0)
	{
		id = (uint32_t*)(msg->data);

		if(remote->proto.pingID == *id)
		{
			// TBD skip/try again with huge latency changes?
			remote->proto.latency = current_time_offset(&remote->proto.pingSentTime) / 2;
			remote->authenticated = 1;
			status = 0;
			printf("ARG: Latency to %s: %li ms\n", remote->name, remote->proto.latency);
		}
		else
		{
			// We sent one, but the ID was incorrect. The remote gateway
			// had the wrong ID or it did not have the correct global key
			// Either way, we don't trust them now
			printf("ARG: The ping ID was incorrect, rejecting other gateway (expected %i, got %i)\n", remote->proto.pingID, *id);
			remote->authenticated = 0;
			status = 0;
		}
	}
	else
	{
		printf("ARG: Not accepting pong, no ping sent\n");
		status = -3;
	}
	
	pthread_spin_unlock(&remote->lock);
	
	free_arg_msg(msg);
	
	// All done with a ping/auth
	remote->proto.state &= ~ARG_DO_AUTH;
	do_next_action(local, remote);
	
	return status;
}
char send_arg_ping(struct arg_network_info *local,
				   struct arg_network_info *remote)
{
	struct argmsg *msg = NULL;
	
	printf("ARG: Sending ping to %s\n", remote->name);

	msg = create_arg_msg(sizeof(remote->proto.pingID));
	if(msg == NULL)
	{
		printf("Unable to allocate space to send ping\n");
		return -1;
	}

	pthread_spin_lock(&remote->lock);

	get_random_bytes(&remote->proto.pingID, sizeof(remote->proto.pingID));
	memcpy(msg->data, &remote->proto.pingID, msg->len);

	if(send_arg_packet(local, remote, ARG_PING_MSG, msg) == 0)
		current_time(&remote->proto.pingSentTime);
	else
		printf("Failed to send ARG ping\n");

	pthread_spin_unlock(&remote->lock);
	
	return 0;
}

char process_arg_ping(struct arg_network_info *local,
					  struct arg_network_info *remote,
					  const struct packet_data *packet)
{
	char status = 0;
	struct argmsg *msg = NULL;

	printf("ARG: Received ping from %s\n", remote->name);
	
	if(process_arg_packet(local, remote, packet, &msg))
	{
		printf("ARG: Stopping pong processing\n");
		return -1;
	}

	if(msg->len == sizeof(remote->proto.pingID))
	{
		// Echo back their data
		status = send_arg_packet(local, remote, ARG_PONG_MSG, msg);
	}
	else
	{
		printf("ARG: Not sending pong, data not a proper ping ID\n");
		status = -2;
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
	
	if(process_arg_packet(local, remote, packet, &msg))
	{
		printf("ARG: Stopping pong processing\n");
		return -1;
	}

	if(msg->data == NULL || msg->len != sizeof(remote->proto.pingID))
	{
		printf("ARG: Not accepting pong, data not a proper ping ID\n");
		free_arg_msg(msg);
		return -2;
	}

	pthread_spin_lock(&remote->lock);

	if(remote->proto.pingID != 0)
	{
		id = (uint32_t*)(msg->data);

		if(remote->proto.pingID == *id)
		{
			// TBD skip/try again with huge latency changes?
			remote->proto.latency = current_time_offset(&remote->proto.pingSentTime) / 2;
			remote->authenticated = 1;
			status = 0;
			printf("ARG: Latency to %s: %li ms\n", remote->name, remote->proto.latency);
		}
		else
		{
			// We sent one, but the ID was incorrect. The remote gateway
			// had the wrong ID or it did not have the correct global key
			// Either way, we don't trust them now
			printf("ARG: The ping ID was incorrect, rejecting other gateway (expected %i, got %i)\n", remote->proto.pingID, *id);
			remote->authenticated = 0;
			status = 0;
		}
	}
	else
	{
		printf("ARG: Not accepting pong, no ping sent\n");
		status = -3;
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
	// Make sure this gateway is authenticated
	if(!remote->authenticated)
	{
		printf("Authenticating %s before sending connection request\n", remote->name);
		return start_connection(local, remote);
	}

	printf("ARG: Sending connect request to %s\n", remote->name);

	pthread_spin_lock(&remote->lock);

	// Send
	if(send_arg_packet(local, remote, ARG_CONN_REQ_MSG, NULL) == 0)
		current_time(&remote->proto.pingSentTime);
	else
		printf("Failed to send ARG connection request\n");

	pthread_spin_unlock(&remote->lock);

	return 0;
}

char process_arg_conn_req(struct arg_network_info *local,
						  struct arg_network_info *remote,
					  	  const struct packet_data *packet)
{
	struct argmsg *msg = NULL;
	struct arg_conn_data *connData = NULL;

	// Make sure this gateway is authenticated
	if(!remote->authenticated)
	{
		printf("Authenticating %s before sending connection data\n", remote->name);
		return start_auth(local, remote);
	}

	printf("ARG: Sending connect information to %s\n", remote->name);

	// Build message
	msg = create_arg_msg(sizeof(struct arg_conn_data));
	if(msg == NULL)
	{
		printf("Unable to allocate space to send connect request\n");
		return -2;
	}

	connData = (struct arg_conn_data*)msg->data;
	memcpy(connData->symKey, local->symKey, sizeof(connData->symKey));
	memcpy(connData->hopKey, local->hopKey, sizeof(connData->hopKey));
	connData->hopInterval = htonl(local->hopInterval);
	connData->timeOffset = htonl(current_time_offset(&local->timeBase));

	pthread_spin_lock(&remote->lock);

	// Send
	if(send_arg_packet(local, remote, ARG_CONN_RESP_MSG, msg) == 0)
		current_time(&remote->proto.pingSentTime);
	else
		printf("Failed to send ARG connection data\n");

	pthread_spin_unlock(&remote->lock);

	free_arg_msg(msg);

	return 0;
}

char process_arg_conn_resp(struct arg_network_info *local,
						   struct arg_network_info *remote,
						   const struct packet_data *packet)
{
	char status = 0;
	struct argmsg *msg = NULL;
	struct arg_conn_data *connData = NULL; 

	printf("ARG: Received connection data from %s\n", remote->name);
	
	// Make sure this gateway is authenticated
	if(!remote->authenticated)
	{
		printf("Refusing to accept connection request, %s is not authenticated\n", remote->name);
		return start_connection(local, remote);
	}
	
	if(process_arg_packet(local, remote, packet, &msg))
	{
		printf("ARG: Stopping connection data processing\n");
		return -1;
	}

	if(msg->len == sizeof(struct arg_conn_data))
	{
		pthread_spin_lock(&remote->lock);
		
		connData = (struct arg_conn_data*)msg->data;
		
		memcpy(remote->symKey, connData->symKey, sizeof(connData->symKey));
		memcpy(remote->hopKey, connData->hopKey, sizeof(connData->hopKey));
		remote->hopInterval = ntohl(connData->hopInterval);
		current_time_plus(&remote->timeBase, -htonl(connData->timeOffset));

		printf("time base for remote %s is now %lu %lu\n", remote->name, remote->timeBase.tv_sec, remote->timeBase.tv_nsec);

		remote->connected = 1;
		
		pthread_spin_unlock(&remote->lock);
	}
	else
	{
		printf("ARG: Connection not properly sized\n");
		status = -2;
	}
	
	free_arg_msg(msg);
	
	// All done with a connection
	remote->proto.state &= ~ARG_DO_CONN;
	do_next_action(local, remote);
	
	return status;
}

char send_arg_wrapped(struct arg_network_info *local,
					  struct arg_network_info *remote,
					  const struct packet_data *packet)
{
	int status = 0;
	struct argmsg msg;

	pthread_spin_lock(&remote->lock);
	
	// Must be connected and authenticated
	if(!remote->authenticated || !remote->connected)
	{
		printf("Refusing to wrap packet, %s is not authenticated/connected\n", remote->name);
		pthread_spin_unlock(&remote->lock);
		return -1;
	}
	
	// Create message containing packet data
	msg.len = packet->len;
	msg.data = packet->data;
	status = send_arg_packet(local, remote, ARG_WRAPPED_MSG, &msg);

	pthread_spin_unlock(&remote->lock);

	return status;
}

char process_arg_wrapped(struct arg_network_info *local,
						 struct arg_network_info *remote,
						 const struct packet_data *packet)
{
	struct argmsg *msg = NULL;
	struct packet_data *newPacket = NULL;
	int status = 0;

	pthread_spin_lock(&remote->lock);
	
	// Must be connectet and authenicated
	if(!remote->authenticated || !remote->connected)
	{
		printf("Refusing to unwrap packet, %s is not authenticated/connected\n", remote->name);
		pthread_spin_unlock(&remote->lock);
		return -1;
	}

	if(process_arg_packet(local, remote, packet, &msg))
	{
		printf("ARG: Stopping connection data processing\n");
		pthread_spin_unlock(&remote->lock);
		return -2;
	}
	
	// Just need to send this message on as a packet
	newPacket = create_packet(msg->len);
	if(newPacket == NULL)
	{
		printf("Unable to create new packet to drop into internal network\n");
		pthread_spin_unlock(&remote->lock);
		return -3;
	}

	memcpy(newPacket->data, msg->data, msg->len);
	parse_packet(newPacket);
	status = send_packet(newPacket);

	pthread_spin_unlock(&remote->lock);

	return status;
}

char send_arg_packet(struct arg_network_info *srcGate,
					 struct arg_network_info *destGate,
					 int type,
					 const struct argmsg *msg)
{
	int ret;
	struct packet_data *packet = NULL;
	uint16_t fullLen = 0;
	uint8_t hash[SHA1_HASH_SIZE];

	// Create packet we will build within, giving it plenty of extra space (encryption padding and such)
	fullLen = 20 + ARG_HDR_LEN;
	if(msg != NULL)
		fullLen += msg->len;
	fullLen += srcGate->rsa.len;
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
	packet->ipv4->tot_len = htons(packet->ipv4->ihl * 4);
	packet->ipv4->check = 0;

	parse_packet(packet);
	
	// Encrypt
	packet->arg->version = 1;
	packet->arg->type = type;
	if(msg != NULL)
	{
		if(type == ARG_WRAPPED_MSG)
		{
			// Symmetric encryption, TBD
			memcpy(packet->unknown_data, msg->data, msg->len);
			packet->arg->len = htons(msg->len + ARG_HDR_LEN);
		}
		else
		{
			// Admin packets can be at most keysize/8 bytes (ie, 128 bytes for a 1024 bit key)
			if(msg->len > destGate->rsa.len)
			{
				printf("Admin packet data must be %lu bytes or less\n", destGate->rsa.len);
				free_packet(packet);
				return -2;
			}

			// RSA encryption with destination public key
			packet->arg->len = htons((uint16_t)destGate->rsa.len + ARG_HDR_LEN);
			rsa_pkcs1_encrypt(&destGate->rsa, ctr_drbg_random, &srcGate->ctr_drbg, RSA_PUBLIC,
				msg->len, msg->data, packet->unknown_data);
		}
	}
	else
		packet->arg->len = htons(ARG_HDR_LEN);

	packet->len = ntohs(packet->ipv4->tot_len) + ntohs(packet->arg->len);
	packet->ipv4->tot_len = htons(packet->len);

	// Sign
	sha1((uint8_t*)packet->arg, ntohs(packet->arg->len), hash);
	//printf("Sig");
	//printRaw(sizeof(hash), hash);
	if((ret = rsa_pkcs1_sign(&srcGate->rsa, NULL, NULL, RSA_PRIVATE, SIG_RSA_SHA1,
		sizeof(hash), hash, packet->arg->sig)) != 0)
	{
		printf("Unable to sign, error %i\n", ret);
		free_packet(packet);
		return -3;
	}
	
	// Send!
	//printf("Msg ");
	//printRaw(msg->len, msg->data);
	//printf("Sending ");
	//printRaw(packet->len, packet->data);
	if(send_packet(packet) < 0)
	{
		printf("Failed to send ARG packet\n");
		return -2;
	}

	free_packet(packet);

	return 0;
}

char process_arg_packet(struct arg_network_info *local,
						struct arg_network_info *remote,
						const struct packet_data *packet,
						struct argmsg **msg)
{
	int ret;
	size_t len;

	uint8_t hash[SHA1_HASH_SIZE];

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

	// Check signature
	memset(newPacket->arg->sig, 0, sizeof(newPacket->arg->sig));
	sha1((uint8_t*)newPacket->arg, ntohs(newPacket->arg->len), hash);
	if((ret = rsa_pkcs1_verify(&remote->rsa, RSA_PUBLIC, SIG_RSA_SHA1,
		sizeof(hash), hash, packet->arg->sig)) != 0 )
	{
		printf("Unable to verify signature, error %i\n", ret);
		free_packet(newPacket);
		return -3;
	}

	//printf("Received ");
	//printRaw(packet->len, packet->data);
	
	// Decrypt
	if(newPacket->arg->len > ARG_HDR_LEN)
	{
		out = create_arg_msg(ntohs(newPacket->arg->len));
		if(out == NULL)
		{
			printf("Unable to allocate space to write decrypted message\n");
			free_packet(newPacket);
			return -3;
		}

		if(newPacket->arg->type == ARG_WRAPPED_MSG)
		{
			// Symmetric decrypt, TBD
			out->len = ntohs(packet->arg->len) - ARG_HDR_LEN;
			memcpy(out->data, packet->unknown_data, out->len);
		}
		else
		{
			// Decrypt with local private key
			if((ret = rsa_pkcs1_decrypt(&local->rsa, RSA_PRIVATE, &len,
				newPacket->unknown_data, out->data, out->len)) != 0)
			{
				printf("Unable to decrypt packet contents, error %i\n", ret);
				free_arg_msg(out);
				free_packet(newPacket);
				return -4;
			}

			out->len = len;
		}
		
		//printf("msg from packet");
		//printRaw(out->len, out->data);
		
		*msg = out;
	}
	else
		*msg = NULL;
	
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

