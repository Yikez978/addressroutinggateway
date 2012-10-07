#include <stdio.h>

#include <arpa/inet.h>
#include <pthread.h>

#include <polarssl/cipher.h>
#include <polarssl/md.h>

#include "protocol.h"
#include "crypto.h"
#include "hopper.h"

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
	if(state & ARG_DO_CONN)
		return send_arg_conn_data(local, remote, 0);
	else if(state & ARG_DO_AUTH)
		return send_arg_ping(local, remote);
	else
		return 0;
}

char send_arg_ping(struct arg_network_info *local,
				   struct arg_network_info *remote)
{
	struct argmsg *msg = NULL;
	
	arglog(LOG_DEBUG, "Sending ping to %s\n", remote->name);

	msg = create_arg_msg(sizeof(remote->proto.pingID));
	if(msg == NULL)
	{
		arglog(LOG_DEBUG, "Unable to allocate space to send ping\n");
		return -1;
	}

	pthread_spin_lock(&remote->lock);

	get_random_bytes(&remote->proto.pingID, sizeof(remote->proto.pingID));
	memcpy(msg->data, &remote->proto.pingID, msg->len);

	if(send_arg_packet(local, remote, ARG_PING_MSG, msg) == 0)
		current_time(&remote->proto.pingSentTime);
	else
		arglog(LOG_DEBUG, "Failed to send ARG ping\n");

	pthread_spin_unlock(&remote->lock);

	free_arg_msg(msg);

	return 0;
}

char process_arg_ping(struct arg_network_info *local,
					  struct arg_network_info *remote,
					  const struct packet_data *packet)
{
	char status = 0;
	struct argmsg *msg = NULL;

	arglog(LOG_DEBUG, "Received ping from %s\n", remote->name);
	
	if(process_arg_packet(local, remote, packet, &msg))
	{
		arglog(LOG_DEBUG, "Stopping pong processing\n");
		return -1;
	}

	if(msg->len == sizeof(remote->proto.pingID))
	{
		// Echo back their data
		status = send_arg_packet(local, remote, ARG_PONG_MSG, msg);
	}
	else
	{
		arglog(LOG_DEBUG, "Not sending pong, data not a proper ping ID\n");
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
	
	arglog(LOG_DEBUG, "Received pong from %s\n", remote->name);
	
	if(process_arg_packet(local, remote, packet, &msg))
	{
		arglog(LOG_DEBUG, "Stopping pong processing\n");
		return -1;
	}

	if(msg->data == NULL || msg->len != sizeof(remote->proto.pingID))
	{
		arglog(LOG_DEBUG, "Not accepting pong, data not a proper ping ID\n");
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
			status = 0;
			arglog(LOG_DEBUG, "Latency to %s: %li ms\n", remote->name, remote->proto.latency);
		}
		else
		{
			// We sent one, but the ID was incorrect. The remote gateway
			// had the wrong ID or it did not have the correct global key
			// Either way, we don't trust them now
			arglog(LOG_DEBUG, "The ping ID was incorrect, rejecting other gateway (expected %i, got %i)\n", remote->proto.pingID, *id);
			status = 0;
		}
	}
	else
	{
		arglog(LOG_DEBUG, "Not accepting pong, no ping sent\n");
		status = -3;
	}
	
	// All done with a ping/auth
	remote->proto.state &= ~ARG_DO_AUTH;
	
	pthread_spin_unlock(&remote->lock);
	
	free_arg_msg(msg);
	do_next_action(local, remote);
	
	return status;
}

// Connect
char send_arg_conn_data(struct arg_network_info *local,
							struct arg_network_info *remote,
							char isResponse)
{
	struct argmsg *msg = NULL;
	struct arg_conn_data *connData = NULL;

	arglog(LOG_DEBUG, "Sending connect information to %s\n", remote->name);

	// Build message
	msg = create_arg_msg(sizeof(struct arg_conn_data));
	if(msg == NULL)
	{
		arglog(LOG_DEBUG, "Unable to allocate space to send connect request\n");
		return -2;
	}

	connData = (struct arg_conn_data*)msg->data;
	memcpy(connData->symKey, local->symKey, sizeof(connData->symKey));
	memcpy(connData->iv, local->iv, sizeof(connData->iv));
	memcpy(connData->hopKey, local->hopKey, sizeof(connData->hopKey));
	connData->hopInterval = htonl(local->hopInterval);
	connData->timeOffset = htonl(current_time_offset(&local->timeBase));

	pthread_spin_lock(&remote->lock);

	//arglog(LOG_DEBUG, "We are presently at hop %lu / %lu = %lu\n", ntohl(connData->timeOffset), local->hopInterval, (ntohl(connData->timeOffset) / local->hopInterval));

	// Send
	if(send_arg_packet(local, remote,
			(isResponse ? ARG_CONN_DATA_RESP_MSG : ARG_CONN_DATA_REQ_MSG), msg) < 0)
	{
		arglog(LOG_DEBUG, "Failed to send ARG connection data\n");
	}

	pthread_spin_unlock(&remote->lock);

	free_arg_msg(msg);

	return 0;
}

char process_arg_conn_data_req(struct arg_network_info *local,
							   struct arg_network_info *remote,
							   const struct packet_data *packet)
{
	int ret = 0;
	if((ret = process_arg_conn_data_resp(local, remote, packet)) < 0)
		return ret;

	return send_arg_conn_data(local, remote, 1);
}

char process_arg_conn_data_resp(struct arg_network_info *local,
								struct arg_network_info *remote,
								const struct packet_data *packet)
{
	char status = 0;
	struct argmsg *msg = NULL;
	struct arg_conn_data *connData = NULL; 

	arglog(LOG_DEBUG, "Received connection data from %s\n", remote->name);
	
	if(process_arg_packet(local, remote, packet, &msg))
	{
		arglog(LOG_DEBUG, "Stopping connection data processing\n");
		return -1;
	}

	if(msg->len == sizeof(struct arg_conn_data))
	{
		pthread_spin_lock(&remote->lock);
		
		connData = (struct arg_conn_data*)msg->data;
		
		memcpy(remote->symKey, connData->symKey, sizeof(remote->symKey));
		memcpy(remote->iv, connData->iv, sizeof(remote->iv));
		
		// TBD do this completely separately in time message?
		memcpy(remote->hopKey, connData->hopKey, sizeof(remote->hopKey));
		remote->hopInterval = ntohl(connData->hopInterval);
		current_time_plus(&remote->timeBase, -ntohl(connData->timeOffset));

		/*arglog(LOG_DEBUG, "Time base for remote %s is now %lus %luns, at hop %li\n",
			remote->name, remote->timeBase.tv_sec, remote->timeBase.tv_nsec,
			(current_time_offset(&remote->timeBase) / remote->hopInterval));*/

		// Initialize AES/SHA for this new data
		cipher_setkey(&remote->cipher, remote->symKey, sizeof(remote->symKey) * 8, POLARSSL_ENCRYPT);
		md_hmac_starts(&remote->md, remote->symKey, sizeof(remote->symKey));

		remote->connected = 1;
		current_time(&remote->lastDataUpdate);
		
		pthread_spin_unlock(&remote->lock);
	}
	else
	{
		arglog(LOG_DEBUG, "Connection not properly sized\n");
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
	
	// Must be connected
	if(!remote->connected)
	{
		arglog(LOG_DEBUG, "Refusing to wrap packet, %s is not authenticated/connected\n", remote->name);
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
	
	// Must be connected
	if(!remote->connected)
	{
		arglog(LOG_DEBUG, "Refusing to unwrap packet, %s is not authenticated/connected\n", remote->name);
		pthread_spin_unlock(&remote->lock);
		return -1;
	}

	if(process_arg_packet(local, remote, packet, &msg))
	{
		arglog(LOG_DEBUG, "Stopping connection data processing\n");
		pthread_spin_unlock(&remote->lock);
		return -2;
	}
	
	// Just need to send this message on as a packet
	newPacket = create_packet(msg->len);
	if(newPacket == NULL)
	{
		arglog(LOG_DEBUG, "Unable to create new packet to drop into internal network\n");
		free_arg_msg(msg);
		pthread_spin_unlock(&remote->lock);
		return -3;
	}

	memcpy(newPacket->data, msg->data, msg->len);
	parse_packet(newPacket);
	status = send_packet(newPacket);

	pthread_spin_unlock(&remote->lock);

	free_arg_msg(msg);
	free_packet(newPacket);

	return status;
}

char send_arg_packet(struct arg_network_info *local,
					 struct arg_network_info *remote,
					 int type,
					 const struct argmsg *msg)
{
	int i = 0;
	int blockSize;
	size_t ilen;
	size_t olen;

	int ret;
	struct packet_data *packet = NULL;
	uint16_t fullLen = 0;
	uint8_t hash[SHA1_HASH_SIZE];

	uint8_t nounce[AES_BLOCK_SIZE];

	// Create packet we will build within, giving it plenty of extra space (encryption padding and such)
	fullLen = 20 + ARG_HDR_LEN;
	if(msg != NULL)
		fullLen += msg->len;
	fullLen += local->rsa.len;
	packet = create_packet(fullLen);
	if(packet == NULL)
	{
		arglog(LOG_DEBUG, "Unable to allocate space for ARG packet\n");
		return -1;
	}
	
	// Ensure IPs are up-to-date
	update_ips(local);
	update_ips(remote);

	// IP header
	packet->ipv4->version = 4;
	packet->ipv4->ihl = 5;
	packet->ipv4->ttl = 32;
	packet->ipv4->tos = 0;
	packet->ipv4->protocol = ARG_PROTO;
	memcpy(&packet->ipv4->saddr, local->currIP, sizeof(packet->ipv4->saddr));
	memcpy(&packet->ipv4->daddr, remote->currIP, sizeof(packet->ipv4->daddr));
	packet->ipv4->id = 0;
	packet->ipv4->frag_off = 0;
	packet->ipv4->tot_len = htons(packet->ipv4->ihl * 4);
	packet->ipv4->check = 0;

	parse_packet(packet);

	// Basic info
	packet->arg->version = 1;
	packet->arg->type = type;
	packet->arg->seq = htonl(remote->proto.outSeqNum++);
	
	// Encrypt
	if(msg != NULL)
	{
		if(type == ARG_WRAPPED_MSG)
		{
			// Symmetric encryption with remote symmetric key
			memcpy(nounce, remote->iv, sizeof(nounce));
			for(i = 0; i < sizeof(packet->arg->seq); i++)
				nounce[i] ^= ((packet->arg->seq >> (i * 8)) & 0xFF);
			cipher_reset(&remote->cipher, nounce);

			blockSize = cipher_get_block_size(&remote->cipher);

			packet->arg->len = 0;

			for(i = 0; i < msg->len; i += blockSize)
			{
				ilen = (size_t)(msg->len - i);
				if(ilen > blockSize)
					ilen = blockSize;

				cipher_update(&remote->cipher, msg->data + i, ilen, packet->unknown_data + i, &olen);
			
				packet->arg->len += olen;
			}

			packet->arg->len = htons(packet->arg->len + ARG_HDR_LEN);
		}
		else
		{
			// Admin packets can be at most keysize/8 bytes (ie, 128 bytes for a 1024 bit key)
			if(msg->len > remote->rsa.len)
			{
				arglog(LOG_DEBUG, "Admin packet data must be %lu bytes or less\n", remote->rsa.len);
				free_packet(packet);
				return -2;
			}

			// RSA encryption with destination public key
			packet->arg->len = htons((uint16_t)remote->rsa.len + ARG_HDR_LEN);
			rsa_pkcs1_encrypt(&remote->rsa, ctr_drbg_random, &local->ctr_drbg, RSA_PUBLIC,
				msg->len, msg->data, packet->unknown_data);
		}
	}
	else
		packet->arg->len = htons(ARG_HDR_LEN);

	packet->len = ntohs(packet->ipv4->tot_len) + ntohs(packet->arg->len);
	packet->ipv4->tot_len = htons(packet->len);
	
	//arglog(LOG_DEBUG, "seq num out %u\n", packet->arg->seq);

	if(type == ARG_WRAPPED_MSG)
	{
		// HMAC using local symmetric key
		md_hmac_starts(&local->md, local->symKey, sizeof(local->symKey));
		md_hmac_update(&local->md, (uint8_t*)packet->arg, ntohs(packet->arg->len));
		md_hmac_finish(&local->md, packet->arg->sig);
	}
	else
	{
		// Sign with private key
		sha1((uint8_t*)packet->arg, ntohs(packet->arg->len), hash);
		if((ret = rsa_pkcs1_sign(&local->rsa, NULL, NULL, RSA_PRIVATE, SIG_RSA_SHA1,
			sizeof(hash), hash, packet->arg->sig)) != 0)
		{
			arglog(LOG_DEBUG, "Unable to sign, error %i\n", ret);
			free_packet(packet);
			return -3;
		}
	}

	// Send!
	if(send_packet(packet) < 0)
	{
		arglog(LOG_DEBUG, "Failed to send ARG packet\n");
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
	int i = 0;
	int blockSize;
	size_t ilen;
	size_t olen;

	uint8_t hash[SHA1_HASH_SIZE];
	uint8_t nounce[AES_BLOCK_SIZE];

	char recheckSeq = 0;

	int ret;
	size_t len;
	uint16_t argLen;

	struct packet_data *newPacket = NULL;
	struct argmsg *out = NULL;

	// Look at the sequence number and see if it makes sense
	//arglog(LOG_DEBUG, "seq num in %u\n", packet->arg->seq);
	if(ntohl(packet->arg->seq) > remote->proto.inSeqNum
		|| (ntohl(packet->arg->seq) < SEQ_NUM_WRAP_ALLOWANCE
			&& remote->proto.inSeqNum > UINT16_MAX - SEQ_NUM_WRAP_ALLOWANCE))
	{
		remote->proto.inSeqNum = ntohl(packet->arg->seq);
	}
	else if(packet->arg->type == ARG_CONN_DATA_REQ_MSG)
	{
		// IF this is an initial data send, then they must be using a new IV (compared to
		// what we have currently). We will check once everything is decrypted
		recheckSeq = 1;
	}
	else
	{
		// Fail, sequence numbers should always advance (except for wrap-around)
		arglog(LOG_DEBUG, "Sequence number not monotonic (got %u, should be > %u)\n", ntohl(packet->arg->seq), remote->proto.inSeqNum);
		return -2;
	}
	
	// Duplicate packet so we can remove the hash and check
	newPacket = copy_packet(packet);
	if(newPacket == NULL)
	{
		arglog(LOG_DEBUG, "Unable to duplicate packet for checking\n");
		return -1;
	}

	argLen = ntohs(newPacket->arg->len);
	
	memset(newPacket->arg->sig, 0, sizeof(newPacket->arg->sig));
	if(newPacket->arg->type == ARG_WRAPPED_MSG)
	{
		// Check hmac with remote symmetric key
		md_hmac_starts(&remote->md, remote->symKey, sizeof(remote->symKey));
		md_hmac_update(&remote->md, (uint8_t*)newPacket->arg, ntohs(newPacket->arg->len));
		md_hmac_finish(&remote->md, newPacket->arg->sig);

		if(memcmp(newPacket->arg->sig, packet->arg->sig, sizeof(newPacket->arg->sig)))
		{
			arglog(LOG_DEBUG, "Unable to verify hmac\n");
			free_packet(newPacket);
			return -3;
		}
	}
	else
	{
		// Check private key signature
		sha1((uint8_t*)newPacket->arg, argLen, hash);
		if((ret = rsa_pkcs1_verify(&remote->rsa, RSA_PUBLIC, SIG_RSA_SHA1,
			sizeof(hash), hash, packet->arg->sig)) != 0 )
		{
			arglog(LOG_DEBUG, "Unable to verify signature, error %i\n", ret);
			free_packet(newPacket);
			return -3;
		}
	}

	// Decrypt
	if(argLen > ARG_HDR_LEN)
	{
		out = create_arg_msg(argLen);
		if(out == NULL)
		{
			arglog(LOG_DEBUG, "Unable to allocate space to write decrypted message\n");
			free_packet(newPacket);
			return -3;
		}

		if(newPacket->arg->type == ARG_WRAPPED_MSG)
		{
			// Symmetric decrypt using local symmetric key
			memcpy(nounce, local->iv, sizeof(nounce));
			for(i = 0; i < sizeof(newPacket->arg->seq); i++)
				nounce[i] ^= ((newPacket->arg->seq >> (i * 8)) & 0xFF);
			cipher_reset(&local->cipher, nounce);

			blockSize = cipher_get_block_size(&local->cipher);

			out->len = 0;

			for(i = 0; i < argLen - ARG_HDR_LEN; i += blockSize)
			{
				ilen = (size_t)(argLen - ARG_HDR_LEN - i);
				if(ilen > blockSize)
					ilen = blockSize;

				cipher_update(&local->cipher, packet->unknown_data + i, ilen, out->data + i, &olen);
				out->len += olen;
			}
		}
		else
		{
			// Decrypt with local private key
			if((ret = rsa_pkcs1_decrypt(&local->rsa, RSA_PRIVATE, &len,
				newPacket->unknown_data, out->data, out->len)) != 0)
			{
				arglog(LOG_DEBUG, "Unable to decrypt packet contents, error %i\n", ret);
				free_arg_msg(out);
				free_packet(newPacket);
				return -4;
			}

			out->len = len;
		}
		
		//arglog(LOG_DEBUG, "msg from packet");
		//printRaw(out->len, out->data);
		
		*msg = out;
	}
	else
		*msg = NULL;
	
	// Allow improper sequence number through if this is a seemingly valid connection
	// data packet. This lets gateways die and then rejoin
	if(recheckSeq)
	{
		if(*msg == NULL)
			return -2;
		
		if(memcmp(((struct arg_conn_data*)out->data)->iv, remote->iv, sizeof(remote->iv)) == 0)
			return -2;
		
		remote->proto.inSeqNum = ntohl(packet->arg->seq);
	}
	
	free_packet(newPacket);

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

