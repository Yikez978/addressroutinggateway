#include <stdio.h>
#include <errno.h>

#include <arpa/inet.h>
#include <pthread.h>

#include <polarssl/cipher.h>
#include <polarssl/md.h>

#include "protocol.h"
#include "arg_error.h"
#include "crypto.h"
#include "hopper.h"

void init_protocol_locks(void)
{

}

void start_time_sync(struct arg_network_info *local, struct arg_network_info *remote)
{
	remote->proto.sendPing = true;
}

void start_connection(struct arg_network_info *local, struct arg_network_info *remote)
{
	remote->proto.sendConnData = true;
}

void end_connection(struct arg_network_info *local, struct arg_network_info *remote)
{
	gate->proto.timeBaseAvailable = false;
	gate->proto.connDataAvailable = false;
	gate->connected = false;
}

int do_next_protocol_action(struct arg_network_info *local, struct arg_network_info *remote)
{
	int ret = 0;

	// Do whatever is requested, although don't exceed the maximum rates

	if(remote->proto.sendPing && current_time_offset(&remote->proto.pingSentTime) > MIN_PING_TIME * 1000)
	{
		if(!(ret = send_arg_ping(local, remote)))
			remote->proto.sendPing = false;
	}

	if(remote->proto.sendConnData
		&& current_time_offset(&remote->proto.lastConnAttemptTime) > CONNECT_WAIT_TIME * 1000)
	{
		if(!(ret = send_arg_conn_data(local, remote, false)))
			remote->proto.sendConnData = false;
	}

	if(remote->proto.sendTrust && remote->connected)
	{
		if(!(ret = send_all_trust(local, remote)))
			remote->proto.sendTrust = false;
	}

	return ret;
}

int send_arg_ping(struct arg_network_info *local,
				   struct arg_network_info *remote)
{
	int ret;
	struct argmsg *msg = NULL;

	arglog(LOG_DEBUG, "Sending ping to %s\n", remote->name);

	msg = create_arg_msg(sizeof(struct arg_ping_data));
	if(msg == NULL)
	{
		arglog(LOG_DEBUG, "Unable to allocate space to send ping\n");
		return -ENOMEM;
	}

	pthread_mutex_lock(&remote->lock);

	struct arg_ping_data *data = (struct arg_ping_data*)msg->data;
	get_random_bytes(&remote->proto.sentPingID, sizeof(remote->proto.sentPingID));

	data->requestID = htonl(remote->proto.sentPingID);
	data->responseID = 0; // This is the original send, we don't know their ID yet

	// Allow them to update their timeBase for us. This really won't be used until
	// a ping RESPONSE, because that allows the latency for that particular packet
	// to be applied, but just to keep everything consistent we'll place it here as well
	data->timeOffset = htonl(current_time_offset(&local->timeBase));

	current_time(&remote->proto.pingSentTime);

	// Create and send
	if((ret = send_arg_packet(local, remote, ARG_PING_MSG, msg, "ping sent", NULL)) < 0)
		arglog(LOG_DEBUG, "Failed to send ping\n");

	pthread_mutex_unlock(&remote->lock);
	free_arg_msg(msg);

	return ret;
}

int process_arg_ping(struct arg_network_info *local,
					  struct arg_network_info *remote,
					  const struct packet_data *packet)
{
	int ret;
	struct argmsg *msg = NULL;

	arglog(LOG_DEBUG, "Received ping from %s\n", remote->name);
	
	if((ret = process_arg_packet(local, remote, packet, &msg)))
	{
		arglog(LOG_DEBUG, "Stopping ping processing\n");
		return ret;
	}

	if(msg->len == sizeof(struct arg_ping_data))
	{
		struct arg_ping_data *data = (struct arg_ping_data*)msg->data;
		bool accepted = false;

		pthread_mutex_lock(&remote->lock);

		// Is this a response to a ping? We can tell because responseID will be set,
		// hopefully giving the same data as what we recorded when we original sent
		if(data->responseID)
		{
			if(remote->proto.sentPingID == ntohl(data->responseID))
			{
				// Latency of this particular exchange
				long latency = current_time_offset(&remote->proto.pingSentTime);
				latency /= 2;

				// Save the new time offset they gave us, adjusted backwards for the latency
				struct timespec newBase;
				current_time_plus(&newBase, -ntohl(data->timeOffset) - latency);
				int diff = time_offset(&remote->timeBase, &newBase);
				if(diff < -LARGE_TIMEBASE_CHANGE || diff > LARGE_TIMEBASE_CHANGE)
					arglog(LOG_ALERT, "Time base changed by %i milliseconds. Connection may be unstable\n", diff);

				if(remote->timeBase.tv_sec > 0)
				{
					arglog(LOG_DEBUG, "Setting average time base for %s (was %li %li, new %li %li)\n", remote->name, remote->timeBase.tv_sec, remote->timeBase.tv_nsec, newBase.tv_sec, newBase.tv_nsec);
					time_plus(&remote->timeBase, diff/2);
				}
				else
				{
					arglog(LOG_DEBUG, "Setting initial time base for %s\n", remote->name);
					remote->timeBase.tv_sec = newBase.tv_sec;
					remote->timeBase.tv_nsec = newBase.tv_nsec;
				}
				
				// Average in latency
				if(remote->proto.latency > 0)
				{
					// We heavily prefer our previous latency here because new hops will result in a doubled
					// latency, due to the new ARP being sent. If the hop rate is fast, then this will occur
					// often and we can anticipate the generally high delay. Otherwise, the low latency will
					// be the typical value. Either way, we want to go towards the more common value and ignore
					// the outliers either way.
					remote->proto.latency = remote->proto.latency * .75 + latency * .25;
				}
				else
					remote->proto.latency = latency;

				arglog(LOG_DEBUG, "Latency of this packet was %li, %s latency set to %li ms\n",
					latency, remote->name, remote->proto.latency);

				// If the change was large (greater than... 25%, let's say), then ping again soon
				diff = remote->proto.latency - latency;
				if(diff < 0)
					diff = -diff;
				if(diff > remote->proto.latency / 4)
					remote->proto.sendPing = true;

				// Fully connected now?
				remote->proto.timeBaseAvailable = true;
				if(remote->proto.connDataAvailable)
					remote->connected = true;

				ret = 0;
				accepted = true;
			}
			else
				arglog(LOG_DEBUG, "Ping response ID incorrect. Got %i, should be %i\n", ntohl(data->responseID), remote->proto.sentPingID);
		}

		// Do they want a response ping?
		if(data->requestID)
		{
			// Echo back their ID and OUR timeOffset, allowing them to adjust it based on the latency
			// of this particular exchange.
			data->responseID = data->requestID;
			data->timeOffset = htonl(current_time_offset(&local->timeBase));

			// Only request a response if this packet didn't include one
			if(!data->responseID)
			{
				get_random_bytes(&remote->proto.sentPingID, sizeof(remote->proto.sentPingID));
				data->requestID = htonl(remote->proto.sentPingID);
			}
			else
				data->requestID = 0;

			accepted = true;
			if((ret = send_arg_packet(local, remote, ARG_PING_MSG, msg, "pong sent", NULL)) < 0)
				arglog(LOG_DEBUG, "Failed to send pong\n");
		}
	
		// Record packet reception
		if(accepted)
			arglog_result(packet, NULL, 1, 1, "Admin", "ping accepted");

		pthread_mutex_unlock(&remote->lock);
	}
	else
		ret = -ARG_MSG_SIZE_BAD;
	
	free_arg_msg(msg);
	return ret;
}

// Connect
int send_arg_conn_data(struct arg_network_info *local,
						struct arg_network_info *remote,
						bool isResponse)
{
	int ret = 0;
	struct argmsg *msg = NULL;
	struct arg_conn_data *connData = NULL;

	arglog(LOG_DEBUG, "Sending connect information to %s\n", remote->name);

	// Build message
	msg = create_arg_msg(sizeof(struct arg_conn_data));
	if(msg == NULL)
	{
		arglog(LOG_DEBUG, "Unable to allocate space to send connect request\n");
		return -ENOMEM;
	}

	connData = (struct arg_conn_data*)msg->data;
	memcpy(connData->symKey, local->symKey, sizeof(connData->symKey));
	memcpy(connData->iv, local->iv, sizeof(connData->iv));
	memcpy(connData->hopKey, local->hopKey, sizeof(connData->hopKey));
	connData->hopInterval = htonl(local->hopInterval);
	connData->timeOffset = htonl(current_time_offset(&local->timeBase));

	pthread_mutex_lock(&remote->lock);

	//arglog(LOG_DEBUG, "We are presently at hop %lu / %lu = %lu\n", ntohl(connData->timeOffset), local->hopInterval, (ntohl(connData->timeOffset) / local->hopInterval));

	// Send
	if((ret = send_arg_packet(local, remote,
			(isResponse ? ARG_CONN_DATA_RESP_MSG : ARG_CONN_DATA_REQ_MSG), msg,
			"connection data sent", NULL)) < 0)
		arglog(LOG_DEBUG, "Failed to send connection data: error %i\n", ret);
	
	if(!ret)
		current_time(&remote->proto.lastConnAttemptTime);

	pthread_mutex_unlock(&remote->lock);
	free_arg_msg(msg);

	return ret;
}

int process_arg_conn_data_req(struct arg_network_info *local,
							   struct arg_network_info *remote,
							   const struct packet_data *packet)
{
	int ret = 0;
	if((ret = process_arg_conn_data_resp(local, remote, packet)) < 0)
		return ret;

	if((ret = send_arg_conn_data(local, remote, true)) < 0)
		return ret;

	remote->proto.sendPing = true;
	remote->proto.sendTrust = true;

	return ret;
}

int process_arg_conn_data_resp(struct arg_network_info *local,
								struct arg_network_info *remote,
								const struct packet_data *packet)
{
	int ret;
	int status = 0;
	struct argmsg *msg = NULL;
	struct arg_conn_data *connData = NULL; 

	arglog(LOG_DEBUG, "Received connection data from %s\n", remote->name);
	
	if((ret = process_arg_packet(local, remote, packet, &msg)))
	{
		arglog(LOG_DEBUG, "Stopping connection data processing\n");
		return ret;
	}

	if(msg->len == sizeof(struct arg_conn_data))
	{
		pthread_mutex_lock(&remote->lock);
		
		connData = (struct arg_conn_data*)msg->data;
		
		memcpy(remote->symKey, connData->symKey, sizeof(remote->symKey));
		memcpy(remote->iv, connData->iv, sizeof(remote->iv));
		
		memcpy(remote->hopKey, connData->hopKey, sizeof(remote->hopKey));
		remote->hopInterval = ntohl(connData->hopInterval);

		/*arglog(LOG_DEBUG, "Time base for remote %s is now %lus %luns, at hop %li\n",
			remote->name, remote->timeBase.tv_sec, remote->timeBase.tv_nsec,
			(current_time_offset(&remote->timeBase) / remote->hopInterval));*/

		// Initialize AES/SHA for this new data
		cipher_setkey(&remote->cipher, remote->symKey, sizeof(remote->symKey) * 8, POLARSSL_ENCRYPT);
		md_hmac_starts(&remote->md, remote->symKey, sizeof(remote->symKey));

		current_time(&remote->lastDataUpdate);

		// We no longer use the time base from connection data. Instead, we wait to get it in ping packets
		remote->proto.connDataAvailable = true;
		if(remote->proto.timeBaseAvailable)
			remote->connected = true;

		pthread_mutex_unlock(&remote->lock);
	}
	else
	{
		arglog(LOG_DEBUG, "Connection not properly sized\n");
		status = -ARG_MSG_SIZE_BAD;
	}
	
	free_arg_msg(msg);

	if(!status)
		arglog_result(packet, NULL, 1, 1, "Admin", "connection data received");

	if(!status)
	{
		remote->proto.sendPing = true;
		remote->proto.sendTrust = true;
	}

	return status;
}

// Trust packets. Allow gateways we know to tell us about ones they know
int send_all_trust(struct arg_network_info *local,
					struct arg_network_info *remote)
{
	struct arg_network_info *curr = NULL;
	char ret = 0;

	arglog(LOG_DEBUG, "Sending all trust data from %s\n", local->name);

	// Send data an each gate we know about to remote. Obviously,
	// skip ourselves and the remote
	curr = local;
	while(curr)
	{
		curr = curr->next;
	
		if(curr == NULL)
			break;
		if(curr == local)
			continue;
		if(curr == remote)
			continue;

		if(send_arg_trust(local, remote, curr))
			ret = 1;
	}

	return ret;
}

int send_arg_trust(struct arg_network_info *local,
					struct arg_network_info *remote,
					struct arg_network_info *gate)
{
	struct argmsg *msg = NULL;
	struct arg_trust_data *trust = NULL;
	int ret = 0;

	arglog(LOG_DEBUG, "Sending trust information about %s to %s\n", gate->name, remote->name);

	// Build message
	msg = create_arg_msg(sizeof(struct arg_trust_data));
	if(msg == NULL)
	{
		arglog(LOG_ALERT, "Unable to allocate space to send trust data\n");
		return -ENOMEM;
	}

	trust = (struct arg_trust_data*)msg->data;
	strncpy(trust->name, gate->name, sizeof(trust->name) - 1);
	memcpy(trust->baseIP, gate->baseIP, sizeof(trust->baseIP));
	memcpy(trust->mask, gate->mask, sizeof(trust->mask));
	if((ret = mpi_write_binary(&gate->rsa.N, trust->n, sizeof(trust->n))))
	{
		arglog(LOG_ALERT, "Failed to write N to trust data, got error %i\n", ret);
		free_arg_msg(msg);
		return -ARG_CONFIG_BAD;
	}
	if((ret = mpi_write_binary(&gate->rsa.E, trust->e, sizeof(trust->e))))
	{
		arglog(LOG_ALERT, "Failed to write E to trust data, got error %i\n", ret);
		free_arg_msg(msg);
		return -ARG_CONFIG_BAD;
	}

	pthread_mutex_lock(&remote->lock);

	// Send
	if(send_arg_packet(local, remote, ARG_TRUST_DATA_MSG, msg, "trust data sent", NULL) < 0)
		arglog(LOG_ALERT, "Failed to send ARG trust data\n");

	pthread_mutex_unlock(&remote->lock);

	free_arg_msg(msg);

	return 0;
}

int process_arg_trust(struct arg_network_info *local,
						struct arg_network_info *remote,
						const struct packet_data *packet)
{
	int status = 0;
	int ret = 0;
	struct argmsg *msg = NULL;
	struct arg_trust_data *trust = NULL;

	struct arg_network_info *newGate = NULL;
	struct arg_network_info *curr = NULL;

	arglog(LOG_DEBUG, "Received trust data from %s\n", remote->name);
	
	if((ret = process_arg_packet(local, remote, packet, &msg)) < 0)
	{
		arglog(LOG_DEBUG, "Stopping trust data processing\n");
		return ret;
	}

	if(msg->len == sizeof(struct arg_trust_data))
	{
		// See if we already know about this gate
		trust = (struct arg_trust_data*)msg->data;
		curr = local;
		while(curr != NULL)
		{
			arglog(LOG_DEBUG, "Checking if %s matches %s (curr ip %x, mask %x. Trust ip %x, mask %x)\n",
				curr->name, trust->name, curr->baseIP, curr->mask, trust->baseIP, trust->mask);

			if(mask_array_cmp(sizeof(trust->baseIP), curr->mask, curr->baseIP, trust->baseIP) == 0)
			{
				arglog(LOG_ALERT, "Already know about %s\n", trust->name);
				free_arg_msg(msg);
				arglog_result(packet, NULL, 1, 1, "Admin", "trust data received");
				return 0;
			}
			
			curr = curr->next;
		}
		
		// Create a new gate
		newGate = create_arg_network_info();
		
		strncpy(newGate->name, trust->name, sizeof(newGate->name) - 1);
		memcpy(newGate->baseIP, trust->baseIP, sizeof(newGate->baseIP));
		memcpy(newGate->mask, trust->mask, sizeof(newGate->mask));
		if((ret = mpi_read_binary(&newGate->rsa.N, trust->n, sizeof(trust->n))))
		{
			arglog(LOG_ALERT, "Failed to read N from trust data, got error %i\n", ret);
			remove_arg_network(newGate);
			free_arg_msg(msg);
			return -ARG_CONFIG_BAD;
		}
		if((ret = mpi_read_binary(&newGate->rsa.E, trust->e, sizeof(trust->e))))
		{
			arglog(LOG_ALERT, "Failed to read E from trust data, got error %i\n", ret);
			remove_arg_network(newGate);
			free_arg_msg(msg);
			return -ARG_CONFIG_BAD;
		}
		
		newGate->rsa.len = (mpi_msb(&newGate->rsa.N) + 7) >> 3;	
		mask_array(sizeof(newGate->baseIP), newGate->baseIP, newGate->mask, newGate->baseIP);

		// Hook it up
		pthread_mutex_lock(&local->lock);
		newGate->next = local->next;
		newGate->prev = local;
		local->next = newGate;
		pthread_mutex_unlock(&local->lock);

		arglog(LOG_INFO, "Added %s as a new gate\n", newGate->name);
		start_connection(local, newGate);
	}
	else
	{
		arglog(LOG_DEBUG, "Trust data not properly sized\n");
		status = -ARG_MSG_SIZE_BAD;
	}

	if(!status)
		arglog_result(packet, NULL, 1, 1, "Admin", "trust data received");
	
	free_arg_msg(msg);
	
	return status;
}

// "Normal" packets between gateways
int send_arg_wrapped(struct arg_network_info *local,
					  struct arg_network_info *remote,
					  const struct packet_data *packet)
{
	int ret;
	struct argmsg msg;
	struct packet_data *newPacket = NULL;

	pthread_mutex_lock(&remote->lock);
	
	// Must be connected
	if(!remote->connected)
	{
		arglog(LOG_DEBUG, "Refusing to wrap packet, %s is not authenticated/connected\n", remote->name);
		pthread_mutex_unlock(&remote->lock);
		return -ARG_NOT_CONNECTED;
	}
	
	// Create message containing packet data
	msg.len = packet->len - packet->linkLayerLen;
	msg.data = packet->data + packet->linkLayerLen;
	
	if((ret = create_arg_packet(local, remote, ARG_WRAPPED_MSG, &msg, &newPacket)) < 0)
	{
		arglog(LOG_DEBUG, "Unable to wrap packet\n");
		return ret;
	}
	
	if((ret = send_packet(newPacket)) >= 0)
		arglog_result(packet, newPacket, 0, 1, "Hopper", "wrapped");

	free_packet(newPacket);
	pthread_mutex_unlock(&remote->lock);

	return ret;
}

int process_arg_wrapped(struct arg_network_info *local,
						 struct arg_network_info *remote,
						 const struct packet_data *packet)
{
	int ret = 0;
	struct argmsg *msg = NULL;
	struct packet_data *newPacket = NULL;

	pthread_mutex_lock(&remote->lock);
	
	// Must be connected
	if(!remote->connected)
	{
		pthread_mutex_unlock(&remote->lock);
		return -ARG_NOT_CONNECTED;
	}

	if((ret = process_arg_packet(local, remote, packet, &msg)))
	{
		pthread_mutex_unlock(&remote->lock);
		return ret;
	}
	
	// Just need to send this message on as a packet
	newPacket = create_packet(msg->len);
	if(newPacket == NULL)
	{
		arglog(LOG_DEBUG, "Unable to create new packet to drop into internal network\n");
		free_arg_msg(msg);
		pthread_mutex_unlock(&remote->lock);
		return -ENOMEM;
	}

	memcpy(newPacket->data, msg->data, msg->len);
	parse_packet(newPacket);
	if((ret = send_packet(newPacket)) >= 0)
		arglog_result(packet, newPacket, 1, 1, "Hopper", "unwrapped");

	pthread_mutex_unlock(&remote->lock);

	free_arg_msg(msg);
	free_packet(newPacket);

	return ret;
}

int send_arg_packet(struct arg_network_info *local,
					 struct arg_network_info *remote,
					 int type, const struct argmsg *msg,
					 const char *logMsg, const struct packet_data *originalPacket)
{
	int ret = 0;
	struct packet_data *packet = NULL;

	if((ret = create_arg_packet(local, remote, type, msg, &packet)) < 0)
		return ret;

	if((ret = send_packet(packet)) >= 0)
		arglog_result(originalPacket, packet, 0, 1, "Admin", logMsg);
	else
		arglog(LOG_DEBUG, "Failed to send ARG packet\n");

	free_packet(packet);

	return ret;
}

int create_arg_packet(struct arg_network_info *local,
					 struct arg_network_info *remote,
					 int type, const struct argmsg *msg,
					 struct packet_data **packetOut)
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
		return -ENOMEM;
	}
	
	// IP header
	packet->ipv4->version = 4;
	packet->ipv4->ihl = 5;
	packet->ipv4->ttl = 32;
	packet->ipv4->tos = 0;
	packet->ipv4->protocol = ARG_PROTO;

	// We only jump forward by a quarter of the latency here for a few reasons.
	// First, without any adjustment at all we should work even with a latency of half
	// our hop rate. Second, on the test network latency frequently triples (seemingly),
	// due to the frequent ARPs that take just as long as actual packets (in the real world,
	// they would take negligible time). As a result, latency is often much higher than
	// it needs to be, but /4 always puts us into a safe realm.
	generate_ip_corrected(local, remote->proto.latency / 4, (uint8_t*)&packet->ipv4->saddr);
	generate_ip_corrected(remote, remote->proto.latency / 4, (uint8_t*)&packet->ipv4->daddr);

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
		if(type == ARG_WRAPPED_MSG || type == ARG_TRUST_DATA_MSG)
		{
			if(!remote->connected)
			{
				arglog(LOG_ALERT, "Attempt to send symmetrically-encrypted data to unconnected gateway\n");
				return -ARG_NOT_CONNECTED;
			}

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
				return -ARG_INTERNAL_ERROR;
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

	// Reparse, now that we've added in ARG informatino
	parse_packet(packet);
	
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
			return -ARG_SIGNING_FAILED;
		}
	}

	*packetOut = packet;
	return 0;
}

int process_arg_packet(struct arg_network_info *local,
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
	else if(packet->arg->type == ARG_CONN_DATA_REQ_MSG || packet->arg->type == ARG_CONN_DATA_RESP_MSG)
	{
		// IF this is an initial data send, then they must be using a new IV (compared to
		// what we have currently). We will check once everything is decrypted
		recheckSeq = 1;
	}
	else
	{
		// Fail, sequence numbers should always advance (except for wrap-around)
		arglog(LOG_DEBUG, "Sequence number not monotonic (got %u, should be > %u)\n",
			ntohl(packet->arg->seq), remote->proto.inSeqNum);
		return -ARG_SEQ_BAD;
	}
	
	// Duplicate packet so we can remove the hash and check
	newPacket = copy_packet(packet);
	if(newPacket == NULL)
	{
		arglog(LOG_DEBUG, "Unable to duplicate packet for checking\n");
		return -ENOMEM;
	}

	argLen = ntohs(newPacket->arg->len);
	
	memset(newPacket->arg->sig, 0, sizeof(newPacket->arg->sig));
	if(newPacket->arg->type == ARG_WRAPPED_MSG)
	{
		if(!remote->connected)
		{
			arglog(LOG_DEBUG, "%s is not connected, discarding packet\n", remote->name);
			free_packet(newPacket);
			return -ARG_NOT_CONNECTED;
		}
		
		// Check hmac with remote symmetric key
		md_hmac_starts(&remote->md, remote->symKey, sizeof(remote->symKey));
		md_hmac_update(&remote->md, (uint8_t*)newPacket->arg, ntohs(newPacket->arg->len));
		md_hmac_finish(&remote->md, newPacket->arg->sig);
		
		if(memcmp(newPacket->arg->sig, packet->arg->sig, sizeof(newPacket->arg->sig)))
		{
			arglog(LOG_DEBUG, "Unable to verify hmac\n");
			free_packet(newPacket);
			return -ARG_SIG_CHECK_FAILED;
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
			return -ARG_SIG_CHECK_FAILED;
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
			return -ENOMEM;
		}

		if(newPacket->arg->type == ARG_WRAPPED_MSG || newPacket->arg->type == ARG_TRUST_DATA_MSG)
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
				return -ARG_DECRYPT_FAILED;
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
		{
			arglog(LOG_DEBUG, "Failing sequence number check because message is null (got %u, should be > %u)\n",
				ntohl(packet->arg->seq), remote->proto.inSeqNum);
			return -ARG_SEQ_BAD;
		}

		if(memcmp(((struct arg_conn_data*)out->data)->iv, remote->iv, sizeof(remote->iv)) == 0)
		{
			arglog(LOG_DEBUG, "Failing sequence number check because IV did not change in new connection data (replay?) (got %u, should be > %u)\n",
				ntohl(packet->arg->seq), remote->proto.inSeqNum);
			return -ARG_SEQ_BAD;
		}
		
		arglog(LOG_DEBUG, "Resetting sequence number for %s\n", remote->name);
		remote->proto.inSeqNum = 0;
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

int get_msg_type(const struct arghdr *msg)
{
	return msg->type;
}

bool is_wrapped_msg(const struct arghdr *msg)
{
	return get_msg_type(msg) == ARG_WRAPPED_MSG;
}

bool is_admin_msg(const struct arghdr *msg)
{
	return get_msg_type(msg) != ARG_WRAPPED_MSG;
}

