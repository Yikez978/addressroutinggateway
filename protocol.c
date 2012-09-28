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
	memmove(msg->data, &remote->proto.pingID, msg->len);

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
	
	if(process_arg_packet(argGlobalKey, argGlobalKey, packet->arg, &msg))
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
	
	if(process_arg_packet(argGlobalKey, argGlobalKey, packet->arg, &msg))
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
			printf("ARG: Latency to %s: %li jiffies\n", remote->name, remote->proto.latency);
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
	struct arghdr *hdr = NULL;
	uint8_t *fullData = NULL;
	uint16_t fullLen = ARG_HDR_LEN;
	char r = 0;

	if(msg != NULL)
		fullLen += msg->len;

	// Create wrapper around data
	// TBD we could probably get a nice boost out of pre-allocating extra space
	// then just moving bytes forward as needed
	fullData = malloc(fullLen);
	if(fullData == NULL)
	{
		printf("ARG: Unable to allocate space to create ARG packet\n");
		return 0;
	}

	// TBD encrypt
	//if(encKey != NULL)
	//	;

	memset(fullData, 0, fullLen);
	hdr = (struct arghdr *)fullData;
	hdr->version = 1;
	hdr->type = type;
	hdr->len = htons(fullLen);
	
	if(msg != NULL)
		memmove(fullData + ARG_HDR_LEN, msg->data, msg->len);

	if(hmacKey != NULL)
		hmac_sha1(hmacKey, AES_KEY_SIZE, fullData, fullLen, hdr->hmac);
	
	// Ensure IPs are up-to-date and send it on its way
	update_ips(srcGate);
	update_ips(destGate);
	r = send_packet(srcGate->currIP, destGate->currIP, fullData, fullLen);
	free(fullData);
	return r;
}

char process_arg_packet(const uint8_t *hmacKey, const uint8_t *encKey,
						const struct arghdr *hdr,
						struct argmsg **msg)
{
	struct argmsg *out;
	uint8_t packetHmac[HMAC_SIZE];
	uint8_t computedHmac[HMAC_SIZE];

	// Duplicate packet so we can remove the hash and check
	out = create_arg_msg(hdr->len);
	if(out == NULL)
	{
		printf("Unable to allocate space to process arg packet\n");
		return -1;
	}

	memmove(out->data, hdr, hdr->len);

	// Check hash
	if(hmacKey != NULL)
	{
		memmove(packetHmac, &hdr->hmac, sizeof(hdr->hmac));
		
		memset(&(((struct arghdr*)(out->data))->hmac), 0, sizeof(hdr->hmac));
		hmac_sha1(hmacKey, AES_KEY_SIZE, out->data, out->len, computedHmac);
		
		if(memcmp(packetHmac, computedHmac, sizeof(hdr->hmac)) != 0)
		{
			printf("ARG: Received packet did not have a matching HMAC\n");
			return -2;
		}
	}

	// TBD unencrypt
	//if(encKey != NULL)
	//	;
	// else
	
	// Received data:
	//printf("ARG: data in thing we received:");
	//printRaw(*outLen, *out);

	*msg = out;
	
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

char send_packet(uint8_t *srcIP, uint8_t *destIP, uint8_t *data, int dlen)
{
	// A lot of this code is taken from pkggen.c/fill_packet_ipv4()
	/*struct socket *s = NULL;
	struct sockaddr_in addr;
	const int ipv4_hdrsize = 20;
	
	int r = -1;

	uint8_t *fullData = NULL;
	int fullDataLen;
	
	int iplen;
	struct iphdr *iph;

	struct msghdr msg;
	struct iovec iov;
	
	mm_segment_t oldfs;

	// Compose message
	fullDataLen = ipv4_hdrsize + dlen;
	fullData = malloc(fullDataLen);
	if(fullData == NULL)
	{
		printf("ARG: Unable to allocate space for adding IP header to packet\n");
		return 0;
	}

	iph = (struct iphdr*)fullData;
	iph->ihl = ipv4_hdrsize / 4;
	iph->version = 4;
	iph->ttl = 32;
	iph->tos = 0;
	iph->protocol = ARG_PROTO;
	memmove(&iph->saddr, srcIP, sizeof(iph->saddr));
	memmove(&iph->daddr, destIP, sizeof(iph->daddr));
	iph->id = 0;
	iph->frag_off = 0;
	iplen = fullDataLen;
	iph->tot_len = htons(iplen);
	iph->check = 0;
	iph->check = ip_fast_csum((void*)iph, iph->ihl);

	memmove(fullData + ipv4_hdrsize, data, dlen);

	//printf("ARG: thing we want to send:");
	//printRaw(fullDataLen, fullData);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	memmove(&addr.sin_addr.s_addr, destIP, ADDR_SIZE);
	addr.sin_port = htons(ARG_ADMIN_PORT);

	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0; // TBD flags?

	iov.iov_len = fullDataLen;
	iov.iov_base = fullData;

	// Send
	r = sock_create(PF_INET, SOCK_RAW, IPPROTO_RAW, &s);
	if(r < 0)
	{
		printf("ARG: Error in create socket: %i\n", r);
		free(fullData);
		return 0;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	r = sock_sendmsg(s, &msg, fullDataLen);
	set_fs(oldfs);

	kernel_sock_shutdown(s, SHUT_RDWR);
	
	free(fullData);
	
	if(r < 0)
	{
		printf("ARG: Error in sendmsg: %i\n", r);
		return 0;
	}
	else
		return 1;*/
	return 0;
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

