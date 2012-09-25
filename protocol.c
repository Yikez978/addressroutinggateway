#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/random.h>

#include "protocol.h"
#include "hopper.h"

// In a full implementation, we would use public and private keys for authentication
// and initial connection to other gateways. For the test implementation, we used a
// globally shared key for HMACs, rather than digital signatures
static const uchar argGlobalKey[AES_KEY_SIZE] = {25, -18, -127, -10,
												 67, 30, 7, -49,
												 68, -70, 19, 106,
												 -100, -11, 72, 18};

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
	else if(state & ARG_DO_TIME)
		return send_arg_time_req(local, remote);
	else if(state & ARG_DO_CONN)
		return send_arg_conn_req(local, remote);
	else
		return 1;
}

char send_arg_ping(struct arg_network_info *local,
				   struct arg_network_info *remote)
{
	char r;
	
	printk("ARG: Sending ping to ");
	printIP(sizeof(remote->baseIP), remote->baseIP);
	printk("\n");
	
	write_lock(&local->lock);
	get_random_bytes(&remote->proto.pingID, sizeof(remote->proto.pingID));

	r = send_arg_packet(local, remote, ARG_PING_MSG, argGlobalKey, argGlobalKey, (uchar*)&remote->proto.pingID, sizeof(remote->proto.pingID));
	if(r)
		remote->proto.pingSentTime = jiffies;
	
	write_unlock(&local->lock);
	
	return r;
}

char process_arg_ping(struct arg_network_info *local,
					  struct arg_network_info *remote,
					  const uchar *packet, int plen)
{
	char status = 0;
	uchar *data = NULL;
	int dlen = 0;
	
	printk("ARG: Received ping from ");
	printIP(sizeof(remote->baseIP), remote->baseIP);
	printk("\n");
	
	if(!process_arg_packet(argGlobalKey, argGlobalKey, packet, plen, &data, &dlen))
	{
		printk("ARG: Stopping pong processing\n");
		return 0;
	}

	if(dlen == sizeof(remote->proto.pingID))
		status = send_arg_packet(local, remote, ARG_PONG_MSG, argGlobalKey, argGlobalKey, data, dlen);
	else
	{
		printk("ARG: Not sending pong, data not a proper ping ID\n");
		status = 0;
	}
	
	free_arg_data(data);
	return status;
}

char process_arg_pong(struct arg_network_info *local,
					  struct arg_network_info *remote,
					  const uchar *packet, int plen)
{
	char status = 0;
	uchar *data = NULL;
	int dlen = 0;
	
	printk("ARG: Received pong from ");
	printIP(sizeof(remote->baseIP), remote->baseIP);
	printk("\n");
	
	if(!process_arg_packet(argGlobalKey, argGlobalKey, packet, plen, &data, &dlen))
	{
		printk("ARG: Stopping pong processing\n");
		return 0;
	}

	if(dlen != sizeof(remote->proto.pingID))
	{
		printk("ARG: Not accepting pong, data not a proper ping ID\n");
		free_arg_data(data);
		return 0;
	}

	write_lock(&remote->lock);

	if(remote->proto.pingSentTime != 0)
	{
		if(remote->proto.pingID == (__be32)*data)
		{
			remote->proto.latency = (jiffies - remote->proto.pingSentTime) / 2;
			remote->proto.pingSentTime = 0;
			remote->authenticated = 1;
			status = 1;
		}
		else
		{
			// We sent one, but the ID was incorrect. The remote gateway
			// had the wrong ID or it did not have the correct global key
			// Either way, we don't trust them now
			remote->authenticated = 0;
			status = 1;
		}
	}
	else
	{
		printk("ARG: Not accepting pong, no ping sent or improper ping ID\n");
		status = 0;
	}
	
	// All done with a ping/auth
	remote->proto.state &= ~ARG_DO_AUTH;
	do_next_action(local, remote);
	
	write_unlock(&remote->lock);
	
	free_arg_data(data);
	
	return status;
}

// Time
char send_arg_time_req(struct arg_network_info *local,
					   struct arg_network_info *remote)
{
	return 0;
}

char process_arg_time_req(struct arg_network_info *local,
						  struct arg_network_info *remote,
						  const uchar *packet, int plen)
{
	return 0;
}

char process_arg_time_resp(struct arg_network_info *remote, const uchar *packet, int plen)
{
	return 0;
}

// Connect
char send_arg_conn_req(struct arg_network_info *local,
					   struct arg_network_info *remote)
{
	return 0;
}

char process_arg_conn_req(struct arg_network_info *local,
						  struct arg_network_info *remote,
						  const uchar *packet, int plen)
{
	return 0;
}

char process_arg_conn_resp(struct arg_network_info *remote, const uchar *packet, int plen)
{
	return 0;
}

char send_arg_packet(struct arg_network_info *srcGate,
					 struct arg_network_info *destGate,
					 int type,
					 const uchar *hmacKey,
					 const uchar *encKey,
					 const uchar *data, int dlen)
{
	struct arghdr *hdr = NULL;
	uchar *fullData = NULL;
	__be16 fullLen = dlen + ARG_HDR_LEN;
	char r = 0;

	// Create wrapper around data
	// TBD we could probably get a nice boost out of pre-allocating extra space
	// then just moving bytes forward as needed
	fullData = kmalloc(fullLen, GFP_KERNEL);
	if(fullData == NULL)
	{
		printk("ARG: Unable to allocate space to create ARG packet\n");
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
	
	if(data != NULL && dlen > 0)
		memmove(fullData + ARG_HDR_LEN, data, dlen);

	if(hmacKey != NULL)
		hmac_sha1(hmacKey, AES_KEY_SIZE, fullData, fullLen, hdr->hmac);
	
	// Ensure IPs are up-to-date and send it on its way
	update_ips(srcGate);
	update_ips(destGate);
	r = send_packet(srcGate->currIP, destGate->currIP, fullData, fullLen);
	kfree(fullData);
	return r;
}

char process_arg_packet(const uchar *hmacKey, const uchar *encKey,
						const uchar *data, const int dlen,
						uchar **out, int *outLen)
{
	struct arghdr *hdr;
	uchar packetHmac[HMAC_SIZE];
	uchar computedHmac[HMAC_SIZE];

	hdr = (struct arghdr*)data;

	// Received data:
	printk("ARG: thing we received:");
	printRaw(dlen, data);
	
	if(hmacKey != NULL)
	{
		memmove(packetHmac, &hdr->hmac, sizeof(hdr->hmac));
		
		//printk("ARG: hmac");
		//printRaw(sizeof(hdr->hmac), packetHmac);
		
		memset(&hdr->hmac, 0, sizeof(hdr->hmac));
		hmac_sha1(hmacKey, AES_KEY_SIZE, data, dlen, computedHmac);

		//printk("ARG: zero'd:");
		//printRaw(dlen, data);
		//printk("ARG: hmac computed");
		//printRaw(sizeof(computedHmac), computedHmac);
		
		if(memcmp(packetHmac, computedHmac, sizeof(hdr->hmac)) != 0)
		{
			printk("ARG: Received packet did not have a matching HMAC\n");
			return 0;
		}
	}

	// Allocate space for decryption/data extraction
	*outLen = dlen - ARG_HDR_LEN;
	*out = kmalloc(*outLen, GFP_KERNEL);
	if(*out == NULL)
	{
		printk("ARG: Unable to allocate memory for extracting packet data\n");
		return 0;
	}
	
	// TBD unencrypt
	//if(encKey != NULL)
	//	;
	// else
	memcpy(*out, data + ARG_HDR_LEN, *outLen);
	
	// Received data:
	//printk("ARG: data in thing we received:");
	//printRaw(*outLen, *out);
	
	return 1;
}

void free_arg_data(uchar *data)
{
	if(data != NULL)
		kfree(data);
}

char send_packet(uchar *srcIP, uchar *destIP, uchar *data, int dlen)
{
	// A lot of this code is taken from pkggen.c/fill_packet_ipv4()
	struct socket *s = NULL;
	struct sockaddr_in addr;
	const int ipv4_hdrsize = 20;
	
	int r = -1;

	uchar *fullData = NULL;
	int fullDataLen;
	
	int iplen;
	struct iphdr *iph;

	struct msghdr msg;
	struct iovec iov;
	
	mm_segment_t oldfs;

	// Compose message
	fullDataLen = ipv4_hdrsize + dlen;
	fullData = kmalloc(fullDataLen, GFP_KERNEL);
	if(fullData == NULL)
	{
		printk(KERN_ALERT "ARG: Unable to allocate space for adding IP header to packet\n");
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

	//printk("ARG: thing we want to send:");
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
		printk(KERN_ALERT "ARG: Error in create socket: %i\n", r);
		kfree(fullData);
		return 0;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	r = sock_sendmsg(s, &msg, fullDataLen);
	set_fs(oldfs);

	kernel_sock_shutdown(s, SHUT_RDWR);
	kfree(fullData);
	if(r < 0)
	{
		printk(KERN_ALERT "ARG: Error in sendmsg: %i\n", r);
		return 0;
	}
	else
		return 1;
}

char get_msg_type(uchar *data, int dlen)
{
	struct arghdr *hdr = (struct arghdr *)data;
	return hdr->type;
}

char is_wrapped_msg(uchar *data, int dlen)
{
	return get_msg_type(data, dlen) == ARG_WRAPPED_MSG;
}

char is_admin_msg(uchar *data, int dlen)
{
	return get_msg_type(data, dlen) != ARG_WRAPPED_MSG;
}

char skbuff_to_msg(struct sk_buff *skb, uchar **data, int *dlen)
{
	struct iphdr *iph = (struct iphdr*)ip_hdr(skb);
	*data = skb_transport_header(skb);
	*dlen = skb->len - skb_network_header_len(skb);
	return 1;	
}

