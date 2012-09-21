#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>

#include "protocol.h"
#include "hopper.h"

char send_arg_ping(struct arg_network_info *srcGate,
				   struct arg_network_info *destGate)
{
	char *hi = "hifromping";
	char r = send_arg_packet(srcGate, destGate, ARG_PING_MSG, NULL, hi, strlen(hi));
	srcGate->pingSentTime = jiffies;
	srcGate->state &= HOP_STATE_PING_SENT;
	return r;
}

char send_arg_pong(struct arg_network_info *srcGate,
				   struct arg_network_info *destGate)
{
	send_arg_packet(srcGate, destGate, ARG_PONG_MSG, NULL, NULL, 0);
	return 1;
}

char process_arg_pong(struct arg_network_info *srcGate)
{
	srcGate->latency = (jiffies - srcGate->pingSentTime) / 2;
	srcGate->state &= ~HOP_STATE_PING_SENT;
	return 1;
}

char send_arg_auth(struct arg_network_info *srcGate,
					   struct arg_network_info *destGate,
					   __u32 localID,
					   __u32 remoteID)
{
	return 1;	
}

char send_arg_connect(struct arg_network_info *srcGate,
					  struct arg_network_info *destGate)
{
	return 1;
	//return send_arg_packet(srcGate, destGate, data, dlen);
}

char send_arg_packet(struct arg_network_info *srcGate,
					 struct arg_network_info *destGate,
					 int type,
					 uchar *hmacKey,
					 uchar *data, int dlen)
{
	struct arghdr *hdr = NULL;
	uchar *fullData = NULL;
	int fullLen = dlen + ARG_HDR_LEN;

	// Create wrapper around data
	fullData = kmalloc(fullLen, GFP_KERNEL);
	if(fullData == NULL)
	{
		printk("ARG: Unable to allocate space to create ARG packet\n");
		return 0;
	}

	memset(fullData, 0, fullLen);
	hdr = (struct arghdr *)fullData;
	hdr->version = 1;
	hdr->type = type;
	hdr->len = fullLen;
	
	if(data != NULL && dlen > 0)
		memmove(fullData + ARG_HDR_LEN, data, dlen);

	if(hmacKey != NULL)
		hmac_sha1(hmacKey, AES_KEY_SIZE, fullData, fullLen, hdr->hmac);
	
	// Ensure IPs are up-to-date and send it on its way
	update_ips(srcGate);
	update_ips(destGate);
	return send_packet(srcGate->currIP, destGate->currIP, fullData, fullLen);
}

char send_packet(uchar *srcIP, uchar *destIP, uchar *data, int dlen)
{
	// A lot of this code is taken from pkggen.c/fill_packet_ipv4()
	struct socket *s = NULL;
	struct sockaddr_in addr;
	
	int r = -1;

	uchar *fullData = NULL;
	int fullDataLen;
	
	int iplen;
	struct iphdr *iph;

	struct msghdr msg;
	struct iovec iov;
	
	mm_segment_t oldfs;

	// Compose message
	fullDataLen = 20 + dlen;
	fullData = kmalloc(fullDataLen, GFP_KERNEL);
	if(fullData == NULL)
	{
		printk(KERN_ALERT "ARG: Unable to allocate space for adding IP header to packet\n");
		return 0;
	}

	iph = (struct iphdr*)fullData;
	iph->ihl = 5;
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

	memmove(fullData + 20, data, dlen);

	printk("ARG: thing we want to send:");
	printRaw(fullDataLen, fullData);

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
		return 0;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	r = sock_sendmsg(s, &msg, dlen);
	set_fs(oldfs);

	if(r < 0)
	{
		printk(KERN_ALERT "ARG: Error in sendmsg: %i\n", r);
		kernel_sock_shutdown(s, SHUT_RDWR);
		return 0;
	}

	kernel_sock_shutdown(s, SHUT_RDWR);
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
	*data = skb_transport_header(skb);
	*dlen = skb->len - skb_network_header_len(skb);
	return 1;	
}

