#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/in.h>

#include "protocol.h"
#include "hopper.h"

char send_arg_packet(struct arg_network_info *srcGate,
					 struct arg_network_info *destGate,
					 int type, uchar *data, int dlen)
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
	
	memmove(fullData + ARG_HDR_LEN, data, dlen);

	hmac_sha1(srcGate->symKey, sizeof(srcGate->symKey), fullData, fullLen, hdr->hmac);
	
	// Ensure IPs are up-to-date and send it on its way
	update_ips(srcGate);
	update_ips(destGate);
	return send_packet(srcGate->currIP, destGate->currIP, fullData, fullLen);
}

char send_packet(uchar *srcIP, uchar *destIP, uchar *data, int dlen)
{
	struct socket *s;
	struct sockaddr_in addr;
	struct msghdr msg;
	struct iovec iov;
	mm_segment_t oldfs;
	int r = -1;

	// Compose message
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	memmove(&addr.sin_addr.s_addr, destIP, ADDR_SIZE);
	addr.sin_port = htons(7654);

	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0; // TBD flags?

	iov.iov_len = dlen;
	iov.iov_base = data;

	// Send
	r = sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &s);
	if(r < 0)
	{
		printk(KERN_ALERT "ARG: Error in create socket: %i", r);
		return 0;
	}

	r = s->ops->connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr), 0);
	if(r < 0)
	{
		printk(KERN_ALERT "ARG: Error in connect socket: %i", r);
		sock_release(s);
		return 0;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	r = sock_sendmsg(s, &msg, dlen);
	set_fs(oldfs);

	if(r < 0)
	{
		printk(KERN_ALERT "ARG: Error in sendmsg: %i", r);
		sock_release(s);
		return 0;
	}

	sock_release(s);
	return 1;
}

