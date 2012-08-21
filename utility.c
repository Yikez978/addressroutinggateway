#include "utility.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "net_info.h"

// Show hex of all data in buf
void printRaw(int len, const void *buf)
{
	int i = 0;
	uchar *bufC = (uchar*)buf;

	for(i = 0; i < len; i++)
	{
		// Tag beginning of line
		if(i % 16 == 0)
			printk("\nARG: [%4i]  ", i);
		
		printk("%2x ", bufC[i]);
	}

	printk("\n");
}

// Display printable data in buf
void printAscii(int len, const void *buf)
{
	char c = 0;
	int i = 0;
	int shown = 0;
	
	uchar *bufC = (uchar*)buf;

	for(i = 0; i < len; i++)
	{
		c = bufC[i];
		if(c < 32 || c > 126)
		{
			// Break current string we're displaying
			shown = 0;
			continue;
		}

		// Tag beginning of line?
		if(shown % 40 == 0)
			printk("\nARG: [%4i]  ", i);
		
		printk("%c", c);
		shown++;
	}

	printk("\n");
}

void printIP(int len, const void *buf)
{
	int i = 0;
	uchar *bufC = (uchar*)buf;

	for(i = 0; i < len; i++)
	{
		printk("%i", bufC[i]);

		if(i < len - 1)
			printk(".");
	}
}

void printPacket(const struct sk_buff *skb)
{
	printRaw(skb->len, skb->data);
}

void printPacketInfo(const struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	
	printk(" proto=%i s=", iph->protocol);
	printIP(ADDR_SIZE, (uchar*)&iph->saddr);
	printk(":%i d=", get_source_port(skb));
	printIP(ADDR_SIZE, (uchar*)&iph->daddr);
	printk(":%i ", get_dest_port(skb));
}

__be16 get_source_port(const struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	
	// Find port numbers for appropriate protocol
	switch(iph->protocol)
	{
	case ICMP_PROTO:
		return 0;
	
	case TCP_PROTO:
		tcph = tcp_hdr(skb);
		printk("ARG: reading source port via tcp\n");
		printRaw(4, &tcph->source);
		return ntohs(tcph->source);

	case UDP_PROTO:
		udph = udp_hdr(skb);
		printRaw(4, &udph->source);
		return ntohs(udph->source);

	default:
		printk("ARG: Unsupported protocol (%i) seen\n", iph->protocol);
		return 0;
	}
}

__be16 get_dest_port(const struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	
	// Find port numbers for appropriate protocol
	switch(iph->protocol)
	{
	case ICMP_PROTO:
		return 0;
	
	case TCP_PROTO:
		tcph = tcp_hdr(skb);
		printk("ARG: reading dest port via tcp\n");
		printRaw(4, &tcph->dest);
		return ntohs(tcph->dest);

	case UDP_PROTO:
		udph = udp_hdr(skb);
		printRaw(4, &udph->dest);
		return ntohs(udph->dest);

	default:
		printk("ARG: Unsupported protocol (%i) seen\n", iph->protocol);
		return 0;
	}
}

void set_source_port(const struct sk_buff *skb, const __be16 port)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	
	// Find port numbers for appropriate protocol
	switch(iph->protocol)
	{
	case ICMP_PROTO:
		break;
	
	case TCP_PROTO:
		tcph = tcp_hdr(skb);
		tcph->source = htons(port);
		break;

	case UDP_PROTO:
		udph = udp_hdr(skb);
		udph->source = htons(port);
		break;

	default:
		printk("ARG: Unsupported protocol (%i) seen\n", iph->protocol);
		return;
	}
}

void set_dest_port(const struct sk_buff *skb, const __be16 port)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	
	// Find port numbers for appropriate protocol
	switch(iph->protocol)
	{
	case ICMP_PROTO:
		break;
	
	case TCP_PROTO:
		tcph = tcp_hdr(skb);
		tcph->dest = htons(port);
		break;

	case UDP_PROTO:
		udph = udp_hdr(skb);
		udph->dest = htons(port);
		break;

	default:
		printk("ARG: Unsupported protocol (%i) seen\n", iph->protocol);
		return;
	}
}

char is_conn_oriented(const struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	return iph->protocol == TCP_PROTO;
}


