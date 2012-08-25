#ifndef NET_INFO_H
#define NET_INFO_H

#include <linux/types.h>

// Protocol numbers
#define ICMP_PROTO 0x01
#define TCP_PROTO 0x06
#define UDP_PROTO 0x11

// Size of IP addresses (bytes)
#define ADDR_SIZE sizeof(__be32)

#endif

