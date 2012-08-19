#include "utility.h"
#include "director.h"
#include "hopper.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>

// General information about this module
MODULE_LICENSE("Proprietary");
MODULE_AUTHOR("Ryan Morehart") ;
MODULE_DESCRIPTION("Address Routing Gateway (ARG)") ;
MODULE_VERSION("0.1");

/* After promisc drops, checksum checks. */
#define NF_IP_PRE_ROUTING       0
/* If the packet is destined for this box. */
#define NF_IP_LOCAL_IN          1
/* If the packet is destined for another interface. */
#define NF_IP_FORWARD           2
/* Packets coming from a local process. */
#define NF_IP_LOCAL_OUT         3
/* Packets about to hit the wire. */
#define NF_IP_POST_ROUTING      4
#define NF_IP_NUMHOOKS          5

// Netfilter hooking variables
static struct nf_hook_ops net_ops;
static struct nf_hook_ops net_ops_out;

// Handle packets coming from external network
unsigned int inbound_handler(unsigned int hooknum, struct sk_buff *skb, 
							const struct net_device *in,
							const struct net_device *out, 
							int (*okfn)(struct sk_buff *))
{   
	return direct_inbound(skb);
}

// Handles packets bound for outside network
unsigned int outbound_handler(unsigned int hooknum, struct sk_buff *skb, 
								const struct net_device *in,
								const struct net_device *out,
								int (*okfn)(struct sk_buff *))
{
	return direct_outbound(skb);
}

// Hook the network call stack to intercept traffic
int hook_network(void)
{
	// Hook the inboud traffic
	net_ops.hook = inbound_handler;                       
	net_ops.hooknum = NF_IP_PRE_ROUTING;
	net_ops.pf = PF_INET;
	net_ops.priority = NF_IP_PRI_FIRST;

	// Register the hook
	nf_register_hook(&net_ops);

	// Hook the outbound local traffic
	net_ops_out.hook = outbound_handler;
	net_ops_out.hooknum = NF_IP_LOCAL_OUT; // change to IP_FORWARD later
	net_ops_out.pf = PF_INET;
	net_ops_out.priority = NF_IP_PRI_FIRST;

	// Register the hook
	nf_register_hook(&net_ops_out);

	return 0;
}

// Called when the module is initialized
static int __init arg_init(void)
{
	printk(KERN_INFO "ARG: initializing\n");

	// Init various components
	init_hopper();

	// Hook network communication to listen for instructions
	hook_network();

	printk(KERN_INFO "ARG: running\n");
    
	return 0;
}

// Called when the module is unloaded
static void __exit arg_exit(void)
{
	printk(KERN_INFO "ARG: unhooking\n");

	// Unregister our network hooks so the system doesn't crash
	nf_unregister_hook(&net_ops);
	nf_unregister_hook(&net_ops_out);	

	printk(KERN_INFO "ARG: finished\n");
}


module_init(arg_init);
module_exit(arg_exit);

