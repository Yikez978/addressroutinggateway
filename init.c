#include "utility.h"
#include "director.h"
#include "hopper.h"
#include "nat.h"

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
static struct nf_hook_ops *incomingTrafficHook = NULL;
static struct nf_hook_ops *outgoingTrafficHook = NULL;

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
char hook_network(void)
{
	// Hook the inboud traffic
	incomingTrafficHook = (struct nf_hook_ops*)kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
	if(incomingTrafficHook == NULL)
	{
		printk(KERN_ALERT "ARG: Unable to create hook for incoming traffic\n");
		return 1;
	}
	
	incomingTrafficHook->hook = inbound_handler;                       
	incomingTrafficHook->hooknum = NF_IP_PRE_ROUTING;
	incomingTrafficHook->pf = PF_INET;
	incomingTrafficHook->priority = NF_IP_PRI_FIRST;

	nf_register_hook(incomingTrafficHook);

	// Hook the outbound local traffic
	outgoingTrafficHook = (struct nf_hook_ops*)kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
	if(outgoingTrafficHook == NULL)
	{
		printk(KERN_ALERT "ARG: Unable to create hook for outgoing traffic\n");
		return 1;
	}

	outgoingTrafficHook->hook = outbound_handler;                       
	outgoingTrafficHook->hooknum = NF_IP_LOCAL_OUT; // TBD IP_FORWARD later
	outgoingTrafficHook->pf = PF_INET;
	outgoingTrafficHook->priority = NF_IP_PRI_FIRST;

	nf_register_hook(outgoingTrafficHook);

	return 0;
}

char unhook_network(void)
{
	if(incomingTrafficHook != NULL)
	{
		nf_unregister_hook(incomingTrafficHook);
		kfree(incomingTrafficHook);
		incomingTrafficHook = NULL;
	}
	
	if(outgoingTrafficHook != NULL)
	{
		nf_unregister_hook(outgoingTrafficHook);
		kfree(outgoingTrafficHook);
		outgoingTrafficHook = NULL;
	}

	return 0;
}

// Called when the module is initialized
static int __init arg_init(void)
{
	printk(KERN_INFO "ARG: initializing\n");

	// Init various components
	if(!init_hopper())
		printk(KERN_ALERT "ARG: Unable to initialize hopper\n");

	init_nat();

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
	unhook_network();	

	// Cleanup any resources as needed
	uninit_nat();
	//uninit_hopper();

	printk(KERN_INFO "ARG: finished\n");
}


module_init(arg_init);
module_exit(arg_exit);

