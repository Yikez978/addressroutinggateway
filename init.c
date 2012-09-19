#include "utility.h"
#include "director.h"
#include "hopper.h"
#include "nat.h"

#include <linux/module.h>
#include <linux/kernel.h>

// General information about this module
MODULE_LICENSE("GPL"); // proprietary
MODULE_AUTHOR("Ryan Morehart");
MODULE_DESCRIPTION("Address Routing Gateway (ARG)") ;
MODULE_VERSION("0.1");

// Called when the module is initialized
static int __init arg_init(void)
{
	printk(KERN_INFO "ARG: Starting\n");

	// Take care of locks first so that we know they're ALWAYS safe to use
	init_nat_locks();
	init_hopper_locks();

	// Init various components
	if(!init_hopper())
	{
		printk(KERN_ALERT "ARG: Unable to initialize hopper\n");
		
		uninit_hopper();
		
		return 0;
	}

	if(!init_nat())
	{
		printk(KERN_ALERT "ARG: NAT failed to initialize\n");

		uninit_nat();
		uninit_hopper();

		return 0;
	}

	// Hook network communication to listen for instructions
	if(!init_director())
	{
		printk(KERN_ALERT "ARG: Director failed to initialized, disabling subsystems\n");
		
		uninit_director();
		uninit_nat();
		uninit_hopper();
		
		return 0;
	}

	printk(KERN_INFO "ARG: Running\n");
    
	return 0;
}

// Called when the module is unloaded
static void __exit arg_exit(void)
{
	printk(KERN_INFO "ARG: Shutting down\n");

	// Unregister our network hooks so the system doesn't crash
	uninit_director();

	// Cleanup any resources as needed
	uninit_nat();
	uninit_hopper();

	printk(KERN_INFO "ARG: Finished\n");
}

module_init(arg_init);
module_exit(arg_exit);

