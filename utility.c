#include "utility.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>

// Show hex of all data in buf
void printRaw(int len, uchar *buf)
{
	int i = 0;

	for(i = 0; i < len; i++)
	{
		// Tag beginning of line
		if(i % 16 == 0)
			printk("\nARG: [%4i]  ", i);
		
		printk("%2x ", buf[i]);
	}

	printk("\n");
}

// Display printable data in buf
void printAscii(int len, uchar *buf)
{
	char c = 0;
	int i = 0;
	int shown = 0;

	for(i = 0; i < len; i++)
	{
		c = buf[i];
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

