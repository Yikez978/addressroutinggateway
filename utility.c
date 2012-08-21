#include "utility.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>

// Show hex of all data in buf
void printRaw(int len, void *buf)
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
void printAscii(int len, void *buf)
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

void printIP(int len, void *buf)
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

