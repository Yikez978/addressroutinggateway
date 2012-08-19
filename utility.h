#ifndef UTILITY_H
#define UTILITY_H

#include <linux/types.h>

typedef unsigned char uchar;

void printRaw(int len, void *buf);
void printAscii(int len, void *buf);

#endif

