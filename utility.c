#include <stdio.h>

#include "utility.h"

// Show hex of all data in buf
void printRaw(int len, const void *buf)
{
	int i = 0;
	uint8_t *bufC = (uint8_t*)buf;

	for(i = 0; i < len; i++)
	{
		// Tag beginning of line
		if(i % 16 == 0)
			printf("\nARG: [%4i]  ", i);
		
		printf("%02x ", bufC[i]);
	}

	printf("\n");
}

// Display printable data in buf
void printAscii(int len, const void *buf)
{
	char c = 0;
	int i = 0;
	int shown = 0;
	
	uint8_t *bufC = (uint8_t*)buf;

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
			printf("\nARG: [%4i]  ", i);
		
		printf("%c", c);
		shown++;
	}

	printf("\n");
}

void printIP(int len, const void *buf)
{
	int i = 0;
	uint8_t *bufC = (uint8_t*)buf;

	for(i = 0; i < len; i++)
	{
		printf("%i", bufC[i]);

		if(i < len - 1)
			printf(".");
	}
}

void current_time(struct timespec *out)
{
	clock_gettime(CLOCK_MONOTONIC, out);
}

long current_time_offset(const struct timespec *begin)
{
	struct timespec end;
	current_time(&end);
	return time_offset(begin, &end);
}

long time_offset(const struct timespec *begin, const struct timespec *end)
{
	long diff = 0;
  
	diff = 1000 * ((long)end->tv_sec - (long)begin->tv_sec);

	if(end->tv_nsec > begin->tv_nsec)
	{
		diff += (end->tv_nsec - begin->tv_nsec) / 1000000;
	}
	else
	{
		diff -= (begin->tv_nsec - end->tv_nsec) / 1000000;
	}

	return diff;
}

void time_plus(struct timespec *ts, int ms)
{
	if(ms == 0)
		return;

	ts->tv_sec += ms / 1000;
	ts->tv_nsec += (ms % 1000) * 1000000;
	if(ts->tv_nsec > 1000000000)
	{
		ts->tv_sec++;
		ts->tv_nsec -= 1000000000;
	}
}

void mask_array(int len, void *orig, void *mask, void *result)
{
	int i = 0;
	uint8_t *oCast = (uint8_t*)orig;
	uint8_t *mCast = (uint8_t*)mask;
	uint8_t *rCast = (uint8_t*)result;

	for(i = 0; i < len; i++, oCast++, rCast++, mCast++)
		*rCast = *oCast & *mCast;
}

char mask_array_cmp(int len, const void *mask, const void *left, const void *right)
{
	int i = 0;
	uint8_t *mCast = (uint8_t*)mask;
	uint8_t *lCast = (uint8_t*)left;
	uint8_t *rCast = (uint8_t*)right;

	//printf("ARG: doing mask compare with:\n");
	//printRaw(len, mask);
	//printRaw(len, left);
	//printRaw(len, right);

	for(i = 0; i < len; i++, lCast++, rCast++, mCast++)
	{
		if((*lCast & *mCast) != (*rCast & *mCast))
			return 1;
	}

	return 0;
}

