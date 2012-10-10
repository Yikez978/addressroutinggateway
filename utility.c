#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include "utility.h"

static int logLevel = LOG_DEBUG;

// Show hex of all data in buf
void printRaw(int len, const void *buf)
{
	int i = 0;
	uint8_t *bufC = (uint8_t*)buf;

	for(i = 0; i < len; i++)
	{
		// Tag beginning of line
		if(i % 16 == 0)
			arglog(LOG_DEBUG, "\n[%4i]  ", i);
		
		arglog(LOG_DEBUG, "%02x ", bufC[i]);
	}

	arglog(LOG_DEBUG, "\n");
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
			arglog(LOG_DEBUG, "\n[%4i]  ", i);
		
		arglog(LOG_DEBUG, "%c", c);
		shown++;
	}

	arglog(LOG_DEBUG, "\n");
}

void printIP(int len, const void *buf)
{
	int i = 0;
	uint8_t *bufC = (uint8_t*)buf;

	for(i = 0; i < len; i++)
	{
		arglog(LOG_DEBUG, "%i", bufC[i]);

		if(i < len - 1)
			arglog(LOG_DEBUG, ".");
	}
}

int set_log_level(int level)
{
	int old = logLevel;
	logLevel = level;
	return old;
}

void arglog(int level, char *fmt, ...)
{
	va_list ap;
	int fmtLen = 0;
	int fullLen = 40;
	char *line = NULL;
	struct timespec curr;

	if(level <= logLevel)
	{
		current_time(&curr);
		
		fmtLen = strlen(fmt);
		fullLen += fmtLen;
		line = (char*)calloc(fullLen, 1);
		if(line)
		{
			// Include timestamp and log level
			snprintf(line, fullLen, "%lu.%lu LOG%i %s", curr.tv_sec, curr.tv_nsec, level, fmt);

			va_start(ap, fmt);
			vprintf(line, ap);
			va_end(ap);

			free(line);
		}
		else
		{
			// Print without including extra details
			va_start(ap, fmt);
			vprintf(fmt, ap);
			va_end(ap);
		}
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

	//arglog(LOG_DEBUG, "CURRENT TIME: %lu : %lu\n  BEGIN TIME %lu : %lu\n", end.tv_sec, end.tv_nsec, begin->tv_sec, begin->tv_nsec);

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

void current_time_plus(struct timespec *ts, int ms)
{
	current_time(ts);
	time_plus(ts, ms);
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

void mask_array(int len, const void *orig, const void *mask, void *result)
{
	int i = 0;
	const uint8_t *oCast = (const uint8_t*)orig;
	const uint8_t *mCast = (const uint8_t*)mask;
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

	//arglog(LOG_DEBUG, "doing mask compare with:\n");
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

