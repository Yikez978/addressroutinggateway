#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "utility.h"
#include "settings.h"
#include "packet.h"

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

int set_log_level(int level)
{
	int old = logLevel;
	logLevel = level;
	return old;
}

void arglog(int level, char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	varglog(level, fmt, ap);
	va_end(ap);
}

void varglog(int level, char *fmt, va_list ap)
{
	int fmtLen = 0;
	int fullLen = 40;
	char *line = NULL;
	struct timespec curr;

	#ifndef DISP_RESULTS
	if(level == LOG_RESULTS)
	{
		// Make the check always fail
		level = logLevel + 1;
	}
	#endif

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
			vprintf(line, ap);
			free(line);
		}
		else
		{
			// Print without including extra details
			vprintf(fmt, ap);
		}
	}
}

void arglog_result(const struct packet_data *inPacket,
				   const struct packet_data *outPacket,
				   char is_inbound, char is_accepted,
				   const char *processor, const char *reason)
{
	char inPacketID[MAX_PACKET_ID_SIZE] = "";
	char outPacketID[MAX_PACKET_ID_SIZE] = "";

	if(inPacket)
		create_packet_id(inPacket, inPacketID, sizeof(inPacketID));
	if(outPacket)
		create_packet_id(outPacket, outPacketID, sizeof(outPacketID));

	arglog(LOG_RESULTS, "%s: %s: %s: %s: %s/%s\n",
		(is_inbound ? "Inbound" : "Outbound"),
		(is_accepted ? "Accept" : "Reject"),
		processor, reason,
		inPacketID, outPacketID);
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

