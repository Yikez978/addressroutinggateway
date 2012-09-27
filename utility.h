#ifndef UTILITY_H
#define UTILITY_H

#include <stdint.h>
#include <time.h>

typedef unsigned char uchar;

void printRaw(int len, const void *buf);
void printAscii(int len, const void *buf);
void printIP(int len, const void *buf);

// Returns the current monotonic time (not real-world time)
void current_time(struct timespec *out);

// Computes the offset from the beginning time to now. See time_offset
long current_time_offset(const struct timespec *begin);

// Computes the offset from the beginning time to end and returns 
// the number of milliseconds. Positive values indicate begin is before end
long time_offset(const struct timespec *begin, const struct timespec *end);

// Returns the current time + the given number of milliseconds.
// ms may be negative
void time_plus(struct timespec *ts, int ms);

// Mask an arbitrarilly long number of bytes. Eh, whatever. It's a hack
// orig, mask, and result must all be the same length
void mask_array(int len, void *orig, void *mask, void *result);

// Compares two arrays (left and right) based on the mask given
// If equal, 0 is returned. Otherwise, non-0 (undefined beyond that)
char mask_array_cmp(int len, const void *mask, const void *left, const void *right);

#endif

