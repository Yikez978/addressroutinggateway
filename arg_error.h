#ifndef ARG_ERRORS_H
#define ARG_ERRORS_H

#include <errno.h>

#define MAX_ERROR_STR_LEN 35

// Possible error returns from ARG processing functions
enum {
	ARG_MIN_ERROR = 150,

	// Message errors
	ARG_SEQ_BAD = ARG_MIN_ERROR,
	ARG_UNHANDLED_TYPE,
	ARG_SIG_CHECK_FAILED,
	ARG_SIGNING_FAILED,
	ARG_DECRYPT_FAILED,
	ARG_ENCRYPT_FAILED,

	ARG_MSG_SIZE_BAD,
	ARG_MSG_UNEXPECTED,
	ARG_MSG_ID_BAD,

	ARG_PACKET_PARSE_ERROR,

	// NAT errors
	ARG_BUCKET_NOT_FOUND,
	ARG_ENTRY_NOT_FOUND,

	// Gateway issues
	ARG_NOT_CONNECTED,
	ARG_CONFIG_BAD,

	ARG_INTERNAL_ERROR,
};

// Functions the same as strerror_r, but works with ARG error codes as well
// If the errnum is not an ARG error, it is passed off to normal strerror_r
void arg_strerror_r(int errnum, char *buf, int buflen);

#endif

