#include <string.h>

#include "arg_error.h"
	
void arg_strerror_r(int errnum, char *buf, int buflen)
{
	if(-errnum < ARG_MIN_ERROR)
	{
		strerror_r(-errnum, buf, buflen);
	}
	else
	{
		switch(errnum)
		{
		case -ARG_SEQ_BAD:
			strncpy(buf, "sequence number incorrect", buflen);
			break;
		
		case -ARG_UNHANDLED_TYPE:
			strncpy(buf, "unhandled message type", buflen);
			break;

		case -ARG_SIG_CHECK_FAILED:
			strncpy(buf, "unable to verify sig", buflen);
			break;
		
		case -ARG_SIGNING_FAILED:
			strncpy(buf, "signing failed", buflen);
			break;

		case -ARG_DECRYPT_FAILED:
			strncpy(buf, "unable to decrypt", buflen);
			break;
		
		case -ARG_ENCRYPT_FAILED:
			strncpy(buf, "unable to encrypt", buflen);
			break;
		
		case -ARG_MSG_SIZE_BAD:
			strncpy(buf, "improper msg size", buflen);
			break;
		
		case -ARG_MSG_UNEXPECTED:
			strncpy(buf, "msg unexpected", buflen);
			break;
		
		case -ARG_MSG_ID_BAD:
			strncpy(buf, "msg identifier bad", buflen);
			break;
		
		case -ARG_PACKET_PARSE_ERROR:
			strncpy(buf, "unable to parse packet", buflen);
			break;
		
		case -ARG_BUCKET_NOT_FOUND:
			strncpy(buf, "NAT bucket not found", buflen);
			break;
		
		case -ARG_ENTRY_NOT_FOUND:
			strncpy(buf, "NAT entry not found", buflen);
			break;
		
		case -ARG_NOT_CONNECTED:
			strncpy(buf, "gateway not connected", buflen);
			break;
		
		case -ARG_CONFIG_BAD:
			strncpy(buf, "problem in configuration", buflen);
			break;
		
		case -ARG_INTERNAL_ERROR:
			strncpy(buf, "internal error", buflen);
			break;
		
		default:
			strncpy(buf, "unknown reason", buflen);
		}
	}
}

