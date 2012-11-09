#include <string.h>

#include "arg_error.h"
	
void arg_strerror_r(int errnum, char *buf, int buflen)
{
	if(-errnum < ARG_MIN_ERROR)
	{
		strerror_r(-errnum, buf, buflen-1);
	}
	else
	{
		switch(errnum)
		{
		case -ARG_SEQ_BAD:
			strncpy(buf, "sequence number incorrect", buflen-1);
			break;
		
		case -ARG_UNHANDLED_TYPE:
			strncpy(buf, "unhandled message type", buflen-1);
			break;

		case -ARG_SIG_CHECK_FAILED:
			strncpy(buf, "unable to verify sig", buflen-1);
			break;
		
		case -ARG_SIGNING_FAILED:
			strncpy(buf, "signing failed", buflen-1);
			break;

		case -ARG_DECRYPT_FAILED:
			strncpy(buf, "unable to decrypt", buflen-1);
			break;
		
		case -ARG_ENCRYPT_FAILED:
			strncpy(buf, "unable to encrypt", buflen-1);
			break;
		
		case -ARG_MSG_SIZE_BAD:
			strncpy(buf, "improper msg size", buflen-1);
			break;
		
		case -ARG_MSG_UNEXPECTED:
			strncpy(buf, "msg unexpected", buflen-1);
			break;
		
		case -ARG_MSG_ID_BAD:
			strncpy(buf, "msg identifier bad", buflen-1);
			break;
		
		case -ARG_PACKET_PARSE_ERROR:
			strncpy(buf, "unable to parse packet", buflen-1);
			break;
		
		case -ARG_BUCKET_NOT_FOUND:
			strncpy(buf, "NAT bucket not found", buflen-1);
			break;
		
		case -ARG_ENTRY_NOT_FOUND:
			strncpy(buf, "NAT entry not found", buflen-1);
			break;
		
		case -ARG_NOT_CONNECTED:
			strncpy(buf, "gateway not connected", buflen-1);
			break;
		
		case -ARG_CONFIG_BAD:
			strncpy(buf, "problem in configuration", buflen-1);
			break;
		
		case -ARG_INTERNAL_ERROR:
			strncpy(buf, "internal error", buflen-1);
			break;
		
		default:
			strncpy(buf, "unknown reason", buflen-1);
		}
	}
}

