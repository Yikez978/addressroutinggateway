#ifndef SETTINGS_H
#define SETTINGS_H

/***********************************************
* Display and thesis-specific flags
***********************************************/
// Compute latency based on running with simulated latency, i.e., tc qdisc
// This means that traffic is only truly slowed outbound
#define LATENCY_TC_SIMULATED

// How often, in seconds, to display information on associated gates
#define GATE_PRINT_TIME 30

/***********************************************
* Timeouts
***********************************************/
// Disable the packet accepted/rejected messages
#define DISP_RESULTS

// Number of seconds before an auth request times out and must be initiated again
#define AUTH_TIMEOUT 5

// Number of seconds between attempts to connect to any gateways we aren't connected to yet
#define CONNECT_WAIT_TIME 10

// Maximum number of seconds to wait for new data before declaring a gate disconnected
#define MAX_UPDATE_TIME 120

// Minimum number of seconds between ping attempts
#define MIN_PING_TIME 5

// Minimum proportion of good (IP-wise) packet to bad per gate
// Listed an good packets/bad packets
#define MIN_VALID_IP_PROP 5 

// Number of seconds to wait before trying initial connection (gives all the other threads time to
// be ready to receive. Easier than an overkill barrier.)
#define INITIAL_CONNECT_WAIT 3

// Number of seconds between full checks of the NAT table for expired connections
#define NAT_CLEAN_TIME 20

// Number of seconds before an inactive connection is removed
#define NAT_OLD_CONN_TIME 120

/************************************************
* Packet settings
************************************************/
// Sequence numbers may have to wrap if they reach 2^32. How far from the boundary will we
// accept a sudden reversion to the beginnig?
#define SEQ_NUM_WRAP_ALLOWANCE 10

// Actually compute new UDP, TCP, and IP checksums as needed. If disabled, checksums are set to 0
#define COMPUTE_CHECKSUMS

/***********************************************
* Buffers and lengths
***********************************************/
// Maximum length of a name for a gate (including null)
#define MAX_NAME_SIZE 10

#define MAX_CONF_LINE 300

#define MAX_PACKET_SIZE UINT16_MAX
#define MAX_PACKET_ID_SIZE 90

#define RSA_KEY_SIZE 128
#define RSA_SIG_SIZE 128

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

#define HOP_KEY_SIZE 16
#define SHA1_HASH_SIZE 20

/***********************************************
* Misc
***********************************************/
#define SYMMETRIC_ALGO "AES-256-CTR"
#define HASH_ALGO "SHA256"

/***********************************************
* Configuration/settings manager
***********************************************/
struct arg_network_info;

typedef struct gate_list {
	char name[MAX_CONF_LINE];
	struct gate_list *next;
} gate_list;

typedef struct config_data {
	char file[MAX_CONF_LINE];
	char dir[MAX_CONF_LINE];
	
	char ourGateName[MAX_CONF_LINE];

	char intDev[16];
	char extDev[16];

	struct gate_list *gate;
	long hopRate;
} config_data;

int read_config(struct config_data *conf);
void release_config(struct config_data *conf);

int read_public_key(const struct config_data *conf, struct arg_network_info *gate);
int read_private_key(const struct config_data *conf, struct arg_network_info *gate);

// Reads until finding a not-blank line (COMPLETELY blank, not whitespace skipping)
// Line has \n removed if needed
// Returns 0 if line is found, 1 if not (eof, probably)
int get_next_line(FILE *f, char *line, int max);

#endif

