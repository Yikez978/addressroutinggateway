#ifndef SETTINGS_H
#define SETTINGS_H

#define INT_DEV_NAME "eth2"
#define EXT_DEV_NAME "eth1"

// Number of milliseconds between hops
#define HOP_TIME 5000

// Number of seconds before an auth request times out and must be initiated again
#define AUTH_TIMEOUT 5

// Number of seconds between attempts to connect to any gateways we aren't connected to yet
#define CONNECT_WAIT_TIME 30

// Maximum number of seconds to wait for new data before declaring a gate disconnected
#define MAX_UPDATE_TIME 300

// Number of seconds to wait before trying initial connection (gives all the other threads time to
// be ready to receive. Easier than an overkill barrier.)
#define INITIAL_CONNECT_WAIT 3

// Number of seconds between full checks of the NAT table for expired connections
#define NAT_CLEAN_TIME 20

// Number of seconds before an inactive connection is removed
#define NAT_OLD_CONN_TIME 120

// Sequence numbers may have to wrap if they reach 2^32. How far from the boundary will we
// accept a sudden reversion to the beginnig?
#define SEQ_NUM_WRAP_ALLOWANCE 10

#define MAX_PACKET_SIZE UINT16_MAX
#define MAX_CONF_LINE 300

#define SYMMETRIC_ALGO "AES-256-CTR"
#define HASH_ALGO "SHA256"

#define RSA_KEY_SIZE 128
#define RSA_SIG_SIZE 128

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

#define HOP_KEY_SIZE 16
#define SHA1_HASH_SIZE 20

#endif

