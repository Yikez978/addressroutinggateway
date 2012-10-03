#ifndef SETTINGS_H
#define SETTINGS_H

#define INT_DEV_NAME "eth2"
#define EXT_DEV_NAME "eth1"

// Whether or not to show accept/reject messages (and why)
#define DISP_RESULTS

// Number of milliseconds between hops
#define HOP_TIME 5000

// Number of seconds before an auth request times out and must be initiated again
#define AUTH_TIMEOUT 5

// Number of seconds between attempts to connect to any gateways we aren't connected to yet
#define CONNECT_WAIT_TIME 15

// Number of seconds between full checks of the NAT table for expired connections
#define NAT_CLEAN_TIME 20

// Number of seconds before an inactive connection is removed
#define NAT_OLD_CONN_TIME 120

#define MAX_PACKET_SIZE 65536

#define MAX_CONF_LINE 300
#define RSA_KEY_SIZE 128
#define RSA_SIG_SIZE 128
#define AES_KEY_SIZE 16
#define HOP_KEY_SIZE 16
#define SHA1_HASH_SIZE 20

#endif

