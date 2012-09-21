#ifndef SETTINGS_H
#define SETTINGS_H

#define INT_DEV_NAME "eth2"
#define EXT_DEV_NAME "eth1"

// Whether or not to show accept/reject messages (and why)
#define DISP_RESULTS

// Number of MILLIseconds between hops
#define HOP_TIME 5000

// Number of seconds between attempts to connect to any gateways we aren't connected to yet
#define CONNECT_WAIT_TIME 20

// Number of seconds between full checks of the NAT table for expired connections
#define NAT_CLEAN_TIME 30

// Number of seconds before an inactive connection is removed
#define NAT_OLD_CONN_TIME 120

#endif

