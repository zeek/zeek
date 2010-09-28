/* $Id:$ */
/* Written by Bernhard Ager (2007). */
/* For now this only works with IPv4. */

#include "../../config.h"

/* Enough for NFv5 - how about the others? */
#define MAX_PKT_SIZE 8192

/* from FlowSrc.h */
typedef struct {
  double network_time;
  int pdu_length;
  u_int32_t ipaddr;
} FlowFileSrcPDUHeader;

typedef struct {
  u_int16_t version;
  u_int16_t count;
  u_int32_t sysuptime;
  u_int32_t unix_secs;
  u_int32_t unix_nsecs;
  u_int32_t flow_seq;
  u_int8_t  eng_type;
  u_int8_t  eng_id;
  u_int16_t sample_int;
} NFv5Header;

#define V5_RECORD_SIZE 48
#define V5_RECORD_MAXCOUNT 30

typedef struct {
  char data[V5_RECORD_SIZE];
} NFv5Record;

typedef struct {
  NFv5Header header;
  NFv5Record records[V5_RECORD_MAXCOUNT];
} NFv5PDU;

/* TODO: replace char data[] by NFv5PDU pdu*/
typedef struct {
  FlowFileSrcPDUHeader header;
  char data [MAX_PKT_SIZE];
} FlowFilePDU;
