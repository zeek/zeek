/*
       B R O C C O L I  --  The Bro Client Communications Library

Copyright (C) 2004-2008 Christian Kreibich <christian (at) icir.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies of the Software and its documentation and acknowledgment shall be
given in the documentation and software packages that this Software was
used.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#ifndef broccoli_types_h
#define broccoli_types_h

#include <sys/queue.h>
#include <openssl/bio.h>

#include <broccoli.h>
#include <bro_buf.h>
#include <bro_hashtable.h>
#include <bro_list.h>
#include <bro_openssl.h>

/* Protocol version */
#define BRO_PROTOCOL_VERSION       0x06

/* Data format version */
#define BRO_DATA_FORMAT_VERSION    18

/* The maximum number of messages we queue before we start
 * dropping messages. Might be worth moving this to the
 * config file.
 *
 * FIXME: this should become configurable via the config file.
 *
 */
#define BRO_MSG_QUEUELEN_MAX      1000

/* Message codes, taken from RemoteSerializer.cc.
 * Don't know why the hex -- 0a-0f seem to be missing.
 * Doesn't really matter though.
 */
#define BRO_MSG_NONE               0x00
#define BRO_MSG_VERSION            0x01
#define BRO_MSG_SERIAL             0x02
#define BRO_MSG_CLOSE              0x03
#define BRO_MSG_CLOSE_ALL          0x04
#define BRO_MSG_ERROR              0x05
#define BRO_MSG_CONNECTTO          0x06
#define BRO_MSG_CONNECTED          0x07
#define BRO_MSG_REQUEST            0x08
#define BRO_MSG_LISTEN             0x09
#define BRO_MSG_LISTEN_STOP        0x0a
#define BRO_MSG_STATS              0x0b
#define BRO_MSG_CAPTURE_FILTER     0x0c
#define BRO_MSG_REQUEST_SYNC       0x0d
#define BRO_MSG_PHASE_DONE         0x0e
#define BRO_MSG_PING               0x0f
#define BRO_MSG_PONG               0x10
#define BRO_MSG_CAPS               0x11
#define BRO_MSG_COMPRESS           0x12
#define BRO_MSG_MAX                0x13

/* State of the handshake of a connection. Both sides
 * can be in the handshake phase or have finished it.
 */
#define BRO_CONNSTATE_SETUP        0 /* Version numbers, cache size...*/
#define BRO_CONNSTATE_HANDSHAKE    1 /* Event request, capabilities... */
#define BRO_CONNSTATE_SYNC         2 /* State synchronization */
#define BRO_CONNSTATE_RUNNING      3 /* Up and running. */

/* Capabilities we might have.
 */
#define BRO_CAP_COMPRESS           1
#define BRO_CAP_DONTCACHE          2

/* Message payload types -- these do not
 * respond to anything inside Bro and are
 * used only locally.
 */
#define BRO_MSG_CONT_NONE          0
#define BRO_MSG_CONT_RAW           1 /* BroBufs, for strings, integer arrays, etc */
#define BRO_MSG_CONT_EVENT         2 /* Events */
#define BRO_MSG_CONT_REQUEST       3 /* Requests for events etc */
#define BRO_MSG_CONT_PACKET        4 /* Pcap packets */

/* Messages between master process and I/O handler in
 * shared connections case.
 */
#define BRO_IOMSG_NONE             0
#define BRO_IOMSG_STOP             1
#define BRO_IOMSG_READ             2
#define BRO_IOMSG_WRITE            3

/* Event handler callback invocation styles
 */
#define BRO_CALLBACK_EXPANDED      0 /* Each argument passed separately */
#define BRO_CALLBACK_COMPACT       1 /* All arguments passed as a single BroEvArg* */

typedef struct bro_type BroType;
typedef struct bro_type_list BroTypeList;
typedef struct bro_record_type BroRecordType;
typedef struct bro_index_type BroIndexType;
typedef struct bro_table_type BroTableType;
typedef struct bro_set_type BroSetType;

typedef struct bro_id BroID;
typedef struct bro_val BroVal;
typedef struct bro_list_val BroListVal;
typedef struct bro_mutable_val BroMutableVal;
typedef struct bro_record_val BroRecordVal;
typedef struct bro_table_val BroTableVal;

typedef struct bro_msg_header BroMsgHeader;
typedef struct bro_msg BroMsg;
typedef struct bro_event_reg BroEventReg;
typedef struct bro_event_handler BroEventHandler;
typedef struct bro_event_cb BroEventCB;
typedef struct bro_request BroRequest;

/* General per-connection state information that we keep in a separate
 * structure so we can put it into shared memory if required. This is
 * a remnant from older code, but seems to make sense to preserve.
 */
typedef struct bro_conn_state
{
  /* Whether we are currently attempting a reconnect. Used to make
   * sure we do not attempt reconnects while we are attempting a 
   * reconnect. :)
   */
  int                          in_reconnect;
  
  /* Timestamp of the last reconnection attempt of this connection. */
  time_t                       last_reconnect;
  
  
  /* Flags declaring whether or not individual transmission
   * directions have shut down (e.g., because of an error).
   */
  int                          tx_dead;
  int                          rx_dead;

  /* State of the connection, for ourselves and the peer.
   * Connections go through a 
   *
   *   (1) setup
   *   (2) handshake
   *   (3) state synchronization
   *   (4) normal operation
   *
   * lifecycle, of which phase 3 is optional.
   */
  int                          conn_state_self;
  int                          conn_state_peer;

  /* True if the other side has requested synchronized state. Then
   * there is an additional phase in the communication. 
   */
  int                          sync_state_requested;

  /* Messages for I/O handler. Only used in shared connection case. */
  int                          io_msg;

  /* If != 0, ID of writer process for messages in the tx buffer. */
  pid_t                        io_pid;
  
} BroConnState;


/* The most important structure: Bro connection handles.
 * =====================================================
 */
struct bro_conn
{
  /* Flags set for this connection at creation time by the user.
   */
  int                          conn_flags;
  
  /* Two numerical values used for creating identifiers based on
   * connection handles.
   */
  pid_t                        id_pid;
  int                          id_num;

  /* The peer we connect to, in <host>:<ip> format */
  char                        *peer;

  /* The class of this connection. It's just an (optional) string.
   * If set, gets sent in the setup phase of the connection's
   * configuration.
   */
  char                        *class;

  /* A similar class identifier, if sent by the remote side. */
  char                        *peer_class;

  /* OpenSSL I/O buffer for communication regardless of whether
   * we're using encryption or not.
   */
  BIO                         *bio;

  /* Incoming data are buffered in the following buffer
   * structure. Each time data arrive, Broccoli checks
   * whether there's enough data in the buffer to do
   * anything useful with in, in which case those data
   * are consumed and make room for more input.
   *
   * The main purpose of the buffer is to disconnect
   * the arrival of data from the time of processing
   * because we want to avoid blocking of the instrumented
   * application by all means.
   *
   * Note that the buffers are used in the code directly
   * as rx_buf/tx_buf, but may actually live in the shared
   * memory segments pointed to by rx_buf_shm/tx_buf_shm.
   */
  BroBuf                      *rx_buf;

  /* Fields to mark the currently processed event in the
   * input buffer if event is currently processed, NULLs
   * otherwise:
   */
  const char                  *rx_ev_start;
  const char                  *rx_ev_end;

  /* Similar buffer for outgoing data:
   */
  BroBuf                      *tx_buf;

  /* A message queue plus its length counter for messages
   * that we haven't yet sent to the peer.
   */
  TAILQ_HEAD(mqueue, bro_msg)  msg_queue;
  uint                         msg_queue_len;

  /* A hashtable of all the names of events the peer accepts
   * from us.
   */
  BroHT                       *ev_mask;

  /* We maintain an event handler registry per conection:
   * these registries define callbacks for events that we
   * receive and at the same time can be using to request
   * event delivery from the peering Bro agent.
   */
  BroEventReg                 *ev_reg;

  /* Serialization data are cached when they will be
   * repeated identically. To handle this, there's a per-
   * connection cache implemented as a hash table:
   */
  BroHT                       *io_cache;

  /* Size limit for io_cache. *Must* match MAX_CACHE_SIZE
   * value defined in Bro's RemoteSerialier.cc.
   */
  int                          io_cache_maxsize;

  /* Storage for arbitrary user data:
   */
  BroHT                       *data;

#ifdef BRO_PCAP_SUPPORT
  uint32                       pcap_link_type;
#endif

  /* General connection state */
  BroConnState                *state;

  /* Externally provided socket to be used for connection. */
  int                         socket;
};

struct bro_msg_header
{
  char                         hdr_type;
  uint32                       hdr_peer_id;
};

struct bro_msg
{
  /* Messages get queued inside BroConns.
   * These are the list pointers for that.
   */
  TAILQ_ENTRY(bro_msg)         msg_queue;
  uint32                       msg_size;
  
  /* Header of the message, a CMsg in Bro.
   */
  struct bro_msg_header        msg_header;

  /* A counter for identifying this message. Not used otherwise. */
  int                          msg_num;

  /* We know the header size, but we need to store it
   * somewhere when we send the message. We use this:
   */
  uint32                       msg_header_size;

  /* A BRO_MSG_CONT_xxx value to identify the type of
   * data in the union below. This is easier to use than
   * using the type field in the message header all the time.
   */
  char                         msg_cont_type; 

  union {
    BroBuf                    *msg_raw;
    BroEvent                  *msg_ev;
    BroRequest                *msg_req;
#ifdef BRO_PCAP_SUPPORT
    BroPacket                 *msg_packet;
#endif
  } msg_cont;

#define msg_cont_raw     msg_cont.msg_raw
#define msg_cont_ev      msg_cont.msg_ev
#define msg_cont_req     msg_cont.msg_req
#define msg_cont_packet  msg_cont.msg_packet
};

struct bro_event
{
  /* Name of the event, as listed in event.bif.
   */
  BroString                    name;
  
  /* Timestamp (seconds since epoch) of creation of event.
   */
  double                       ts;

  /* A list of values to pass to the event, plus the
   * length of the list.
   */
  BroList                     *val_list;
  int                          val_len;
};


struct bro_request
{
  int                          req_len;
  char                        *req_dat;
};

/* The Bro event registry:
 * =======================
 *
 * Each Bro connection handle contains a BroEventReg structure.
 * In it, a list of BroEventHandlers registered. Each
 * handler represents one particular type of event that can
 * be received, and contains a list of BroEventCBs. Each of
 * those represents one actual callback performed when an
 * event for the handler is received (similarly to Bro, Broccoli
 * can have multiple event handlers for a single event type).
 *
 * Since the number and type of each event will vary, the callback
 * mechanism becomes a little tricky. When an event is received,
 * its parameters are deserialized accordingly. The registered
 * callbacks are then called with POINTERS to all these values --
 * since the size of a pointer is always the same no matter what
 * it's pointing to, we can in fact call the callbacks with
 * pointers to all these arguments. The number of parameters is
 * currently limited to a maximum of 15. If you need that many,
 * chances are you'll forget one anyway ;)
 */

struct bro_event_cb
{
  TAILQ_ENTRY(bro_event_cb)    cb_list;

  /* One of the various styles of callbacks,
   * identified by cb_style below.
   */
  union {
    BroEventFunc               cb_expd;  
    BroCompactEventFunc        cb_comp;  
  } cb_func;

#define cb_expanded_func       cb_func.cb_expd
#define cb_compact_func        cb_func.cb_comp

  void                        *cb_user_data;
  int                          cb_style; /* A BRO_CALLBACK_xxx value */
};

struct bro_event_handler
{
  char                        *ev_name;

  TAILQ_ENTRY(bro_event_handler) handler_list;
  TAILQ_HEAD(cblist, bro_event_cb) cb_list;
};

struct bro_event_reg
{
  TAILQ_HEAD(hlist, bro_event_handler) handler_list;
  int                          num_handlers;
};

#endif 
