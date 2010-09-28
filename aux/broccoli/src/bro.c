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
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#ifdef __MINGW32__
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#endif

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include "broccoli.h"
#include "bro_debug.h"
#include "bro_buf.h"
#include "bro_config.h"
#include "bro_hashtable.h"
#include "bro_types.h"
#include "bro_type.h"
#include "bro_val.h"
#include "bro_id.h"
#include "bro_event.h"
#include "bro_event_reg.h"
#include "bro_io.h"
#include "bro_util.h"
#include "bro_openssl.h"
#include "bro_record.h"
#include "bro_table.h"
#ifdef BRO_PCAP_SUPPORT
#include "bro_packet.h"
#endif


/* Don't attempt to reconnect more than once every 5 seconds: */
#define BRO_RECONNECT_MAX_RATE   5

/* Default maximum cache size. */
#define BRO_MAX_CACHE_SIZE       1000

/* Macro for putting safety brakes on some functions to ensure the
 * user is now calling bro_init() first.
 */
#define BRO_SAFETY_CHECK init_check(__FUNCTION__);

/* Pointer to BroCtx provided by the user at initialization time. */
const BroCtx *global_ctx = NULL;

/* To make MinGW happy, we provide an initialization handler for the
 * DLL if we are building on Windows.
 */
#ifdef __MINGW32__
int main() { return 0; }
#endif

static int
conn_init_await(BroConn *bc, int conn_state)
{
  /* Wait for a maximum of 10 seconds until the connection
   * reaches the desired state. We check every 0.2 seconds.
   */
  int i = 0, intervals = 10 * 5 + 1;

  D_ENTER;

  if (bc->state->conn_state_self == conn_state)
    {
      D(("Self already in requested state.\n"));
      D_RETURN_(TRUE);
    }

  /* Set our own connection state to the requested one.
   */
  bc->state->conn_state_self = conn_state;

  /* Wait for a while, processing the peer's input,
   * and return as soon as we reach the desired state.
   */
  while (i++ < intervals)
    {
      struct timeval timeout;
      timeout.tv_sec  = 0;
      timeout.tv_usec = 200000;

      if (bc->state->conn_state_peer >= conn_state)
	D_RETURN_(TRUE);
      
      if (select(0, NULL, NULL, NULL, &timeout) < 0)
	{
	  D(("select() caused '%s'\n", strerror(errno)));
	  D_RETURN_(FALSE);
	}
      
      __bro_io_process_input(bc);      
    }
  
  D_RETURN_(FALSE);
}
  
static int
conn_init_setup(BroConn *bc)
{
  BroBuf buf;
  uint32 descriptor[4];
  int result;

  D_ENTER;
   
  descriptor[0] = htonl((uint32) BRO_PROTOCOL_VERSION);
  descriptor[1] = htonl((uint32) BRO_MAX_CACHE_SIZE);
  descriptor[2] = htonl((uint32) BRO_DATA_FORMAT_VERSION);
  descriptor[3] = 0; /* Relative uptime of the process */

  __bro_buf_init(&buf);
  __bro_buf_append(&buf, descriptor, 4 * sizeof(uint32));

  if (bc->class)
    __bro_buf_append(&buf, bc->class, strlen(bc->class) + 1);

  if (! __bro_io_raw_queue(bc, BRO_MSG_VERSION,
			   __bro_buf_get(&buf),
			   __bro_buf_get_used_size(&buf)))
    {
      D(("Setup data not sent to %p\n", bc));
      __bro_buf_cleanup(&buf);
      D_RETURN_(FALSE);
    }

  __bro_buf_cleanup(&buf);

  /* This phase does NOT send PHASE_END ... */
  
  D(("Phase done to peer on %p, self now in HANDSHAKE stage.\n", bc));
  result = conn_init_await(bc, BRO_CONNSTATE_HANDSHAKE);  
  D_RETURN_(result);
}

static int
conn_init_handshake(BroConn *bc)
{
  uint32 caps[3];
  int result;

  D_ENTER;

  /* --- Request events, if any -------------------------------------- */
  if (bc->ev_reg->num_handlers > 0)
    __bro_event_reg_request(bc);

  /* --- Capabilities ------------------------------------------------ */

  /* We never compress at the moment. */

  /* Unless user requested caching, tell peer we do not cache. Note
   * that at the moment we never cache data we send, so this only
   * affects received data.
   */
  caps[0] = 0;
  caps[1] = 0;
  caps[2] = 0;

  caps[0] |= (bc->conn_flags & BRO_CFLAG_CACHE) ? 0 : BRO_CAP_DONTCACHE;

  caps[0] = htonl(caps[0]);
  caps[1] = htonl(caps[1]);
  caps[2] = htonl(caps[2]);

  if (! __bro_io_raw_queue(bc, BRO_MSG_CAPS,
			   (uchar*) caps, 3 * sizeof(uint32)))
    {
      D(("Handshake data not sent to %p\n", bc));
      D_RETURN_(FALSE);
    }

  /* --- End of phase ------------------------------------------------ */
  
  if (! __bro_io_raw_queue(bc, BRO_MSG_PHASE_DONE, NULL, 0))
    {
      D(("End-of-Handshake not sent to %p\n", bc));
      D_RETURN_(FALSE);
    }
  
  if (bc->state->sync_state_requested)
    {
      D(("Phase done to peer on %p, sync requested, self now in SYNC stage.\n", bc));
      result = conn_init_await(bc, BRO_CONNSTATE_SYNC);  
    }
  else
    {
      D(("Phase done to peer on %p, no sync requested, self now in RUNNING stage.\n", bc));
      result = conn_init_await(bc, BRO_CONNSTATE_RUNNING);  
    }

  D_RETURN_(result);
}

static int
conn_init_sync(BroConn *bc)
{
  int result = TRUE;

  D_ENTER;

  /* If the peer requested synced state, we just send another phase done.
   * Otherwise we don't do anything and immediately move to the "running"
   * state.
   */
  if (bc->state->sync_state_requested)
    {
      if (! __bro_io_raw_queue(bc, BRO_MSG_PHASE_DONE, NULL, 0))
	{
	  D(("End-of-Sync not sent to %p\n", bc));
	  D_RETURN_(FALSE);
	}

      D(("Phase done to peer on %p\n", bc));
    }
  
  D(("Self now in RUNNING stage.\n"));
  result = conn_init_await(bc, BRO_CONNSTATE_RUNNING);
  
  D_RETURN_(result);
}

/* This function walks lock-step with the peer through
 * the entire handshake procedure.
 */
static int
conn_init_configure(BroConn *bc)
{
  if (! conn_init_setup(bc))
    return FALSE;
  if (! conn_init_handshake(bc))
    return FALSE;
  if (! conn_init_sync(bc))
    return FALSE;
  
  return TRUE;
}

static int
conn_init(BroConn *bc)
{
  D_ENTER;

  if (! (bc->rx_buf = __bro_buf_new()))
    goto error_exit;
  if (! (bc->tx_buf = __bro_buf_new()))
    goto error_exit;

  if (! (bc->state = calloc(1, sizeof(BroConnState))))
    goto error_exit;
  
  bc->state->conn_state_self = BRO_CONNSTATE_SETUP;
  bc->state->conn_state_peer = BRO_CONNSTATE_SETUP;

  if (! __bro_openssl_connect(bc))
    goto error_exit;

  D_RETURN_(TRUE);
  
 error_exit:
  __bro_buf_free(bc->rx_buf);
  __bro_buf_free(bc->tx_buf);
  bc->rx_buf = NULL;
  bc->tx_buf = NULL;

  D_RETURN_(FALSE);
}

static void
conn_free(BroConn *bc)
{
  D_ENTER;

  __bro_openssl_shutdown(bc);

  if (bc->state)
    free(bc->state);

  __bro_buf_free(bc->rx_buf);
  __bro_buf_free(bc->tx_buf);
  bc->rx_buf = NULL;
  bc->tx_buf = NULL;

  D_RETURN;
}

static void
init_check(const char *func)
{
  if (global_ctx == NULL) {
    fprintf(stderr,
	    "*** Broccoli error: %s called without prior initialization.\n"
	    "*** Initialization of the Broccoli library is now required.\n"
	    "*** See documentation for details. Aborting.\n",
	    func);
    exit(-1);
  }
}

int
bro_init(const BroCtx* ctx)
{
  if (global_ctx != NULL)
    return TRUE;

  if (ctx == NULL) {
    ctx = calloc(1, sizeof(BroCtx));
    bro_ctx_init((BroCtx*) ctx);
  }

  global_ctx = ctx;
  __bro_conf_init();
  if (! __bro_openssl_init())
    return FALSE;

  return TRUE;
}

void
bro_ctx_init(BroCtx *ctx)
{
  memset(ctx, 0, sizeof(BroCtx));
}

BroConn *
bro_conn_new_str(const char *hostname, int flags)
{
  BroConn *bc;
  static int counter = 0;
  
  BRO_SAFETY_CHECK;

  D_ENTER;
  
  if (! hostname || !*hostname)
    D_RETURN_(NULL);
  
  if (! (bc = (BroConn *) calloc(1, sizeof(BroConn))))
    D_RETURN_(NULL);
  
  D(("Connecting to host %s\n", hostname));

  bc->conn_flags = flags;
  bc->id_pid = getpid();
  bc->id_num = counter++;
  bc->peer = strdup(hostname);
  bc->io_cache_maxsize = BRO_MAX_CACHE_SIZE;
  bc->socket = -1;

  TAILQ_INIT(&bc->msg_queue);
  bc->msg_queue_len = 0;

  if (! (bc->ev_reg = __bro_event_reg_new()))
    goto error_exit;

  if (! (bc->io_cache = __bro_ht_new(__bro_ht_int_hash,
				     __bro_ht_int_cmp,
				     NULL,
				     (BroHTFreeFunc) __bro_sobject_release,
				     TRUE)))
    goto error_exit;
  
  if (! (bc->data = __bro_ht_new(__bro_ht_str_hash,
				 __bro_ht_str_cmp,
				 __bro_ht_mem_free,
				 NULL, FALSE)))
    goto error_exit;
  
  if (! (bc->ev_mask = __bro_ht_new(__bro_ht_str_hash,
				    __bro_ht_str_cmp,
				    __bro_ht_mem_free,
				    NULL, FALSE)))
    goto error_exit;  
  
  D_RETURN_(bc);

 error_exit:
  __bro_event_reg_free(bc->ev_reg);
  __bro_ht_free(bc->ev_mask);
  __bro_ht_free(bc->io_cache);
  __bro_ht_free(bc->data);
  
  if (bc->peer)
    free(bc->peer);
  
  free(bc);
  D_RETURN_(NULL);
}


BroConn *
bro_conn_new(struct in_addr *ip_addr, uint16 port, int flags)
{
  BroConn *bc;
  char hostname[1024];

  BRO_SAFETY_CHECK;

  D_ENTER;
  __bro_util_snprintf(hostname, 1024, "%s:%hu", inet_ntoa(*ip_addr), ntohs(port));
  bc = bro_conn_new_str(hostname, flags);
  D_RETURN_(bc);
}

BroConn *
bro_conn_new_socket(int fd, int flags)
{
  BroConn *bc;

  BRO_SAFETY_CHECK;

  D_ENTER;

  if ( fd < 0 )
    D_RETURN_(NULL);

  bc = bro_conn_new_str("<fd>", flags);
  if (! bc)
    D_RETURN_(NULL);

  bc->socket = fd;
  D_RETURN_(bc);
}

void
bro_conn_set_class(BroConn *bc, const char *class)
{
  if (! bc)
    return;

  if (bc->class)
    free(bc->class);

  bc->class = strdup(class);
}

const char *
bro_conn_get_peer_class(const BroConn *bc)
{
  if (! bc)
    return NULL;

  return bc->peer_class;
}

void
bro_conn_get_connstats(const BroConn *bc, BroConnStats *cs)
{
  if (! bc || ! cs)
    return;

  memset(cs, 0, sizeof(BroConnStats));
  cs->tx_buflen =  __bro_buf_get_used_size(bc->tx_buf);
  cs->rx_buflen =  __bro_buf_get_used_size(bc->rx_buf);
}

int
bro_conn_connect(BroConn *bc)
{
  D_ENTER;

  if (! bc)
    D_RETURN_(FALSE);

  if ( (bc->conn_flags & BRO_CFLAG_SHAREABLE))
    fprintf(stderr, "WARNING: BRO_CFLAG_SHAREABLE is no longer supported.\n");

  if (! conn_init(bc))
    D_RETURN_(FALSE);
  
  /* Handshake procedure. */
  if (! conn_init_configure(bc))
    D_RETURN_(FALSE);

  D_RETURN_(TRUE);
}


int
bro_conn_reconnect(BroConn *bc)
{
  BroMsg *msg, *msg_first, **msg_last;
  int msg_queue_len;
  time_t current_time;

  D_ENTER;

  if (! bc)
    D_RETURN_(FALSE);

  if (bc->state->in_reconnect)
    D_RETURN_(FALSE);
  
  if ( (current_time = time(NULL)) > 0)
    {
      if (current_time - bc->state->last_reconnect < BRO_RECONNECT_MAX_RATE)
	{
	  D(("Less than %i seconds since last reconnect attempt, not reconnecting.\n",
	     BRO_RECONNECT_MAX_RATE));
	  D_RETURN_(FALSE);
	}

      bc->state->last_reconnect = current_time;
    }
  
  D(("Attempting reconnection...\n"));
  bc->state->in_reconnect = TRUE;
  
  /* NOTE: the sequencing in this function is quite tricky and very picky.
   * Don't move things around unneccesarily ...
   */
  bc->state->tx_dead = bc->state->rx_dead = FALSE;
  
  /* Clean up the old connection state: */
  bc->state->conn_state_self = BRO_CONNSTATE_SETUP;
  bc->state->conn_state_peer = BRO_CONNSTATE_SETUP;
  bc->state->sync_state_requested = FALSE;
  
  if (bc->bio)
    {
      BIO_free_all(bc->bio);
      bc->bio = NULL;
    }

  /* Attempt to establish new connection */
  if (! __bro_openssl_reconnect(bc))
    goto error_return;

  __bro_buf_reset(bc->rx_buf);
  __bro_buf_reset(bc->tx_buf);

  /* Only *after* we managed to connect, we clear the event mask for events
   * the peer expects, etc. If we do this earlier and fail to connect, then future
   * sent events never trigger a reconnect because they're never sent since
   * they don't seem to be requested.
   */

  /* Temporarily unhook messages from the message queue so the new messages
   * get sent right away. We hook the old ones back in below.
   */
  msg_first = bc->msg_queue.tqh_first;
  msg_last  = bc->msg_queue.tqh_last;
  msg_queue_len = bc->msg_queue_len;
  bc->msg_queue_len = 0;
  TAILQ_INIT(&bc->msg_queue);

  __bro_ht_free(bc->ev_mask);

  if (! (bc->ev_mask = __bro_ht_new(__bro_ht_str_hash,
				    __bro_ht_str_cmp,
				    __bro_ht_mem_free,
				    NULL, FALSE)))				    
    goto reset_error_return;

  __bro_ht_free(bc->io_cache);
  
  if (! (bc->io_cache = __bro_ht_new(__bro_ht_int_hash,
				     __bro_ht_int_cmp,
				     NULL,
				     (BroHTFreeFunc) __bro_sobject_release,
				     TRUE)))
    goto reset_error_return;

  if (! conn_init_configure(bc))
    goto reset_error_return;

  /* Hook old events back in */
  if (bc->msg_queue_len == 0)
    bc->msg_queue.tqh_first = msg_first;
  else
    {
      msg_first->msg_queue.tqe_prev = bc->msg_queue.tqh_last;
      *bc->msg_queue.tqh_last = msg_first;
    }

  bc->msg_queue.tqh_last = msg_last;
  bc->msg_queue_len += msg_queue_len;

  D(("Reconnect completed successfully.\n"));
  bc->state->in_reconnect = FALSE;
  
  D_RETURN_(TRUE);

 reset_error_return:

  /* If the reconnect went wrong somehow, nuke the queue and
   * place old queue contents back in.
   */
  while ( (msg = bc->msg_queue.tqh_first))
    {
      TAILQ_REMOVE(&bc->msg_queue, msg, msg_queue);
      __bro_io_msg_free(msg);
    }
  
  bc->msg_queue.tqh_first = msg_first;
  bc->msg_queue.tqh_last = msg_last;
  bc->msg_queue_len = msg_queue_len;
  
 error_return:
  bc->state->tx_dead = bc->state->rx_dead = TRUE;
  bc->state->in_reconnect = FALSE;

  D_RETURN_(FALSE);
}


int 
bro_conn_delete(BroConn *bc)
{
  BroMsg *msg;

  D_ENTER;

  if (!bc || !bc->state)
    D_RETURN_(FALSE);

  if (! bc->state->tx_dead)
    {
      /* Try to flush command queue */
      __bro_io_msg_queue_flush(bc);
    }

  while ( (msg = bc->msg_queue.tqh_first))
    {
      TAILQ_REMOVE(&bc->msg_queue, msg, msg_queue);
      __bro_io_msg_free(msg);
    }

  __bro_ht_free(bc->ev_mask);
  __bro_event_reg_free(bc->ev_reg);
  __bro_ht_free(bc->io_cache);
  __bro_ht_free(bc->data);

  conn_free(bc);

  if (bc->class)
    free(bc->class);
  if (bc->peer_class)
    free(bc->peer_class);

  if (bc->peer)
    free(bc->peer);

  free(bc);
  D_RETURN_(TRUE);
}


int
bro_conn_alive(const BroConn *bc)
{
  if (!bc || !bc->state)
    return FALSE;

  return (! bc->state->tx_dead && ! bc->state->rx_dead);
}


static int
conn_adopt_events_cb(char *ev_name, void *data, BroHT *dst)
{
  char *key;

  /* If the event is already reported, ignore. */
  if (__bro_ht_get(dst, ev_name))
    return TRUE;
  
  D(("Adopting event %s\n", ev_name));
  key = strdup(ev_name);
  __bro_ht_add(dst, key, key);
  
  return TRUE;
  data = NULL;
}

void
bro_conn_adopt_events(BroConn *src, BroConn *dst)
{
  D_ENTER;

  if (!src || !dst)
    D_RETURN;

  __bro_ht_foreach(src->ev_mask, (BroHTCallback) conn_adopt_events_cb, dst->ev_mask);

  D_RETURN;
}


int
bro_conn_get_fd(BroConn *bc)
{
  int fd;

  if (! bc || !bc->state || bc->state->tx_dead || bc->state->rx_dead || !bc->bio)
    return -1;
  
#ifdef __MINGW32__
  return 0;
#else
  BIO_get_fd(bc->bio, &fd);
  return fd;
#endif
}


int
bro_conn_process_input(BroConn *bc)
{
  if (! bc || !bc->state || bc->state->rx_dead)
    return FALSE;

  return __bro_io_process_input(bc);
}


int
bro_event_queue_length(BroConn *bc)
{
  if (! bc)
    return 0;

  return bc->msg_queue_len;
}


int
bro_event_queue_length_max(BroConn *bc)
{
  return BRO_MSG_QUEUELEN_MAX;
  bc = NULL;
}


int            
bro_event_queue_flush(BroConn *bc)
{
  return __bro_io_msg_queue_flush(bc);
}


int
bro_event_send(BroConn *bc, BroEvent *ev)
{
  int result;

  D_ENTER;

  if (! bc || !ev)
    {
      D(("Input error\n"));
      D_RETURN_(FALSE);
    }

  D(("Sending event with %i args\n", __bro_list_length(ev->val_list)));
  result = __bro_io_event_queue(bc, ev);
  D_RETURN_(result);
}


int
bro_event_send_raw(BroConn *bc, const uchar *data, int data_len)
{
  BroBuf *buf = NULL;

  D_ENTER;

  if (! bc || !data)
    {
      D(("Input error\n"));
      D_RETURN_(FALSE);
    }

  if (data_len == 0)
    {
      D(("Nothing to send\n"));
      D_RETURN_(TRUE);
    }

  if (! (buf = __bro_buf_new()))
    {
      D(("Out of memory\n"));
      D_RETURN_(FALSE);
    }
      
  __bro_buf_write_char(buf, 'e');
  __bro_buf_write_data(buf, data, data_len);

  __bro_io_rawbuf_queue(bc, BRO_MSG_SERIAL, buf);
  __bro_io_msg_queue_flush(bc);

  D_RETURN_(TRUE);
}


void
bro_conn_data_set(BroConn *bc, const char *key, void *val)
{
  if (!bc || !key || !*key)
    return;

  __bro_ht_add(bc->data, strdup(key), val);
}


void *
bro_conn_data_get(BroConn *bc, const char *key)
{
  if (!bc || !key || !*key)
    return NULL;

  return __bro_ht_get(bc->data, (void *) key);
}


void *
bro_conn_data_del(BroConn *bc, const char *key)
{
  if (!bc || !key || !*key)
    return NULL;
  
  return __bro_ht_del(bc->data, (void *) key);
}


/* ----------------------------- Bro Events -------------------------- */

BroEvent *
bro_event_new(const char *event_name)
{
  BroString name;
  BroEvent *result;

  bro_string_set(&name, event_name);
  result = __bro_event_new(&name);
  bro_string_cleanup(&name);

  return result;
}


void
bro_event_free(BroEvent *be)
{
  __bro_event_free(be);
}


int
bro_event_add_val(BroEvent *be, int type, const char *type_name, const void *val)
{
  BroVal *v;

  D_ENTER;

  if (! be || ! val || type < 0 || type >= BRO_TYPE_MAX)
    {
      D(("Invalid input: (%p, %i, %p)\n", be, type, val));
      D_RETURN_(FALSE);
    }
  
  if (! (v = __bro_val_new_of_type(type, type_name)))
    D_RETURN_(FALSE);

  if (! __bro_val_assign(v, val))
    {
      __bro_sobject_release((BroSObject *) v);
      D_RETURN_(FALSE);
    }

  __bro_event_add_val(be, v);

  D_RETURN_(TRUE);
}


int
bro_event_set_val(BroEvent *be, int val_num,
		  int type, const char *type_name,
		  const void *val)
{
  BroVal *v;
  int result;

  D_ENTER;

  if (! be || ! val || type < 0 || type >= BRO_TYPE_MAX)
    {
      D(("Invalid input: (%p, %i, %p)\n", be, type, val));
      D_RETURN_(FALSE);
    }

  if (! (v = __bro_val_new_of_type(type, type_name)))
    D_RETURN_(FALSE);

  if (! __bro_val_assign(v, val))
    {
      __bro_sobject_release((BroSObject *) v);
      D_RETURN_(FALSE);
    }
  
  result = __bro_event_set_val(be, val_num, v);
  D_RETURN_(result);
}


void
bro_event_registry_add(BroConn *bc,
		       const char *event_name,
		       BroEventFunc func,
		       void *user_data)		       
{
  __bro_event_reg_add(bc, event_name, func, user_data);
}


void
bro_event_registry_add_compact(BroConn *bc,
			       const char *event_name,
			       BroCompactEventFunc func,
			       void *user_data)		       
{
  __bro_event_reg_add_compact(bc, event_name, func, user_data);
}


void
bro_event_registry_remove(BroConn *bc, const char *event_name)
{
  __bro_event_reg_remove(bc, event_name);
}


void
bro_event_registry_request(BroConn *bc)
{
  D_ENTER;
  
  if (!bc || !bc->state)
    D_RETURN;

  /* A connection that isn't up and running yet cannot request
   * events. The handshake phase will request any registered
   * events automatically.
   */
  if (bc->state->conn_state_self != BRO_CONNSTATE_RUNNING)
    D_RETURN;
  
  __bro_event_reg_request(bc);
  
  D_RETURN;
}



/* ------------------------ Dynamic-size Buffers --------------------- */

BroBuf *
bro_buf_new(void)
{
  BroBuf *buf;

  if (! (buf = calloc(1, sizeof(BroBuf))))
    return NULL;

  __bro_buf_init(buf);
  return buf;
}


void
bro_buf_free(BroBuf *buf)
{
  if (!buf)
    return;

  __bro_buf_cleanup(buf);
  free(buf);
}


int
bro_buf_append(BroBuf *buf, void *data, int data_len)
{
  return __bro_buf_append(buf, data, data_len);
}


void
bro_buf_consume(BroBuf *buf)
{
  __bro_buf_consume(buf);
}


void
bro_buf_reset(BroBuf *buf)
{
  __bro_buf_reset(buf);
}


uchar *
bro_buf_get(BroBuf *buf)
{
  return __bro_buf_get(buf);
}


uchar *
bro_buf_get_end(BroBuf *buf)
{
  return __bro_buf_get_end(buf);
}


uint
bro_buf_get_size(BroBuf *buf)
{
  return __bro_buf_get_size(buf);
}


uint
bro_buf_get_used_size(BroBuf *buf)
{
  return __bro_buf_get_used_size(buf);
}


uchar *
bro_buf_ptr_get(BroBuf *buf)
{
  return __bro_buf_ptr_get(buf);
}


uint32
bro_buf_ptr_tell(BroBuf *buf)
{
  return __bro_buf_ptr_tell(buf);
}


int
bro_buf_ptr_seek(BroBuf *buf, int offset, int whence)
{
  return __bro_buf_ptr_seek(buf, offset, whence);
}


int
bro_buf_ptr_check(BroBuf *buf, int size)
{
  return __bro_buf_ptr_check(buf, size);
}


int
bro_buf_ptr_read(BroBuf *buf, void *data, int size)
{
  return __bro_buf_ptr_read(buf, data, size);
}


int
bro_buf_ptr_write(BroBuf *buf, void *data, int size)
{
  return __bro_buf_ptr_write(buf, data, size);
}



/* ------------------------ Configuration Access --------------------- */

void
bro_conf_set_domain(const char *domain)
{
  BRO_SAFETY_CHECK;
  __bro_conf_set_domain(domain);
}


int
bro_conf_get_int(const char *val_name, int *val)
{
  BRO_SAFETY_CHECK;

  if (! val_name || ! val)
    return FALSE;

  return __bro_conf_get_int(val_name, val);
}


int
bro_conf_get_dbl(const char *val_name, double *val)
{
  BRO_SAFETY_CHECK;

  if (! val_name || ! val)
    return FALSE;

  return __bro_conf_get_dbl(val_name, val);
}


const char *
bro_conf_get_str(const char *val_name)
{
  BRO_SAFETY_CHECK;

  if (! val_name)
    return FALSE;
  
  return __bro_conf_get_str(val_name);
}


/* -------------------------- Record Handling ------------------------ */

BroRecord *
bro_record_new(void)
{
  return __bro_record_new();
}


void
bro_record_free(BroRecord *rec)
{
  __bro_record_free(rec);
}

int
bro_record_get_length(BroRecord *rec)
{
  return __bro_record_get_length(rec);
}

int
bro_record_add_val(BroRecord *rec, const char *name,
		   int type, const char *type_name, const void *val)
{
  BroVal *v;

  D_ENTER;

  if (! rec)
    {
      D(("Input error: (%p, %s, %i, %p)\n", rec, name, type, val));
      D_RETURN_(FALSE);
    }
  
  if (! (v = __bro_val_new_of_type(type, type_name)))
    {
      D(("Could not get val of type %i\n", type));
      D_RETURN_(FALSE);
    }
  
  if (! name)
    name = "";

  __bro_sobject_data_set((BroSObject *) v, "field", strdup(name));

  if (! __bro_val_assign(v, val))
    {
      D(("Could not assign value to the new val.\n"));
      __bro_sobject_release((BroSObject *) v);
      D_RETURN_(FALSE);
    }

  __bro_record_add_val(rec, v);
  D_RETURN_(TRUE);
}


const char* 
bro_record_get_nth_name(BroRecord *rec, int num)
{
  const char *name;
 
  if ( (name = __bro_record_get_nth_name(rec, num)))
    return name;

  return NULL;
}
 

void *
bro_record_get_nth_val(BroRecord *rec, int num, int *type)
{
  BroVal *val;
  int type_found;
  void *result = NULL;

  if (type && (*type < BRO_TYPE_UNKNOWN || *type >= BRO_TYPE_MAX))
    {
      D(("Invalid value for type pointer (%i)\n", *type));
      return NULL;
    }

  if (! (val = __bro_record_get_nth_val(rec, num)))
    return NULL;

  /* Now transform the val into a form expected in *result,
   * based on the type given in the val.
   */
  if (! __bro_val_get_data(val, &type_found, &result))
    return NULL;
  
  if (type)
    {
      if (*type != BRO_TYPE_UNKNOWN && type_found != *type)
	{
	  D(("Type mismatch: expected type tag %i, found type tag %i\n", *type, type_found));
	  result = NULL;
	}
      
      *type = type_found;
    }
  
  return result;
}


void *
bro_record_get_named_val(BroRecord *rec, const char *name, int *type)
{
  BroVal *val;
  int type_found;
  void *result = NULL;
 
  if (type && (*type < BRO_TYPE_UNKNOWN || *type >= BRO_TYPE_MAX))
    {
      D(("Invalid value for type pointer (%i)\n", *type));
      return NULL;
    }
 
  if (! (val = __bro_record_get_named_val(rec, name)))
    return NULL;

  /* Now transform the val into a form expected in *result,
   * based on the type given in the val.
   */
  if (! __bro_val_get_data(val, &type_found, &result))
    return NULL;
  
  if (type)
    {
      if (*type != BRO_TYPE_UNKNOWN && type_found != *type)
	{
	  D(("Type mismatch: expected type tag %i for field '%s', found tag %i\n",
	     *type, name, type_found));
	  result = NULL;
	}

      *type = type_found;
    }
  
  return result;
}


int
bro_record_set_nth_val(BroRecord *rec, int num,
		       int type, const char *type_name, const void *val)
{
  BroVal *v;
  char *name;

  D_ENTER;

  if (! rec || num < 0 || num >= rec->val_len ||
      type < 0 || type >= BRO_TYPE_MAX || ! val)
    {
      D(("Input error: (%p, %i, %i, %p)\n", rec, num, type, val));
      D_RETURN_(FALSE);
    }
  
  if (! (v = __bro_record_get_nth_val(rec, num)))
    D_RETURN_(FALSE);

  if (! (name = __bro_sobject_data_get((BroSObject *) v, "field")))
    D_RETURN_(FALSE);
  
  if (! (v = __bro_val_new_of_type(type, type_name)))
    {
      D(("Could not get val of type %i\n", type));
      D_RETURN_(FALSE);
    }
  
  __bro_sobject_data_set((BroSObject *) v, "field", strdup(name));

  if (! __bro_val_assign(v, val))
    {
      D(("Could not assign value to the new val.\n"));
      __bro_sobject_release((BroSObject *) v);
      D_RETURN_(FALSE);
    }

  __bro_record_set_nth_val(rec, num, v);
  D_RETURN_(TRUE);
}


int
bro_record_set_named_val(BroRecord *rec, const char *name,
			 int type, const char *type_name, const void *val)
{
  BroVal *v;

  D_ENTER;

  if (! rec || ! name || !*name ||
      type < 0 || type >= BRO_TYPE_MAX || ! val)
    {
      D(("Input error: (%p, %s, %i, %p)\n", rec, name, type, val));
      D_RETURN_(FALSE);
    }
  
  if (! (v = __bro_val_new_of_type(type, type_name)))
    {
      D(("Could not get val of type %i\n", type));
      D_RETURN_(FALSE);
    }
    
  if (! __bro_val_assign(v, val))
    {
      D(("Could not assign value to the new val.\n"));
      __bro_sobject_release((BroSObject *) v);
      D_RETURN_(FALSE);
    }
  
  __bro_record_set_named_val(rec, name, v);
  D_RETURN_(TRUE);
}


/* -------------------------- Tables & Sets -------------------------- */

BroTable *
bro_table_new(void)
{
  BroTable *tbl;

  D_ENTER;
  tbl = __bro_table_new();
  D_RETURN_(tbl);
}


void
bro_table_free(BroTable *tbl)
{
  D_ENTER;
  __bro_table_free(tbl);
  D_RETURN;
}


int
bro_table_insert(BroTable *tbl,
		 int key_type, const void *key,
		 int val_type, const void *val)
{
  BroVal *vv = NULL;
  BroListVal *lv;

  D_ENTER;

  if (! tbl || !key || !val)
    D_RETURN_(FALSE);

  if (tbl->tbl_key_type != BRO_TYPE_UNKNOWN &&
      tbl->tbl_key_type != key_type)
    {
      D(("Type mismatch when inserting key of type %d, expecting %d\n",
	 key_type, tbl->tbl_key_type));
      D_RETURN_(FALSE);
    }

  tbl->tbl_key_type = key_type;

  if (tbl->tbl_val_type != BRO_TYPE_UNKNOWN &&
      tbl->tbl_val_type != val_type)
    {
      D(("Type mismatch when inserting val of type %d, expecting %d\n",
	 val_type, tbl->tbl_val_type));
      D_RETURN_(FALSE);
    }

  tbl->tbl_val_type = val_type;

  /* Now need to creat BroVals out of the raw data provided.
   * If the key_type is BRO_TYPE_LIST, it means the argument
   * is expected to be a BroRecord and its elements will be
   * used as elements of a list of values, as used internally
   * by Bro. For all other BRO_TYPE_xxx values, the type is
   * used in the obvious way.
   */
  lv = __bro_list_val_new();
  
  if (key_type == BRO_TYPE_LIST)
    {
      /* We need to unroll the record elements and put them
       * all in the list val.
       */
      
      BroRecord *rec = (BroRecord*) key;
      int i;

      for (i = 0; i < __bro_record_get_length(rec); i++)
	{
	  /* We can here leverage the fact that internally, all
	   * elements of a BroRec are BroVals.
	   */
	  BroVal *v = __bro_record_get_nth_val(rec, i);
	  BroVal *v_copy = (BroVal*) __bro_sobject_copy((BroSObject*) v);
	  __bro_list_val_append(lv, v_copy); 
	}
    }
  else
    {
      BroVal *kv;

      /* In this case we actually need to create a BroVal from
       * the user's raw data first.
       */
      if (! (kv = __bro_val_new_of_type(key_type, NULL)))
	{
	  D(("Could not create val of type %d\n", key_type));
	  D_RETURN_(FALSE);
	}
      
      __bro_val_assign(kv, key);
      __bro_list_val_append(lv, kv);
    }  
  
  if (val)
    {
      if (! (vv = __bro_val_new_of_type(val_type, NULL)))
	{
	  D(("Could not crate val of type %d\n", val_type));
	  D_RETURN_(FALSE);
	}
      
      __bro_val_assign(vv, val);
    }

  __bro_table_insert(tbl, (BroVal*) lv, vv);  
  
  D_RETURN_(TRUE);
}


void *
bro_table_find(BroTable *tbl, const void *key)
{
  BroListVal *lv;
  BroVal *val, *result_val;
  void *result = NULL;
  BroRecord *rec = NULL;

  D_ENTER;

  lv = __bro_list_val_new();

  if (tbl->tbl_key_type == BRO_TYPE_LIST)
    {
      /* Need to interpret the given key as a record and hook its
       * elements into the list. Below we unhook the list from the
       * ListVal before releasing it.
       */
      rec = (BroRecord *) key;
      lv->list = rec->val_list;
      lv->len = rec->val_len;
    }
  else
    {
      if (! (val = __bro_val_new_of_type(tbl->tbl_key_type, NULL)))
	{
	  D(("Could not create val of type %d.\n", tbl->tbl_key_type));
	  D_RETURN_(NULL);
	}
      
      __bro_val_assign(val, key);
      __bro_list_val_append(lv, val);
    }
  
  if ( (result_val = __bro_table_find(tbl, (BroVal*) lv)))
    {
      if (! __bro_val_get_data(result_val, NULL, &result))
	{
	  __bro_sobject_release((BroSObject*) lv);
	  D_RETURN_(NULL);	  
	}
    }
  
  if (rec)
    {
      lv->list = NULL;
      lv->len = 0;
    }

  __bro_sobject_release((BroSObject*) lv);
  
  D_RETURN_(result);
}


int
bro_table_get_size(BroTable *tbl)
{
  int result;

  D_ENTER;
  result = __bro_table_get_size(tbl);
  D_RETURN_(result);
}

typedef struct bro_table_cb_data
{ 
  void *user_data;
  BroTableCallback cb;
  int is_set;
} BroTableCBData;

static int
bro_table_foreach_cb(BroListVal *key, BroVal *val, BroTableCBData *data)
{
  int result;
  void *key_data = NULL, *val_data = NULL;
  BroRecord *rec = NULL;
  
  if (__bro_list_val_get_length(key) > 1)
    {
      /* Need to shrink-wrap it into a record. */
      BroList *l;
      rec = __bro_record_new();
      
      for (l = key->list; l; l = __bro_list_next(l))
	{
	  BroVal *tmp = (BroVal*) __bro_list_data(l);
	  
	  /* __bro_record_add_val() does not internally copy the added
	   * val. Without bumping up the val's refcount, __bro_record_free()
	   * below would possibly nuke the val when it decrements the count
	   * by 1.
	   */
	  __bro_sobject_ref((BroSObject*) tmp);
	  __bro_record_add_val(rec, tmp);
	}

      key_data = (void*) rec;
    }
  else
    {
      /* Direct passthrough. */
      BroVal *v = __bro_list_val_get_front(key);
      D(("Index type is atomic, type %d/%d\n",
	 v->val_type->tag, v->val_type->internal_tag));
    
      if (! __bro_val_get_data(v, NULL, &key_data))
	{
	  D(("Failed to obtain user-suitable data representation.\n"));
	  return TRUE;
	}
    }
  
  if (! data->is_set && ! __bro_val_get_data(val, NULL, &val_data))
    {
      D(("Failed to obtain user-suitable data representation.\n"));
      result = FALSE;
      goto return_result;
    }
  
  result = data->cb(key_data, val_data, data->user_data);
  
 return_result:
  if (rec)
    __bro_record_free(rec);
  
  return result;
}

void
bro_table_foreach(BroTable *tbl,
		  BroTableCallback cb,
		  void *user_data)
{
  BroTableCBData data;

  D_ENTER;

  data.user_data = user_data;
  data.cb = cb;
  data.is_set = __bro_table_is_set(tbl);

  __bro_table_foreach(tbl,
		      (BroTableCallback) bro_table_foreach_cb,
		      &data);
  D_RETURN;
}

void
bro_table_get_types(BroTable *tbl,
		    int *key_type, int *val_type)
{
  if (! tbl)
    return;

  if (key_type)
    *key_type = tbl->tbl_key_type;
  if (val_type)
    *val_type = tbl->tbl_val_type;
}


BroSet *
bro_set_new(void)
{
  BroSet *result;

  D_ENTER;
  result = (BroSet*) __bro_table_new();
  D_RETURN_(result);
}

void
bro_set_free(BroSet *set)
{
  D_ENTER;
  __bro_table_free((BroTable*) set);
  D_RETURN;
}

int
bro_set_insert(BroSet *set, int type, const void *val)
{
  int result;

  D_ENTER;
  
  result = bro_table_insert((BroTable*) set,
			    type, val,
			    BRO_TYPE_UNKNOWN, NULL);
  
  D_RETURN_(result);
}

int
bro_set_find(BroSet *set, const void *key)
{
  int result;

  D_ENTER;
  result = (bro_table_find((BroTable*) set, key) != NULL);
  D_RETURN_(result);
}

int
bro_set_get_size(BroSet *set)
{
  int result;

  D_ENTER;
  result = __bro_table_get_size((BroTable*) set);
  D_RETURN_(result);
}

typedef struct bro_set_cb_data
{ 
  void *user_data;
  BroSetCallback cb;
} BroSetCBData;

static int
bro_set_foreach_cb(void *key, void *val, BroSetCBData *data)
{
  return data->cb(key, data->user_data);
}

void
bro_set_foreach(BroSet *set,
		BroSetCallback cb,
		void *user_data)
{
  BroSetCBData data;

  D_ENTER;
  
  data.user_data = user_data;
  data.cb = cb;

  bro_table_foreach((BroTable*) set,
		    (BroTableCallback) bro_set_foreach_cb,
		    &data);
  
  D_RETURN;
}

void
bro_set_get_type(BroSet *set, int *type)
{
  return bro_table_get_types((BroTable*) set, type, NULL);
}

/* ------------------------------ Strings ---------------------------- */

void
bro_string_init(BroString *bs)
{
  if (! bs)
    return;

  memset(bs, 0, sizeof(BroString));
}


int
bro_string_set(BroString *bs, const char *s)
{
  if (! bs || !s)
    return FALSE;
  
  return bro_string_set_data(bs, (const uchar *) s, strlen(s));
}


int
bro_string_set_data(BroString *bs, const uchar *data, int data_len)
{
  uchar *data_copy;
  
  if (! bs || !data || data_len < 0)
    return FALSE;
  
  if (! (data_copy = malloc(data_len + 1)))
    return FALSE;
  
  memcpy(data_copy, data, data_len);
  data_copy[data_len] = '\0';
  
  bs->str_len = data_len;
  bs->str_val = data_copy;

  return TRUE;
}


const uchar   *
bro_string_get_data(const BroString *bs)
{
  return bs ? bs->str_val : NULL;
}


uint32
bro_string_get_length(const BroString *bs)
{
  return bs ? bs->str_len : 0;
}


BroString *
bro_string_copy(BroString *bs)
{
  BroString *result;

  if (! bs)
    return NULL;

  if (! (result = calloc(1, sizeof(BroString))))
    return NULL;

  bro_string_assign(bs, result);
  return result;
}


void
bro_string_assign(BroString *src, BroString *dst)
{
  if (! src || ! dst)
    return;

  bro_string_cleanup(dst);
  dst->str_len = src->str_len;

  if (! (dst->str_val = malloc(dst->str_len + 1)))
    {
      D(("Out of memory.\n"));
      dst->str_len = 0;
      return;
    }

  memcpy(dst->str_val, src->str_val, dst->str_len);
  dst->str_val[dst->str_len] = '\0';
}


void
bro_string_cleanup(BroString *bs)
{
  if (! bs)
    return;

  if (bs->str_val)
    free(bs->str_val);

  memset(bs, 0, sizeof(BroString));
}


void
bro_string_free(BroString *bs)
{
  if (! bs)
    return;

  bro_string_cleanup(bs);
  free(bs);
}

/* ----------------------- Pcap Packet Handling ---------------------- */
#ifdef BRO_PCAP_SUPPORT

void
bro_conn_set_packet_ctxt(BroConn *bc, int link_type)
{
  if (! bc)
    return;

  bc->pcap_link_type = link_type;
}


void
bro_conn_get_packet_ctxt(BroConn *bc, int *link_type)
{
  if (! bc)
    return;

  if (link_type)
    *link_type = bc->pcap_link_type;
}


BroPacket *
bro_packet_new(const struct pcap_pkthdr *hdr, const u_char *data, const char *tag)
{
  BroPacket *packet;

  if (! hdr || ! data)
    return NULL;

  if (! (packet = calloc(1, sizeof(BroPacket))))
    return NULL;
 
  packet->pkt_pcap_hdr = *hdr;
  packet->pkt_tag = strdup(tag ? tag : "");

  if (! (packet->pkt_data = malloc(hdr->caplen)))
    {
      free(packet);
      return NULL;
    }

  memcpy((u_char *) packet->pkt_data, data, hdr->caplen);
  return packet;
}


BroPacket *
bro_packet_clone(const BroPacket *src)
{
  BroPacket *dst;
  
  if (! (dst = calloc(1, sizeof(BroPacket))))
    return NULL;
  
  if (! __bro_packet_clone(dst, src))
    {
      bro_packet_free(dst);
      return NULL;
    }

  return dst;
}


void
bro_packet_free(BroPacket *packet)
{
  if (! packet)
    return;

  if (packet->pkt_data)
    free((u_char *) packet->pkt_data);

  if (packet->pkt_tag)
    free((u_char *) packet->pkt_tag);

  free(packet);
}

int
bro_packet_send(BroConn *bc, BroPacket *packet)
{
  if (! bc || ! packet)
    {
      D(("Invalid input.\n"));
      return FALSE;
    }

  return __bro_io_packet_queue(bc, packet);
}

#endif

/* --------------------------- Miscellaneous ------------------------- */

double
bro_util_current_time(void)
{
  return __bro_util_get_time();
}


double 
bro_util_timeval_to_double(const struct timeval *tv)
{
  return __bro_util_timeval_to_double(tv);
}



