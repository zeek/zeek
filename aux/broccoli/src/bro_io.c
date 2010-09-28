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
#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <errno.h>

#ifdef __MINGW32__
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <bro_types.h>
#include <bro_debug.h>
#include <bro_buf.h>
#include <bro_event.h>
#include <bro_event_reg.h>
#include <bro_util.h>
#include <bro_type.h>
#include <bro_val.h>
#include <bro_io.h>
#include <bro_id.h>
#ifdef BRO_PCAP_SUPPORT
#include <bro_packet.h>
#endif

/* A static array that can translate message types into strings so
 * it's clearer what's going on when debugging:
 */
static char * msg_type_str[] = {
  "BRO_MSG_NONE",
  "BRO_MSG_VERSION",
  "BRO_MSG_SERIAL",
  "BRO_MSG_CLOSE",
  "BRO_MSG_CLOSE_ALL",
  "BRO_MSG_ERROR",
  "BRO_MSG_CONNECTTO",
  "BRO_MSG_CONNECTED",
  "BRO_MSG_REQUEST",
  "BRO_MSG_LISTEN",
  "BRO_MSG_LISTEN_STOP",
  "BRO_MSG_STATS",
  "BRO_MSG_CAPTURE_FILTER",
  "BRO_MSG_REQUEST_SYNC",
  "BRO_MSG_PHASE_DONE",
  "BRO_MSG_PING",
  "BRO_MSG_PONG",
  "BRO_MSG_CAPS",
  "BRO_MSG_COMPRESS",
};

static const char *
msg_type_2_str(int type)
{
  if (type < 0 || type >= BRO_MSG_MAX)
    return "<invalid>";

  return msg_type_str[type];
}

/* The maximum number of attempts we make in one go in order
 * to extract data from the pipe. It appears that OpenSSL does
 * not fully hide the record-oriented transfer and repeated
 * writes at one end also require repeated reads at the other
 * end. If anyone can confirm or deny this, please get in touch.
 */
#define BRO_BIO_READ_ROUNDS_MAX   20

/* Reading-related --------------------------------------------------- */

static int
io_read_chunk_size(BroConn *bc, uint32 *chunk_size)
{
  if (! __bro_buf_ptr_read(bc->rx_buf, chunk_size, sizeof(uint32)))
    {
      D(("Couldn't read chunk size\n"));
      return FALSE;
    }

  *chunk_size = ntohl(*chunk_size);

  if (! __bro_buf_ptr_check(bc->rx_buf, *chunk_size))
    {
      D(("Not all chunk data available\n"));
      return FALSE;
    }

  D(("We have a chunk of size %i\n", *chunk_size));
  return TRUE;
}

static int
io_read_msg_hdr(BroConn *bc, BroMsgHeader *msg_hdr)
{
  if (! __bro_buf_ptr_read(bc->rx_buf, msg_hdr, sizeof(BroMsgHeader)))
    {
      D(("Couldn't read message header\n"));
      return FALSE;
    }
  
  msg_hdr->hdr_peer_id = ntohs(msg_hdr->hdr_peer_id);
  
  return TRUE;
}

static int
io_msg_fill_rx(BroConn *bc)
{
  BroBuf tmp_buf;
  int i, n, total = 0;

  if (bc->state->rx_dead)
    {
      if (! (bc->conn_flags & BRO_CFLAG_RECONNECT))
	return FALSE;
      
      D(("Connection dead and we want to reconnect ...\n"));
      
      if (! bro_conn_reconnect(bc))
	return FALSE;
    }
  
  for (i = 0; i < BRO_BIO_READ_ROUNDS_MAX; i++)
    {
      __bro_buf_init(&tmp_buf);

      n = __bro_openssl_read(bc, __bro_buf_get(&tmp_buf),
			     __bro_buf_get_size(&tmp_buf));
      
      if (n <= 0)
	{
	  __bro_buf_cleanup(&tmp_buf);      	  
	  
	  if (n < 0)
	    {
	      D(("Read returned error after %i/%i rounds and %i bytes\n",
		 i, BRO_BIO_READ_ROUNDS_MAX, total));
	      return -1;
	    }
#ifdef BRO_DEBUG
	  if (total > 0)
	    D(("Read %i bytes in %i/%i rounds.\n",
	       total, i, BRO_BIO_READ_ROUNDS_MAX));
#endif	  
	  if (total == 0)
	    continue;
	  
	  return total;
	}
      
      __bro_buf_append(bc->rx_buf, __bro_buf_get(&tmp_buf), n);
      __bro_buf_cleanup(&tmp_buf);
      total += n;      
    }
  
  D(("Read %i bytes in %i/%i rounds.\n",
     total, i, BRO_BIO_READ_ROUNDS_MAX));
  
  return total;
}


static int
io_skip_chunk(BroBuf *buf, uint32 buf_off, uint32 chunk_size)
{
  if (! buf)
    return FALSE;

  if (! __bro_buf_ptr_seek(buf, buf_off, SEEK_SET))
    return FALSE;

  /* We skip a uint32 for the chunk size and then chunk_size
   * bytes.
   */
  if (! __bro_buf_ptr_seek(buf, sizeof(uint32) + chunk_size, SEEK_CUR))
    return FALSE;
  
  D(("Skipping %i + %i\n", sizeof(uint32), chunk_size));

  return TRUE;
}


static int
io_process_serialization(BroConn *bc)
{
  BroVal vbuf;

  D_ENTER;

  if (! __bro_buf_read_char(bc->rx_buf, &vbuf.val_char))
    {
      D(("Couldn't read serialization type\n"));
      D_RETURN_(FALSE);
    }

  switch (vbuf.val_char)
    {
    case 'e':
      {
	BroEvent *ev;

	bc->rx_ev_start = (const char*) bro_buf_ptr_get(bc->rx_buf);

	D(("Processing serialized event.\n"));
	if (! (ev = __bro_event_unserialize(bc)))
	  {
	    bc->rx_ev_start = bc->rx_ev_end = NULL;
	    D_RETURN_(FALSE);
	  }

	bc->rx_ev_end = (const char*) bro_buf_ptr_get(bc->rx_buf);	
	__bro_event_reg_dispatch(bc, ev);
	__bro_event_free(ev);      
	bc->rx_ev_start = bc->rx_ev_end = NULL;
      }
      break;

    case 'i':
      {
	BroID *id;

	D(("Processing serialized ID.\n"));
	if (! (id = (BroID *) __bro_sobject_unserialize(SER_IS_ID, bc)))
	  D_RETURN_(FALSE);
	
	D(("ID read successfully.\n"));
	/* Except we don't do anything with it yet. :) */
	__bro_sobject_release((BroSObject *) id);
      }
      break;

    case 'p':
      {
#ifdef BRO_PCAP_SUPPORT
	BroPacket *packet;
	
	if (! (packet = __bro_packet_unserialize(bc)))
	  D_RETURN_(FALSE);
	
	D(("Packet read successfully.\n"));
	bro_packet_free(packet);
#else
	D_RETURN_(FALSE);
#endif
      }
      break;

    default:
      /* We do not handle anything else yet -- just say
       * we are happy and return.
       */
      D(("Unknown serialization of type %c\n", vbuf.val_char));
      D_RETURN_(FALSE);
    }

  /* After a complete unserialization, we enforce the size limit
   * of the cache. We can't do it on the go as a new object that
   * is unserialized may still contain references to previously
   * cached items which we might evict.
   */
  while (__bro_ht_get_size(bc->io_cache) > bc->io_cache_maxsize)
    __bro_ht_evict_oldest(bc->io_cache);
  
  D_RETURN_(TRUE);
}


/* Writing-related --------------------------------------------------- */

static int
io_fill_raw(BroBuf *buf, BroBuf *data)
{
  return __bro_buf_write_data(buf, __bro_buf_get(data), __bro_buf_get_used_size(data));
}


static int
io_fill_request(BroBuf *buf, BroRequest *req)
{
  return __bro_buf_write_data(buf, req->req_dat, req->req_len);
}

static int
io_fill_msg_header(BroBuf *buf, BroMsgHeader *mh)
{
  mh->hdr_peer_id = htonl(mh->hdr_peer_id);
  return __bro_buf_write_data(buf, mh, sizeof(BroMsgHeader));
}

static int
io_msg_empty_tx(BroConn *bc)
{
  int n;
  int todo;

  D_ENTER;

  if (bc->state->tx_dead && (bc->conn_flags & BRO_CFLAG_RECONNECT))
    bro_conn_reconnect(bc);      

  if (bc->state->tx_dead)
    {
      D(("Connection dead, not writing anything. Todo: %i\n", __bro_buf_get_used_size(bc->tx_buf)));
      D_RETURN_(FALSE);
    }

  /* This function loops until the entire buffer contents
   * are written out. This is not perfect but easier for now.
   * Revisit this as a FIXME.
   */
  for ( ; ; )
    {
      todo = __bro_buf_get_used_size(bc->tx_buf);

      if (todo == 0)
	D_RETURN_(TRUE);
      
      n = __bro_openssl_write(bc, __bro_buf_get(bc->tx_buf), todo);
      
      /* If we couldn't write out anything at all, then we report
       * failure.
       */      
      if (n < 0)
	{
	  D(("SSL error -- nothing written.\n"));
	  D_RETURN_(FALSE);
	}
      
      if (0 < n && n < todo)
	{
	  /* We have an incomplete write. Consume what we were
	   * able to write out.
	   */
	  D(("*** Incomplete write: %i/%i\n", n, todo));
	  
	  if (! __bro_buf_ptr_seek(bc->tx_buf, n, SEEK_SET))
	    {
	      /* This should never happen. */
	      D(("*** Buffer contents are screwed :(\n"));
	      D_RETURN_(FALSE);
	    }
	  
	  __bro_buf_consume(bc->tx_buf);
	}
      
      D(("<<< Sent %i/%i bytes.\n", n, todo));
      
      if (n == todo)
	{
	  /* If we wrote out everything that was left, report success. */
	  __bro_buf_reset(bc->tx_buf);
	  D_RETURN_(TRUE);
	}
    }
}

static int      
io_msg_fill_tx(BroConn *bc, BroMsg *msg)
{
  int result = TRUE;

  D_ENTER;

  if (!bc || !msg)
    {
      D(("Input error.\n"));
      D_RETURN_(FALSE);
    }

  /* Check if anything is still left in the input buffer. In that case,
   * we don't fill anything in but return right away, so the message
   * gets queued.
   */
  if (__bro_buf_get_used_size(bc->tx_buf) > 0)
    {
      D(("Buffer not empty; not filling!\n"));
      D_RETURN_(FALSE);
    }
  
  D((">>> Attempting write of %s\n", msg_type_2_str(msg->msg_header.hdr_type)));

  /* We will collect the message chunk in the connection's tx buffer.
   * We append stuff to it as we go along and at the end write it out.
   * When being sent, he buffer has the amount of octets to send at
   * the beginning, so the reader knows how much is coming.
   */
  __bro_buf_reset(bc->tx_buf);

  msg->msg_header_size = sizeof(BroMsgHeader);
  
  if (! __bro_buf_write_int(bc->tx_buf, msg->msg_header_size))
    {
      __bro_buf_reset(bc->tx_buf);
      D_RETURN_(FALSE);
    }
  
  /* Hook in the Bro message header */
  if (! io_fill_msg_header(bc->tx_buf, &msg->msg_header))
    {
      __bro_buf_reset(bc->tx_buf);
      D_RETURN_(FALSE);
    }
  
  if (msg->msg_cont_type != BRO_MSG_CONT_NONE)
    {
      uint32 msg_size_pos, msg_size_end;

      /* This starts another chunk of data (in Bro protocol speak),
       * but here we cannot yet know how big the chunk will be.
       * We save the offset in the buffer and return to it later,
       * overwriting the value with the then correct one.
       */
      msg_size_pos = __bro_buf_get_used_size(bc->tx_buf);
      if (! __bro_buf_write_int(bc->tx_buf, msg->msg_size))
	{
	  __bro_buf_reset(bc->tx_buf);
	  D_RETURN_(FALSE);
	}
      
      /* Gather the payload of the message we are about
       * to send into the buffer BUF.
       */
      switch (msg->msg_cont_type)
	{
	case BRO_MSG_CONT_RAW:
	  D(("Filling raw data into buffer\n"));
	  if (! io_fill_raw(bc->tx_buf, msg->msg_cont_raw))
	    {
	      __bro_buf_reset(bc->tx_buf);
	      D_RETURN_(FALSE);
	    }
	  break;
	  
	case BRO_MSG_CONT_EVENT:
	  /* Check if the peer actually requested the event, and if not,
	   * drop it silently (i.e., still return success).
	   */
	  if (! __bro_ht_get(bc->ev_mask, msg->msg_cont_ev->name.str_val))
	    {
	      D(("Event '%s' not requested by peer -- dropping.\n",
		 msg->msg_cont_ev->name.str_val));
	      __bro_buf_reset(bc->tx_buf);

	      /* This is not an error but a silent drop, so we
	       * return success.
	       */
	      D_RETURN_(TRUE);
	    }
	  
	  D(("Filling event into buffer\n"));
	  
	  if (! __bro_event_serialize(msg->msg_cont_ev, bc))
	    {
	      D(("Error during serialization.\n"));
	      __bro_buf_reset(bc->tx_buf);
	      D_RETURN_(FALSE);	
	    }
	  break;
	  
	case BRO_MSG_CONT_REQUEST:
	  D(("Filling request into buffer\n"));
	  if (! io_fill_request(bc->tx_buf, msg->msg_cont_req))
	    {
	      __bro_buf_reset(bc->tx_buf);
	      D_RETURN_(FALSE);	
	    }
	  break;

#ifdef BRO_PCAP_SUPPORT	  
	case BRO_MSG_CONT_PACKET:
	  if (! __bro_packet_serialize(msg->msg_cont_packet, bc))
	    {
	      __bro_buf_reset(bc->tx_buf);	      
	      D_RETURN_(FALSE);
	    }
	  break;
#endif
	default:
	  D(("ERROR -- invalid message content code %i\n", msg->msg_cont_type));
	  break;
	}
      
      /* Now calculate length of entire transmission --
       * we know where we wrote the uint32 containing the
       * size of the chunk, and we know where we are now,
       * so the length is their difference, minus the uint32
       * itself.
       */
      msg_size_end = __bro_buf_get_used_size(bc->tx_buf);
      msg->msg_size = msg_size_end - msg_size_pos - sizeof(uint32);
      D(("Serialized message sized %i bytes.\n", msg->msg_size));
      
      if (! __bro_buf_ptr_seek(bc->tx_buf, msg_size_pos, SEEK_SET))
	{
	  D(("Cannot seek to position %u -- we're screwed.\n", msg_size_pos));
	  __bro_buf_reset(bc->tx_buf);
	  D_RETURN_(FALSE);
	}
      
      if (! __bro_buf_write_int(bc->tx_buf, msg->msg_size))
	{
	  __bro_buf_reset(bc->tx_buf);
	  D_RETURN_(FALSE);
	}
    }
  
  D_RETURN_(result);
}


static int
io_msg_queue(BroConn *bc, BroMsg *msg)
{
  D_ENTER;

  if (!bc || !msg)
    D_RETURN_(FALSE);

  /* If anything is left over in the buffer, write it out now.
   * We don't care if it succeeds or not.
   */
  io_msg_empty_tx(bc);

  /* If the queue is empty, try to send right away.
   * If not, enqueue the event, and try to flush.
   */
  D(("Enqueing msg of type %s\n", msg_type_2_str(msg->msg_header.hdr_type)));

  if (! bc->msg_queue.tqh_first)
    {
      D(("No queue yet.\n"));
      if (io_msg_fill_tx(bc, msg))
	{
	  D(("Message serialized.\n"));

	  if (io_msg_empty_tx(bc))
	    {
	      D(("Message sent.\n"));
	    }

	  __bro_io_msg_free(msg);
	  bc->state->io_msg = BRO_IOMSG_WRITE;
	  D_RETURN_(TRUE);
	}
    }
  
  if (bc->state->tx_dead && ! (bc->conn_flags & BRO_CFLAG_ALWAYS_QUEUE))
    {
      D(("Connection %p disconnected, and no queuing requested: dropping message.\n", bc));
      __bro_io_msg_free(msg);
      D_RETURN_(FALSE);
    }

  TAILQ_INSERT_TAIL(&bc->msg_queue, msg, msg_queue);
  bc->msg_queue_len++;
  D(("Queue length now %i\n", bc->msg_queue_len));
  
  __bro_io_msg_queue_flush(bc);

  /* Check that the queue does not grow too big: */
  while (bc->msg_queue_len > BRO_MSG_QUEUELEN_MAX)
    {
      BroMsg *msg = bc->msg_queue.tqh_first;

      TAILQ_REMOVE(&bc->msg_queue, msg, msg_queue);
      __bro_io_msg_free(msg);
      bc->msg_queue_len--;
      
      D(("Dropped one message due to excess queue length, now %i\n", bc->msg_queue_len));
    }
  
  D_RETURN_(TRUE);
}


/* Non-static stuff below: ------------------------------------------- */

BroMsg *
__bro_io_msg_new(char type, uint32 peer_id)
{
  static int msg_counter = 0;
  BroMsg *msg;

  if (! (msg = calloc(1, sizeof(BroMsg))))
    return NULL;  
  
  msg->msg_header.hdr_type = type;
  msg->msg_header.hdr_peer_id = peer_id;
  msg->msg_cont_type = BRO_MSG_CONT_NONE;
  msg->msg_num = msg_counter++;

  return msg;
}


void
__bro_io_msg_free(BroMsg *msg)
{
  if (!msg)
    return;

  switch (msg->msg_cont_type)
    {
    case BRO_MSG_CONT_RAW:
      __bro_buf_free(msg->msg_cont_raw);
      break;
      
    case BRO_MSG_CONT_EVENT:
      __bro_event_free(msg->msg_cont_ev);
      break;
      
    case BRO_MSG_CONT_REQUEST:
      __bro_event_request_free(msg->msg_cont_req);
      break;
#ifdef BRO_PCAP_SUPPORT
    case BRO_MSG_CONT_PACKET:
      bro_packet_free(msg->msg_cont_packet);
      break;
#endif

    default:
      break;
    }
  
  free(msg);
}


void     
__bro_io_msg_set_cont(BroMsg *msg, int type, void *content)
{
  if (!msg)
    return;

  msg->msg_cont_type = type;

  switch (type)
    {
    case BRO_MSG_CONT_RAW:
      msg->msg_cont_raw = (BroBuf*) content;
      D(("Setting raw buffer content for message, type now %i, buffer data: %p\n",
	 msg->msg_cont_type, content));
      break;
      
    case BRO_MSG_CONT_EVENT:
      msg->msg_cont_ev = (BroEvent *) content;
      D(("Setting event content for message, type now %i, event: %s\n",
	 msg->msg_cont_type, msg->msg_cont.msg_ev->name.str_val));
      break;
      
    case BRO_MSG_CONT_REQUEST:
      msg->msg_cont_req = (BroRequest *) content;
      D(("Setting request content for message, type now %i\n", msg->msg_cont_type));
      break;

#ifdef BRO_PCAP_SUPPORT
    case BRO_MSG_CONT_PACKET:
      msg->msg_cont_packet = (BroPacket *) content;
      break;
#endif

    default:
      msg->msg_cont_type = BRO_MSG_CONT_NONE;
    }
}


int      
__bro_io_msg_queue_flush(BroConn *bc)
{
  BroMsg *msg;
  int result;

  D_ENTER;
    
  if (! bc)
    D_RETURN_(-1);
  
  for ( ; ; )
    {
      if (! io_msg_empty_tx(bc))
	break;

      if (! (msg = bc->msg_queue.tqh_first))
	break;
      
      if (! io_msg_fill_tx(bc, msg))
	break;
      
      TAILQ_REMOVE(&bc->msg_queue, msg, msg_queue);
      __bro_io_msg_free(msg);
      bc->msg_queue_len--;
      
      bc->state->io_msg = BRO_IOMSG_WRITE;
    }
  
  result = bc->msg_queue_len;  
  D_RETURN_(result);
}


void
__bro_io_msg_queue_dump(BroConn *bc, const char *message)
{
  BroMsg *msg;
  
  printf("%s: connection %p, length %i\n", message, bc, bc->msg_queue_len);
  
  for (msg = bc->msg_queue.tqh_first; msg; msg = msg->msg_queue.tqe_next)
    printf(" -- %s(%i)\n", msg_type_2_str(msg->msg_header.hdr_type), msg->msg_num);
}

int
__bro_io_raw_queue(BroConn *bc, int type, uchar *data, int data_len)
{
  BroMsg *msg;
  int result = FALSE;
  
  D_ENTER;

  if (!bc)
    D_RETURN_(FALSE);
  
  if (! (msg = __bro_io_msg_new(type, 0)))
    D_RETURN_(FALSE);

  if (data_len > 0)
    {      
      BroBuf *buf;

      if (! (buf = __bro_buf_new()))
	{
	  __bro_io_msg_free(msg);
	  D_RETURN_(FALSE);
	}
      
      __bro_buf_append(buf, data, data_len);
      __bro_io_msg_set_cont(msg, BRO_MSG_CONT_RAW, buf);
    }

  result = io_msg_queue(bc, msg);
  
  D_RETURN_(result);
}

int
__bro_io_rawbuf_queue(BroConn *bc, int type, BroBuf *buf)
{
  BroMsg *msg;
  int result = FALSE;
  
  D_ENTER;

  if (!bc || !buf)
    D_RETURN_(FALSE);
  
  if (! (msg = __bro_io_msg_new(type, 0)))
    D_RETURN_(FALSE);

  __bro_io_msg_set_cont(msg, BRO_MSG_CONT_RAW, buf);
  result = io_msg_queue(bc, msg);
  
  D_RETURN_(result);
}

int
__bro_io_event_queue(BroConn *bc, BroEvent *ev)
{
  BroEvent *ev_copy;
  BroMsg *msg;
  int result;

  D_ENTER;

  if (!bc)
    D_RETURN_(FALSE);
  
  if (! (msg = __bro_io_msg_new(BRO_MSG_SERIAL, 0)))
    D_RETURN_(FALSE);

  if (! (ev_copy = __bro_event_copy(ev)))
    {
      D(("Could not clone event\n"));
      D_RETURN_(FALSE);
    }

  __bro_io_msg_set_cont(msg, BRO_MSG_CONT_EVENT, ev_copy);
  result = io_msg_queue(bc, msg);
  D_RETURN_(result);  
}

int
__bro_io_request_queue(BroConn *bc, BroRequest *req)
{
  BroMsg *msg;
  int result;

  D_ENTER;

  if (!bc)
    D_RETURN_(FALSE);

  if (! (msg = __bro_io_msg_new(BRO_MSG_REQUEST, 0)))
    D_RETURN_(FALSE);

  __bro_io_msg_set_cont(msg, BRO_MSG_CONT_REQUEST, req);
  result = io_msg_queue(bc, msg);
  D_RETURN_(result);
}

#ifdef BRO_PCAP_SUPPORT
int
__bro_io_packet_queue(BroConn *bc, BroPacket *packet)
{
  BroPacket *clone;
  BroMsg *msg;
  int result;

  D_ENTER;

  if (!bc)
    D_RETURN_(FALSE);

  if (! (msg = __bro_io_msg_new(BRO_MSG_SERIAL, 0)))
    D_RETURN_(FALSE);

  if (! (clone = bro_packet_clone(packet)))
    {
      __bro_io_msg_free(msg);
      D_RETURN_(FALSE);
    }
  
  __bro_io_msg_set_cont(msg, BRO_MSG_CONT_PACKET, clone);
  result = io_msg_queue(bc, msg);
  D_RETURN_(result);
}
#endif

int
__bro_io_process_input(BroConn *bc)
{
  uint32          buf_off, chunk_size;
  BroMsgHeader    msg_hdr;
  int             result = FALSE;
  
  D_ENTER;
  
  /* Read all available data into receive buffer. Our socket is
   * nonblocking so if nothing's available we'll be back right
   * away. If nothing was read, the subsequent for loop will exit
   * right away, so the io_msg_fill_rx() return code need not be
   * checked here.
   */
  io_msg_fill_rx(bc);

  /* Try to process as much in the input buffer as we can */
  for ( ; ; )
    {  
      D(("----- Attempting to extract a message\n"));

      /* Get the current offset of the buffer pointer to make
       * sure we can reset to it if things go wrong.
       */
      buf_off = __bro_buf_ptr_tell(bc->rx_buf);
      
      /* Now check the buffer contents and see if there's enough
       * for us to analyze it. Start with a uint32 for the size
       * of the first chunk, and then the chunk itself.
       */
      if (! io_read_chunk_size(bc, &chunk_size))
	goto reset_return;
      
      if (chunk_size != sizeof(BroMsgHeader))
	{
	  D(("Received chunk should be %i bytes, but is %i\n",
	     sizeof(BroMsgHeader), chunk_size));
	  io_skip_chunk(bc->rx_buf, buf_off, chunk_size);
	  result = TRUE;
	  continue;
	}
      
      if (! io_read_msg_hdr(bc, &msg_hdr))
	goto reset_return;
      
      switch (msg_hdr.hdr_type)
	{
	case BRO_MSG_REQUEST:
	  {
	    char *tmp = NULL, *tmp2 = NULL;
	        
	    D(("Received MSQ_REQUEST\n"));
	        
	    /* We need to read another chunk, whose data will contain
	     * a sequence of 0-terminated strings, each one being the
	     * name of an event that the peering Bro is interested in.
	     */
	    if (! io_read_chunk_size(bc, &chunk_size))
	      goto reset_return;
	        
	    if (! (tmp = (char *) malloc(chunk_size * sizeof(char))))
	      goto reset_return;
	        
	    if (! __bro_buf_read_data(bc->rx_buf, tmp, chunk_size))
	      {
		free(tmp);
		goto reset_return;
	      }
	        
	    for (tmp2 = tmp; tmp2 < tmp + chunk_size; tmp2 = tmp2 + strlen(tmp2) + 1)
	      {
		char *key;

		if (__bro_ht_get(bc->ev_mask, tmp2))
		  continue;
		
		key = strdup(tmp2);
		__bro_ht_add(bc->ev_mask, key, key);
		D(("Will report event '%s'\n", tmp2));
	      }

	    D(("Now reporting %i event(s).\n", __bro_ht_get_size(bc->ev_mask)));
	    free(tmp);
	  }
	  break;
	    
	case BRO_MSG_VERSION:
	  {
	    uchar *data;
	    uint32 proto_version;
	    uint32 cache_size;
	    uint32 data_version;
	    uint32 runtime; /* unused */

	    D(("Received MSG_VERSION\n"));

	    /* We need to read another chunk for the raw data.
	     */
	    if (! io_read_chunk_size(bc, &chunk_size))
	      goto reset_return;

	    if (! (data = malloc(sizeof(uchar) * chunk_size)))
	      goto reset_return;

	    if (! __bro_buf_read_data(bc->rx_buf, data, chunk_size))
	      {
		free(data);
		goto reset_return;
	      }
	        
	    proto_version = ntohl(((uint32 *) data)[0]);
	    cache_size    = ntohl(((uint32 *) data)[1]);
	    data_version  = ntohl(((uint32 *) data)[2]);
	    runtime       = ntohl(((uint32 *) data)[3]);

	    /* If there are more bytes than required for the 4 uint32s
	     * used above, it means that the peer has sent a connection class
	     * identifier. Extract and register in the handle.
	     */
	    if (chunk_size > 4 * sizeof(uint32))
	      {
		if (bc->peer_class)
		  free(bc->peer_class);
		
		bc->peer_class = strdup((char *) (data + 4 * sizeof(uint32)));
	      }

	    if (proto_version != BRO_PROTOCOL_VERSION)
	      {
		D(("EEEK -- we speak protocol version %i, peer speeks %i. Aborting.\n",
		   BRO_PROTOCOL_VERSION, proto_version));		
		__bro_openssl_shutdown(bc);
		goto reset_return;
	      } else {
		D(("Protocols compatible, we speak version %i\n", BRO_PROTOCOL_VERSION));
	      }
	    
	    if (data_version != 0 && data_version != BRO_DATA_FORMAT_VERSION)
	      {
		D(("EEEK -- we speak data format version %i, peer speeks %i. Aborting.\n",
		   BRO_DATA_FORMAT_VERSION, data_version));		
		__bro_openssl_shutdown(bc);
		goto reset_return;
	      } else {
		D(("Data formats compatible, we speak version %i\n", BRO_DATA_FORMAT_VERSION));
	      }
	    
	    bc->io_cache_maxsize = cache_size;
	    D(("Receiver cache size set to %i entries.\n", cache_size));
	    free(data);

	    bc->state->conn_state_peer = BRO_CONNSTATE_HANDSHAKE;
	    D(("VERSION received, on %p, peer now in HANDSHAKE stage.\n"));
	  }
	  break;
	    
	case BRO_MSG_SERIAL:
	  {
	    uint32 pre_serial;
	        
	    D(("Received MSQ_SERIAL\n"));
	    pre_serial = __bro_buf_ptr_tell(bc->rx_buf);

	    if (! io_read_chunk_size(bc, &chunk_size))
	      goto reset_return;
	        
	    if (! io_process_serialization(bc))
	      io_skip_chunk(bc->rx_buf, pre_serial, chunk_size);
	  }
	  break;
	    
	case BRO_MSG_CAPTURE_FILTER:
	  {
	    uint32 pre_capture;

	    D(("Received MSQ_CAPTURE_FILTER\n"));
	    pre_capture = __bro_buf_ptr_tell(bc->rx_buf);
	        
	    if (! io_read_chunk_size(bc, &chunk_size))
	      goto reset_return;
	        
	    io_skip_chunk(bc->rx_buf, pre_capture, chunk_size);
	  }
	  break;

	case BRO_MSG_PHASE_DONE:
	  /* No additional content for this one. */
	  switch (bc->state->conn_state_peer)
	    {
	    case BRO_CONNSTATE_HANDSHAKE:
	      /* When we complete the handshake phase, it depends
	       * on whether or not the peer has requested synced
	       * state. If so, enter the sync phase, otherwise
	       * we're up and running.
	       */
	      if (bc->state->sync_state_requested)
		{
		  bc->state->conn_state_peer = BRO_CONNSTATE_SYNC;
		  D(("Phase done from peer on %p, sync requested, peer now in SYNC stage.\n", bc));
		}
	      else
		{
		  bc->state->conn_state_peer = BRO_CONNSTATE_RUNNING;
		  D(("Phase done from peer on %p, no sync requested, peer now in RUNNING stage.\n", bc));
		}
	      break;

	    case BRO_CONNSTATE_SYNC:
	      bc->state->conn_state_peer = BRO_CONNSTATE_RUNNING;
	      D(("Phase done from peer on %p, peer now in RUNNING stage.\n", bc));
	      break;
	      
	    default:
	      D(("Ignoring PHASE_DONE in conn state %i/%i on conn %p\n",
		 bc->state->conn_state_self, bc->state->conn_state_peer, bc));
	    }
	  break;
	  
	case BRO_MSG_REQUEST_SYNC:
		{   	  
	    uchar *data;
		
	    D(("Received MSQ_REQUEST_SYNC, peer now in SYNC stage.\n"));
		
	    bc->state->sync_state_requested = 1;
	    bc->state->conn_state_peer = BRO_CONNSTATE_SYNC;

	    /* We need to read another chunk for the raw data.
	     */
	    if (! io_read_chunk_size(bc, &chunk_size))
	      goto reset_return;

	    if (! (data = malloc(sizeof(uchar) * chunk_size)))
	      goto reset_return;

	    if (! __bro_buf_read_data(bc->rx_buf, data, chunk_size))
	      {
		free(data);
		goto reset_return;
	      }
	    D(("Skipping sync interpretation\n"));
	    free(data);
	    break;
	  }
	
	
	case BRO_MSG_CAPS:
	  {
	    uchar *data;

	    D(("Received MSG_CAPS\n"));

	    /* We need to read another chunk for the raw data.
	     */
	    if (! io_read_chunk_size(bc, &chunk_size))
	      goto reset_return;

	    if (! (data = malloc(sizeof(uchar) * chunk_size)))
	      goto reset_return;

	    if (! __bro_buf_read_data(bc->rx_buf, data, chunk_size))
	      {
		free(data);
		goto reset_return;
	      }
	    D(("Skipping capabilities interpretation\n"));
	    free(data);
	    break;
	  }

	default:
	  D(("Skipping unknown message type %i\n", msg_hdr.hdr_type));
	  break;
	}
      
      __bro_buf_consume(bc->rx_buf);
      result = TRUE;

      if ((bc->conn_flags & BRO_CFLAG_YIELD) &&
	  bc->state->conn_state_self == BRO_CONNSTATE_RUNNING &&
	  bc->state->conn_state_peer == BRO_CONNSTATE_RUNNING)	  
	break;
    }
  
 reset_return:
  __bro_buf_ptr_seek(bc->rx_buf, buf_off, SEEK_SET);
  D_RETURN_(result);
}


void
__bro_io_loop(BroConn *bc)
{
  D_ENTER;
  
  for ( ; ; )
    {
      D(("I/O loop iteration\n"));
      
      switch (bc->state->io_msg)
	{
	case BRO_IOMSG_STOP:
	  D(("I/O process %u exiting by request.\n", getpid()));
	  __bro_openssl_shutdown(bc);
	  exit(0);
	  
	case BRO_IOMSG_WRITE:
	  if (bc->state->tx_dead)
	    break;

	  if (! io_msg_empty_tx(bc))
	    {	      
	      D(("I/O handler %u encountered write error.\n", getpid()));
	      __bro_openssl_shutdown(bc);
	    }
	  break;

	case BRO_IOMSG_READ:
	  if (bc->state->rx_dead)
	    break;

	  if (io_msg_fill_rx(bc) < 0)
	    {
	      D(("I/O handler %u encountered read error.\n", getpid()));
	      __bro_openssl_shutdown(bc);
	    }
	  break;
	}
            
      bc->state->io_msg = BRO_IOMSG_NONE;
    }  
}
