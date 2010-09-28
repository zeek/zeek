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
#include <string.h>
#include <unistd.h>
#include <errno.h>

#ifdef __EMX__
#include <strings.h>
#endif 

#include <bro_types.h>
#include <bro_event.h>
#include <bro_debug.h>
#include <bro_io.h>
#include <bro_event_reg.h>

typedef void (*BroEvDispatcher)(BroConn *bc, BroEventCB *cb, BroEvent *ev);

#define DISPATCH_TABLE_SIZE 15

/* Goes through all vals in the given event ev and extracts
 * from each val a pointer to its actual value, storing it
 * into the vals array.
 */
static int
event_reg_init_vals(BroEvent *ev, void **vals)
{
  int i;
  BroList *l;
  BroVal *val;
  
  for (i = 0, l = ev->val_list; l; i++, l = __bro_list_next(l))
    {
      val = __bro_list_data(l);
      
      if (! __bro_val_get_data(val, NULL, &(vals[i])))
	{
	  D(("Error during callback parameter marshaling of parameter %i\n", i));
	  return FALSE;
	}
    }
  
  return TRUE;
}

/* Goes through all vals in the given event ev and extracts
 * from each val a pointer to its actual value and the type
 * of the val, storing it into the given BroEvArg and BroValMeta
 * structures.
 */
static int
event_reg_init_args(BroEvent *ev, BroEvArg *args)
{
  int i;
  BroList *l;
  BroVal *val;
  
  for (i = 0, l = ev->val_list; l; l = __bro_list_next(l), args++, i++)
    {
      val = __bro_list_data(l);

      if (! __bro_val_get_data(val, &args->arg_type, &args->arg_data))
	{
	  D(("Error during callback parameter marshaling of parameter %i\n", i));
	  return FALSE;
	}
    }
  
  return TRUE;
}

static void
dispatcher_compact(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  BroEvMeta meta;
  BroEvArg *args = NULL;

  memset(&meta, 0, sizeof(meta));

  if (! (args = calloc(ev->val_len, sizeof(BroEvArg)))) {
    D(("Out of memory when allocating %d BroEvArgs\n", ev->val_len));
    return;
  }
  
  meta.ev_name = (const char*) bro_string_get_data(&ev->name);
  meta.ev_ts = ev->ts;
  meta.ev_numargs = ev->val_len;
  meta.ev_args = args;
  meta.ev_start = (const uchar*) bc->rx_ev_start;
  meta.ev_end = (const uchar*) bc->rx_ev_end;

  if (! event_reg_init_args(ev, args)) {
    free(args);
    return;
  }
  
  cb->cb_compact_func(bc, cb->cb_user_data, &meta);

  free(args);
}

static void
dispatcher0(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  cb->cb_expanded_func(bc, cb->cb_user_data);
  return; ev = 0;
}

static void
dispatcher1(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[1];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0]);
}

static void
dispatcher2(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[2];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0], vals[1]);
}

static void
dispatcher3(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[3];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0], vals[1], vals[2]);
}

static void
dispatcher4(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[4];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0], vals[1], vals[2], vals[3]);
}

static void
dispatcher5(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[5];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0], vals[1], vals[2],
		       vals[3], vals[4]);
}

static void
dispatcher6(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[6];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0], vals[1], vals[2],
		       vals[3], vals[4], vals[5]);
}

static void
dispatcher7(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[7];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0], vals[1], vals[2],
		       vals[3], vals[4], vals[5], vals[6]);
}

static void
dispatcher8(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[8];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0], vals[1], vals[2],
		       vals[3], vals[4], vals[5], vals[6], vals[7]);
}

static void
dispatcher9(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[9];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0], vals[1], vals[2],
		       vals[3], vals[4], vals[5], vals[6], vals[7],
		       vals[8]);
}

static void
dispatcher10(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[10];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0], vals[1], vals[2],
		       vals[3], vals[4], vals[5], vals[6], vals[7],
		       vals[8], vals[9]);
}

static void
dispatcher11(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[11];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0], vals[1], vals[2],
		       vals[3], vals[4], vals[5], vals[6], vals[7],
		       vals[8], vals[9], vals[10]);
}

static void
dispatcher12(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[12];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0], vals[1], vals[2],
		       vals[3], vals[4], vals[5], vals[6], vals[7],
		       vals[8], vals[9], vals[10], vals[11]);
}

static void
dispatcher13(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[13];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0], vals[1], vals[2],
		       vals[3], vals[4], vals[5], vals[6], vals[7],
		       vals[8], vals[9], vals[10], vals[11], vals[12]);
}

static void
dispatcher14(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[14];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0], vals[1], vals[2],
		       vals[3], vals[4], vals[5], vals[6], vals[7],
		       vals[8], vals[9], vals[10], vals[11], vals[12],
	      vals[13]);
}

static void
dispatcher15(BroConn *bc, BroEventCB *cb, BroEvent *ev)
{
  void *vals[15];
  
  if (! event_reg_init_vals(ev, vals))
    return;
  
  cb->cb_expanded_func(bc, cb->cb_user_data, vals[0], vals[1], vals[2],
		       vals[3], vals[4], vals[5], vals[6], vals[7],
		       vals[8], vals[9], vals[10], vals[11], vals[12],
		       vals[13], vals[14]);
}

static BroEvDispatcher disp_table[] = 
  {
    dispatcher0, dispatcher1, dispatcher2, dispatcher3,
    dispatcher4, dispatcher5, dispatcher6, dispatcher7,
    dispatcher8, dispatcher9, dispatcher10, dispatcher11,
    dispatcher12, dispatcher13, dispatcher14, dispatcher15,
  };

static BroEventHandler*
event_reg_handler_new(const char *ev_name)
{
  BroEventHandler *beh;

  if (!ev_name || !*ev_name)
    return NULL;

  if (! (beh = calloc(1, sizeof(BroEventHandler))))
    return NULL;

  beh->ev_name = strdup(ev_name);
  TAILQ_INIT(&beh->cb_list);
  
  return beh;
}

static void
event_reg_handler_free(BroEventHandler *beh)
{
  BroEventCB *cb;

  if (!beh)
    return;

  if (beh->ev_name)
    free(beh->ev_name);

  while ( (cb = beh->cb_list.tqh_first))
    {
      TAILQ_REMOVE(&beh->cb_list, cb, cb_list);
      free(cb);
    }
  
  free(beh);  
}

static void
event_reg_handler_dispatch(BroConn *bc, BroEventHandler *beh, BroEvent *ev)
{
  BroEventCB *cb;

  if (!beh || !ev)
    return;

  if (ev->val_len > DISPATCH_TABLE_SIZE)
    return;

  for (cb = beh->cb_list.tqh_first; cb; cb = cb->cb_list.tqe_next)
    {
      switch (cb->cb_style) {
      case BRO_CALLBACK_EXPANDED:
	disp_table[ev->val_len](bc, cb, ev);
	break;

      case BRO_CALLBACK_COMPACT:
	dispatcher_compact(bc, cb, ev);
	break;

      default:
	;
      };
    }
}


BroEventReg   *
__bro_event_reg_new(void)
{
  BroEventReg *reg;

  if (! (reg = calloc(1, sizeof(BroEventReg))))
    return NULL;

  TAILQ_INIT(&reg->handler_list);
  return reg;
}


void
__bro_event_reg_free(BroEventReg *reg)
{
  BroEventHandler *beh;

  if (!reg)
    return;

  while ( (beh = reg->handler_list.tqh_first))
    {
      TAILQ_REMOVE(&reg->handler_list, beh, handler_list);
      event_reg_handler_free(beh);
    }

  free(reg);
}

static void           
event_reg_add(BroEventCB *cb, BroEventReg *reg,
	      const char *ev_name)
{
  BroEventHandler *beh;

  for (beh = reg->handler_list.tqh_first; beh; beh = beh->handler_list.tqe_next)
    {
      if (strcmp(beh->ev_name, ev_name))
	continue;
      
      /* We have found a handler for this event.
       * Add the new callback and return.
       */
      TAILQ_INSERT_TAIL(&beh->cb_list, cb, cb_list);      
      reg->num_handlers++;
      return;
    }
  
  /* We don't have a handler for this event yet.
   * Create it, add a callback for the given func,
   * and register it.
   */
  if (! (beh = event_reg_handler_new(ev_name)))
    {
      free(cb);
      return;
    }

  TAILQ_INSERT_TAIL(&beh->cb_list, cb, cb_list);
  TAILQ_INSERT_TAIL(&reg->handler_list, beh, handler_list);  
  reg->num_handlers++;
}

void           
__bro_event_reg_add(BroConn *bc, const char *ev_name,
		    BroEventFunc func, void *user_data)
{
  BroEventHandler *beh;
  BroEventCB *cb;
  BroEventReg *reg;

  if (!bc || !ev_name || !*ev_name)
    return;
  if (! (reg = bc->ev_reg))
    return;
      
  /* Create a new callback data structure */
  if (! (cb = calloc(1, sizeof(BroEventCB))))
    return;
  
  cb->cb_expanded_func = func;
  cb->cb_user_data = user_data;
  cb->cb_style = BRO_CALLBACK_EXPANDED;
  
  event_reg_add(cb, reg, ev_name);
}


void           
__bro_event_reg_add_compact(BroConn *bc, const char *ev_name,
			    BroCompactEventFunc func, void *user_data)
{
  BroEventHandler *beh;
  BroEventCB *cb;
  BroEventReg *reg;

  if (!bc || !ev_name || !*ev_name)
    return;
  if (! (reg = bc->ev_reg))
    return;
      
  /* Create a new callback data structure */
  if (! (cb = calloc(1, sizeof(BroEventCB))))
    return;
  
  cb->cb_compact_func = func;
  cb->cb_user_data = user_data;
  cb->cb_style = BRO_CALLBACK_COMPACT;
  
  event_reg_add(cb, reg, ev_name);
}


int
__bro_event_reg_remove(BroConn *bc, const char *ev_name)
{
  BroEventHandler *beh;
  BroEventReg *reg;

  if (!bc || !ev_name || !*ev_name)
    return FALSE;
  if (! (reg = bc->ev_reg))
    return FALSE;

  for (beh = reg->handler_list.tqh_first; beh; beh = beh->handler_list.tqe_next)
    {
      if (strcmp(beh->ev_name, ev_name))
	continue;

      TAILQ_REMOVE(&reg->handler_list, beh, handler_list);
      event_reg_handler_free(beh);
      reg->num_handlers--;
      return TRUE;
    }

  return FALSE;
}


int
__bro_event_reg_request(BroConn *bc)
{
  BroEventReg *reg;
  BroEventHandler *beh;
  BroRequest *req;
  int len = 0;
  int result;
  char *ptr;

  D_ENTER;

  if (!bc)
    D_RETURN_(FALSE);
  
  if (! (reg = bc->ev_reg))
    D_RETURN_(FALSE);
  
  /* Go over all handlers once, and collect the total length of
   * all event names including terminating 0s.
   */
  for (beh = reg->handler_list.tqh_first; beh; beh = beh->handler_list.tqe_next)
    len += strlen(beh->ev_name) + 1;

  /* Allocate a request structure for that length */
  if (! (req = __bro_event_request_new(len)))
    D_RETURN_(FALSE);

  /* Go through again and copy all event names into the
   * request structure.
   */
  ptr = req->req_dat;
  for (beh = reg->handler_list.tqh_first; beh; beh = beh->handler_list.tqe_next)
    {
      D(("Requesting event '%s'\n", beh->ev_name));
      memcpy(ptr, beh->ev_name, strlen(beh->ev_name));
      ptr += strlen(ptr) + 1;
    }
  
  if (! __bro_io_request_queue(bc, req))
    D_RETURN_(FALSE);

  D_RETURN_(TRUE);
}


void
__bro_event_reg_dispatch(BroConn *bc, BroEvent *ev)
{
  BroEventReg *reg;
  BroEventHandler *beh;

  D_ENTER;

  if (!bc || !ev || ! (reg = bc->ev_reg))
    {
      D(("Input error\n"));
      D_RETURN;
    }
  
  D(("Dispatching event '%s' with %i paramaters.\n", ev->name.str_val, ev->val_len));

  for (beh = reg->handler_list.tqh_first; beh; beh = beh->handler_list.tqe_next)
    {
      if (strcmp(__bro_event_get_name(ev), beh->ev_name) == 0)
	event_reg_handler_dispatch(bc, beh, ev);
    }  
  
  D_RETURN;
}


BroRequest *
__bro_event_request_new(int len)
{
  BroRequest *req;

  if (len <= 0)
    return NULL;

  if (! (req = calloc(1, sizeof(BroRequest))))
    return NULL;

  if (! (req->req_dat = calloc(len + 1, sizeof(char))))
    {
      free(req);
      return NULL;
    }
  
  req->req_len = len;
  return req;
}


void
__bro_event_request_free(BroRequest *req)
{
  if (! req)
    return;

  if (req->req_dat)
    free(req->req_dat);
  
  free(req);
}

