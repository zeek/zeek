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
#include <sys/time.h>

#ifdef __EMX__
#include <strings.h>
#endif 

#include <bro_types.h>
#include <bro_type.h>
#include <bro_val.h>
#include <bro_debug.h>
#include <bro_event.h>

BroEvent      *
__bro_event_new(BroString *name)
{
  BroEvent *ev;

  if (!name)
    return NULL;

  if (! (ev = calloc(1, sizeof(BroEvent))))
    return NULL;

  if (! bro_string_set_data(&(ev->name), name->str_val, name->str_len))
    {
      free(ev);
      return NULL;
    }

  return ev;
}


void           
__bro_event_free(BroEvent *ev)
{
  if (!ev)
    return;

  bro_string_cleanup(&ev->name);
  __bro_list_free(ev->val_list, (BroFunc) __bro_sobject_release);
  free(ev);
}


BroEvent      *
__bro_event_copy(BroEvent *ev)
{
  BroEvent *ev_copy;
  BroVal *val, *val_copy;
  BroList *l;

  if (! ev)
    return NULL;
  
  if (! (ev_copy = __bro_event_new(&ev->name)))
    return NULL;
  
  for (l = ev->val_list; l; l = __bro_list_next(l))
    {
      val = __bro_list_data(l);

      if (! (val_copy = (BroVal *) __bro_sobject_copy((BroSObject *) val)))
	{
	  __bro_event_free(ev_copy);
	  return NULL;
	}
      
      __bro_event_add_val(ev_copy, val_copy);
    }
  
  D(("Copied event has %i arguments.\n", __bro_list_length(ev->val_list)));

  return ev_copy;
}


const char *
__bro_event_get_name(BroEvent *ev)
{
  if (! ev)
    return NULL;

  return (const char*) ev->name.str_val;
}


int
__bro_event_serialize(BroEvent *ev, BroConn *bc)
{
  BroVal *val;
  BroList *l;

  D_ENTER;

  /* Prepare the beginning of a serialized event call --
   * event identifier, event name plus argument description.
   */
  if (! __bro_buf_write_char(bc->tx_buf, 'e'))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_string(bc->tx_buf, &ev->name))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_write_double(bc->tx_buf, __bro_util_get_time()))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_int(bc->tx_buf, ev->val_len))
    D_RETURN_(FALSE);
    
  /* Now serialize each remaining parameter into the buffer: */
  D(("Serializing event parameters\n"));
  for (l = ev->val_list; l; l = __bro_list_next(l))
    {
      val = __bro_list_data(l);

      if (! __bro_sobject_serialize((BroSObject *) val, bc))
	D_RETURN_(FALSE);

      D(("  Serialized one argument\n"));
    }

  D_RETURN_(TRUE);
}


BroEvent *
__bro_event_unserialize(BroConn *bc)
{
  int i;
  BroString ev_name;
  double ev_ts;
  uint32 ev_args;
  BroEvent *ev = NULL;
  BroVal *val = NULL;

  D_ENTER;
  
  if (! __bro_buf_read_string(bc->rx_buf, &ev_name))
    {
      D(("Couldn't read event name.\n"));
      D_RETURN_(NULL);
    }
  
  if (! __bro_buf_read_double(bc->rx_buf, &ev_ts))
    {
      D(("Couldn't read event time.\n"));
      bro_string_cleanup(&ev_name);
      D_RETURN_(NULL);
    }
  
  if (! __bro_buf_read_int(bc->rx_buf, &ev_args))
    {
      D(("Couldn't read number of event arguments.\n"));
      bro_string_cleanup(&ev_name);
      D_RETURN_(NULL);
    }
  
  D(("Reading %i arguments for event %s\n", ev_args, ev_name.str_val));
  ev = __bro_event_new(&ev_name);
  ev->ts = ev_ts;
  bro_string_cleanup(&ev_name);
  
  for (i = 0; i < (int) ev_args; i++)
    {
      D(("Reading parameter %i\n", i+1));
      if (! (val = (BroVal *) __bro_sobject_unserialize(SER_IS_VAL, bc)))
	{
	  D(("Couldn't read parameter val %i.\n", i+1));
	  __bro_event_free(ev);
	  D_RETURN_(NULL);
	}
      
      __bro_event_add_val(ev, val);
    }

  D_RETURN_(ev);
}


void
__bro_event_add_val(BroEvent *ev, BroVal *v)
{
  D_ENTER;
  ev->val_list = __bro_list_append(ev->val_list, v);
  ev->val_len++;
  D_RETURN;
}


int
__bro_event_set_val(BroEvent *ev, int val_num, BroVal *v)
{
  BroList *l;

  D_ENTER;

  if (val_num < 0 || val_num >= ev->val_len)
    {
      D(("Invalid val index: given %i, having %i elements.\n", val_num, ev->val_len));
      D_RETURN_(FALSE);
    }

  if ( (l = __bro_list_nth(ev->val_list, val_num)))
    {
      BroVal *val = __bro_list_set_data(l, v);
      __bro_sobject_release((BroSObject *) val);
      D_RETURN_(TRUE);
    }

  D_RETURN_(FALSE);
}
