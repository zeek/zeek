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

#include <bro_debug.h>
#include <bro_location.h>

BroLoc      *
__bro_loc_new(void)
{
  BroLoc *loc;

  D_ENTER;

  if (! (loc = calloc(1, sizeof(BroLoc)))) {
    D_RETURN_(NULL);
  }

  __bro_loc_init(loc);
  
  D_RETURN_(loc);
}


void
__bro_loc_init(BroLoc *loc)
{
  BroSObject *sobj = (BroSObject *) loc;

  D_ENTER;

  __bro_sobject_init(sobj);

  sobj->read  = (BroSObjectRead) __bro_loc_read;
  sobj->write = (BroSObjectWrite)__bro_loc_write;
  sobj->free  = (BroSObjectFree) __bro_loc_free;
  sobj->clone = (BroSObjectClone) __bro_loc_clone;
  sobj->hash  = (BroSObjectHash) __bro_loc_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_loc_cmp;
  
  sobj->type_id = SER_LOCATION;
  bro_string_init(&loc->filename);

  D_RETURN;
}


void
__bro_loc_free(BroLoc *loc)
{
  D_ENTER;

  if (! loc)
    D_RETURN;

  bro_string_cleanup(&loc->filename);
  __bro_sobject_free((BroSObject *) loc);

  D_RETURN;
}


int
__bro_loc_read(BroLoc *loc, BroConn *bc)
{
  D_ENTER;
  
  if (! loc || ! bc)
    D_RETURN_(FALSE);
  
  if (! __bro_sobject_read((BroSObject *) loc, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_read_string(bc->rx_buf, &loc->filename))
    D_RETURN_(FALSE);  
  if (! __bro_buf_read_int(bc->rx_buf, &loc->first_line))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_int(bc->rx_buf, &loc->last_line))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_int(bc->rx_buf, &loc->first_column))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_int(bc->rx_buf, &loc->last_column))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


int
__bro_loc_write(BroLoc *loc, BroConn *bc)
{
  D_ENTER;

  if (! loc || ! bc)
    D_RETURN_(FALSE);
  
  if (! __bro_sobject_write((BroSObject *) loc, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_string(bc->tx_buf, &loc->filename))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_int(bc->tx_buf, loc->first_line))
    D_RETURN_(FALSE);  
  if (! __bro_buf_write_int(bc->tx_buf, loc->last_line))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_int(bc->tx_buf, loc->first_column))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_int(bc->tx_buf, loc->last_column))
    D_RETURN_(FALSE);

  D_RETURN_(TRUE);
}


int
__bro_loc_clone(BroLoc *dst, BroLoc *src)
{
  BroString *string;

  D_ENTER;

  if (! __bro_sobject_clone((BroSObject *) dst, (BroSObject *) src))
    D_RETURN_(FALSE);
  
  if (! (string = bro_string_copy(&src->filename)))
    D_RETURN_(FALSE);
  
  dst->filename = *string;
  dst->first_line = src->first_line;
  dst->last_line = src->last_line;
  dst->first_column = src->first_column;
  dst->last_column = src->last_column;
  
  D_RETURN_(TRUE);
}


uint32
__bro_loc_hash(BroLoc *loc)
{
  uint32 result;

  D_ENTER;

  if (! loc)
    D_RETURN_(0);

  result = __bro_ht_str_hash(loc->filename.str_val);
  result ^= loc->first_line;
  result ^= loc->last_line;
  result ^= loc->first_column;
  result ^= loc->last_column;

  D_RETURN_(result);

}


int
__bro_loc_cmp(BroLoc *loc1, BroLoc *loc2)
{
  D_ENTER;

  if (! __bro_ht_str_cmp(loc1->filename.str_val, loc2->filename.str_val))
    D_RETURN_(FALSE);
  
  if (loc1->first_line != loc2->first_line ||
      loc1->last_line != loc2->last_line ||
      loc1->first_column < loc2->first_column ||
      loc1->last_column < loc2->last_column ||
      loc1->last_column > loc2->last_column)
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}
