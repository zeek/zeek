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
#include <bro_object.h>

BroObject      *
__bro_object_new(void)
{
  BroObject *obj;

  D_ENTER;

  if (! (obj = calloc(1, sizeof(BroObject))))
    D_RETURN_(NULL);

  __bro_object_init(obj);

  D_RETURN_(obj);
}

void
__bro_object_init(BroObject *obj)
{
  BroSObject *sobj = (BroSObject *) obj;

  D_ENTER;

  __bro_sobject_init(sobj);

  sobj->read  = (BroSObjectRead) __bro_object_read;
  sobj->write = (BroSObjectWrite)__bro_object_write;
  sobj->free  = (BroSObjectFree) __bro_object_free;
  sobj->clone = (BroSObjectClone) __bro_object_clone;
  sobj->hash  = (BroSObjectHash) __bro_object_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_object_cmp;
  
  D_RETURN;
}

void
__bro_object_free(BroObject *obj)
{
  D_ENTER;

  if (! obj)
    D_RETURN;
  
  __bro_sobject_release((BroSObject *) obj->loc);
  __bro_sobject_free((BroSObject *) obj);
  
  D_RETURN;
}


int
__bro_object_read(BroObject *obj, BroConn *bc)
{
  char opt;

  D_ENTER;

  if (! __bro_sobject_read((BroSObject *) obj, bc))
    D_RETURN_(FALSE);
    
  if (! __bro_buf_read_char(bc->rx_buf, &opt))
    D_RETURN_(FALSE);
  if (opt)
    {
      if (! (obj->loc = (BroLoc *) __bro_sobject_unserialize(SER_LOCATION, bc)))
	D_RETURN_(FALSE);      
    }

  D_RETURN_(TRUE);
}


int
__bro_object_write(BroObject *obj, BroConn *bc)
{
  D_ENTER;
  
  if (! __bro_sobject_write((BroSObject *) obj, bc))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_write_char(bc->tx_buf, obj->loc ? 1 : 0))
    D_RETURN_(FALSE);

  if (obj->loc && ! __bro_sobject_serialize((BroSObject *) obj->loc, bc))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


int
__bro_object_clone(BroObject *dst, BroObject *src)
{
  D_ENTER;
  
  if (! __bro_sobject_clone((BroSObject *) dst, (BroSObject *) src))
    {
      D(("Cloning parent failed.\n"));
      D_RETURN_(FALSE);
    }
  
  if (src->loc && ! (dst->loc = (BroLoc *) __bro_sobject_copy((BroSObject *) src->loc)))
    {
      D(("Cloning location failed.\n"));
      D_RETURN_(FALSE);
    }
  
  D_RETURN_(TRUE);
}


uint32
__bro_object_hash(BroObject *obj)
{
  uint32 result;
  
  D_ENTER;

  if (! obj)
    D_RETURN_(0);
  
  result = __bro_sobject_hash((BroSObject *) obj);
  result ^= __bro_loc_hash(obj->loc);

  D_RETURN_(result);

}


int
__bro_object_cmp(BroObject *obj1, BroObject *obj2)
{
  D_ENTER;
  
  if (! obj1 || ! obj2)
    D_RETURN_(FALSE);
  
  D_RETURN_(__bro_loc_cmp(obj1->loc, obj2->loc));
}
