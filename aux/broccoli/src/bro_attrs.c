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

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#ifdef __EMX__
#include <strings.h>
#endif 

#include <bro_types.h>
#include <bro_debug.h>
#include <bro_attrs.h>
#include <bro_type.h>


BroAttrs         *
__bro_attrs_new(void)
{
  BroAttrs *attrs;

  D_ENTER;
  
  if (! (attrs = calloc(1, sizeof(BroAttrs))))
    D_RETURN_(NULL);

  __bro_attrs_init(attrs);
  D_RETURN_(attrs);
}


void
__bro_attrs_init(BroAttrs *attrs)
{
  BroSObject *sobj = (BroSObject *) attrs;

  D_ENTER;

  __bro_object_init((BroObject *) attrs);

  sobj->read  = (BroSObjectRead) __bro_attrs_read;
  sobj->write = (BroSObjectWrite) __bro_attrs_write;
  sobj->free  = (BroSObjectFree) __bro_attrs_free;
  sobj->clone = (BroSObjectClone) __bro_attrs_clone;
  sobj->hash  = (BroSObjectHash) __bro_attrs_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_attrs_cmp;

  sobj->type_id = SER_ATTRIBUTES;

  D_RETURN;
}


void
__bro_attrs_free(BroAttrs *attrs)
{
  uint32 i;

  D_ENTER;

  __bro_sobject_release((BroSObject *) attrs->type);
  
  for (i = 0; i < attrs->num_attrs; i++)
    __bro_attr_free(attrs->attrs[i]);
  free(attrs->attrs);
  
  __bro_object_free((BroObject *) attrs);
  D_RETURN;
}


int
__bro_attrs_read(BroAttrs *attrs, BroConn *bc)
{
  uint32 i;

  D_ENTER;

  if (! __bro_object_read((BroObject *) attrs, bc))
    D_RETURN_(FALSE);

  if (attrs->type)
    __bro_sobject_release((BroSObject *) attrs->type);

  if (! (attrs->type = (BroType *) __bro_sobject_unserialize(SER_IS_TYPE, bc)))
    D_RETURN_(FALSE);

  if (attrs->attrs)
    {
      for (i = 0; i < attrs->num_attrs; i++)
	__bro_attr_free(attrs->attrs[i]);
      free(attrs->attrs);
    }

  if (! __bro_buf_read_int(bc->rx_buf, &attrs->num_attrs))
    D_RETURN_(FALSE);
  
  if (! (attrs->attrs = calloc(attrs->num_attrs, sizeof(BroAttr*))))
    D_RETURN_(FALSE);
  
  for (i = 0; i < attrs->num_attrs; i++)
    {
      BroAttr *attr;
      
      if (! (attr = __bro_attr_new()))
	D_RETURN_(FALSE);
      
      if (! __bro_attr_read(attr, bc))
	D_RETURN_(FALSE);
      
      attrs->attrs[i] = attr;
    }
  
  D_RETURN_(TRUE);
}


int
__bro_attrs_write(BroAttrs *attrs, BroConn *bc)
{
  uint32 i;
  
  D_ENTER;

  if (! __bro_object_write((BroObject *) attrs, bc))
    D_RETURN_(FALSE);
  
  if (! __bro_sobject_serialize((BroSObject *) attrs->type, bc))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_write_int(bc->tx_buf, attrs->num_attrs))
    D_RETURN_(FALSE);
  
  for (i = 0; i < attrs->num_attrs; i++)
    {
      if (! __bro_sobject_serialize((BroSObject *) attrs->attrs[i], bc))
	D_RETURN_(FALSE);
    }
  
  D_RETURN_(TRUE);
}


int
__bro_attrs_clone(BroAttrs *dst, BroAttrs *src)
{
  uint32 i;

  D_ENTER;

  if (! __bro_object_clone((BroObject *) dst, (BroObject *) src))
    D_RETURN_(FALSE);

  if (src->type && ! (dst->type = (BroType *) __bro_sobject_copy((BroSObject *) dst->type)))
    D_RETURN_(FALSE);

  if (dst->attrs)
    {
      for (i = 0; i < dst->num_attrs; i++)
	__bro_attr_free(dst->attrs[i]);
      free(dst->attrs);
    }

  dst->num_attrs = src->num_attrs;

  if (! (dst->attrs = calloc(dst->num_attrs, sizeof(BroAttr *))))
    D_RETURN_(FALSE);
  
  for (i = 0; i < dst->num_attrs; i++)
    {
      if (! (dst->attrs[i] = __bro_attr_copy(src->attrs[i])))
	D_RETURN_(FALSE);
    }
  
  D_RETURN_(TRUE);
}

uint32
__bro_attrs_hash(BroAttrs *attrs)
{
  uint32 result, i, shift;

  D_ENTER;

  if (! attrs)
    D_RETURN_(0);

  result = __bro_sobject_hash((BroSObject*) attrs->type) ^ attrs->num_attrs;
  
  /* Cycle through the attributes and XOR their tags, also
   * cycling through a shifting regime shifting by 0, 8, 16,
   * 24, 0, etc.
   */
  for (i = 0, shift = 0; i < attrs->num_attrs; i++, shift += 8)
    {
      uint32 val;

      if (shift > 24)
	shift = 0;
      
      val = (uint32) attrs->attrs[i]->tag;
      result ^= val << shift;
    }
  
  D_RETURN_(result);
}

int
__bro_attrs_cmp(BroAttrs *attrs1, BroAttrs *attrs2)
{
  uint32 i, j;
  
  D_ENTER;
  
  if (! __bro_sobject_cmp((BroSObject*) attrs1->type, (BroSObject*) attrs2->type))
    D_RETURN_(FALSE);
  
  if (attrs1->num_attrs != attrs2->num_attrs)
    D_RETURN_(FALSE);
  
  for (i = 0, j = 0; i < attrs1->num_attrs && attrs2->num_attrs;
       i++, j++)
    {
      if (attrs1->attrs[i]->tag != attrs2->attrs[j]->tag)
	D_RETURN_(FALSE);
    }
  
  D_RETURN_(TRUE);
}

