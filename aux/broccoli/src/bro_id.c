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
#include <bro_debug.h>
#include <bro_id.h>

BroID *
__bro_id_new(void)
{
  BroID *id;

  D_ENTER;

  if (! (id = calloc(1, sizeof(BroID))))
    D_RETURN_(NULL);

  __bro_id_init(id);

  D_RETURN_(id);
}

void
__bro_id_init(BroID *id)
{
  BroSObject *sobj = (BroSObject *) id;

  D_ENTER;

  /* First initialize parent */
  __bro_object_init((BroObject *) id);

  /* Now hook our callbacks into the vtable */
  sobj->read  = (BroSObjectRead) __bro_id_read;
  sobj->write = (BroSObjectWrite) __bro_id_write;
  sobj->free  = (BroSObjectFree) __bro_id_free;
  sobj->clone = (BroSObjectClone) __bro_id_clone;
  sobj->hash  = (BroSObjectHash) __bro_id_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_id_cmp;

  sobj->type_id = SER_ID;

  /* And finally initialize our own stuff */
  bro_string_init(&id->name);
  id->type = __bro_type_new();

  /* For now we don't have attrs + val, these get
   * hooked in on demand.
   */
  D_RETURN;
}

void
__bro_id_free(BroID *id)
{
  D_ENTER;

  if (!id)
    D_RETURN;

  /* First clean up our stuff */
  bro_string_cleanup(&id->name);

  __bro_sobject_release((BroSObject *) id->type);
  __bro_sobject_release((BroSObject *) id->attrs);
  __bro_sobject_release((BroSObject *) id->val);
  
  /* Then clean up parent -- will eventually call free() */
  __bro_object_free((BroObject *) id);

  D_RETURN;
}

int
__bro_id_read(BroID *id, BroConn *bc)
{
  char opt;

  D_ENTER;

  if (! id || ! bc)
    D_RETURN_(FALSE);

  if (! __bro_object_read((BroObject *) id, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_read_string(bc->rx_buf, &id->name))
    D_RETURN_(FALSE);

  if (! __bro_buf_read_char(bc->rx_buf, &id->scope))
    D_RETURN_(FALSE);

  if (! __bro_buf_read_char(bc->rx_buf, &id->is_export))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_int(bc->rx_buf, &id->is_const))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_int(bc->rx_buf, &id->is_enum_const))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_int(bc->rx_buf, &id->is_type))
    D_RETURN_(FALSE);

  if (! __bro_buf_read_int(bc->rx_buf, &id->offset))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_read_char(bc->rx_buf, &id->infer_return_type))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_char(bc->rx_buf, &id->weak_ref))
    D_RETURN_(FALSE);
  
  if (id->type)
    __bro_sobject_release((BroSObject*) id->type);
  if (! (id->type = (BroType *) __bro_sobject_unserialize(SER_IS_TYPE, bc)))
    D_RETURN_(FALSE);

  if (! __bro_buf_read_char(bc->rx_buf, &opt))
    D_RETURN_(FALSE);
  if (opt)
    {
      if (id->attrs)
	__bro_sobject_release((BroSObject *) id->attrs);

      if (! (id->attrs = (BroAttrs *) __bro_sobject_unserialize(SER_ATTRIBUTES, bc)))
	D_RETURN_(FALSE);
    }

  if (! __bro_buf_read_char(bc->rx_buf, &opt))
    D_RETURN_(FALSE);
  if (opt)
    {
      if (id->val)
	__bro_sobject_release((BroSObject *) id->val);

      if (! (id->val = (BroVal *) __bro_sobject_unserialize(SER_IS_VAL, bc)))
	D_RETURN_(FALSE);
    }
  
  D_RETURN_(TRUE);
}

int
__bro_id_write(BroID *id, BroConn *bc)
{
  D_ENTER;

  if (! id || ! bc)
    D_RETURN_(FALSE);

  if (! __bro_object_write((BroObject *) id, bc))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_write_string(bc->tx_buf, &id->name))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_char(bc->tx_buf, id->scope))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_char(bc->tx_buf, id->is_export))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_int(bc->tx_buf, id->is_const))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_int(bc->tx_buf, id->is_enum_const))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_int(bc->tx_buf, id->is_type))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_int(bc->tx_buf, id->offset))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_write_char(bc->tx_buf, id->infer_return_type))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_char(bc->tx_buf, id->weak_ref))
    D_RETURN_(FALSE);
  
  if (! __bro_sobject_serialize((BroSObject *) id->type, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_char(bc->tx_buf, id->attrs ? 1 : 0))
    D_RETURN_(FALSE);
  if (id->attrs && ! __bro_sobject_serialize((BroSObject *) id->attrs, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_char(bc->tx_buf, id->val ? 1 : 0))
    D_RETURN_(FALSE);
  if (id->attrs && ! __bro_sobject_serialize((BroSObject *) id->val, bc))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


int
__bro_id_clone(BroID *dst, BroID *src)
{
  BroString *string;

  D_ENTER;
  
  if (! __bro_object_clone((BroObject *) dst, (BroObject *) src))
    D_RETURN_(FALSE);
  
  if (! (string = bro_string_copy(&src->name)))
    D_RETURN_(FALSE);
  
  dst->name = *string;
  dst->scope = src->scope;
  dst->is_export = src->is_export;
  dst->is_const = src->is_const;
  dst->is_enum_const = src->is_enum_const;
  dst->is_type = src->is_type;
  dst->offset = src->offset;
  dst->infer_return_type = src->infer_return_type;
  dst->weak_ref = src->weak_ref;
  
  if (src->type && ! (dst->type = (BroType *) __bro_sobject_copy((BroSObject *) src->type)))
    D_RETURN_(FALSE);
  
  if (src->val && ! (dst->val = (BroVal *) __bro_sobject_copy((BroSObject *) src->val)))
    D_RETURN_(FALSE);
  
  if (src->attrs && ! (dst->attrs = (BroAttrs *) __bro_sobject_copy((BroSObject *) src->attrs)))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


uint32
__bro_id_hash(BroID *id)
{
  uint32 result = 0;

  D_ENTER;

  if (! id)
    D_RETURN_(0);

  result ^= __bro_ht_str_hash(id->name.str_val);
  result ^= ((uint32) id->scope) << 8;
  result ^= (uint32) id->is_export;
  result ^= id->is_const;
  result ^= id->is_enum_const;
  result ^= id->is_type;
  result ^= id->offset;
  
  D_RETURN_(result);
}


int
__bro_id_cmp(BroID *id1, BroID *id2)
{
  D_ENTER;

  if (! id1 || ! id2)
    D_RETURN_(FALSE);

  D_RETURN_(__bro_ht_str_cmp(id1->name.str_val, id2->name.str_val));
}
