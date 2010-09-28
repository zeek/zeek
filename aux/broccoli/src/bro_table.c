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
#include <bro_io.h>
#include <bro_debug.h>
#include <bro_val.h>
#include <bro_table.h>


BroTable *
__bro_table_new(void)
{
  BroTable *tbl;

  if (! (tbl = calloc(1, sizeof(BroTable))))
    return NULL;

  tbl->tbl_impl = __bro_ht_new((BroHTHashFunc) __bro_table_hash_key,
			       (BroHTCmpFunc) __bro_table_cmp_key,
			       (BroHTFreeFunc) __bro_sobject_release,
			       (BroHTFreeFunc) __bro_sobject_release, FALSE);

  if (! tbl->tbl_impl)
    {
      free(tbl);
      return NULL;
    }
  
  return tbl;
}

void
__bro_table_free(BroTable *tbl)
{
  if (! tbl)
    return;

  __bro_ht_free(tbl->tbl_impl);
  free(tbl);
}

static int __bro_table_copy_cb(BroVal *key, BroVal *val, BroTable *dest)
{
  __bro_table_insert(dest, key, val);
  return TRUE; /* Continue the iteration */
}

BroTable *
__bro_table_copy(BroTable *tbl)
{
  BroVal *val, *val_copy;
  BroTable *copy;

  if (! tbl)
    return NULL;
  
  if (! (copy = __bro_table_new()))
    return NULL;
  
  __bro_ht_foreach(tbl->tbl_impl,
		   (BroHTCallback) __bro_table_copy_cb,
		   (void *) copy);
  
  return copy;
}

void
__bro_table_insert(BroTable *tbl, BroVal *key, BroVal *val)
{
  if (! tbl || ! key) /* NULL for val is okay -- that's a set. */
    return;
  
  __bro_ht_add(tbl->tbl_impl, key, val);  
}

BroVal *
__bro_table_find(BroTable *tbl, const BroVal *key)
{
  if (! tbl || ! key)
    return NULL;

  return __bro_ht_get(tbl->tbl_impl, key);
}

int
__bro_table_get_size(BroTable *tbl)
{
  if (! tbl)
    return -1;
  
  return __bro_ht_get_size(tbl->tbl_impl);
}

void
__bro_table_foreach(BroTable *tbl, BroTableCallback cb, void *user_data)
{
  if (! tbl || ! cb)
    return;

  __bro_ht_foreach(tbl->tbl_impl, cb, user_data);
}

int
__bro_table_is_set(BroTable *tbl)
{
  return tbl->tbl_val_type == BRO_TYPE_UNKNOWN;
}

uint32
__bro_table_hash_key(BroVal *key)
{
  return ((BroSObject *) key)->hash((BroSObject *) key);
}

int
__bro_table_cmp_key(BroVal *val1, BroVal *val2)
{
  BroSObject *obj1 = (BroSObject *) val1;
  BroSObject *obj2 = (BroSObject *) val2;

  return obj1->cmp(obj1, obj2);
}

static int
__bro_table_hash_cb(BroVal *key, BroVal *val, int *result)
{
  *result ^= __bro_sobject_hash((BroSObject*) key);
  *result ^= __bro_sobject_hash((BroSObject*) val);
  return TRUE;
}

uint32
__bro_table_hash(BroTable *tbl)
{
  uint32 result;
  
  D_ENTER;
  
  if (! tbl)
    D_RETURN_(0);
  
  result = __bro_ht_get_size(tbl->tbl_impl);
  
  __bro_ht_foreach(tbl->tbl_impl, (BroHTCallback) __bro_table_hash_cb, &result);
  
  D_RETURN_(result);
}

typedef struct bro_table_cmp
{
  BroHT *table;
  int result;
} BroTableCmp;

static int
__bro_table_cmp_cb(BroVal *key, BroVal *val, BroTableCmp *cmp)
{
  BroVal *val2 = __bro_ht_get(cmp->table, key);

  if (! val2)
    goto no_luck;
  
  if (! __bro_sobject_cmp((BroSObject*) val, (BroSObject*) val2))
    goto no_luck;

  return TRUE;

 no_luck:  
  cmp->result = FALSE;
  return FALSE;
}

int
__bro_table_cmp(BroTable *tbl1, BroTable *tbl2)
{
  BroTableCmp cmp;

  D_ENTER;

  cmp.table = tbl2->tbl_impl;
  cmp.result = TRUE;
  
  if (__bro_ht_get_size(tbl1->tbl_impl) != __bro_ht_get_size(tbl2->tbl_impl))
    D_RETURN_(FALSE);

  __bro_ht_foreach(tbl1->tbl_impl, (BroHTCallback) __bro_table_cmp_cb, &cmp);

  D_RETURN_(TRUE);
}
