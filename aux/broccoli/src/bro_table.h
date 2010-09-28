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
#ifndef broccoli_table_h
#define broccoli_table_h

#include <broccoli.h>
#include <bro_types.h>
#include <bro_hashtable.h>

/* BroTable is the table type we export to the user. It relies
 * on BroHTs for the implementation.
 *
 * Related typedefs are in broccoli.h because the users need
 * to know them -- we keep the definition opaque here.
 */
struct bro_table
{
  /* The underlying hashtable */
  BroHT   *tbl_impl;
  int tbl_key_type, tbl_val_type;
};

BroTable      *__bro_table_new(void);
void           __bro_table_free(BroTable *tbl);
BroTable      *__bro_table_copy(BroTable *tbl);

/* Inserts the given key-val pair and adopts ownership,
 * i.e., the values are not duplicated internally.
 */
void           __bro_table_insert(BroTable *tbl, BroVal *key, BroVal *val);

BroVal        *__bro_table_find(BroTable *tbl, const BroVal *key);
int            __bro_table_get_size(BroTable *tbl);

void           __bro_table_foreach(BroTable *tbl, BroTableCallback cb, void *user_data);

/* Sets are just tables that have no meaningful values associated
 * with the keys. As long as a table's tbl_val_type remains unknown,
 * a table is in fact a set.
 */
int            __bro_table_is_set(BroTable *tbl);

uint32         __bro_table_hash_key(BroVal *key);
int            __bro_table_cmp_key(BroVal *val1, BroVal *val2);

uint32         __bro_table_hash(BroTable *tbl);
int            __bro_table_cmp(BroTable *tbl1, BroTable *tbl2);

#endif
