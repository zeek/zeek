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
#ifndef broccoli_val_h
#define broccoli_val_h

#include <broccoli.h>
#include <bro_types.h>
#include <bro_util.h>
#include <bro_id.h>
#include <bro_attrs.h>

typedef void *(* BroValAccessor) (BroVal *val);

struct bro_val
{
  BroObject                    object;

  /* A class method for accessing the data contained by
   * a val:
   */
  BroValAccessor               get_data;
  
  /* The full type object of this val -- this also yields
   * what member of the union is used below (unless we're
   * inside a derived type and store our data elsewhere).
   * If val_type is NULL, it means we're dealing with an
   * unassigned val.
   */
  BroType                     *val_type;
  
  BroRecordVal                *val_attrs;

  union {
    char                       char_val;
    uint32                     int_val;
    double                     double_val;
    BroPort                    port_val;
    BroString                  str_val;
    BroSubnet                  subnet_val;
  } val;

#define val_char               val.char_val
#define val_int                val.int_val
#define val_double             val.double_val
#define val_port               val.port_val
#define val_str                val.str_val
#define val_strlen             val.str_val.str_len
#define val_subnet             val.subnet_val
};

struct bro_list_val
{
  BroVal                       val;

  char                         type_tag;
  int                          len;

  BroList                     *list;
};

struct bro_mutable_val
{
  BroVal                       val;

  BroID                       *id;
  char                         props;
};

#define BRO_VAL_PROP_PERS      0x01
#define BRO_VAL_PROP_SYNC      0x02

struct bro_record_val
{
  BroMutableVal                mutable;
  
  /* We don't use the full record val when interacting
   * with the user, but only what's really necessary.
   */
  BroRecord                   *rec;
};

struct bro_table_val
{
  BroMutableVal                mutable;

  BroTableType                *table_type;
  BroAttrs                    *attrs;
  
  BroTable                    *table;
};


BroVal          *__bro_val_new(void);
BroVal          *__bro_val_new_of_type(int type, const char *type_name);
int              __bro_val_assign(BroVal *val, const void *data);

/* Returns a pointer to the val's data depending on its type.
 * Type is returned through *type if provided.
 */
int              __bro_val_get_data(BroVal *val, int *type, void **data);
int              __bro_val_get_type_num(const BroVal *val);

BroListVal      *__bro_list_val_new(void);

/* Append a val to the list. This does not duplicate, so adopts the
 * given val.
 */
void             __bro_list_val_append(BroListVal *lv, BroVal *val);

/* Removes the first value from the list and returns it. */
BroVal          *__bro_list_val_pop_front(BroListVal *lv);

/* Only returns the first value from the list. */
BroVal          *__bro_list_val_get_front(BroListVal *lv);
int              __bro_list_val_get_length(BroListVal *lv);

BroMutableVal   *__bro_mutable_val_new(void);

BroRecordVal    *__bro_record_val_new(void);

BroTableVal     *__bro_table_val_new(void);
int              __bro_table_val_has_atomic_key(BroTableVal *tv);

#endif
