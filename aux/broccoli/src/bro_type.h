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
#ifndef broccoli_type_h
#define broccoli_type_h

#include <bro_attrs.h>
#include <bro_object.h>

/* Internal types used to represent a Bro type.
 * Taken from Type.h.
 */
#define BRO_INTTYPE_INT            1
#define BRO_INTTYPE_UNSIGNED       2
#define BRO_INTTYPE_DOUBLE         3
#define BRO_INTTYPE_STRING         4
#define BRO_INTTYPE_IPADDR         5
#define BRO_INTTYPE_SUBNET         6
#define BRO_INTTYPE_OTHER          7
#define BRO_INTTYPE_ERROR          8

/* typedefs are in bro_types.h */

struct bro_type
{
  BroObject        object;

  char             tag;
  char             internal_tag;

  char             is_nbo;
  char             is_base_type;
  char             is_global_attrs_type;
  
  /* Whether or not this is a complete type object or
   * just the name of type. In the latter case, type_name
   * (below) will contain the name of the type.
   */
  char             is_complete;

  BroString        type_name;

  BroRecordType   *attrs_type;
};

struct bro_type_list
{
  BroType          type;

  uint32           num_types;
  BroList         *types;
  BroType         *pure_type;
};

struct bro_record_type
{
  BroType          type;

  BroTypeList     *base;
  uint32           num_fields;

  uint32           num_types;
  BroList         *type_decls;
};

struct bro_index_type
{
  BroType          type;

  BroTypeList     *indices;
  BroType         *yield_type; /* optional */
};

struct bro_table_type
{
  BroIndexType     type;
};

struct bro_set_type
{
  BroTableType     type;
};

BroType         *__bro_type_new(void);
BroType         *__bro_type_new_of_type(int type, const char *type_name);
void             __bro_type_set_incomplete_impl(BroType *type, const BroString *type_name);

BroTypeList     *__bro_type_list_new(void);

BroRecordType   *__bro_record_type_new(void);
void             __bro_record_type_add_type(BroRecordType *rt, const char *field, BroType *type);
const char      *__bro_record_type_get_nth_field(BroRecordType *rt, int num);

BroIndexType    *__bro_index_type_new(void);
void             __bro_index_type_set_indices(BroIndexType *it, BroTypeList *indices);
void             __bro_index_tye_set_yield_type(BroIndexType *it, BroType *yield_type);

BroTableType    *__bro_table_type_new(void);

BroSetType      *__bro_set_type_new();

#endif
