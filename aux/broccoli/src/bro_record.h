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
#ifndef broccoli_record_h
#define broccoli_record_h

#include <broccoli.h>
#include <bro_types.h>

/* Typedef is in broccoli.h because the users need to know it -- we keep
 * it opaque for them though by defining it here.
 */
struct bro_record
{
  BroList                     *val_list;
  int                          val_len;
};

BroRecord     *__bro_record_new(void);
void           __bro_record_free(BroRecord *rec);
BroRecord     *__bro_record_copy(BroRecord *rec);
int            __bro_record_get_length(BroRecord *rec);

/* Adds the given val as a new field and adopts ownership,
 * i.e, the value is not duplicated internally.
 */
void           __bro_record_add_val(BroRecord *rec, BroVal *val);

BroVal        *__bro_record_get_nth_val(BroRecord *rec, int num);
const char    *__bro_record_get_nth_name(BroRecord *rec, int num);
BroVal        *__bro_record_get_named_val(BroRecord *rec, const char *name);

int            __bro_record_set_nth_val(BroRecord *rec, int num, BroVal *val);
int            __bro_record_set_nth_name(BroRecord *rec, int num, const char *name);
int            __bro_record_set_named_val(BroRecord *rec, const char *name, BroVal *val);

uint32         __bro_record_hash(BroRecord *rec);
int            __bro_record_cmp(BroRecord *rec1, BroRecord *rec2);

#endif
