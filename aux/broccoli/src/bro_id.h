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
#ifndef broccoli_id_h
#define broccoli_id_h

#include <bro_object.h>
#include <bro_val.h>
#include <bro_type.h>
#include <bro_attrs.h>

struct bro_id
{
  BroObject                    object;
  BroString                    name;
  char                         scope;

  char                         is_export;
  uint32                       is_const;
  uint32                       is_enum_const;
  uint32                       is_type;

  uint32                       offset;

  char                         infer_return_type;
  char                         weak_ref;

  BroType                     *type;
  BroVal                      *val;
  BroAttrs                    *attrs;
};

BroID         *__bro_id_new(void);
void           __bro_id_init(BroID *id);
void           __bro_id_free(BroID *id);

int            __bro_id_write(BroID *id, BroConn *bc);
int            __bro_id_read(BroID *id, BroConn *bc);
int            __bro_id_clone(BroID *dst, BroID *src);
uint32         __bro_id_hash(BroID *obj);
int            __bro_id_cmp(BroID *obj1, BroID *obj2);

#endif
