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
#ifndef broccoli_object_h
#define broccoli_object_h

#include <bro_location.h>
#include <bro_sobject.h>

typedef struct bro_object
{
  /* See comments in bro_sobject.h for how Broccoli models
   * classes, objects, and inheritance. --cpk
   */
  BroSObject       sobject;
  BroLoc          *loc;
} BroObject;

BroObject       *__bro_object_new(void);
void             __bro_object_init(BroObject *obj);
void             __bro_object_free(BroObject *obj);

int              __bro_object_read(BroObject *obj, BroConn *bc);
int              __bro_object_write(BroObject *obj, BroConn *bc);
int              __bro_object_clone(BroObject *dst, BroObject *src);
uint32           __bro_object_hash(BroObject *obj);
int              __bro_object_cmp(BroObject *obj1, BroObject *obj2);

#endif
