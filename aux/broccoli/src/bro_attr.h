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
#ifndef broccoli_attr_h
#define broccoli_attr_h

#include <bro_object.h>

/* Definitions of attribute type identifiers.
 * They must match the values of attr_tag in Bro's Attrs.h.
 */
#define BRO_ATTR_OPTIONAL          0
#define BRO_ATTR_DEFAULT           1
#define BRO_ATTR_REDEF             2
#define BRO_ATTR_ROTATE_INTERVAL   3
#define BRO_ATTR_ROTATE_SIZE       4
#define BRO_ATTR_ADD_FUNC          5
#define BRO_ATTR_DEL_FUNC          6
#define BRO_ATTR_EXPIRE_FUNC       7
#define BRO_ATTR_EXPIRE_READ       8
#define BRO_ATTR_EXPIRE_WRITE      9
#define BRO_ATTR_EXPIRE_CREATE    10
#define BRO_ATTR_PERSISTENT       11
#define BRO_ATTR_SYNCHRONIZED     12
#define BRO_ATTR_POSTPROCESSOR    13
#define BRO_ATTR_ENCRYPT          14
#define BRO_ATTR_MATCH            15

typedef struct bro_expr
{
} BroExpr;

/* NOTE: these attributes do *not* follow the inheritance approach,
 * unlike the attributes in Bro. This is because they're not currently
 * using the serialization framework like the rest of the Bro objects,
 * and all we need for Broccoli purposes is a (non-inherited) simple
 * way to read and write an attribute.
 */
typedef struct bro_attr
{
  char             tag;
  BroExpr         *expr;
} BroAttr;

BroAttr         *__bro_attr_new(void);
BroAttr         *__bro_attr_copy(BroAttr *attr);
void             __bro_attr_free(BroAttr *attr);

int              __bro_attr_read(BroAttr *attr, BroConn *bc);
int              __bro_attr_write(BroAttr *attr, BroConn *bc);

#endif
