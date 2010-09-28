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
#ifndef broccoli_type_decl_h
#define broccoli_type_decl_h

#include <bro_attrs.h>
#include <bro_type.h>

/* BroTypeDecls live outside the inheritance chain and are currently
 * only of interest for bro_type.c. The function names only resemble
 * the virtualized ones for easier integration with the virtualized
 * code.
 */

typedef struct bro_type_decl
{
  BroAttrs        *attrs;
  BroType         *type;
  BroString        id;
} BroTypeDecl;

BroTypeDecl *__bro_type_decl_new(void);
BroTypeDecl *__bro_type_decl_copy(BroTypeDecl *td);
void         __bro_type_decl_free(BroTypeDecl *td);
int          __bro_type_decl_read(BroTypeDecl *td, BroConn *bc);
int          __bro_type_decl_write(BroTypeDecl *td, BroConn *bc);
uint32       __bro_type_decl_hash(BroTypeDecl *td);
int          __bro_type_decl_cmp(BroTypeDecl *td1, BroTypeDecl *td2);

#endif
