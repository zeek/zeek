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
#ifndef broccoli_location_h
#define broccoli_location_h

#include <bro_types.h>
#include <bro_sobject.h>

typedef struct bro_loc BroLoc;

struct bro_loc
{
  BroSObject       sobject;
  
  BroString        filename;
  uint32           first_line;
  uint32           last_line;
  uint32           first_column;
  uint32           last_column;
};

BroLoc          *__bro_loc_new(void);
void             __bro_loc_init(BroLoc *loc);
void             __bro_loc_free(BroLoc *loc);

int              __bro_loc_read(BroLoc *loc, BroConn *bc);
int              __bro_loc_write(BroLoc *loc, BroConn *bc);
int              __bro_loc_clone(BroLoc *dst, BroLoc *src);

uint32           __bro_loc_hash(BroLoc *loc);
int              __bro_loc_cmp(BroLoc *loc1, BroLoc *loc2);

#endif
