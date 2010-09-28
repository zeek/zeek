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
#ifndef broccoli_event_reg_h
#define broccoli_event_reg_h

#include <broccoli.h>

BroEventReg   *__bro_event_reg_new(void);
void           __bro_event_reg_free(BroEventReg *reg);

void           __bro_event_reg_add(BroConn *bc,
				   const char *ev_name,
				   BroEventFunc func,
				   void *user_data);

void           __bro_event_reg_add_compact(BroConn *bc,
					   const char *ev_name,
					   BroCompactEventFunc func,
					   void *user_data);

int            __bro_event_reg_remove(BroConn *bc, const char *ev_name);
int            __bro_event_reg_request(BroConn *bc);
void           __bro_event_reg_dispatch(BroConn *bc, BroEvent *ev);

BroRequest    *__bro_event_request_new(int len);
void           __bro_event_request_free(BroRequest *req);

#endif
