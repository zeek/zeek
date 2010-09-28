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
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>

#include <bro_debug.h>
#include <bro_util.h>

int bro_debug_calltrace = 0;
int bro_debug_messages  = 0;

static int calldepth = 0;

static void 
debug_whitespace(void)
{
  int i;
  
  for (i = 0; i < 2*calldepth; i++)
    fprintf(stderr, "-");
}


void
bro_debug(const char *fmt, ...)
{
  va_list argp;

  if (bro_debug_messages)
    {
      va_start(argp, fmt);
      vfprintf(stderr, fmt, argp);
      va_end(argp);
    }
}


void
bro_debug_enter(const char *function, int line)
{
  if (! bro_debug_calltrace)
    return;

  fprintf(stderr, "%u ", getpid());
  calldepth++;
  debug_whitespace();
  fprintf(stderr, "> %s(%i)\n", function, line);
}


void
bro_debug_return(const char *function, int line)
{
  if (! bro_debug_calltrace)
    return;

  fprintf(stderr, "%u <", getpid());
  debug_whitespace();
  fprintf(stderr, " %s(%i)\n", function, line);
  
  if (--calldepth < 0)
    calldepth = 0;
}
