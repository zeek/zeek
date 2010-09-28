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
#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>

#ifdef __EMX__
#include <strings.h>
#endif 

#include <bro_util.h>

#ifdef __MINGW32__

/* MinGW does not define a gettimeofday so we need to roll our own.
 * This one is largely following 
 * http://lists.gnu.org/archive/html/bug-gnu-chess/2004-01/msg00020.html
 */

static int
gettimeofday(struct timeval* p, void* tz /* IGNORED */){
  union {
    long long ns100; /*time since 1 Jan 1601 in 100ns units */
    FILETIME ft;
  } _now;
  
  GetSystemTimeAsFileTime( &(_now.ft) );
  p->tv_usec=(long)((_now.ns100 / 10LL) % 1000000LL );
  p->tv_sec= (long)((_now.ns100-(116444736000000000LL))/10000000LL);
  return 0;
}
#endif


int
__bro_util_snprintf(char *str, size_t size, const char *format, ...)
{
  int result;
  va_list al;
  va_start(al, format);
  result = vsnprintf(str, size, format, al);
  va_end(al);
  str[size-1] = '\0';
  
  return result;
}

void
__bro_util_fill_subnet(BroSubnet *sn, uint32 net, uint32 width)
{
  if (! sn)
    return;

  sn->sn_net = net;
  sn->sn_width = width;
}


double
__bro_util_get_time(void)
{
  struct timeval tv;
  
  if (gettimeofday(&tv, 0) < 0)
    return 0.0;
  
  return __bro_util_timeval_to_double(&tv);
}


double
__bro_util_timeval_to_double(const struct timeval *tv)
{
  if (! tv)
    return 0.0;

  return ((double) tv->tv_sec) + ((double) tv->tv_usec) / 1000000;
}

#ifndef WORDS_BIGENDIAN
double
__bro_util_htond(double d)
{
  /* Should work as long as doubles have an even length */
  int i, dsize;
  double tmp;
  char* src = (char*) &d;
  char* dst = (char*) &tmp;
  
  dsize = sizeof(d) - 1;
  
  for (i = 0; i <= dsize; i++)
    dst[i] = src[dsize - i];
  
  return tmp;
}

double
__bro_util_ntohd(double d)
{
  return __bro_util_htond(d);
}
#endif
