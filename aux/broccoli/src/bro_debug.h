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
#ifndef __broccoli_debug_h
#define __broccoli_debug_h

#include <unistd.h>
#include <stdio.h>

#include <broccoli.h>
#include <bro_util.h>

void    bro_debug_enter(const char *function, int line);
void    bro_debug_return(const char *function, int line);

#ifdef BRO_DEBUG

void    bro_debug(const char *msg, ...);

/**
 * D - prints debugging output
 * @x: debugging information.
 *
 * Use this macro to output debugging information. @x is
 * the content as you would pass it to printf(), including
 * braces to make the arguments appear as one argument to
 * the macro. The macro is void if BRO_DEBUG is not defined
 * at compile time.
 */
#undef  D
#define D(x)                  do { bro_debug("%u %f %s/%i ", getpid(), __bro_util_get_time(),  __FILE__, __LINE__); bro_debug x ; } while (0) 

#undef  D_ENTER
#define D_ENTER               bro_debug_enter(__FUNCTION__, __LINE__)

#undef  D_RETURN
#define D_RETURN              do { bro_debug_return(__FUNCTION__, __LINE__); return; } while (0)

#undef  D_RETURN_
#define D_RETURN_(x)          do { bro_debug_return(__FUNCTION__, __LINE__); return (x); } while (0)

#else

#undef  D
#define D(x)  

#undef  D_ENTER
#define D_ENTER

#undef  D_RETURN
#define D_RETURN              return

#undef  D_RETURN_
#define D_RETURN_(x)          return (x)

#endif /* BRO_DEBUG */

#endif 

