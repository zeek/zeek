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
#ifndef broccoli_buf_h
#define broccoli_buf_h

#include <stdio.h>
#include <broccoli.h>

/*
 * BroBufs are self-allocating, seekable, and read/writable
 * buffers. You can repeatedly append data to the buffer
 * while the buffer makes sure it is large enough to handle
 * the amount requested. A buffer has a content pointer that
 * points to an arbitrary location between the start of the
 * buffer and the first byte after the last byte currently
 * used in the buffer (buf_off). The content pointer can be
 * seeked to arbitrary locations, and data can be copied from
 * the buffer, adjusting the content pointer at the same time.
 *
 * Illustration:
 *
 * <---------------- allocated buffer space ------------>
 * <======== used buffer space ========>
 * ^              ^                    ^               ^                 
 * |              |                    |               |
 * `buf           `buf_ptr             `buf_off        `buf_len
 */

struct bro_buf {
  uchar       *buf;
  
  /* The size of the allocated buffer BUF: */
  uint32       buf_len;

  /* The first byte in BUF after the ones occupied */
  uint32       buf_off;

  /* A pointer to a position between the start of BUF
   * and BUF + BUF_OFF.
   */
  uint32       buf_ptr;

  /* Flag that indicates whether or not the allocated buffer
   * can grow or not. It can't if we require the buffer to
   * live in a fixed amount of memory.
   */
  int          may_grow;
};

/* See API comments in broccoli.h for details */

BroBuf  *__bro_buf_new(void);

/* Creates a new buffer using a given chunk of memory. We use
 * this for example to allocate a buffer in shared memory.
 */
BroBuf  *__bro_buf_new_mem(u_char *mem, int mem_size);

void     __bro_buf_free(BroBuf *buf);

/* Initializes an existing buffer structure to default values */
void     __bro_buf_init(BroBuf *buf);
void     __bro_buf_cleanup(BroBuf *buf);

int      __bro_buf_append(BroBuf *buf, void *data, int data_len);
void     __bro_buf_consume(BroBuf *buf);
void     __bro_buf_reset(BroBuf *buf);

uchar   *__bro_buf_get(BroBuf *buf);
uchar   *__bro_buf_get_end(BroBuf *buf);
uint     __bro_buf_get_size(BroBuf *buf);
uint     __bro_buf_get_used_size(BroBuf *buf);
uchar   *__bro_buf_ptr_get(BroBuf *buf);
uint32   __bro_buf_ptr_tell(BroBuf *buf);
int      __bro_buf_ptr_seek(BroBuf *buf, int offset, int whence);
int      __bro_buf_ptr_check(BroBuf *buf, int size);
int      __bro_buf_ptr_read(BroBuf *buf, void *data, int size);
int      __bro_buf_ptr_write(BroBuf *buf, const void *data, int size);


/* Buffer-based I/O API --------------------------------------------- */

/* The read functions read data from the given buffer into the variables
 * pointed to by the arguments, the write functions to the opposite and
 * write the passed-in parameters into the given buffers.
 */

int      __bro_buf_read_data(BroBuf *buf, void *dest, int size);
int      __bro_buf_read_char(BroBuf *buf, char *val);
int      __bro_buf_read_string(BroBuf *buf, BroString *val);
int      __bro_buf_read_double(BroBuf *buf, double *d);
int      __bro_buf_read_int(BroBuf *buf, uint32 *i);
int      __bro_buf_read_short(BroBuf *buf, uint16 *i);

int      __bro_buf_write_data(BroBuf *buf, const void *data, int size);
int      __bro_buf_write_char(BroBuf *buf, char val);
int      __bro_buf_write_string(BroBuf *buf, BroString *val);
int      __bro_buf_write_double(BroBuf *buf, double d);
int      __bro_buf_write_int(BroBuf *buf, uint32 i);
int      __bro_buf_write_short(BroBuf *buf, uint16 i);

#endif
