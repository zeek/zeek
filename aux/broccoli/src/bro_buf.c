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
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#ifdef __EMX__
#include <strings.h>
#endif 

#include <bro_buf.h>
#include <bro_types.h>
#include <bro_debug.h>
#include <bro_util.h>

#define BRO_BUF_DEFAULT   4096

#ifdef BRO_DEBUG

/* Use this to get detailed output of what is read --
 * useful for debugging serialization format bugs.
 */
#define DEBUG_READS

#endif

#ifndef DEBUG_READS
#  define D(x)
#endif

BroBuf *
__bro_buf_new(void)
{
  BroBuf *buf;

  if (! (buf = calloc(1, sizeof(BroBuf))))
    return NULL;

  __bro_buf_init(buf);
  buf->may_grow = TRUE;

  return buf;
}

BroBuf *
__bro_buf_new_mem(u_char *mem, int mem_size)
{
  BroBuf *buf;

  if (! mem)
    {
      D(("Input error.\n"));
      return NULL;
    }

  if ((size_t) mem_size < sizeof(BroBuf) + BRO_BUF_DEFAULT)
    {
      D(("Given memory chunk of size %i is not big enough, need at least %i\n",
	 mem_size, sizeof(BroBuf) + BRO_BUF_DEFAULT));
      return NULL;
    }

  buf = (BroBuf *) mem;
  memset(buf, 0, sizeof(BroBuf));

  buf->buf = mem + sizeof(BroBuf);
  buf->buf_len = mem_size - sizeof(BroBuf);
  buf->may_grow = FALSE;

  return buf;
}


void
__bro_buf_free(BroBuf *buf)
{
  if (! buf)
    return;
  
  __bro_buf_cleanup(buf);
  free(buf);
}

void
__bro_buf_init(BroBuf *buf)
{
  D_ENTER;

  if (!buf)
    D_RETURN;

  memset(buf, 0, sizeof(BroBuf));
  buf->buf = calloc(1, BRO_BUF_DEFAULT);
  buf->buf_len = BRO_BUF_DEFAULT;

  D_RETURN;
}


void     
__bro_buf_cleanup(BroBuf *buf)
{
  D_ENTER;

  if (!buf)
    D_RETURN;

  if (buf->buf)
    free(buf->buf);

  memset(buf, 0, sizeof(BroBuf));

  D_RETURN;
}


int
__bro_buf_append(BroBuf *buf, void *data, int data_len)
{
  if (!buf)
    return FALSE;
  
  if (data_len == 0)
    return TRUE;
  
  if (buf->buf_off + data_len >= buf->buf_len)
    {
      uchar *new_buf;
      
      if (! buf->may_grow)
	{
	  D(("Cannot expand this buffer, sorry.\n"));
	  return FALSE;
	}
      
      buf->buf_len += MAX(BRO_BUF_DEFAULT, data_len);
      
      D(("Reallocating buffer\n"));      
      if (! (new_buf = realloc(buf->buf, sizeof(uchar) * buf->buf_len)))
	{
	  D(("Realloc'ing buffer failed.\n"));
	  return FALSE;
	}
      
      buf->buf = new_buf;
    }
  
  memcpy(buf->buf + buf->buf_off, data, data_len);
  buf->buf_off += data_len;

  return TRUE;
}


void
__bro_buf_consume(BroBuf *buf)
{
  if (!buf || buf->buf_ptr == 0)
    return;

  D(("Consuming %i bytes in buffer.\n", buf->buf_ptr));
  memmove(buf->buf, buf->buf + buf->buf_ptr, buf->buf_len - buf->buf_ptr);
  buf->buf_off -= buf->buf_ptr;
  buf->buf_ptr = 0;
}


void
__bro_buf_reset(BroBuf *buf)
{
  if (! buf)
    return;
  
  buf->buf_off = buf->buf_ptr = 0;
}


uchar *
__bro_buf_get(BroBuf *buf)
{
  if (!buf)
    return NULL;

  return buf->buf;
}

uchar *
__bro_buf_get_end(BroBuf *buf)
{
  if (!buf)
    return NULL;

  return (buf->buf + buf->buf_off);
}


uint     
__bro_buf_get_size(BroBuf *buf)
{
  if (!buf)
    return 0;

  return buf->buf_len;
}


uint     
__bro_buf_get_used_size(BroBuf *buf)
{
  if (!buf)
    return 0;

  return buf->buf_off;
}


uchar *
__bro_buf_ptr_get(BroBuf *buf)
{
  if (!buf)
    return NULL;

  return (buf->buf + buf->buf_ptr);
}


uint32
__bro_buf_ptr_tell(BroBuf *buf)
{
  if (!buf)
    return 0;

  return buf->buf_ptr;
}


int
__bro_buf_ptr_seek(BroBuf *buf, int offset, int whence)
{
  if (!buf)
    return FALSE;

  switch (whence)
    {
    case SEEK_SET:
      if (offset >= 0 && (uint32) offset <= buf->buf_off)
	{
	  buf->buf_ptr = offset;
	  return TRUE;
	}
      break;

    case SEEK_CUR:
      if ((int) buf->buf_ptr + offset >= 0 &&
	  buf->buf_ptr + offset <= buf->buf_off)
	{
	  buf->buf_ptr += offset;
	  return TRUE;
	}
      break;

    case SEEK_END:
      if ((int) buf->buf_off + offset >= 0 &&
	  buf->buf_off + offset <= buf->buf_off)
	{
	  buf->buf_ptr = buf->buf_off + offset;
	  return TRUE;
	}
      break;
      
    default:
      break;
    }

  return FALSE;
}


int      
__bro_buf_ptr_check(BroBuf *buf, int size)
{
  if (!buf || size < 0)
    return FALSE;

  if (buf->buf_ptr + size > buf->buf_off)
    {
      D(("Checking for %i bytes available, but have only %i\n",
	 size, buf->buf_off - buf->buf_ptr));
      return FALSE;
    }

  return TRUE;
}


int
__bro_buf_ptr_read(BroBuf *buf, void *data, int size)
{
  if (size == 0)
    return TRUE;

  if (!buf || !data)
    return FALSE;

  if (! __bro_buf_ptr_check(buf, size))
    return FALSE;

  memcpy(data, buf->buf + buf->buf_ptr, size);
  buf->buf_ptr += size;

  return TRUE;
}


int
__bro_buf_ptr_write(BroBuf *buf, const void *data, int size)
{
  if (! buf || size < 0)
    return FALSE;
  
  if (size == 0)
    return TRUE;
  
  if (! data)
    {
      D(("Input error -- data length is %i but no data given.\n", size));
      return FALSE;
    }

  if (buf->buf_ptr + size >= buf->buf_len)
    {
      /* Check how much the requested amount is bigger than
       * what we have, and add some extra buffering on top of it.
       */
      uchar *new_buf;
      int inc = size - (buf->buf_off - buf->buf_ptr);
      
      if (! buf->may_grow)
	{
	  D(("Cannot expand this buffer, sorry.\n"));
	  return FALSE;
	}
      
      D(("Reallocating buffer\n"));      

      if (! (new_buf = realloc(buf->buf, buf->buf_len + inc + BRO_BUF_DEFAULT)))
	{
	  D(("Realloc'ing buffer failed.\n"));
	  return FALSE;
	}
      
      buf->buf_len += inc + BRO_BUF_DEFAULT;
      buf->buf = new_buf;
    }
  
  memcpy(buf->buf + buf->buf_ptr, data, size);
  buf->buf_ptr += size;
  
  if (buf->buf_off < buf->buf_ptr)
    buf->buf_off = buf->buf_ptr;
  
  return TRUE;
}



/* I/O API below ---------------------------------------------------- */

int 
__bro_buf_read_data(BroBuf *buf, void *dest, int size)
{
  return __bro_buf_ptr_read(buf, dest, size);
}


int
__bro_buf_read_char(BroBuf *buf, char *val)
{
  int result;
  
  result = __bro_buf_ptr_read(buf, val, sizeof(char));
  D(("Read char: %i/0x%02x\n", *val, *val));
  
  return result;
}


int
__bro_buf_read_string(BroBuf *buf, BroString *val)
{
  if (!buf || !val)
    return FALSE;
  
  bro_string_init(val);
  
  if (! __bro_buf_read_int(buf, &val->str_len))
    return FALSE;
  
  /* We create space for the string's length plus one extra byte that
   * we use as the string terminator so things work with normal C strings.
   */
  if (! (val->str_val = malloc(val->str_len + 1)))
    return FALSE;
  
  if (val->str_len > 0)
    {
      if (! (__bro_buf_ptr_read(buf, val->str_val, val->str_len)))
	{
	  free(val->str_val);
	  return FALSE;
	}
    }
  
  /* Terminate the string.
   */
  val->str_val[val->str_len] = '\0';
  
  D(("Read string: '%s'\n", val->str_val));
  return TRUE;
}


int
__bro_buf_read_double(BroBuf *buf, double *d)
{
  if (! buf || ! d)
    return FALSE;

  if (! __bro_buf_ptr_read(buf, d, sizeof(double)))
    return FALSE;
  
  *d = __bro_util_ntohd(*d);
  D(("Read double: %f\n", *d));

  return TRUE;
}


int
__bro_buf_read_int(BroBuf *buf, uint32 *i)
{
  if (! __bro_buf_ptr_read(buf, i, sizeof(uint32)))
    return FALSE;
  
  *i = ntohl(*i);
  D(("Read int: %i/0x%08x\n", *i, *i));

  return TRUE;
}


int
__bro_buf_read_short(BroBuf *buf, uint16 *i)
{
  if (! __bro_buf_ptr_read(buf, i, sizeof(uint16)))
    return FALSE;
  
  *i = ntohs(*i);
  D(("Read short: %i/0x%04x\n", *i, *i));

  return TRUE;
}


int
__bro_buf_write_data(BroBuf *buf, const void *data, int size)
{
  return __bro_buf_ptr_write(buf, data, size);
}


int
__bro_buf_write_char(BroBuf *buf, char val)
{
  int result;
  
  result = __bro_buf_ptr_write(buf, &val, sizeof(char));
  D(("Wrote char: %i/0x%02x\n", val, val));
  return result;
}


int
__bro_buf_write_string(BroBuf *buf, BroString *val)
{
  int result;
  BroString tmp_val;

  if (! buf)
    return FALSE;

  if (! val)
    {
      tmp_val.str_val = (uchar*) "";
      tmp_val.str_len = 0;
      
      val = &tmp_val;
    }
  
  if (! (__bro_buf_write_int(buf, val->str_len)))
    return FALSE;
  
  result = __bro_buf_write_data(buf, val->str_val, val->str_len);
  
  D(("Wrote string: '%s'\n", val->str_val));
  return result;
}


int
__bro_buf_write_double(BroBuf *buf, double d)
{
  int result;
  double d_tmp;

  if (! buf)
    return FALSE;

  d_tmp = __bro_util_htond(d);
  result =  __bro_buf_ptr_write(buf, &d_tmp, sizeof(double));
  D(("Wrote double: %f\n", d));

  return result;
}


int
__bro_buf_write_int(BroBuf *buf, uint32 i)
{
  int result;
  uint32 i_tmp;

  if (! buf)
    return FALSE;

  i_tmp = htonl(i);
  result = __bro_buf_write_data(buf, &i_tmp, sizeof(uint32));
  D(("Wrote int: %i/0x%08x\n", i, i));

  return result;
}


int
__bro_buf_write_short(BroBuf *buf, uint16 i)
{
  int result;
  uint16 i_tmp;
  
  if (! buf)
    return FALSE;
  
  i_tmp = htons(i);
  result =__bro_buf_write_data(buf, &i_tmp, sizeof(uint16));
  D(("Wrote short: %i/0x%04x\n", i, i));

  return result;
}
