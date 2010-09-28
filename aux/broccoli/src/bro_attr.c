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

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#ifdef __EMX__
#include <strings.h>
#endif 

#include <bro_types.h>
#include <bro_val.h>
#include <bro_debug.h>
#include <bro_attr.h>


BroAttr *
__bro_attr_new(void)
{
  BroAttr *attr;

  D_ENTER;
  
  if (! (attr = calloc(1, sizeof(BroAttr))))
    D_RETURN_(NULL);
  
  D_RETURN_(attr);
}


BroAttr *
__bro_attr_copy(BroAttr *attr)
{
  BroAttr *copy;

  D_ENTER;

  if (! (copy = __bro_attr_new()))
    D_RETURN_(NULL);

  if (! attr)
    D_RETURN_(NULL);

  copy->tag = attr->tag;
  
  /* FIXME copy->expr = __bro_sobject_copy((BroSObject *) attr->expr); */
  
  D_RETURN_(copy);
}


void
__bro_attr_free(BroAttr *attr)
{
  D_ENTER;

  /* FIXME __bro_expr_free(attr->expr); */
  free(attr);

  D_RETURN;
}


int
__bro_attr_read(BroAttr *attr, BroConn *bc)
{
  char opt;

  D_ENTER;
  
  if (! __bro_buf_read_char(bc->rx_buf, &opt))
    D_RETURN_(FALSE);
  if (opt)
    {
      /* FIXME
      if (attr->expr)
	__bro_expr_free(attr->expr);
      if (! (attr->expr = (BroExpr *) __bro_sobject_unserialize(SER_IS_EXPR, buf)))
	D_RETURN_(FALSE);
      */
    }
  
  if (! __bro_buf_read_char(bc->rx_buf, &attr->tag))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


int
__bro_attr_write(BroAttr *attr, BroConn *bc)
{
  D_ENTER;
  
  if (! __bro_buf_write_char(bc->tx_buf, attr->expr ? 1 : 0))
    D_RETURN_(FALSE);
  if (attr->expr && ! __bro_sobject_serialize((BroSObject *) attr->expr, bc))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_write_char(bc->tx_buf, attr->tag))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}
