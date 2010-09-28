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

#include <bro_debug.h>
#include <bro_type_decl.h>

BroTypeDecl *
__bro_type_decl_new(void)
{
  BroTypeDecl *td;

  D_ENTER;

  if (! (td = calloc(1, sizeof(BroTypeDecl))))
    D_RETURN_(NULL);

  D_RETURN_(td);
}


BroTypeDecl     *
__bro_type_decl_copy(BroTypeDecl *td)
{
  BroTypeDecl *copy;

  D_ENTER;

  if (! td)
    D_RETURN_(NULL);

  if (! (copy = __bro_type_decl_new()))
    D_RETURN_(NULL);

  if (td->attrs && ! (copy->attrs = (BroAttrs *) __bro_sobject_copy((BroSObject *) td->attrs)))
    goto error_result;

  if (td->type && ! (copy->type = (BroType *) __bro_sobject_copy((BroSObject *) td->type)))
    goto error_result;
  
  if (! (bro_string_set_data(&copy->id,
			     bro_string_get_data(&td->id),
			     bro_string_get_length(&td->id))))
    goto error_result;
  
  D_RETURN_(copy);
  
 error_result:
  __bro_type_decl_free(copy);
  D_RETURN_(NULL);
}


void
__bro_type_decl_free(BroTypeDecl *td)
{
  D_ENTER;

  if (! td)
    D_RETURN;
  
  __bro_sobject_release((BroSObject *) td->type);
  __bro_sobject_release((BroSObject *) td->attrs);
  bro_string_cleanup(&td->id);
  free(td);
  
  D_RETURN;
}


int
__bro_type_decl_read(BroTypeDecl *td, BroConn *bc)
{
  char opt;

  D_ENTER;

  if (! td || !bc)
    D_RETURN_(FALSE);

  /* Read an optional BroAttrs */

  if (td->attrs)
    __bro_sobject_release((BroSObject *) td->attrs);
  td->attrs = NULL;

  if (! __bro_buf_read_char(bc->rx_buf, &opt))
    D_RETURN_(FALSE);
  if (opt)
    {
      if (! (td->attrs = (BroAttrs *) __bro_sobject_unserialize(SER_ATTRIBUTES, bc)))
	D_RETURN_(FALSE);
    }

  /* Read a type */

  if (td->type)
    __bro_sobject_release((BroSObject *) td->type);
  td->type = NULL;

  if (! (td->type = (BroType *) __bro_sobject_unserialize(SER_IS_TYPE, bc)))
    D_RETURN_(FALSE);

  /* Read ID name string */
  
  bro_string_cleanup(&td->id);
  if (! __bro_buf_read_string(bc->rx_buf, &td->id))
    D_RETURN_(FALSE);

  D_RETURN_(TRUE);
}


int
__bro_type_decl_write(BroTypeDecl *td, BroConn *bc)
{
  D_ENTER;

  if (! td || !bc)
    D_RETURN_(FALSE);

  if (! __bro_buf_write_char(bc->tx_buf, td->attrs ? 1 : 0))
    D_RETURN_(FALSE);

  if (td->attrs && ! __bro_sobject_serialize((BroSObject *) td->attrs, bc))
    D_RETURN_(FALSE);
  
  if (! __bro_sobject_serialize((BroSObject *) td->type, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_string(bc->tx_buf, &td->id))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


uint32
__bro_type_decl_hash(BroTypeDecl *td)
{
  uint32 result;

  D_ENTER;

  if (! td)
    D_RETURN_(0);

  result = __bro_ht_str_hash(td->id.str_val);
  result ^= __bro_sobject_hash((BroSObject*) td->attrs);
  result ^= __bro_sobject_hash((BroSObject*) td->type);

  D_RETURN_(result);
}


int
__bro_type_decl_cmp(BroTypeDecl *td1, BroTypeDecl *td2)
{
  D_ENTER;

  if (! td1 || ! td2)
    D_RETURN_(FALSE);

  if (! __bro_sobject_cmp((BroSObject*) td1->attrs, (BroSObject*) td2->attrs) ||
      ! __bro_sobject_cmp((BroSObject*) td1->type, (BroSObject*) td2->type))
    D_RETURN_(FALSE);  
  
  D_RETURN_(TRUE);
}


