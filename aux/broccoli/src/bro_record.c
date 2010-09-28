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

#include <bro_types.h>
#include <bro_io.h>
#include <bro_debug.h>
#include <bro_val.h>
#include <bro_record.h>


BroRecord *
__bro_record_new(void)
{
  BroRecord *rec;

  if (! (rec = calloc(1, sizeof(BroRecord))))
    return NULL;

  return rec;
}


void
__bro_record_free(BroRecord *rec)
{
  BroList *l;

  if (! rec)
    return;

  for (l = rec->val_list; l; l = __bro_list_next(l))
    {
      char *field;
      BroSObject *obj = __bro_list_data(l);
      
      if ( (field = __bro_sobject_data_del(obj, "field")))
	free(field);
      
      __bro_sobject_release(obj);
    }
  
  __bro_list_free(rec->val_list, NULL);
  free(rec);
}

int
__bro_record_get_length(BroRecord *rec)
{
  D_ENTER;

  if (! rec)
    D_RETURN_(0);

  D_RETURN_(rec->val_len);
}

BroRecord     *
__bro_record_copy(BroRecord *rec)
{
  BroList *l;
  BroVal *val, *val_copy;
  BroRecord *copy;

  D_ENTER;
  
  if (! rec)
    D_RETURN_(NULL);
  
  if (! (copy = __bro_record_new()))
    D_RETURN_(NULL);

  for (l = rec->val_list; l; l = __bro_list_next(l))
    {
      char *field;
      
      val = __bro_list_data(l);
      
      /* Check if it's an assigned val or not */
      if (! val->val_type)
	{
	  D(("Error: unassigned val in record.\n"));
	  goto error_return;
	}
      
      if (! (val_copy = (BroVal *) __bro_sobject_copy((BroSObject *) val)))
	goto error_return;
      
#ifdef BRO_DEBUG
      if (! val_copy->val_type)
	D(("WARNING -- typeless val duplicated as %p, original %p had type %p\n",
	   val_copy, val, val->val_type));
#endif
      if (! (field = __bro_sobject_data_get((BroSObject *) val, "field")))
	{
	  D(("Val %p in record %p doesn't have a field name.\n", val, rec));
	  goto error_return;
	}
            
      __bro_sobject_data_set((BroSObject *) val_copy, "field", strdup(field));      
      __bro_record_add_val(copy, val_copy);
    }
  
  D_RETURN_(copy);
  
 error_return:
  __bro_record_free(copy);
  D_RETURN_(NULL);
}


void
__bro_record_add_val(BroRecord *rec, BroVal *val)
{
  if (! rec || ! val)
    return;
  
  rec->val_list = __bro_list_append(rec->val_list, val);
  rec->val_len++;
}


BroVal *
__bro_record_get_nth_val(BroRecord *rec, int num)
{
  BroList *l;
  
  if (! rec || num < 0 || num >= rec->val_len)
    return NULL;

  if( (l = __bro_list_nth(rec->val_list, num)))
    return __bro_list_data(l);
  
  return NULL;
}


const char *
__bro_record_get_nth_name(BroRecord *rec, int num)
{
  BroList *l;

  if (! rec || num < 0 || num >= rec->val_len)
    return NULL;

  if( (l = __bro_list_nth(rec->val_list, num)))
    return __bro_sobject_data_get((BroSObject *) __bro_list_data(l), "field");
  
  return NULL;
}


BroVal *
__bro_record_get_named_val(BroRecord *rec, const char *name)
{
  BroList *l;
  BroVal *val;
  
  if (! rec || ! name || ! *name)
    return NULL;
  
  for (l = rec->val_list; l; l = __bro_list_next(l))
    {
      char *val_name;
      
      val = __bro_list_data(l);
      val_name = __bro_sobject_data_get((BroSObject *) val, "field");
      
      if (val_name && ! strcmp(val_name, name))
	return val;
    }
  
  return NULL;
}


int
__bro_record_set_nth_val(BroRecord *rec, int num, BroVal *v)
{
  BroVal *val;
  BroList *l;
  
  if (! rec || num < 0 || num >= rec->val_len || ! v)
    return FALSE;
  
  if ( (l = __bro_list_nth(rec->val_list, num)))
    {
      val = __bro_list_set_data(l, v);
      __bro_sobject_release((BroSObject *) val);	  
      return TRUE;
    }
  
  return FALSE;
}


int
__bro_record_set_nth_name(BroRecord *rec, int num, const char *name)
{  
  BroVal *val;
  BroList *l;

  if (! rec || num < 0 || num >= rec->val_len || ! name)
    return FALSE;

  if ( (l = __bro_list_nth(rec->val_list, num)))
    {
      char *val_name;

      val = __bro_list_data(l);
      val_name = __bro_sobject_data_del((BroSObject *) val, "field");
      if (val_name)
	free(val_name);

      __bro_sobject_data_set((BroSObject *) val, "field", strdup(name));
      return TRUE;
    }

  return FALSE;
}


int
__bro_record_set_named_val(BroRecord *rec, const char *name, BroVal *v)
{
  BroVal *val;
  BroList *l;
  
  if (! rec || ! name || !*name || ! v)
    return FALSE;

  for (l = rec->val_list; l; l = __bro_list_next(l))
    {
      char *val_name;
      
      val = __bro_list_data(l);
      val_name = __bro_sobject_data_get((BroSObject *) val, "field");
      
      if (val_name && ! strcmp(val_name, name))
	{
	  /* We're about to delete the old val, make sure it doesn't have
	   * the name tag associated with it.
	   */
	  __bro_sobject_data_del((BroSObject *) val, "field");
	  free(val_name);

	  /* If the new val has a name tag, likewise delete it.
	   */
	  if ( (val_name = __bro_sobject_data_del((BroSObject *) val, "field")))
	    free(val_name);

	  /* Set the new val's name tag
	   */
	  __bro_sobject_data_set((BroSObject *) v, "field", strdup(name));

	  __bro_list_set_data(l, v);
	  __bro_sobject_release((BroSObject *) val);	  

	  return TRUE;
	}
    }
  
  return FALSE;
}

uint32
__bro_record_hash(BroRecord *rec)
{
  uint32 result;
  BroList *l;
  
  D_ENTER;
  
  if (! rec)
    D_RETURN_(0);
  
  result = rec->val_len;
  
  for (l = rec->val_list; l; l = __bro_list_next(l))
    result ^= __bro_sobject_hash((BroSObject*) __bro_list_data(l));

  D_RETURN_(result);
}

int
__bro_record_cmp(BroRecord *rec1, BroRecord *rec2)
{
  BroList *l1, *l2;

  D_ENTER;

  if (! rec1 || ! rec2)
    D_RETURN_(FALSE);

  if (rec1->val_len != rec2->val_len)
    D_RETURN_(FALSE);

  for (l1 = rec1->val_list, l2 = rec2->val_list; l1 && l2;
       l1 = __bro_list_next(l1), l2 = __bro_list_next(l2))
    {
      if (! __bro_sobject_cmp((BroSObject*) __bro_list_data(l1),
			      (BroSObject*) __bro_list_data(l2)))
	D_RETURN_(FALSE);
    }

  if (l1 || l2)
    {
      D(("WARNING -- value list inconsistency.\n"));
      D_RETURN_(FALSE);
    }
  
  D_RETURN_(TRUE);
}
