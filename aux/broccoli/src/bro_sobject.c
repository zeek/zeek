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
#include <sys/time.h>

#ifdef __EMX__
#include <strings.h>
#endif 

#include <bro_debug.h>
#include <bro_attr.h>
#include <bro_attrs.h>
#include <bro_id.h>
#include <bro_location.h>
#include <bro_object.h>
#include <bro_type.h>
#include <bro_val.h>
#include <bro_sobject.h>

static uint32 __bro_sobject_hash_impl(BroSObject *obj);
static int    __bro_sobject_cmp_impl(BroSObject *obj1, BroSObject *obj2);

/* Factory for object instances -- essentially a mapping from a type ID
 * to a function taking no arguments and returning an object derived
 * from BroSObject.
 */
typedef struct bro_obj_factory_entry
{
  uint16       type_id;
  BroSObject  *(* create)(void);
} BroObjFactoryEntry;

static BroObjFactoryEntry obj_factories[] = {
  { SER_OBJ,              (BroSObjectNew) __bro_object_new },
  { SER_VAL,              (BroSObjectNew) __bro_val_new },
  { SER_INTERVAL_VAL,     (BroSObjectNew) __bro_val_new },
  { SER_PORT_VAL,         (BroSObjectNew) __bro_val_new },
  { SER_ADDR_VAL,         (BroSObjectNew) __bro_val_new },
  { SER_SUBNET_VAL,       (BroSObjectNew) __bro_val_new },
  { SER_NET_VAL,          (BroSObjectNew) __bro_val_new },
  { SER_STRING_VAL,       (BroSObjectNew) __bro_val_new },
  { SER_ENUM_VAL,         (BroSObjectNew) __bro_val_new },
  { SER_LIST_VAL,         (BroSObjectNew) __bro_list_val_new },
  { SER_MUTABLE_VAL,      (BroSObjectNew) __bro_mutable_val_new },
  { SER_RECORD_VAL,       (BroSObjectNew) __bro_record_val_new },
  { SER_TABLE_VAL,        (BroSObjectNew) __bro_table_val_new },

  { SER_TYPE,             (BroSObjectNew) __bro_type_new },
  { SER_TYPE_LIST,        (BroSObjectNew) __bro_type_list_new },
  { SER_RECORD_TYPE,      (BroSObjectNew) __bro_record_type_new },
  { SER_INDEX_TYPE,       (BroSObjectNew) __bro_index_type_new },
  { SER_TABLE_TYPE,       (BroSObjectNew) __bro_table_type_new },
  { SER_SET_TYPE,         (BroSObjectNew) __bro_set_type_new },
  { SER_ATTRIBUTES,       (BroSObjectNew) __bro_attrs_new },
  { SER_ID,               (BroSObjectNew) __bro_id_new },
  { SER_LOCATION,         (BroSObjectNew) __bro_loc_new },
};


BroSObject *
__bro_sobject_create(uint16 type_id)
{
  int i, num_factories;

  D_ENTER;

  num_factories = sizeof(obj_factories) / sizeof(BroObjFactoryEntry);
  
  for (i = 0; i < num_factories; i++)
    {
      if (obj_factories[i].type_id == type_id && obj_factories[i].create)
	{
	  BroSObject *result = obj_factories[i].create();
	  D_RETURN_(result);
	}
    }
  
  D(("Creation of object type 0x%04x failed.\n", type_id));
  D_RETURN_(NULL);
}


void
__bro_sobject_release(BroSObject *obj)
{
  D_ENTER;

  if (! obj)
    D_RETURN;

  obj->ref_count--;

  if (obj->ref_count > 0)
    {
      D(("Object %p has non-zero refcount, not releasing\n", obj));
      D_RETURN;
    }

  if (obj->free)
    obj->free(obj);
  
  D_RETURN;
}


void
__bro_sobject_ref(BroSObject *obj)
{
  obj->ref_count++;
}


BroSObject      *
__bro_sobject_copy(BroSObject *obj)
{
  BroSObject *clone;
  
  D_ENTER;
  
  if (! obj)
    D_RETURN_(NULL);
  
  if (! (clone = __bro_sobject_create(obj->type_id)))
    D_RETURN_(NULL);
  
  if (clone->clone)
    clone->clone(clone, obj);
  
  D_RETURN_(clone);
}


BroSObject      *
__bro_sobject_new(void)
{
  BroSObject *obj;

  D_ENTER;
  
  if (! (obj = calloc(1, sizeof(BroSObject))))
    D_RETURN_(NULL);
  
  __bro_sobject_init(obj);
    
  D_RETURN_(obj);
}

void
__bro_sobject_init(BroSObject *obj)
{
  D_ENTER;
  
  obj->ref_count = 1;

  if (! (obj->data = __bro_ht_new(__bro_ht_str_hash,
				  __bro_ht_str_cmp,
				  __bro_ht_mem_free,
				  NULL,
				  FALSE)))
    {
      D(("Out of memory.\n"));
      /* FIXME -- add return value to initializer methods. */
    }
  
  obj->read  = __bro_sobject_read;
  obj->write = __bro_sobject_write;
  obj->free  = __bro_sobject_free;
  obj->clone = __bro_sobject_clone;
  obj->hash  = __bro_sobject_hash_impl;
  obj->cmp   = __bro_sobject_cmp_impl;

  D_RETURN;
}

void
__bro_sobject_free(BroSObject *obj)
{
  D_ENTER;

  if (! obj)
    D_RETURN;

  __bro_ht_free(obj->data);
  free(obj);

  D_RETURN;
}


int
__bro_sobject_clone(BroSObject *dst, BroSObject *src)
{
  D_ENTER;
  
  dst->perm_id = src->perm_id;
  dst->type_id = src->type_id; /* Should aready be set, but what the heck .. */
  dst->ref_count = 1;
 
  /* We don't clone the contents of the data hashtable -- 
   * actually we can't right now ...
   */
 
  D_RETURN_(TRUE);
}


static uint32
__bro_sobject_hash_impl(BroSObject *obj)
{
  uint32 result;
  
  D_ENTER;
  
  if (! obj)
    D_RETURN_(0);
  
  result = obj->perm_id ^ (uint32) obj->type_id;
  
  D_RETURN_(result);
}


static int
__bro_sobject_cmp_impl(BroSObject *obj1, BroSObject *obj2)
{
  D_ENTER;
  
  if (! obj1 || ! obj2)
    D_RETURN_(FALSE);
  
  if (obj1->perm_id != obj2->perm_id)
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


uint32
__bro_sobject_hash(BroSObject *obj)
{
  D_ENTER;

  if (! obj)
    D_RETURN_(0);

  D_RETURN_(obj->hash(obj));
}

int
__bro_sobject_cmp(BroSObject *obj1, BroSObject *obj2)
{
  D_ENTER;

  if (! obj1 || !obj2)
    D_RETURN_(FALSE);

  D_RETURN_(obj1->cmp(obj1, obj2));
}


int
__bro_sobject_serialize(BroSObject *obj, BroConn *bc)
{
  char full_obj;

  D_ENTER;

  if (! obj || !bc)
    D_RETURN_(FALSE);

  /* Special case for types: they indicate at the very beginning
   * whether they're transferred in their entirety or just via
   * their name (in which case we can't do much at the moment).
   */
  if ( (obj->type_id & SER_TYPE_MASK) == SER_IS_TYPE)
    {      
      BroType *type = (BroType *) obj;
      
      D(("Serializing type %X as type\n", obj->type_id));

      if (! __bro_buf_write_char(bc->tx_buf, type->is_complete))
	D_RETURN_(FALSE);
      
      if (! type->is_complete)
	{
	  if (! __bro_buf_write_string(bc->tx_buf, &type->type_name))
	    D_RETURN_(FALSE);
	  
	  D(("Type sent by type-name '%s' only.\n", bro_string_get_data(&type->type_name)));
	  D_RETURN_(TRUE);
	}
    }
  
  /* FIXME: for now we never use the serialization cache when sending. */
  full_obj = 1;
  
  if (! __bro_buf_write_char(bc->tx_buf, full_obj))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_int(bc->tx_buf, obj->perm_id))
    D_RETURN_(FALSE);

  if (! obj->write(obj, bc))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


BroSObject      *
__bro_sobject_unserialize(uint16 type_id_wanted, BroConn *bc)
{
  BroSObject *obj;
  char full_obj;
  uint32 perm_id;
  uint16 type_id;

  D_ENTER;

  if (! bc)
    D_RETURN_(NULL);
  
  /* Same special case for types as in __bro_sobject_serialize().
   */
  if ( (type_id_wanted & SER_TYPE_MASK) == SER_IS_TYPE)
    {
      D(("Unserializing a type, checking for name-only format.\n"));

      if (! __bro_buf_read_char(bc->rx_buf, &full_obj))
	D_RETURN_(NULL);

      if (! full_obj)
	{
	  BroString tmp;
	  bro_string_init(&tmp);
	  
	  /* We only get the name. */
	  if (! __bro_buf_read_string(bc->rx_buf, &tmp))
	    D_RETURN_(FALSE);
	  
	  /* We don't really have a namespace in which we can now
	   * look up the type, so there's not much we can do!
	   */
	  D(("Received name-only type '%s', reporting failure.\n",
	     bro_string_get_data(&tmp)));
	  D_RETURN_(FALSE);
	}
    }
  
  if (! __bro_buf_read_char(bc->rx_buf, &full_obj))
    D_RETURN_(NULL);
  
  if (! __bro_buf_read_int(bc->rx_buf, &perm_id))
    D_RETURN_(NULL);

  if (! full_obj)
    {
#ifdef BRO_DEBUG
      if (! (bc->conn_flags & BRO_CFLAG_CACHE))
	D(("WARNING: no caching requested, yet peer sends cached data.\n"));
#endif
      if (! (obj = __bro_ht_get(bc->io_cache, (void *)(uintptr_t)  perm_id)))
	{
	  D(("Cache inconsistency: cache should contain object %i\n", perm_id));
	  D_RETURN_(NULL);
	}
      
      __bro_sobject_ref(obj);

      D(("Returning object %i/%p from cache.\n", perm_id, obj));
      D_RETURN_(obj);
    }
 
  if (! __bro_buf_read_short(bc->rx_buf, &type_id))
    D_RETURN_(NULL);
  
  /* Now check if the stuff that's arriving is actually an
   * instance of the type we'd like to see -- we can only do
   * primitive checking for inherited types (when we want to
   * know that it's a type, say, but we cannot know what exact
   * kind of type) -- so we just check whether all the bits set
   * in both type id's match:
   */
  if ((type_id_wanted & SER_TYPE_MASK) != (type_id & SER_TYPE_MASK))
    {
      D(("Type mismatch in serialization: wanted %04x, got %04x.\n",
	 type_id_wanted, type_id));
      D_RETURN_(NULL);
    }
  
  if (! (obj = __bro_sobject_create(type_id)))
    D_RETURN_(NULL);
  
  /* Polymorphism: depending on the constructor of the object,
   * this call will start from the bottom of the hierarchy and
   * read members in step by step, so by the time we return
   * from this function the object is fully unserialized.
   */
  if (! obj->read(obj, bc))
    {
      D(("Reading object %i of type 0x%04x FAILED.\n", perm_id, type_id));
      __bro_sobject_release(obj);
      D_RETURN_(NULL);
    }

  /* If we have asked the peer to use caching,
   * make sure the object is in the cache:
   */
  if ( (bc->conn_flags & BRO_CFLAG_CACHE) &&
       ! __bro_ht_get(bc->io_cache, (void *)(uintptr_t) perm_id))
    {
      D(("Storing object %i in cache.\n", perm_id));
      __bro_ht_add(bc->io_cache, (void *)(uintptr_t) perm_id, obj);
      obj->perm_id = perm_id;
      __bro_sobject_ref(obj);
    }

  D(("Object %i of type 0x%04x unserialized successfully.\n", perm_id, type_id));
  D_RETURN_(obj);
}


int
__bro_sobject_read(BroSObject *obj, BroConn *bc)
{
  D_ENTER;
  D_RETURN_(TRUE);

  obj = NULL;
  bc = NULL;
}


int
__bro_sobject_write(BroSObject *obj, BroConn *bc)
{
  D_ENTER;
  
  if (! __bro_buf_write_short(bc->tx_buf, obj->type_id))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


void
__bro_sobject_data_set(BroSObject *obj, const char *key, void *val)
{
  D_ENTER;

  if (! obj || ! key || ! *key)
    D_RETURN;

  __bro_ht_add(obj->data, strdup(key), val);
  /* D(("Setting data item '%s' in object %p\n", key, obj)); */

  D_RETURN;
}


void *
__bro_sobject_data_get(BroSObject *obj, const char *key)
{
  void *result;

  if (! obj || ! key || ! *key)
    return NULL;

  result = __bro_ht_get(obj->data, (void *) key);
  /* D(("Retrieving data item '%s' from object %p yields %p\n", key, obj, result)); */
  return result;
}


void *
__bro_sobject_data_del(BroSObject *obj, const char *key)
{
  void *result;
  
  D_ENTER;
  
  if (! obj || ! key || ! *key)
    D_RETURN_(NULL);
  
  result = __bro_ht_del(obj->data, (void *) key);
  /* D(("Removing data item '%s' from object %p yields %p\n", key, obj, result)); */
  D_RETURN_(result);
}
