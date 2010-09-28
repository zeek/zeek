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
#include <bro_debug.h>
#include <bro_list.h>
#include <bro_hashtable.h>

#define BRO_HT_NUM_SLOTS 127

#ifdef BRO_DEBUG
#define DEBUG_HTS
#endif

#ifdef DEBUG_HTS
#  define DEBUG_HT(x) do { printf("%s/%i: ", __FILE__, __LINE__); printf x ; } while (0);
#else
#  define DEBUG_HT(x)
#endif

typedef struct bro_hash_item
{
  /* For the age list in the hashtable. We know every node will
   * occur only once in the hashtable, and we want the items 
   * themselves to be the nodes, so the macros are okay.
   */
  TAILQ_ENTRY(bro_hash_item) age_list;

  void         *it_key;
  void         *it_data;

} BroHTIt;

typedef TAILQ_HEAD(hi_list, bro_hash_item) BroHIList;

struct bro_ht
{
  BroList     **ht_slots;
  int           ht_numslots;
  int           ht_size;

  /* Age list for elements in hash table, only used if
   * requested in __bro_ht_new(). The youngest element
   * of the age list sits at the *tail* of the list,
   * the oldest is at the *front*.
   */
  int           use_age_list;
  BroHIList     age_list;

  BroHTHashFunc ht_hash_func;
  BroHTCmpFunc  ht_cmp_func;
  BroHTFreeFunc ht_key_free_func;
  BroHTFreeFunc ht_val_free_func;
};


BroHT *
__bro_ht_new(BroHTHashFunc hash_func,
	     BroHTCmpFunc cmp_func,
	     BroHTFreeFunc key_free_func,
	     BroHTFreeFunc val_free_func,
	     int use_age_list)
{
  BroHT *ht;
  int i;

  D_ENTER;

  /* It may be okay if we get no free_funcs ... */
  if (!hash_func || !cmp_func)
    D_RETURN_(NULL);

  if (! (ht = calloc(1, sizeof(BroHT))))
    D_RETURN_(NULL);

  ht->ht_numslots = BRO_HT_NUM_SLOTS;
  ht->ht_size = 0;
  ht->use_age_list = use_age_list;
  ht->ht_hash_func = hash_func;
  ht->ht_cmp_func = cmp_func;
  ht->ht_key_free_func = key_free_func;
  ht->ht_val_free_func = val_free_func;

  /* ht_slots is kept NULL here to avoid work on tables that are never
   * inserted into.
   */
  
  /* Initialize the age list no matter whether it'll be
   * used or not.
   */
  TAILQ_INIT(&ht->age_list);
  
  D_RETURN_(ht);
}


void
__bro_ht_free(BroHT *ht)
{
  BroList *l;
  BroHTIt *it;
  int i;

  D_ENTER;

  if (! ht)
    D_RETURN;

  /* Age list doesn't need cleaning up as its nodes are 
   * entries in the regular hashtable, which are cleaned
   * up now:
   */
  
  if (ht->ht_slots == NULL)
    {
      free(ht);
      D_RETURN;
    }

  for (i = 0; i < ht->ht_numslots; i++)
    {
      for (l = ht->ht_slots[i]; l; l = __bro_list_next(l))
	{
	  it = __bro_list_data(l);

	  if (ht->ht_key_free_func)    
	    ht->ht_key_free_func(it->it_key);

	  if (ht->ht_val_free_func)
	    ht->ht_val_free_func(it->it_data);

	  free(it);
	}
      
      __bro_list_free(ht->ht_slots[i], NULL);
    }
  
  free(ht->ht_slots);
  free(ht);
  D_RETURN;
}


int
__bro_ht_add(BroHT *ht, void *key, void *data)
{
  uint32 slot;
  BroHTIt *it;

  D_ENTER;

  if (!ht || !key)
    {
      D(("Input error: (%p, %p, %p)\n", ht, key, data));
      D_RETURN_(FALSE);
    }
  
  if (! (it = calloc(1, sizeof(BroHTIt))))
    {
      D(("Out of memory.\n"));
      D_RETURN_(FALSE);
    }
  
  it->it_key = key;
  it->it_data = data;
  
  if (ht->ht_slots == NULL)
    {
      if (! (ht->ht_slots = calloc(ht->ht_numslots, sizeof(BroList*))))
	{
	  D(("Out of memory.\n"));
	  D_RETURN_(FALSE);
	}
    }
  
  slot = ht->ht_hash_func(key) % ht->ht_numslots;
  ht->ht_slots[slot] = __bro_list_append(ht->ht_slots[slot], it);
  ht->ht_size++;

  if (ht->use_age_list)
    TAILQ_INSERT_TAIL(&ht->age_list, it, age_list);

  D_RETURN_(TRUE);
}


void *
__bro_ht_get(BroHT *ht, const void *key)
{
  BroList *l;
  BroHTIt *it;
  uint32 slot;
  
  if (!ht || !key)
    {
      D(("Input error: (%p, %p)\n", ht, key));
      return NULL;
    }

  if (!ht->ht_slots)
    return NULL;
  
  slot = ht->ht_hash_func(key) % ht->ht_numslots;

  for (l = ht->ht_slots[slot]; l; l = __bro_list_next(l))
    {
      it = __bro_list_data(l);
      
      if (ht->ht_cmp_func(it->it_key, key))
	{
	  if (ht->use_age_list)
	    {
	      TAILQ_REMOVE(&ht->age_list, it, age_list);
	      TAILQ_INSERT_TAIL(&ht->age_list, it, age_list);
	    }

	  return it->it_data;
	}
    }

  return NULL;
}


void     *
__bro_ht_del(BroHT *ht, void *key)
{
  void *result;
  BroHTIt *it;
  BroList *l;
  uint32 slot;

  D_ENTER;

  if (!ht || !key)
    D_RETURN_(NULL);

  if (!ht->ht_slots)
    D_RETURN_(NULL);
  
  slot = ht->ht_hash_func(key) % ht->ht_numslots;
  
  for (l = ht->ht_slots[slot]; l; l = __bro_list_next(l))
    {
      it = __bro_list_data(l);

      if (ht->ht_cmp_func(it->it_key, key))
	{
	  result = it->it_data;
	  ht->ht_slots[slot] = __bro_list_remove(ht->ht_slots[slot], l);
	  ht->ht_size--;
	  
	  /* Free the key if possible -- don't free the
	   * value, as we just return that.
	   */
	  if (ht->ht_key_free_func)
	    ht->ht_key_free_func(it->it_key);
	  
	  if (ht->use_age_list)
	    TAILQ_REMOVE(&ht->age_list, it, age_list);
	  
	  free(it);
	  
	  D_RETURN_(result);
	}
    }
  
  D_RETURN_(NULL);
}


int
__bro_ht_get_size(BroHT *ht)
{
  if (! ht)
    return -1;

  return ht->ht_size;
}


void
__bro_ht_get_oldest(BroHT *ht, void **key, void **data)
{
  if (! ht || !ht->use_age_list)
    {
      if (key)
	*key = NULL;
      if (data)
	*data = NULL;

      return;
    }

  if (key)
    *key = ht->age_list.tqh_first->it_key;
  
  if (data)
    *data = ht->age_list.tqh_first->it_data;
}


int
__bro_ht_evict_oldest(BroHT *ht)
{
  if (! ht)
    return 0;
  
  if (ht->use_age_list && ht->age_list.tqh_first)
    __bro_ht_del(ht, ht->age_list.tqh_first->it_key);
  
  return ht->ht_size;
}


void
__bro_ht_foreach(BroHT *ht, BroHTCallback callback, void *user_data)
{
  BroList *l;
  BroHTIt *it;
  int i;

  if (!ht || !callback)
    return;
  
  if (!ht->ht_slots)
    return;

  for (i = 0; i < ht->ht_numslots; i++)
    {
      for (l = ht->ht_slots[i]; l; l = __bro_list_next(l))
	{
	  it = __bro_list_data(l);

	  if (! callback(it->it_key, it->it_data, user_data))
	    return;
	}
    }
}


uint32
__bro_ht_str_hash(const void *val)
{
  char *val_ptr;
  uint32 hash;
  
  if (!val)
    return 0;

  val_ptr = (char *) val;
  
  for (hash = 0; *val_ptr != '\0'; val_ptr++)
    hash = (64 * hash + *val_ptr);

  return hash;
}


int
__bro_ht_str_cmp(const void *val1, const void *val2)
{
  if (! val1 || ! val2)
    return FALSE;

  return strcmp((char*) val1, (char*) val2) == 0;
}


void
__bro_ht_mem_free(void *data)
{
  if (data)
    free(data);
}


uint32
__bro_ht_int_hash(const void *val)
{
  return (uint32)(uintptr_t) val;
}


int
__bro_ht_int_cmp(const void *val1, const void *val2)
{
  return val1 == val2;
}
