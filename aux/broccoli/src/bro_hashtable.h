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
#ifndef broccoli_ht_h
#define broccoli_ht_h

#include <broccoli.h>

typedef struct bro_ht BroHT;

/* Hash function -- pass something in, get integer back.
 */
typedef uint32 (*BroHTHashFunc)(const void *data);	     

/* Key comparison function -- compares two keys, returns %TRUE
 * if equal, %FALSE otherwise, NOT -1/0/1.
 */
typedef int (*BroHTCmpFunc)(const void *key1, const void *key2);

/* Destructor function, one for keys, one for values.
 */
typedef void (*BroHTFreeFunc)(void *data);

/**
 * BroHTCallback - The signature of functions used with __bro_ht_foreach()
 * @key: key of current hash table item
 * @data: value part of current hash table item.
 * @user_data: arbitrary user data passed through from __bro_ht_foreach().
 *
 * Returning %FALSE signals abortion of the loop.
 */
typedef int (*BroHTCallback)(void *key, void *data, void *user_data);

/**
 * __bro_ht_new - creates new hashtable.
 * @hash_func: hashing function to use, see BroHTHashFunc.
 * @cmp_func: element comparison function to use, see BroHTCmpFunc.
 * @key_free_func: callback for erasing key of an item, if desirable.
 * @val_free_func: callback for erasing data item itself, if desirable.
 * @use_age_list: whether to maintain an age list (%TRUE) or not (%FALSE).
 *
 * The function creates and returns a new hashtable. @key_free_func and
 * @val_free_func can be used to clean up contained elements automatically
 * as they are removed from the table. If you don't want this feature,
 * pass %NULL -- you can still iterate over all items in the table using
 * __bro_ht_foreach().
 *
 * The table can optionally maintain an age list (see
 * __bro_ht_get_oldest() and __bro_ht_evict_oldest()), pass %TRUE to
 * @use_age_list if desired.
 *
 * Returns: new table, or %NULL when out of memory.
 */
BroHT    *__bro_ht_new(BroHTHashFunc hash_func,
		       BroHTCmpFunc cmp_func,
		       BroHTFreeFunc key_free_func,
		       BroHTFreeFunc val_free_func,
		       int use_age_list);

void      __bro_ht_free(BroHT *ht);

int       __bro_ht_add(BroHT *ht, void *key, void *data);
void     *__bro_ht_get(BroHT *ht, const void *key);
void     *__bro_ht_del(BroHT *ht, void *key);
int       __bro_ht_get_size(BroHT *ht);

void      __bro_ht_foreach(BroHT *ht, BroHTCallback cb, void *user_data);

/* Returns pointers to key and value of oldest item in the table,
 * if age list is maintained. Otherwise sets both @key and @data
 * to %NULL.
 */
void      __bro_ht_get_oldest(BroHT *ht, void **key, void **data);

/* If age list is used, removes oldest element from the table
 * and returns number of items in the table after eviction.
 * If age list is not used, does nothing and returns table size.
 */
int       __bro_ht_evict_oldest(BroHT *ht);

uint32    __bro_ht_str_hash(const void *val);
int       __bro_ht_str_cmp(const void *val1, const void *val2);
void      __bro_ht_mem_free(void *data);

uint32    __bro_ht_int_hash(const void *val);
int       __bro_ht_int_cmp(const void *val1, const void *val2);

#endif
