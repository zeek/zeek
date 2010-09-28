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
#ifndef broccoli_list_h
#define broccoli_list_h

typedef struct bro_list BroList;
typedef void(*BroFunc) (void *data);

/* Create new list with data item.
 */
BroList *__bro_list_new(void *data);

/* Erase entire list, applying free_func to each item
 * in order to free it. Pass %NULL for free_func if no-op
 * is desired.
 */
void     __bro_list_free(BroList *l, BroFunc free_func);

/* Given list element, returns the head of list by
 * walking back to it.
 */
BroList *__bro_list_head(BroList *l);

/* Next/prev items. */
BroList *__bro_list_next(BroList *l);
BroList *__bro_list_prev(BroList *l);

/* Returns nth list member, starting at 0, or NULL if not found.
 */
BroList *__bro_list_nth(BroList *l, int n);

/* Returns length of list, or 0 on error.
 */
int      __bro_list_length(BroList *l);

/* Appends item to end of list and returns pointer to
 * the list. NOTE: O(N) runtime. Try to use
 * __bro_list_prepend() or track last list
 * element in case lists contain more than a handful
 * of elements.
 */
BroList *__bro_list_append(BroList *l, void *data);

/* Prepends item and returns pointer to it.
 */
BroList *__bro_list_prepend(BroList *l, void *data);

/* Inserts new node for @data after @l.
 * Returns pointer to new item.
 */
BroList *__bro_list_insert(BroList *l, void *data);

/* Removes a node and returns a pointer to the first
 * element of the resulting list.
 */
BroList *__bro_list_remove(BroList *l, BroList *ll);

/* List node data element accessor.
 */
void    *__bro_list_data(BroList *l);

/* Set data of list node, return old ones.
 */
void    *__bro_list_set_data(BroList *l, void *data);

/* Moves an item to the front of the list. For implementing
 * MRU/LRU schemes.
 */
BroList *__bro_list_move_to_front(BroList *l, BroList *item);

#endif
