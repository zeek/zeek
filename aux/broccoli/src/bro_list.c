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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <bro_debug.h>
#include <bro_list.h>

struct bro_list
{
  struct bro_list *prev;
  struct bro_list *next;
  void            *data;
};


BroList *
__bro_list_new(void *data)
{
  BroList *l;

  l = calloc(1, sizeof(BroList));
  l->prev = l->next = NULL;
  l->data = data;

  return l;
}


void      
__bro_list_free(BroList *l, BroFunc free_func)
{
  BroList *lnext;

  while (l)
    {
      lnext = l->next;
      if (l->data && free_func)
	{
	  free_func(l->data);     
	}
      free(l);
      l = lnext;
    }
}


BroList *
__bro_list_head(BroList *l)
{
  if (!l)
    return NULL;

  while (l->prev)
    l = l->prev;
  
  return l;
}


BroList *
__bro_list_next(BroList *l)
{
  if (!l)
    return NULL;

  return l->next;
}


BroList *
__bro_list_prev(BroList *l)
{
  if (!l)
    return NULL;

  return l->prev;
}


BroList *
__bro_list_nth(BroList *l, int n)
{
  while (l && n > 0)
    {
      l = l->next;
      n--;
    }

  return l;
}


int      
__bro_list_length(BroList *l)
{
  int i = 0;

  while (l)
    {
      i++;
      l = l->next;
    }

  return i;
}


BroList *
__bro_list_append(BroList *l, void *data)
{
  BroList *ltmp = NULL;
  BroList *lnew = NULL;

  lnew = __bro_list_new(data);

  if (l)
    {
      ltmp = l;

      while (ltmp->next)
	ltmp = ltmp->next;
 
      ltmp->next = lnew;
    }

  lnew->prev = ltmp;
  return l ? l : lnew;
}


BroList *
__bro_list_prepend(BroList *l, void *data)
{
  BroList *lnew;

  lnew = __bro_list_new(data);
  lnew->next = l;

  if (l)
    l->prev = lnew;

  return lnew;
}


BroList *
__bro_list_insert(BroList *l, void *data)
{
  BroList *new;

  /* Data item can be NULL if user wants that */
  if (!l)
    return NULL;

  new = __bro_list_new(data);
  new->next = l->next;
  new->prev = l;
  
  l->next = new;

  if (new->next)
    new->next->prev = l;
  
  return new;
}


BroList *
__bro_list_remove(BroList *l, BroList *item)
{
  BroList *prev;
  BroList *next;

  if (!l)
    return NULL;

  prev = item->prev;
  next = item->next;
  free(item);

  /* first item */
  if (!prev)
    {
      if (!next)
	return NULL;
      else
	{
	  next->prev = NULL;
	  return next;
	}
    }

  /* last item */
  if (!next)
    {
      if (!prev)
	return l;
      else
	{
	  prev->next = NULL;
	  return l;
	}      
    }

  /* middle item */
  prev->next = next;
  next->prev = prev;

  return l;
}


void     *
__bro_list_data(BroList *l)
{
  if (!l)
    return NULL;

  return l->data;
}


void    *
__bro_list_set_data(BroList *l, void *data)
{
  void *result;

  if (!l)
    return NULL;

  result = l->data;
  l->data = data;

  return result;
}


BroList *
__bro_list_move_to_front(BroList *l, BroList *item)
{
  BroList *prev;
  BroList *next;

  if (!l || !item)
    return NULL;

  prev = item->prev;
  next = item->next;

  /* first item already */
  if (!prev)
    return l;

  /* last item */
  if (!next)
    {
      prev->next = NULL;
      item->prev = NULL;
      item->next = l;
      l->prev = item;

      return item;
    }      

  /* middle item */
  prev->next = next;
  next->prev = prev;

  item->next = l;
  item->prev = NULL;
  l->prev = item;

  return item;
}
