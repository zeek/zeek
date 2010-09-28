/*
       B R O C C O L I  --  The Bro Client Communications Library

Copyright (C) 2004-2007 Christian Kreibich <christian (at) icir.org>

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
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#include <broccoli.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

void
print_val(void *val, int type)
{
  char br_open = '[';
  char br_close = ']';

  if (! val)
    {
      printf("NULL");
      return;
    }

  switch (type) {
  case BRO_TYPE_BOOL:
    printf("%s", *((int*) val) == 0 ? "false" : "true");
    break;

  case BRO_TYPE_INT:
    printf("%i", *((int*) val));
    break;

  case BRO_TYPE_DOUBLE:
    printf("%f", *((double*) val));
    break;

  case BRO_TYPE_STRING:
    printf("'%s'", bro_string_get_data((BroString*) val));
    break;

  case BRO_TYPE_LIST:
    /* This means that we're dealing with a composite indexing type.
     * Except for this differing type code, treatment is exactly as
     * with a record:
     */
    br_open = '{';
    br_close = '}';
    
    /* Fall through */
    
  case BRO_TYPE_RECORD:
    {
      void *item;
      int i, type;
      BroRecord *rec = (BroRecord*) val;
      
      printf("%c", br_open);
      
      for (i = 0; i < bro_record_get_length(rec); i++)
	{
	  /* We don't want to enforce typechecking of the
	   * queried value, so we use BRO_TYPE_UNKNOWN.
	   */
	  type = BRO_TYPE_UNKNOWN;
	  item = bro_record_get_nth_val(rec, i, &type);
	  print_val(item, type);
	  
	  if (i + 1 < bro_record_get_length(rec))
	    printf(", ");
	}      
      
      printf("%c", br_close);
    }
    break;
        
  default:    
    printf("<unimplemented %d>", type);
  }
}

int
table_it_cb(void *key, void *val, BroTable *table)
{
  int key_type, val_type;

  bro_table_get_types(table, &key_type, &val_type);
  
  print_val(key, key_type);
  printf(" -> ");
  print_val(val, val_type);
  printf("\n");

  return TRUE;
}

int
main(int argc, char **argv)
{
  int opt, debugging = 0;

  /* A few tables with different atomic indexing/yield types: */
  BroTable *int_to_str;
  BroTable *str_to_double;
  
  /* A table with a composite indexing type: */
  BroTable *int_str_double_to_int;

  /* Placeholders for the stuff we insert/retrieve: */
  BroString str, *str_ptr;
  BroRecord *rec;
  int i, i2, *i_ptr;
  double d, *d_ptr;
  
  while ( (opt = getopt(argc, argv, "c:p:dh?r")) != -1)
    {
      switch (opt)
	{
	case 'd':
	  debugging++;
	  
	  if (debugging == 1)
	    bro_debug_messages = 1;
	  
	  if (debugging > 1)
	    bro_debug_calltrace = 1;
	  break;
	  
	default:
	  break;
	}
    }

  /* ---- Mandatory initialization ------------------------------------- */
  bro_init(NULL);

  /* ---- int -> string ------------------------------------------------ */

  printf("int_to_str table dump:\n");
  printf("----------------------\n");

  int_to_str = bro_table_new();

  i = 10;
  bro_string_set(&str, "foo");  
  bro_table_insert(int_to_str, BRO_TYPE_INT, &i, BRO_TYPE_STRING, &str);
  bro_string_cleanup(&str);

  i = 20;
  bro_string_set(&str, "bar");  
  bro_table_insert(int_to_str, BRO_TYPE_INT, &i, BRO_TYPE_STRING, &str);
  bro_string_cleanup(&str);

  i = 30;
  bro_string_set(&str, "baz");  
  bro_table_insert(int_to_str, BRO_TYPE_INT, &i, BRO_TYPE_STRING, &str);
  bro_string_cleanup(&str);

  bro_table_foreach(int_to_str, (BroTableCallback) table_it_cb, int_to_str);
  
  printf("\ntest lookup: ");
  i = 20;
  str_ptr = (BroString*) bro_table_find(int_to_str, &i);
  
  print_val(&i, BRO_TYPE_INT);
  printf(" -> ");
  print_val(str_ptr, BRO_TYPE_STRING);
  printf("\n\n");

  bro_table_free(int_to_str);


  /* ---- string -> double --------------------------------------------- */
  
  printf("str_to_double table dump:\n");
  printf("-------------------------\n");

  str_to_double = bro_table_new();

  d = 1.1;
  bro_string_set(&str, "foo");  
  bro_table_insert(str_to_double, BRO_TYPE_STRING, &str, BRO_TYPE_DOUBLE, &d);
  bro_string_cleanup(&str);

  d = 2.2;
  bro_string_set(&str, "bar");  
  bro_table_insert(str_to_double, BRO_TYPE_STRING, &str, BRO_TYPE_DOUBLE, &d);
  bro_string_cleanup(&str);
  
  d = 3.3;
  bro_string_set(&str, "baz");  
  bro_table_insert(str_to_double, BRO_TYPE_STRING, &str, BRO_TYPE_DOUBLE, &d);
  bro_string_cleanup(&str);
  
  bro_table_foreach(str_to_double, (BroTableCallback) table_it_cb, str_to_double);
  
  printf("\ntest lookup: ");
  bro_string_set(&str, "bar");  
  d_ptr = (double*) bro_table_find(str_to_double, &str);
  
  print_val(&str, BRO_TYPE_STRING);
  printf(" -> ");
  print_val(d_ptr, BRO_TYPE_DOUBLE);
  printf("\n\n");
  
  bro_string_cleanup(&str);
  
  bro_table_free(str_to_double);


  /* ---- {int, string, double} -> int --------------------------------- */
  
  printf("int_str_double_to_int table dump:\n");
  printf("---------------------------------\n");

  int_str_double_to_int = bro_table_new();

  /* -- first element -- */

  i = 1;
  d = 1.1;
  bro_string_set(&str, "foo");  
  i2 = 10;

  /* You may pass NULL as the field name, but then of course looking
   * up elements by field name will not work in case you need it.
   */
  rec = bro_record_new();
  bro_record_add_val(rec, NULL, BRO_TYPE_INT, NULL, &i);
  bro_record_add_val(rec, NULL, BRO_TYPE_STRING, NULL, &str);
  bro_record_add_val(rec, NULL, BRO_TYPE_DOUBLE, NULL, &d);
  bro_table_insert(int_str_double_to_int, BRO_TYPE_LIST, rec, BRO_TYPE_INT, &i2);

  bro_string_cleanup(&str);
  bro_record_free(rec);

  /* -- second element -- */

  i = 2;
  d = 2.2;
  bro_string_set(&str, "bar");  
  i2 = 20;

  /* You may pass NULL as the field name, but then of course looking
   * up elements by field name will not work in case you need it.
   */
  rec = bro_record_new();
  bro_record_add_val(rec, NULL, BRO_TYPE_INT, NULL, &i);
  bro_record_add_val(rec, NULL, BRO_TYPE_STRING, NULL, &str);
  bro_record_add_val(rec, NULL, BRO_TYPE_DOUBLE, NULL, &d);
  bro_table_insert(int_str_double_to_int, BRO_TYPE_LIST, rec, BRO_TYPE_INT, &i2);

  bro_string_cleanup(&str);
  bro_record_free(rec);

  /* -- third element -- */

  i = 3;
  d = 3.3;
  bro_string_set(&str, "baz");  
  i2 = 30;

  /* You may pass NULL as the field name, but then of course looking
   * up elements by field name will not work in case you need it.
   */
  rec = bro_record_new();
  bro_record_add_val(rec, NULL, BRO_TYPE_INT, NULL, &i);
  bro_record_add_val(rec, NULL, BRO_TYPE_STRING, NULL, &str);
  bro_record_add_val(rec, NULL, BRO_TYPE_DOUBLE, NULL, &d);
  bro_table_insert(int_str_double_to_int, BRO_TYPE_LIST, rec, BRO_TYPE_INT, &i2);

  bro_string_cleanup(&str);
  bro_record_free(rec);
  
  bro_table_foreach(int_str_double_to_int, (BroTableCallback) table_it_cb, int_str_double_to_int);

  printf("\ntest lookup: ");

  i = 2;
  d = 2.2;
  bro_string_set(&str, "bar");  

  rec = bro_record_new();
  bro_record_add_val(rec, NULL, BRO_TYPE_INT, NULL, &i);
  bro_record_add_val(rec, NULL, BRO_TYPE_STRING, NULL, &str);
  bro_record_add_val(rec, NULL, BRO_TYPE_DOUBLE, NULL, &d);
  
  i_ptr = (int*) bro_table_find(int_str_double_to_int, rec);
  
  print_val(rec, BRO_TYPE_LIST);
  printf(" -> ");
  print_val(i_ptr, BRO_TYPE_INT);
  printf("\n\n");
  
  bro_string_cleanup(&str);
  bro_record_free(rec);
  
  bro_table_free(int_str_double_to_int);

  return 0;
}
