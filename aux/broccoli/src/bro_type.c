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
#include <bro_object.h>
#include <bro_type_decl.h>
#include <bro_type.h>

/* The virtual implementations of BroSObject's functions are
 * kept static in this module, and so are the ..._init() methods
 * not currently needed by other, derived classes.
 */

static void         __bro_type_init(BroType *type);
static void         __bro_type_free(BroType *type);
static int          __bro_type_read(BroType *type, BroConn *bc);
static int          __bro_type_write(BroType *type, BroConn *bc);
static int          __bro_type_clone(BroType *dst, BroType *src);
static uint32       __bro_type_hash(BroType *type);
static int          __bro_type_cmp(BroType *type1, BroType *type2);

static void         __bro_type_list_init(BroTypeList *tl);
static void         __bro_type_list_free(BroTypeList *tl);
static int          __bro_type_list_read(BroTypeList *tl, BroConn *bc);
static int          __bro_type_list_write(BroTypeList *tl, BroConn *bc);
static int          __bro_type_list_clone(BroTypeList *dst, BroTypeList *src);
static uint32       __bro_type_list_hash(BroTypeList *tl);
static int          __bro_type_list_cmp(BroTypeList *tl1, BroTypeList *tl2);

static void         __bro_record_type_init(BroRecordType *rt);
static void         __bro_record_type_free(BroRecordType *rt);
static int          __bro_record_type_read(BroRecordType *rt, BroConn *bc);
static int          __bro_record_type_write(BroRecordType *rt, BroConn *bc);
static int          __bro_record_type_clone(BroRecordType *dst, BroRecordType *src);
static uint32       __bro_record_type_hash(BroRecordType *rt);
static int          __bro_record_type_cmp(BroRecordType *rt1, BroRecordType *rt2);

static void         __bro_index_type_init(BroIndexType *it);
static void         __bro_index_type_free(BroIndexType *it);
static int          __bro_index_type_read(BroIndexType *it, BroConn *bc);
static int          __bro_index_type_write(BroIndexType *it, BroConn *bc);
static int          __bro_index_type_clone(BroIndexType *dst, BroIndexType *src);
static uint32       __bro_index_type_hash(BroIndexType *it);
static int          __bro_index_type_cmp(BroIndexType *it1, BroIndexType *it2);

static void         __bro_table_type_init(BroTableType *tt);
static void         __bro_table_type_free(BroTableType *tt);
static int          __bro_table_type_read(BroTableType *tt, BroConn *bc);
static int          __bro_table_type_write(BroTableType *tt, BroConn *bc);
static int          __bro_table_type_clone(BroTableType *dst, BroTableType *src);
static uint32       __bro_table_type_hash(BroTableType *tt);
static int          __bro_table_type_cmp(BroTableType *tt1, BroTableType *tt2);

static void         __bro_set_type_init(BroSetType *st);
static void         __bro_set_type_free(BroSetType *st);
static int          __bro_set_type_read(BroSetType *st, BroConn *bc);
static int          __bro_set_type_write(BroSetType *st, BroConn *bc);
static int          __bro_set_type_clone(BroSetType *dst, BroSetType *src);
static uint32       __bro_set_type_hash(BroSetType *st);
static int          __bro_set_type_cmp(BroSetType *st1, BroSetType *st2);


BroType *
__bro_type_new(void)
{
  BroType *type;

  D_ENTER;

  if (! (type = calloc(1, sizeof(BroType))))
    D_RETURN_(NULL);

  __bro_type_init(type);

  D_RETURN_(type);
}


BroType *
__bro_type_new_of_type(int type_tag, const char *type_name)
{
  BroType *type = NULL;
  int internal_tag;
  char is_nbo = 0;
  
  D_ENTER;
  
  switch (type_tag)
    {
    case BRO_TYPE_BOOL:
    case BRO_TYPE_INT:
    case BRO_TYPE_ENUM:
      internal_tag = BRO_INTTYPE_INT;
      break;
      
    case BRO_TYPE_COUNT:
    case BRO_TYPE_COUNTER:
      internal_tag = BRO_INTTYPE_UNSIGNED;
      break;
      
    case BRO_TYPE_PORT:
      internal_tag = BRO_INTTYPE_UNSIGNED;
      is_nbo = 1;
      break;
      
    case BRO_TYPE_DOUBLE:
    case BRO_TYPE_TIME:
    case BRO_TYPE_INTERVAL:
      internal_tag = BRO_INTTYPE_DOUBLE;
      break;
      
    case BRO_TYPE_STRING:
      internal_tag = BRO_INTTYPE_STRING;
      break;
      
    case BRO_TYPE_IPADDR:
    case BRO_TYPE_NET:
      internal_tag = BRO_INTTYPE_IPADDR;
      break;
      
    case BRO_TYPE_SUBNET:
      internal_tag = BRO_INTTYPE_SUBNET;
      break;
      
    case BRO_TYPE_PATTERN:
    case BRO_TYPE_TIMER:
    case BRO_TYPE_ANY:
    case BRO_TYPE_UNION:
    case BRO_TYPE_LIST:      
    case BRO_TYPE_FUNC:
    case BRO_TYPE_FILE:
    case BRO_TYPE_VECTOR:
      internal_tag = BRO_INTTYPE_OTHER;
      break;

    case BRO_TYPE_TABLE:
      if (! (type = (BroType *) __bro_table_type_new()))
	D_RETURN_(NULL);
      
      internal_tag = BRO_INTTYPE_OTHER;
      break;
      
    case BRO_TYPE_RECORD:
      if (! (type = (BroType *) __bro_record_type_new()))
	D_RETURN_(NULL);
      
      internal_tag = BRO_INTTYPE_OTHER;
      break;
      
    case BRO_TYPE_SET:
      if (! (type = (BroType *) __bro_set_type_new()))
	D_RETURN_(NULL);

      internal_tag = BRO_INTTYPE_OTHER;
      break;

    case BRO_TYPE_ERROR:
    default:
      internal_tag = BRO_INTTYPE_ERROR;
    }

  if (! type)
    {
      if (! (type = __bro_type_new()))
	D_RETURN_(NULL);
    }
 
  type->tag          = type_tag;
  type->internal_tag = internal_tag;
  type->is_nbo       = is_nbo;
  type->is_complete  = TRUE;
  
  if (type_name)
    {
      type->is_complete = FALSE;
      bro_string_set(&type->type_name, type_name);
    }

  D_RETURN_(type);
}


static void
__bro_type_init(BroType *type)
{
  BroSObject *sobj = (BroSObject *) type;

  D_ENTER;

  __bro_object_init((BroObject *) type);

  sobj->read  = (BroSObjectRead) __bro_type_read;
  sobj->write = (BroSObjectWrite) __bro_type_write;
  sobj->free  = (BroSObjectFree) __bro_type_free;
  sobj->clone = (BroSObjectClone) __bro_type_clone;
  sobj->hash  = (BroSObjectHash) __bro_type_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_type_cmp;

  sobj->type_id = SER_TYPE;

  bro_string_init(&type->type_name);
  type->is_complete = TRUE;

  D_RETURN;
}


static void
__bro_type_free(BroType *type)
{
  D_ENTER;
  bro_string_cleanup(&type->type_name);
  __bro_sobject_release((BroSObject *) type->attrs_type);
  __bro_object_free((BroObject *) type);
  D_RETURN;
}


static int
__bro_type_read(BroType *type, BroConn *bc)
{
  char opt;
  
  D_ENTER;

  if (! __bro_object_read((BroObject *) type, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_read_char(bc->rx_buf, &type->tag))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_char(bc->rx_buf, &type->internal_tag))
    D_RETURN_(FALSE);

  if (! __bro_buf_read_char(bc->rx_buf, &type->is_nbo))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_char(bc->rx_buf, &type->is_base_type))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_char(bc->rx_buf, &type->is_global_attrs_type))
    D_RETURN_(FALSE);

  if (! __bro_buf_read_char(bc->rx_buf, &opt))
    D_RETURN_(FALSE);
  if (opt)
    {
      if (type->attrs_type)
	__bro_sobject_release((BroSObject *) type->attrs_type);
      
      if (! (type->attrs_type = (BroRecordType *)
	     __bro_sobject_unserialize(SER_RECORD_TYPE, bc)))
	D_RETURN_(FALSE);
    }

  D_RETURN_(TRUE);
}


static int
__bro_type_write(BroType *type, BroConn *bc)
{
  D_ENTER;

   if (! __bro_object_write((BroObject *) type, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_char(bc->tx_buf, type->tag))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_char(bc->tx_buf, type->internal_tag))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_char(bc->tx_buf, type->is_nbo))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_char(bc->tx_buf, type->is_base_type))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_char(bc->tx_buf, type->is_global_attrs_type))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_char(bc->tx_buf, type->attrs_type ? 1 : 0))
    D_RETURN_(FALSE);
  
  if (type->attrs_type && ! __bro_sobject_serialize((BroSObject *) type->attrs_type, bc))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


static int
__bro_type_clone(BroType *dst, BroType *src)
{
  D_ENTER;

  if (! __bro_object_clone((BroObject *) dst, (BroObject *) src))
    D_RETURN_(FALSE);

  dst->tag = src->tag;
  dst->internal_tag = src->internal_tag;
  dst->is_nbo = src->is_nbo;
  dst->is_base_type = src->is_base_type;
  dst->is_global_attrs_type = src->is_global_attrs_type;
  dst->is_complete = src->is_complete;
  bro_string_set(&dst->type_name, (const char *) bro_string_get_data(&src->type_name));

  if (src->attrs_type &&
      ! (dst->attrs_type = (BroRecordType *) __bro_sobject_copy((BroSObject *) src->attrs_type)))
    D_RETURN_(FALSE);

  D_RETURN_(TRUE);
}


static uint32
__bro_type_hash(BroType *type)
{
  uint32 result;

  D_ENTER;

  if (! type)
    D_RETURN_(0);

  result = __bro_ht_str_hash(type->type_name.str_val);
  result ^= (uint32) type->tag;
  result ^= ((uint32) type->internal_tag) << 8;
  result ^= ((uint32) type->is_nbo) << 8;
  result ^= ((uint32) type->is_base_type) << 8;
  result ^= (uint32) type->is_global_attrs_type;
  result ^= ((uint32) type->is_complete) << 8;

  D_RETURN_(result);

}


static int
__bro_type_cmp(BroType *type1, BroType *type2)
{
  int result;

  D_ENTER;
 
  if (! type1 || ! type2)
    D_RETURN_(FALSE);

  if (type1->type_name.str_val && type2->type_name.str_val &&
      ! __bro_ht_str_cmp(type1->type_name.str_val, type2->type_name.str_val))
    D_RETURN_(FALSE);
  
  if (type1->tag != type2->tag ||
      type1->internal_tag != type2->internal_tag ||
      type1->is_nbo != type2->is_nbo ||
      type1->is_base_type != type2->is_base_type ||
      type1->is_global_attrs_type != type2->is_global_attrs_type ||
      type1->is_complete != type2->is_complete)
    D_RETURN_(FALSE);

  D_RETURN_(TRUE);

}

BroTypeList *
__bro_type_list_new(void)
{
  BroTypeList *tl;

  D_ENTER;

  if (! (tl = calloc(1, sizeof(BroTypeList))))
    D_RETURN_(NULL);

  __bro_type_list_init(tl);

  D_RETURN_(tl);
}


static void
__bro_type_list_init(BroTypeList *tl)
{
  BroSObject *sobj = (BroSObject *) tl;

  D_ENTER;
  
  __bro_type_init((BroType *) tl);
  
  sobj->read  = (BroSObjectRead) __bro_type_list_read;
  sobj->write = (BroSObjectWrite) __bro_type_list_write;
  sobj->free  = (BroSObjectFree) __bro_type_list_free;
  sobj->clone = (BroSObjectClone) __bro_type_list_clone;
  sobj->hash  = (BroSObjectHash) __bro_type_list_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_type_list_cmp;  

  sobj->type_id = SER_TYPE_LIST;

  tl->types = NULL;

  D_RETURN;
}


static void
__bro_type_list_free(BroTypeList *tl)
{
  D_ENTER;

  __bro_list_free(tl->types, (BroFunc) __bro_sobject_release);
  __bro_sobject_release((BroSObject *) tl->pure_type);  
  __bro_type_free((BroType *) tl);
  
  D_RETURN;
}


static int
__bro_type_list_read(BroTypeList *tl, BroConn *bc)
{
  char opt;
  uint32 i;

  D_ENTER;

  if (! __bro_type_read((BroType *) tl, bc))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_read_char(bc->rx_buf, &opt))
    D_RETURN_(FALSE);
  
  /* Clean out old optional pure type */
  if (tl->pure_type)
    __bro_sobject_release((BroSObject *) tl->pure_type);
  
  if (opt)
    {
      if (! (tl->pure_type = (BroType *) __bro_sobject_unserialize(SER_IS_TYPE, bc)))
	D_RETURN_(FALSE);
    }
  
  if (! __bro_buf_read_int(bc->rx_buf, &tl->num_types))
    D_RETURN_(FALSE);
  
  if (tl->num_types > 0)
    {
      for (i = 0; i < tl->num_types; i++)
	{
	  BroType *type;
	  
	  if (! (type = (BroType *) __bro_sobject_unserialize(SER_IS_TYPE, bc)))
	    D_RETURN_(FALSE);
	  
	  tl->types = __bro_list_append(tl->types, type);
	}
    }
  
  D_RETURN_(TRUE);
}


static int
__bro_type_list_write(BroTypeList *tl, BroConn *bc)
{
  BroList *l;

  D_ENTER;

  if (! __bro_type_write((BroType *) tl, bc))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_write_char(bc->tx_buf, tl->pure_type ? 1 : 0))
    D_RETURN_(FALSE);
  
  if (tl->pure_type && ! __bro_sobject_serialize((BroSObject *) tl->pure_type, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_int(bc->tx_buf, tl->num_types))
    D_RETURN_(FALSE);

  for (l = tl->types; l; l = __bro_list_next(l))
    {
      if (! __bro_sobject_serialize((BroSObject *) __bro_list_data(l), bc))
	D_RETURN_(FALSE);
    }
  
  D_RETURN_(TRUE);
}


static int
__bro_type_list_clone(BroTypeList *dst, BroTypeList *src)
{
  BroList *l;
  BroType *type;

  D_ENTER;

  if (! __bro_type_clone((BroType *) dst, (BroType *) src))
    D_RETURN_(FALSE);

  dst->num_types = src->num_types;

  if (dst->types)
    __bro_list_free(dst->types, (BroFunc) __bro_sobject_release);

  dst->types = NULL;
  
  for (l = src->types; l; l = __bro_list_next(l))
    {
      BroType *type_copy;

      type = __bro_list_data(l);
      
      if (! (type_copy = (BroType *) __bro_sobject_copy((BroSObject *) type)))
	D_RETURN_(FALSE);

      dst->types = __bro_list_append(dst->types, type_copy);
    }
  
  if (src->pure_type && ! (dst->pure_type = (BroType *) __bro_sobject_copy((BroSObject *) src->pure_type)))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


static uint32
__bro_type_list_hash(BroTypeList *tl)
{
  uint32 result;
  BroList *l;

  D_ENTER;

  if (! tl)
    D_RETURN_(0);

  result = tl->num_types;
  result ^= __bro_sobject_hash((BroSObject*) tl->pure_type);
  
  for (l = tl->types; l; l = __bro_list_next(l))
    result ^= __bro_sobject_hash((BroSObject*) __bro_list_data(l));
  
  D_RETURN_(result);
}


static int
__bro_type_list_cmp(BroTypeList *tl1, BroTypeList *tl2)
{
  BroList *l1, *l2;

  D_ENTER;

  if (! tl1 || ! tl2)
    D_RETURN_(FALSE);
  
  if (tl1->num_types != tl2->num_types ||
      ! __bro_sobject_cmp((BroSObject*) tl1->pure_type,
			  (BroSObject*) tl2->pure_type))
    D_RETURN_(FALSE);
  
  for (l1 = tl1->types, l2 = tl2->types; l1 && l2;
       l1 = __bro_list_next(l1), l2 = __bro_list_next(l2))
    {
      if (! __bro_sobject_cmp((BroSObject*) __bro_list_data(l1),
			      (BroSObject*) __bro_list_data(l2)))
	D_RETURN_(FALSE);
    }
  
  if (l1 || l2) D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


BroRecordType *
__bro_record_type_new(void)
{
  BroRecordType *rt;
  
  D_ENTER;
  
  if (! (rt = calloc(1, sizeof(BroRecordType))))
    D_RETURN_(NULL);
  
  __bro_record_type_init(rt);

  D_RETURN_(rt);
}


static void
__bro_record_type_init(BroRecordType *rt)
{
  BroSObject *sobj = (BroSObject *) rt;

  D_ENTER;
  
  __bro_type_init((BroType *) rt);
  
  sobj->read  = (BroSObjectRead) __bro_record_type_read;
  sobj->write = (BroSObjectWrite) __bro_record_type_write;
  sobj->free  = (BroSObjectFree) __bro_record_type_free;
  sobj->clone = (BroSObjectClone) __bro_record_type_clone;
  sobj->hash  = (BroSObjectHash) __bro_record_type_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_record_type_cmp;
  
  sobj->type_id = SER_RECORD_TYPE;
  
  D_RETURN;
}


static void
__bro_record_type_free(BroRecordType *rt)
{
  D_ENTER;
  
  __bro_sobject_release((BroSObject *) rt->base);
  __bro_list_free(rt->type_decls, (BroFunc) __bro_type_decl_free);
  __bro_type_free((BroType *) rt);
  
  D_RETURN;
}


void
__bro_record_type_add_type(BroRecordType *rt, const char *field, BroType *type)
{
  BroTypeDecl *td;
  
  D_ENTER;
  
  if (! rt || ! type)
    D_RETURN;
  
  if (! (td = __bro_type_decl_new()))
    D_RETURN;

  if (! (td->type = (BroType *) __bro_sobject_copy((BroSObject *) type)))
    {
      D(("Cloning of type failed.\n"));
      __bro_type_decl_free(td);
      D_RETURN;
    }
  
  if (! bro_string_set(&td->id, field))
    {
      __bro_type_decl_free(td);
      D_RETURN;
    }
  
  rt->type_decls = __bro_list_append(rt->type_decls, td);
  rt->num_fields++;
  rt->num_types++;
  D_RETURN;
}


const char *
__bro_record_type_get_nth_field(BroRecordType *rt, int num)
{
  BroList *l;
  
  if (! rt || num < 0 || (uint) num >= rt->num_fields)
    return NULL;
  
  if( (l = __bro_list_nth(rt->type_decls, num)))
    {
      BroTypeDecl *td = __bro_list_data(l);
      return (const char *) td->id.str_val;
    }
  
  return NULL;
}


static int
__bro_record_type_read(BroRecordType *rt, BroConn *bc)
{
  uint32 i;
  char opt;

  D_ENTER;

  if (! __bro_type_read((BroType *) rt, bc))
    D_RETURN_(FALSE);

  /* Read type declarations */

  rt->type_decls = NULL;
  rt->num_fields = 0;
  rt->num_types = 0;

  if (! __bro_buf_read_int(bc->rx_buf, &rt->num_fields))
    D_RETURN_(FALSE);

  if (! __bro_buf_read_char(bc->rx_buf, &opt))
    D_RETURN_(FALSE);
  if (opt)
    {
      if (! __bro_buf_read_int(bc->rx_buf, &rt->num_types))
	D_RETURN_(FALSE);
      
      if (rt->num_types > 0)
	{
	  for (i = 0; i < rt->num_types; i++)
	    {
	      BroTypeDecl *td;
	      
	      if (! (td = __bro_type_decl_new()))
		D_RETURN_(FALSE);
	      
	      if (! __bro_type_decl_read(td, bc))
		D_RETURN_(FALSE);

	      rt->type_decls = __bro_list_append(rt->type_decls, td);
	    }
	}
    }

  /* Read optional base */

  __bro_sobject_release((BroSObject *) rt->base);
  rt->base = NULL;
  
  if (! __bro_buf_read_char(bc->rx_buf, &opt))
    D_RETURN_(FALSE);
  if (opt)
    {
      if (! (rt->base = (BroTypeList *) __bro_sobject_unserialize(SER_TYPE_LIST, bc)))
	D_RETURN_(FALSE);
    }
  
  D_RETURN_(TRUE);
}


static int
__bro_record_type_write(BroRecordType *rt, BroConn *bc)
{
  BroList *l;

  D_ENTER;

  if (! __bro_type_write((BroType *) rt, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_int(bc->tx_buf, rt->num_fields))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_char(bc->tx_buf, rt->type_decls ? 1 : 0))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_write_int(bc->tx_buf, rt->num_types))
    D_RETURN_(FALSE);
  
  for (l = rt->type_decls; l; l = __bro_list_next(l))
    {
      BroTypeDecl *td = __bro_list_data(l);
      
      if (! __bro_type_decl_write(td, bc))
	D_RETURN_(FALSE);
    }
  
  if (! __bro_buf_write_char(bc->tx_buf, rt->base ? 1 : 0))
    D_RETURN_(FALSE);
  
  if (rt->base && ! __bro_sobject_serialize((BroSObject *) rt->base, bc))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


static int
__bro_record_type_clone(BroRecordType *dst, BroRecordType *src)
{
  BroList *l;

  D_ENTER;

  if (! __bro_type_clone((BroType *) dst, (BroType *) src))
    D_RETURN_(FALSE);
  
  if (src->base && ! (dst->base = (BroTypeList *) __bro_sobject_copy((BroSObject *) src->base)))
    D_RETURN_(FALSE);
  
  dst->num_fields = src->num_fields;
  dst->num_types = src->num_types;
  
  for (l = src->type_decls; l; l = __bro_list_next(l))
    {
      BroTypeDecl *td = __bro_list_data(l);
      BroTypeDecl *td_copy = __bro_type_decl_copy(td);
      
      if (! td_copy)
	D_RETURN_(FALSE);
 
      dst->type_decls = __bro_list_append(dst->type_decls, td_copy);
    }
  
  D_RETURN_(TRUE);
}


static uint32
__bro_record_type_hash(BroRecordType *rt)
{
  uint32 result;
  BroList *l;

  D_ENTER;

  if (! rt)
    D_RETURN_(0);

  result = __bro_type_list_hash(rt->base);
  result ^= rt->num_fields;
  result ^= rt->num_types << 16;
  
  for (l = rt->type_decls; l; l = __bro_list_next(l))
    result ^= __bro_type_decl_hash((BroTypeDecl*) __bro_list_data(l));

  D_RETURN_(result);
}


static int
__bro_record_type_cmp(BroRecordType *rt1, BroRecordType *rt2)
{
  BroList *l1, *l2;

  D_ENTER;

  if (! rt1 || ! rt2)
    D_RETURN_(FALSE);
  
  if (rt1->num_fields != rt2->num_fields ||
      rt1->num_types != rt2->num_types ||
      ! __bro_type_list_cmp(rt1->base, rt2->base))
    D_RETURN_(FALSE);
  
  for (l1 = rt1->type_decls, l2 = rt2->type_decls; l1 && l2;
       l1 = __bro_list_next(l1), l2 = __bro_list_next(l2))
    {
      if (! __bro_type_decl_cmp((BroTypeDecl*) __bro_list_data(l1),
				(BroTypeDecl*) __bro_list_data(l2)))
	D_RETURN_(FALSE);
    }
  
  if (l1 || l2)
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


BroIndexType *
__bro_index_type_new(void)
{
  BroIndexType *it;
  
  D_ENTER;
  
  if (! (it = calloc(1, sizeof(BroIndexType))))
    D_RETURN_(NULL);
  
  __bro_index_type_init(it);

  D_RETURN_(it);
}

static void
__bro_index_type_init(BroIndexType *it)
{
  BroSObject *sobj = (BroSObject *) it;

  D_ENTER;
  
  __bro_type_init((BroType *) it);
  
  sobj->read  = (BroSObjectRead) __bro_index_type_read;
  sobj->write = (BroSObjectWrite) __bro_index_type_write;
  sobj->free  = (BroSObjectFree) __bro_index_type_free;
  sobj->clone = (BroSObjectClone) __bro_index_type_clone;
  sobj->hash  = (BroSObjectHash) __bro_index_type_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_index_type_cmp;
  
  sobj->type_id = SER_INDEX_TYPE;
  
  D_RETURN;
}

static void
__bro_index_type_free(BroIndexType *it)
{
  D_ENTER;
  
  __bro_sobject_release((BroSObject *) it->indices);
  __bro_sobject_release((BroSObject *) it->yield_type);
  __bro_type_free((BroType *) it);
  
  D_RETURN;
}

void
__bro_index_type_set_indices(BroIndexType *it, BroTypeList *indices)
{
  BroTypeList *tl;

  D_ENTER;

  if (! it || ! indices)
    D_RETURN;

  if (! (tl = __bro_type_list_new()))
    D_RETURN;

  if (! __bro_type_list_clone(tl, indices))
    {
      __bro_type_list_free(tl);
      D_RETURN;
    }

  it->indices = tl;

  D_RETURN;
}

void
__bro_index_type_set_yield_type(BroIndexType *it, BroType *yield_type)
{
  D_ENTER;
  
  if (! it || ! yield_type)
    D_RETURN;
  
  if (! (it->yield_type = (BroType *) __bro_sobject_copy((BroSObject *) yield_type)))
    D_RETURN;
  
  D_RETURN;
}

static int
__bro_index_type_read(BroIndexType *it, BroConn *bc)
{
  char opt;

  D_ENTER;

  if (! __bro_type_read((BroType *) it, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_read_char(bc->rx_buf, &opt))
    D_RETURN_(FALSE);
  if (opt)
    {
      if (! (it->yield_type = (BroType *) __bro_sobject_unserialize(SER_TYPE, bc)))
	D_RETURN_(FALSE);
    }
  
  if (! (it->indices = (BroTypeList *) __bro_sobject_unserialize(SER_TYPE_LIST, bc)))
    D_RETURN_(FALSE);

  D_RETURN_(TRUE);  
}

static int
__bro_index_type_write(BroIndexType *it, BroConn *bc)
{
  D_ENTER;

  if (! __bro_type_write((BroType *) it, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_char(bc->tx_buf, it->yield_type ? 1 : 0))
    D_RETURN_(FALSE);

  if (it->yield_type && ! __bro_sobject_serialize((BroSObject *) it->yield_type, bc))
    D_RETURN_(FALSE);
  
  if (! __bro_sobject_serialize((BroSObject *) it->indices, bc))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}

static int
__bro_index_type_clone(BroIndexType *dst, BroIndexType *src)
{
  D_ENTER;

  if (! __bro_type_clone((BroType *) dst, (BroType *) src))
    D_RETURN_(FALSE);

  if (src->yield_type && ! (dst->yield_type = (BroType *) __bro_sobject_copy((BroSObject *) src->yield_type)))
    D_RETURN_(FALSE);

  if (! (dst->indices = (BroTypeList *) __bro_sobject_copy((BroSObject *) src->indices)))
    D_RETURN_(FALSE);

  D_RETURN_(TRUE);
}

static uint32
__bro_index_type_hash(BroIndexType *it)
{
  uint32 result;

  D_ENTER;

  if (! it)
    D_RETURN_(0);

  result = __bro_type_list_hash(it->indices);
  result ^= __bro_sobject_hash((BroSObject*) it->yield_type);

  D_RETURN_(result);
}

static int
__bro_index_type_cmp(BroIndexType *it1, BroIndexType *it2)
{
  D_ENTER;

  if (! it1 || ! it2)
    D_RETURN_(FALSE);

  if (! __bro_type_list_cmp(it1->indices, it2->indices) ||
      ! __bro_sobject_cmp((BroSObject*) it1->yield_type,
			  (BroSObject*) it2->yield_type))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


BroTableType *
__bro_table_type_new(void)
{
  BroTableType *tt;
  
  D_ENTER;
  
  if (! (tt = calloc(1, sizeof(BroTableType))))
    D_RETURN_(NULL);
  
  __bro_table_type_init(tt);

  D_RETURN_(tt);
}

static void
__bro_table_type_init(BroTableType *tt)
{
  BroSObject *sobj = (BroSObject *) tt;

  D_ENTER;
  
  __bro_index_type_init((BroIndexType *) tt); 

  sobj->read  = (BroSObjectRead) __bro_table_type_read;
  sobj->write = (BroSObjectWrite) __bro_table_type_write;
  sobj->free  = (BroSObjectFree) __bro_table_type_free;
  sobj->clone = (BroSObjectClone) __bro_table_type_clone;
  sobj->hash  = (BroSObjectHash) __bro_table_type_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_table_type_cmp;
  
  sobj->type_id = SER_TABLE_TYPE;
  
  D_RETURN;
}

static void
__bro_table_type_free(BroTableType *tt)
{
  D_ENTER;
  __bro_index_type_free((BroIndexType *) tt);  
  D_RETURN;
}

static int
__bro_table_type_read(BroTableType *tt, BroConn *bc)
{
  D_ENTER;
  
  if (! __bro_index_type_read((BroIndexType *) tt, bc))
    D_RETURN_(FALSE);

  D_RETURN_(TRUE);
}

static int
__bro_table_type_write(BroTableType *tt, BroConn *bc)
{
  D_ENTER;

  if (! __bro_index_type_write((BroIndexType *) tt, bc))
    D_RETURN_(FALSE);

  D_RETURN_(TRUE);
}

static int
__bro_table_type_clone(BroTableType *dst, BroTableType *src)
{
  D_ENTER;
  
  if (! __bro_index_type_clone((BroIndexType *) dst, (BroIndexType *) src))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}

static uint32
__bro_table_type_hash(BroTableType *tt)
{
  uint32 result;

  D_ENTER;
  result = __bro_index_type_hash((BroIndexType*) tt);
  D_RETURN_(result);
}

static int
__bro_table_type_cmp(BroTableType *tt1, BroTableType *tt2)
{
  D_ENTER;
  
  if (! tt1 || ! tt2)
    D_RETURN_(FALSE);

  D_RETURN_(__bro_index_type_cmp((BroIndexType*) tt1,
				 (BroIndexType*) tt2));
}


BroSetType *
__bro_set_type_new(void)
{
  BroSetType *st;
  
  D_ENTER;
  
  if (! (st = calloc(1, sizeof(BroSetType))))
    D_RETURN_(NULL);
  
  __bro_set_type_init(st);
  
  D_RETURN_(st);
}

static void
__bro_set_type_init(BroSetType *st)
{
  BroSObject *sobj = (BroSObject *) st;

  D_ENTER;
  
  __bro_table_type_init((BroTableType *) st); 
  
  sobj->read  = (BroSObjectRead) __bro_set_type_read;
  sobj->write = (BroSObjectWrite) __bro_set_type_write;
  sobj->free  = (BroSObjectFree) __bro_set_type_free;
  sobj->clone = (BroSObjectClone) __bro_set_type_clone;
  sobj->hash  = (BroSObjectHash) __bro_set_type_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_set_type_cmp;
  
  sobj->type_id = SER_SET_TYPE;
  
  D_RETURN;
}

static void
__bro_set_type_free(BroSetType *st)
{
  D_ENTER;  
  __bro_table_type_free((BroTableType *) st);  
  D_RETURN;
}

static int
__bro_set_type_read(BroSetType *st, BroConn *bc)
{
  char opt;

  D_ENTER;
  
  if (! __bro_table_type_read((BroTableType *) st, bc))
    D_RETURN_(FALSE);

  /* To allow unambiguous differentiation between tables and sets,
   * we set the type tag to set here, in divergence of Bro's
   * internal procedure.
   */
  ((BroType*) st)->tag = BRO_TYPE_SET;

  if (! __bro_buf_read_char(bc->rx_buf, &opt))
    D_RETURN_(FALSE);
  if (opt)
    {
      D(("Error: expressions are not yet supported. Sorry.\n"));
      D_RETURN_(FALSE);
    }
  
  D_RETURN_(TRUE);
}

static int
__bro_set_type_write(BroSetType *st, BroConn *bc)
{
  int ret;

  D_ENTER;

  /* Compatibility hack for Bro: its type tags don't differentiate
   * between sets and tables (they always indicate table types), so
   * we must ensure here that we do appear as a table type.
   */
  ((BroType*) st)->tag = BRO_TYPE_TABLE;  
  ret = __bro_table_type_write((BroTableType *) st, bc);
  ((BroType*) st)->tag = BRO_TYPE_SET;  
  
  if (! ret)
    D_RETURN_(FALSE);
  
  /* We never send expressions. */
  if (! __bro_buf_write_char(bc->tx_buf, FALSE))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}

static int
__bro_set_type_clone(BroSetType *dst, BroSetType *src)
{
  D_ENTER;
  
  if (! __bro_table_type_clone((BroTableType *) dst, (BroTableType *) src))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}

static uint32
__bro_set_type_hash(BroSetType *st)
{
  uint32 result;

  D_ENTER;
  result = __bro_table_type_hash((BroTableType*) st);
  D_RETURN_(result);
}

static int
__bro_set_type_cmp(BroSetType *st1, BroSetType *st2)
{
  int result;

  D_ENTER;
  
  if (! st1 || ! st2)
    D_RETURN_(FALSE);
  
  result = __bro_table_type_cmp((BroTableType*) st1,
				(BroTableType*) st2);;
  D_RETURN_(result);
}
