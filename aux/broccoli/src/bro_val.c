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

#include <bro_types.h>
#include <bro_type.h>
#include <bro_io.h>
#include <bro_debug.h>
#include <bro_val.h>
#include <bro_record.h>
#include <bro_table.h>

/* The virtual implementations of BroSObject's functions are
 * kept static in this module, and so are the ..._init() methods
 * not currently needed by other, derived classes.
 */
static void             __bro_val_init(BroVal *val);
static void             __bro_val_free(BroVal *val);
static int              __bro_val_read(BroVal *val, BroConn *bc);
static int              __bro_val_write(BroVal *val, BroConn *bc);
static int              __bro_val_clone(BroVal *dst, BroVal *src);
static uint32           __bro_val_hash(BroVal *val);
static int              __bro_val_cmp(BroVal *val1, BroVal *val2);
static void            *__bro_val_get(BroVal *val);

static void             __bro_list_val_init(BroListVal *lv);
static void             __bro_list_val_free(BroListVal *lv);
static int              __bro_list_val_read(BroListVal *lv, BroConn *bc);
static int              __bro_list_val_write(BroListVal *lv, BroConn *bc);
static int              __bro_list_val_clone(BroListVal *dst, BroListVal *src);
static uint32           __bro_list_val_hash(BroListVal *lv);
static int              __bro_list_val_cmp(BroListVal *lv1, BroListVal *lv2);
static BroList         *__bro_list_val_get(BroListVal *lv);

static void             __bro_mutable_val_init(BroMutableVal *mv);
static void             __bro_mutable_val_free(BroMutableVal *mv);
static int              __bro_mutable_val_read(BroMutableVal *mv, BroConn *bc);
static int              __bro_mutable_val_write(BroMutableVal *mv, BroConn *bc);
static int              __bro_mutable_val_clone(BroMutableVal *dst, BroMutableVal *src);
static uint32           __bro_mutable_val_hash(BroMutableVal *mv);
static int              __bro_mutable_val_cmp(BroMutableVal *mv1, BroMutableVal *mv2);

static void             __bro_record_val_init(BroRecordVal *rv);
static void             __bro_record_val_free(BroRecordVal *rv);
static int              __bro_record_val_read(BroRecordVal *rv, BroConn *bc);
static int              __bro_record_val_write(BroRecordVal *rv, BroConn *bc);
static int              __bro_record_val_clone(BroRecordVal *dst, BroRecordVal *src);
static uint32           __bro_record_val_hash(BroRecordVal *rv);
static int              __bro_record_val_cmp(BroRecordVal *rv1, BroRecordVal *rv2);
static void            *__bro_record_val_get(BroRecordVal *rv);

static void             __bro_table_val_init(BroTableVal *tv);
static void             __bro_table_val_free(BroTableVal *tv);
static int              __bro_table_val_read(BroTableVal *tv, BroConn *bc);
static int              __bro_table_val_write(BroTableVal *tv, BroConn *bc);
static int              __bro_table_val_clone(BroTableVal *dst, BroTableVal *src);
static uint32           __bro_table_val_hash(BroTableVal *tv);
static int              __bro_table_val_cmp(BroTableVal *tv1, BroTableVal *tv2);
static void            *__bro_table_val_get(BroTableVal *tv);

BroVal *
__bro_val_new(void)
{
  BroVal *val;

  D_ENTER;

  if (! (val = calloc(1, sizeof(BroVal))))
    D_RETURN_(NULL);

  __bro_val_init(val);

  D_RETURN_(val);
}


BroVal *
__bro_val_new_of_type(int type, const char *type_name)
{
  BroVal *val;

  D_ENTER;

  switch (type)
    {
    case BRO_TYPE_BOOL:
    case BRO_TYPE_INT:
    case BRO_TYPE_COUNT:
    case BRO_TYPE_COUNTER:
    case BRO_TYPE_DOUBLE:
    case BRO_TYPE_TIME:
    case BRO_TYPE_INTERVAL:
    case BRO_TYPE_STRING:
    case BRO_TYPE_TIMER:
    case BRO_TYPE_PORT:
    case BRO_TYPE_IPADDR:
    case BRO_TYPE_NET:
    case BRO_TYPE_SUBNET:
    case BRO_TYPE_ENUM:
      if (! (val = __bro_val_new()))
	D_RETURN_(NULL);
      break;
      
    case BRO_TYPE_SET:
      /* A hack -- sets are table vals, but have set type,
       * at least while Bro still has SetType.
       */
    case BRO_TYPE_TABLE:
      if (! (val = (BroVal *) __bro_table_val_new()))
	D_RETURN_(NULL);
      break;

    case BRO_TYPE_RECORD:
      if (! (val = (BroVal *) __bro_record_val_new()))
	D_RETURN_(NULL);
      break;
      
    case BRO_TYPE_PATTERN:
    case BRO_TYPE_ANY:
    case BRO_TYPE_UNION:
    case BRO_TYPE_LIST:
    case BRO_TYPE_FUNC:
    case BRO_TYPE_FILE:
    case BRO_TYPE_VECTOR:
    case BRO_TYPE_ERROR:
    default:
      D(("Unsupported value type %i\n", type));
      D_RETURN_(NULL);
    }
  
  if (! (val->val_type = __bro_type_new_of_type(type, type_name)))
    {
      __bro_val_free(val);
      D_RETURN_(NULL);
    }
  
  D_RETURN_(val);
}


int
__bro_val_assign(BroVal *val, const void *data)
{
  D_ENTER;

  if (! val)
    {
      D(("Input error: (%p, %p)\n", val, data));
      D_RETURN_(FALSE);
    }
  
  if (! data)
    {
      if (val->val_type)
	{
	  __bro_sobject_release((BroSObject *) val->val_type);
	  val->val_type = NULL;
	}

      D(("Marked val %p as unassigned.\n", val));
      D_RETURN_(TRUE);
    }


  /* If we intend to assign data to the val, it must have a type. */
  if (! val->val_type)
    {
      D(("Cannot assign to val without a type.\n"));
      D_RETURN_(FALSE);
    }

  switch (val->val_type->tag)
    {
    case BRO_TYPE_BOOL:
      {
	int tmp = *((int *) data);
	val->val.char_val = (tmp != 0 ? 1 : 0);
      }
      break;

    case BRO_TYPE_INT:
    case BRO_TYPE_COUNT:
    case BRO_TYPE_COUNTER:
    case BRO_TYPE_ENUM:
      val->val_int = *((int *) data);
      break;

    case BRO_TYPE_DOUBLE:
    case BRO_TYPE_TIME:
    case BRO_TYPE_INTERVAL:
      val->val_double = *((double *) data);
      break;

    case BRO_TYPE_STRING:
      {
	BroString *str = (BroString *) data;
	bro_string_set_data(&val->val_str, str->str_val, str->str_len);
      }
      break;
      
    case BRO_TYPE_PORT:
      {
	BroPort *tmp = (BroPort *) data;
	
	if (tmp->port_proto != IPPROTO_TCP &&
	    tmp->port_proto != IPPROTO_UDP &&
	    tmp->port_proto != IPPROTO_ICMP)
	  {
	    __bro_sobject_release((BroSObject *) data);
	    D_RETURN_(FALSE);
	  }
	
	val->val_port = *tmp;
      }
      break;
      
    case BRO_TYPE_IPADDR:
    case BRO_TYPE_NET:
      val->val_int = *((uint32 *) data);
      break;
      
    case BRO_TYPE_SUBNET:
      val->val_subnet = *((BroSubnet *) data);
      break;
      
    case BRO_TYPE_RECORD:
      {
	BroList *l;
	BroVal *tmp_val;
	BroRecordVal *rv = (BroRecordVal *) val;
	BroRecord *rec = (BroRecord *) data;
	
	if (rv->rec)
	  __bro_record_free(rv->rec);
	
	rv->rec = __bro_record_copy(rec);

	/* Record vals also have a record type, copy that: */
	for (l = rec->val_list; l; l = __bro_list_next(l))
	  {
	    char *field;
	    
	    tmp_val = __bro_list_data(l);
	    
	    if (! tmp_val->val_type)
	      {
		D(("Cannot create record type component from val without type.\n"));
		D_RETURN_(FALSE);
	      }
	    
	    if (! (field = __bro_sobject_data_get((BroSObject *) tmp_val, "field")))
	      {
		D(("Val in record doesn't have field name associated with it.\n"));
		D_RETURN_(FALSE);
	      }
	    
	    __bro_record_type_add_type((BroRecordType *) val->val_type, field, tmp_val->val_type);;
	  }
      }
      break;
      
    case BRO_TYPE_TABLE:
      {
	BroTableVal *tv = (BroTableVal *) val;
	BroTable *table = (BroTable *) data;
	
	if (tv->table)
	  __bro_table_free(tv->table);
	
	tv->table = __bro_table_copy(table);

	/* XXX need to create the appropriate content in (BroTableType*) val->val_type! */
      }
      break;

    case BRO_TYPE_PATTERN:
    case BRO_TYPE_TIMER:
    case BRO_TYPE_ANY:
    case BRO_TYPE_UNION:
    case BRO_TYPE_LIST:
    case BRO_TYPE_FUNC:
    case BRO_TYPE_FILE:
    case BRO_TYPE_VECTOR:
    case BRO_TYPE_ERROR:
      D(("Type %i currently unsupported.\n", val->val_type->tag));
      D_RETURN_(FALSE);
      
    default:
      D(("Unknown type identifier %i\n", val->val_type->tag));
      D_RETURN_(FALSE);
    }

  D_RETURN_(TRUE);
}


static void
__bro_val_init(BroVal *val)
{
  BroSObject *sobj = (BroSObject *) val;

  D_ENTER;
  
  __bro_object_init((BroObject *) val);
  
  sobj->read  = (BroSObjectRead) __bro_val_read;
  sobj->write = (BroSObjectWrite) __bro_val_write;
  sobj->free  = (BroSObjectFree) __bro_val_free;
  sobj->clone = (BroSObjectClone) __bro_val_clone;
  sobj->hash  = (BroSObjectHash) __bro_val_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_val_cmp;

  /* Note: we don't know yet what type_id we'll be using since
   * that will depend on the type object hooked into this val.
   * We take care of that when we're serializing this val out
   * in that case.
   */
  sobj->type_id = SER_VAL;

  val->get_data = __bro_val_get;

  D_RETURN;
}


static void
__bro_val_free(BroVal *val)
{
  D_ENTER;

  /* If there is no type in the val, then it's unassigned and
   * hence there won't be anything to clean up anyway.
   */
  if (val->val_type)
    {
      switch (val->val_type->tag)
	{
	case BRO_TYPE_STRING:
	  bro_string_cleanup(&val->val_str);
	  break;
	  
	default:
	  /* Nothing to do */
	  break;
	}
    }
  
  __bro_sobject_release((BroSObject *) val->val_type);
  __bro_object_free((BroObject *) val);

  D_RETURN;
}


int
__bro_val_get_type_num(const BroVal *val)
{
  if (! val)
    return 0;

  return val->val_type->tag;
}


int
__bro_val_get_data(BroVal *val, int *type, void **data)
{
  if (! val || ! data)
    return FALSE;

  if (! val->get_data)
    return FALSE;

  if (type && val->val_type)
    *type = val->val_type->tag;
  
  *data = val->get_data(val);
  return TRUE;
}


static int
__bro_val_read(BroVal *val, BroConn *bc)
{
  char opt;
  uint32 tmp;

  D_ENTER;

  if (! val || !bc)
    D_RETURN_(FALSE);

  if (! __bro_object_read((BroObject *) val, bc))
    D_RETURN_(FALSE);

  /* Read type */

  if (val->val_type)
    {
      __bro_sobject_release((BroSObject *) val->val_type);
      val->val_type = NULL;
    }

  if (! (val->val_type = (BroType *) __bro_sobject_unserialize(SER_IS_TYPE, bc)))
    D_RETURN_(FALSE);

  D(("Type in val has type tags %i/%i\n",
     val->val_type->tag, val->val_type->internal_tag));
     
  /* Read optional Attributes */
  
  if (val->val_attrs)
    {
      __bro_sobject_release((BroSObject *) val->val_attrs);
      val->val_attrs = NULL;
    }

  if (! __bro_buf_read_char(bc->rx_buf, &opt))
    D_RETURN_(FALSE);
  if (opt)
    {
      if (! (val->val_attrs = (BroRecordVal *) __bro_sobject_unserialize(SER_RECORD_VAL, bc)))
	D_RETURN_(FALSE);
    }
  
  switch (val->val_type->internal_tag)
    {
    case BRO_INTTYPE_INT:
    case BRO_INTTYPE_UNSIGNED:
      /* Hack for ports */
      if (val->val_type->tag == BRO_TYPE_PORT)
	{
	  if (! __bro_buf_read_int(bc->rx_buf, &tmp))
	    D_RETURN_(FALSE);
	  
	  if ( (tmp & 0xf0000) == 0x10000 )
	    val->val_port.port_proto = IPPROTO_TCP;
	  else if ( (tmp & 0xf0000) == 0x20000 )
	    val->val_port.port_proto = IPPROTO_UDP;
	  else if ( (tmp & 0xf0000) == 0x30000 )
	    val->val_port.port_proto = IPPROTO_ICMP;
	    
	  val->val_port.port_num = (tmp & 0xFFFF);
	}
      else
	{
	  if (! __bro_buf_read_int(bc->rx_buf, &val->val_int))
	    D_RETURN_(FALSE);
	}
      break;
      
    case BRO_INTTYPE_DOUBLE:
      if (! __bro_buf_read_double(bc->rx_buf, &val->val_double))
	D_RETURN_(FALSE);
      break;
      
    case BRO_INTTYPE_STRING:
      if (! __bro_buf_read_string(bc->rx_buf, &val->val_str))
	D_RETURN_(FALSE);
      break;

    case BRO_INTTYPE_IPADDR:
      if (! __bro_buf_read_int(bc->rx_buf, &tmp))
	D_RETURN_(FALSE);
      
      if (tmp != 1)
	{
	  D(("We don't handle IPv6 addresses yet.\n"));
	  D_RETURN_(FALSE);
	}
      
      if (! __bro_buf_read_int(bc->rx_buf, &val->val_int))
	D_RETURN_(FALSE);

      val->val_int = ntohl(val->val_int);
      break;

    case BRO_INTTYPE_SUBNET:
      if (! __bro_buf_read_int(bc->rx_buf, &tmp))
	D_RETURN_(FALSE);
      
      if (tmp != 1)
	{
	  D(("We don't handle IPv6 addresses yet.\n"));
	  D_RETURN_(FALSE);
	}

      if (! __bro_buf_read_int(bc->rx_buf, &val->val_subnet.sn_net))
	D_RETURN_(FALSE);
      val->val_subnet.sn_net = ntohl(val->val_subnet.sn_net);

      if (! __bro_buf_read_int(bc->rx_buf, &val->val_subnet.sn_width))
	D_RETURN_(FALSE);
      break;

    case BRO_INTTYPE_OTHER:
      /* See Val.cc around 165 -- these are handled by derived classes.
       * We only make sure here it's not functions and not files.
       */
      if (val->val_type->tag != BRO_TYPE_FUNC &&
	  val->val_type->tag != BRO_TYPE_FILE)
	break;
      
      /* Otherwise fall through to warning. */

    default:
      D(("Unsupported internal type tag: %i\n", val->val_type->internal_tag));
      D_RETURN_(FALSE);
    }
  
  D_RETURN_(TRUE);
}


static int
__bro_val_write(BroVal *val, BroConn *bc)
{
  BroType *type;
  BroSObject *obj;

  D_ENTER;
  
  if (! val || !bc)
    D_RETURN_(FALSE);

  /* We need to make sure that the BroSObject at the root has the
   * correct type_id (a SER_xxx value). This depends on the type object
   * so map the type tag of that object to a SER_xxx value:
   */
  if (! val->val_type)
    {
      D(("Val %p doesn't have a type.\n", val));
      D_RETURN_(FALSE);
    }

  type = (BroType *) val->val_type;
  obj  = (BroSObject *) val;
  
  switch (type->tag)
    {
    case BRO_TYPE_BOOL:
    case BRO_TYPE_INT:
    case BRO_TYPE_COUNT:
    case BRO_TYPE_COUNTER:
    case BRO_TYPE_STRING:
    case BRO_TYPE_DOUBLE:
    case BRO_TYPE_TIME:
      obj->type_id = SER_VAL;
      break;

    case BRO_TYPE_ENUM:
      obj->type_id = SER_ENUM_VAL;
      break;

    case BRO_TYPE_PORT:
      obj->type_id = SER_PORT_VAL;
      break;
      
    case BRO_TYPE_INTERVAL:
      obj->type_id = SER_INTERVAL_VAL;
      break;
      
    case BRO_TYPE_IPADDR:
      obj->type_id = SER_ADDR_VAL;
      break;
      
    case BRO_TYPE_NET:
      obj->type_id = SER_NET_VAL;
      break;
      
    case BRO_TYPE_SUBNET:
      obj->type_id = SER_SUBNET_VAL;
      break;

    case BRO_TYPE_RECORD:
      obj->type_id = SER_RECORD_VAL;
      break;
      
    default:
      D(("Val %p's type unhandled: type tag is %i.\n", val, type->tag));
      D_RETURN_(FALSE);
    }

  if (! __bro_object_write((BroObject *) val, bc))
    D_RETURN_(FALSE);

  if (! __bro_sobject_serialize((BroSObject *) val->val_type, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_char(bc->tx_buf, val->val_attrs ? 1 : 0))
    D_RETURN_(FALSE);
  
  if (val->val_attrs && ! __bro_sobject_serialize((BroSObject *) val->val_attrs, bc))
    D_RETURN_(FALSE);
  
  switch (val->val_type->internal_tag)
    {
    case BRO_INTTYPE_INT:
    case BRO_INTTYPE_UNSIGNED:
      /* Hack for ports */
      if (val->val_type->tag == BRO_TYPE_PORT)
	{
	  int tmp = val->val_port.port_num;
	  
	  if (val->val_port.port_proto == IPPROTO_TCP)
	    tmp |= 0x10000;
	  else if (val->val_port.port_proto == IPPROTO_UDP)
	    tmp |= 0x20000;
      else if (val->val_port.port_proto == IPPROTO_ICMP)
	    tmp |= 0x30000;

	  if (! __bro_buf_write_int(bc->tx_buf, tmp))
	    D_RETURN_(FALSE);
	}
      else
	{
	  if (! __bro_buf_write_int(bc->tx_buf, val->val_int))
	    D_RETURN_(FALSE);
	}
      break;
      
    case BRO_INTTYPE_DOUBLE:
      if (! __bro_buf_write_double(bc->tx_buf, val->val_double))
	D_RETURN_(FALSE);
      break;
      
    case BRO_INTTYPE_STRING:
      if (! __bro_buf_write_string(bc->tx_buf, &val->val_str))
	D_RETURN_(FALSE);
      break;

    case BRO_INTTYPE_IPADDR:
      if (! __bro_buf_write_int(bc->tx_buf, 1))
	D_RETURN_(FALSE);
      if (! __bro_buf_write_int(bc->tx_buf, htonl(val->val_int)))
	D_RETURN_(FALSE);
      break;

    case BRO_INTTYPE_SUBNET:
      if (! __bro_buf_write_int(bc->tx_buf, 1))
	D_RETURN_(FALSE);
      if (! __bro_buf_write_int(bc->tx_buf, htonl(val->val_subnet.sn_net)))
	D_RETURN_(FALSE);
      if (! __bro_buf_write_int(bc->tx_buf, val->val_subnet.sn_width))
	D_RETURN_(FALSE);
      break;

    case BRO_INTTYPE_OTHER:
      /* That's fine, will be handled in derived classes
       * like __bro_record_val_write().
       */
      break;
      
    default:
      D(("Unknown internal type tag: %i\n", val->val_type->internal_tag));
      D_RETURN_(FALSE);
    }  
  
  D_RETURN_(TRUE);
}

static int
__bro_val_clone(BroVal *dst, BroVal *src)
{
  D_ENTER;
  
  if (! __bro_object_clone((BroObject *) dst, (BroObject *) src))
    {
      D(("Cloning parent failed.\n"));
      D_RETURN_(FALSE);
    }

  if (src->val_type &&
      ! (dst->val_type = (BroType *) __bro_sobject_copy((BroSObject *) src->val_type)))
    {
      D(("Cloning type failed.\n"));
      D_RETURN_(FALSE);      
    }
  
  if (src->val_attrs &&
      ! (dst->val_attrs = (BroRecordVal *) __bro_sobject_copy((BroSObject *) src->val_attrs)))
    {
      D(("Cloning attributes failed.\n"));
      D_RETURN_(FALSE);
    }

  switch (dst->val_type->internal_tag)
    {
    case BRO_INTTYPE_INT:
    case BRO_INTTYPE_UNSIGNED:
    case BRO_INTTYPE_IPADDR:
      /* Hack for ports */
      if (src->val_type->tag == BRO_TYPE_PORT)
	dst->val_port = src->val_port;
      else
	dst->val_int = src->val_int;
      break;
      
    case BRO_INTTYPE_DOUBLE:
      dst->val_double = src->val_double;
      break;
      
    case BRO_INTTYPE_STRING:
      bro_string_assign(&src->val_str, &dst->val_str);
      break;

    case BRO_INTTYPE_SUBNET:
      dst->val_subnet = src->val_subnet;
      break;

    case BRO_INTTYPE_OTHER:
      /* That's okay, handled in subtype */
      break;
      
    default:
      D(("Unknown internal type tag: %i\n", dst->val_type->internal_tag));
      D_RETURN_(FALSE);
    }  
  
  D_RETURN_(TRUE);
}

static uint32
__bro_val_hash(BroVal *val)
{
  uint32 result;

  D_ENTER;

  if (! val)
    D_RETURN_(0);

  result = __bro_sobject_hash((BroSObject*) val->val_type);
  
  switch (val->val_type->internal_tag)
    {
    case BRO_INTTYPE_INT:
    case BRO_INTTYPE_UNSIGNED:
    case BRO_INTTYPE_IPADDR:
      result ^= val->val_int;
      break;
      
    case BRO_INTTYPE_DOUBLE:
      result ^= (uint32) val->val_double;
      break;
      
    case BRO_INTTYPE_STRING:
      result ^= __bro_ht_str_hash(val->val_str.str_val);
      break;
      
    case BRO_INTTYPE_SUBNET:
      result ^= val->val_subnet.sn_net;
      result ^= val->val_subnet.sn_width;
      break;

    case BRO_INTTYPE_OTHER:
      D(("WARNING -- __bro_val_hash() invoked on derived type.\n"));
      break;
      
    default:
      D(("Unknown internal type tag: %i\n", val->val_type->internal_tag));
      break;
    }  

  D_RETURN_(result);
}

static int
__bro_val_cmp(BroVal *val1, BroVal *val2)
{
  D_ENTER;
  
  if (! val1 || ! val2)
    D_RETURN_(FALSE);

  if (! __bro_sobject_cmp((BroSObject*) val1->val_type,
			  (BroSObject*) val2->val_type))
    D_RETURN_(FALSE);
  
  switch (val1->val_type->internal_tag)
    {
    case BRO_INTTYPE_INT:
    case BRO_INTTYPE_UNSIGNED:
    case BRO_INTTYPE_IPADDR:
      if (val1->val_int != val2->val_int)
	D_RETURN_(FALSE);
      break;
      
    case BRO_INTTYPE_DOUBLE:
      if (val1->val_double != val2->val_double)
	D_RETURN_(FALSE);
      break;
      
    case BRO_INTTYPE_STRING:
      if (! __bro_ht_str_cmp(val1->val_str.str_val, val2->val_str.str_val))
	D_RETURN_(FALSE);
      break;
      
    case BRO_INTTYPE_SUBNET:
      if (val1->val_subnet.sn_net != val2->val_subnet.sn_net ||
	  val1->val_subnet.sn_width != val2->val_subnet.sn_width)
	D_RETURN_(FALSE);
      break;

    case BRO_INTTYPE_OTHER:
      D(("WARNING -- __bro_val_cmp() invoked on derived type.\n"));
      break;
      
    default:
      D(("Unknown internal type tag: %i\n", val1->val_type->internal_tag));
      break;
    }  
  
  D_RETURN_(TRUE);
}

static void *
__bro_val_get(BroVal *val)
{
  /* Following the comments in broccoli.h, we return atomic values
   * as copies into *result, and complex types (i.e., structs) have
   * all members assigned to point to internal values so the user
   * does not have to clean up the returned value. The user can 
   * still keep those values around if necessary by copying them.
   */
  if (! val->val_type)
    {
      D(("No type in val %p\n", val));
      return NULL;
    }
  
   switch (val->val_type->tag)    
    {
    case BRO_TYPE_BOOL:
    case BRO_TYPE_INT:
    case BRO_TYPE_ENUM:
    case BRO_TYPE_COUNT:
    case BRO_TYPE_COUNTER:
    case BRO_TYPE_IPADDR:
    case BRO_TYPE_NET:
      return &val->val_int;
      
    case BRO_TYPE_PORT:
      return &val->val_port;
      
    case BRO_TYPE_DOUBLE:
    case BRO_TYPE_TIME:
    case BRO_TYPE_INTERVAL:
      return &val->val_double;
      
    case BRO_TYPE_STRING:
      return &val->val_str;
      
    case BRO_TYPE_SUBNET:
      return &val->val_subnet;
      
    case BRO_TYPE_RECORD:
      D(("WARNING: Inheritance broken -- record types should not be handled here.\n"));
      return NULL;

    case BRO_TYPE_TABLE:
      D(("WARNING: Inheritance broken -- table types should not be handled here.\n"));
      return NULL;
      
    default:
      D(("Type %i currently not extractable.\n", val->val_type->tag));
    }
   
   return NULL;
}


BroListVal *
__bro_list_val_new(void)
{
  BroListVal *val;

  D_ENTER;

  if (! (val = calloc(1, sizeof(BroListVal))))
    D_RETURN_(NULL);

  __bro_list_val_init(val);
  
  D_RETURN_(val);
}

static void
__bro_list_val_init(BroListVal *lv)
{
  BroSObject *sobj = (BroSObject *) lv;
  BroVal *val = (BroVal *) lv;
  
  D_ENTER;
  
  __bro_val_init((BroVal *) lv);
  
  sobj->read  = (BroSObjectRead) __bro_list_val_read;
  sobj->write = (BroSObjectWrite) __bro_list_val_write;
  sobj->free  = (BroSObjectFree) __bro_list_val_free;
  sobj->clone = (BroSObjectClone) __bro_list_val_clone;
  sobj->hash  = (BroSObjectHash) __bro_list_val_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_list_val_cmp;
  
  sobj->type_id = SER_LIST_VAL;

  val->get_data = (BroValAccessor) __bro_list_val_get;

  D_RETURN;
}

static void
__bro_list_val_free(BroListVal *lv)
{
  D_ENTER;
  
  if (! lv)
    D_RETURN;
  
  __bro_list_free(lv->list, (BroFunc) __bro_sobject_release);
  __bro_val_free((BroVal *) lv);
  
  D_RETURN;
}

static int
__bro_list_val_read(BroListVal *lv, BroConn *bc)
{
  int i;
  uint32 ui;

  D_ENTER;
  
  if (! __bro_val_read((BroVal *) lv, bc))
    D_RETURN_(FALSE);
  
  __bro_list_free(lv->list, (BroFunc) __bro_sobject_release);
  lv->list = NULL;
  
  if (! __bro_buf_read_char(bc->rx_buf, &lv->type_tag))
    goto error_return;
  if (! __bro_buf_read_int(bc->rx_buf, &ui))
    goto error_return;
  
  lv->len = (int) ui;

  for (i = 0; i < lv->len; i++)
    {
      BroVal *val;
      
      if (! (val = (BroVal *) __bro_sobject_unserialize(SER_IS_VAL, bc)))
	goto error_return;
      
      lv->list = __bro_list_append(lv->list, val);
    }
  
  D_RETURN_(TRUE);
  
 error_return:
  __bro_list_free(lv->list, (BroFunc) __bro_sobject_release);
  lv->list = NULL;
  D_RETURN_(FALSE);
}

static int
__bro_list_val_write(BroListVal *lv, BroConn *bc)
{
  BroList *l;
  
  D_ENTER;
  
  if (! __bro_val_write((BroVal *) lv, bc))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_write_char(bc->tx_buf, lv->type_tag))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_write_int(bc->tx_buf, lv->len))
    D_RETURN_(FALSE);
  
  for (l = lv->list; l; l = __bro_list_next(l))
    {
      BroVal *val = __bro_list_data(l);
      
      if (! __bro_sobject_serialize((BroSObject *) val, bc))
	D_RETURN_(FALSE);
    }
  
  D_RETURN_(TRUE);
}

static int
__bro_list_val_clone(BroListVal *dst, BroListVal *src)
{
  BroList *l;

  D_ENTER;

  if (! __bro_val_clone((BroVal *) dst, (BroVal *) src))
    D_RETURN_(FALSE);

  dst->type_tag = src->type_tag;
  dst->len = src->len;
  
  if (dst->list)
    {
      __bro_list_free(dst->list, (BroFunc) __bro_sobject_release);
      dst->list = NULL;
    }

  for (l = src->list; l; l = __bro_list_next(l))
    dst->list = __bro_list_append(dst->list, __bro_sobject_copy(__bro_list_data(l)));
  
  D_RETURN_(TRUE);
}

static uint32
__bro_list_val_hash(BroListVal *lv)
{
  uint32 result;
  BroList *l;

  D_ENTER;
  
  if (! lv)
    D_RETURN_(0);
  
  result = lv->len ^ lv->type_tag;
  
  for (l = lv->list; l; l = __bro_list_next(l))
    result ^= __bro_sobject_hash((BroSObject *) __bro_list_data(l));
  
  D_RETURN_(result);
}

static int
__bro_list_val_cmp(BroListVal *lv1, BroListVal *lv2)
{
  BroList *l1, *l2;

  D_ENTER;
  
  if (! lv1 || ! lv2)
    D_RETURN_(FALSE);

  if (lv1->len != lv2->len ||
      lv1->type_tag != lv2->type_tag)    
    D_RETURN_(FALSE);
      
  for (l1 = lv1->list, l2 = lv2->list; l1 && l2;
       l1 = __bro_list_next(l1), l2 = __bro_list_next(l2))
    {
      if (! __bro_sobject_cmp((BroSObject*) __bro_list_data(l1),
			      (BroSObject*) __bro_list_data(l2)))
	D_RETURN_(FALSE);
    }

  if (l1 || l2)
    {
      D(("WARNING -- list length inconsistency.\n"));
      D_RETURN_(FALSE);
    }
  
  D_RETURN_(TRUE);
}

static BroList *
__bro_list_val_get(BroListVal *lv)
{
  D_ENTER;
  D_RETURN_(lv->list);
}

void
__bro_list_val_append(BroListVal *lv, BroVal *val)
{
  D_ENTER;

  if (! lv || ! val)
    D_RETURN;

  lv->list = __bro_list_append(lv->list, val);
  lv->len++;

  D_RETURN;
}

BroVal *
__bro_list_val_pop_front(BroListVal *lv)
{
  BroVal *result;
  BroList *l;

  D_ENTER;

  if (! lv)
    D_RETURN_(NULL);
  
  l = lv->list;
  lv->list = __bro_list_remove(lv->list, lv->list);
  
  result = (BroVal*) __bro_list_data(l);
  __bro_list_free(l, NULL);
  
  D_RETURN_(result);
}

BroVal *
__bro_list_val_get_front(BroListVal *lv)
{
  BroVal *result;
  BroList *l;

  D_ENTER;

  if (! lv)
    D_RETURN_(NULL);
  
  D_RETURN_((BroVal*) __bro_list_data(lv->list));
}

int
__bro_list_val_get_length(BroListVal *lv)
{
  D_ENTER;
  
  if (! lv)
    D_RETURN_(0);
  
  D_RETURN_(lv->len);
}



BroMutableVal *
__bro_mutable_val_new(void)
{
  BroMutableVal *val;

  D_ENTER;

  if (! (val = calloc(1, sizeof(BroMutableVal))))
    D_RETURN_(NULL);

  __bro_mutable_val_init(val);

  D_RETURN_(val);
}


static void
__bro_mutable_val_init(BroMutableVal *mv)
{
  BroSObject *sobj = (BroSObject *) mv;
  
  D_ENTER;
  
  __bro_val_init((BroVal *) mv);
  
  sobj->read  = (BroSObjectRead) __bro_mutable_val_read;
  sobj->write = (BroSObjectWrite) __bro_mutable_val_write;
  sobj->free  = (BroSObjectFree) __bro_mutable_val_free;
  sobj->clone = (BroSObjectClone) __bro_mutable_val_clone;
  sobj->hash  = (BroSObjectHash) __bro_mutable_val_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_mutable_val_cmp;
  
  sobj->type_id = SER_MUTABLE_VAL;

  /* BroMutableVal inherits __bro_val_get and doesn't override it. */

  D_RETURN;
}


static void
__bro_mutable_val_free(BroMutableVal *mv)
{
  D_ENTER;
  
  __bro_sobject_release((BroSObject *) mv->id);
  __bro_val_free((BroVal *) mv);
  
  D_RETURN;
}


static int
__bro_mutable_val_read(BroMutableVal *mv, BroConn *bc)
{
  BroString tmp;

  D_ENTER;

  bro_string_init(&tmp);

  if (! __bro_val_read((BroVal *) mv, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_read_char(bc->rx_buf, &mv->props))
    D_RETURN_(FALSE);

  if (! __bro_buf_read_string(bc->rx_buf, &tmp))
    D_RETURN_(FALSE);

  /* FIXME: now need to obtain real BroID from that name */
  bro_string_cleanup(&tmp);

  D_RETURN_(TRUE);
}


static int
__bro_mutable_val_write(BroMutableVal *mv, BroConn *bc)
{
  D_ENTER;
  
  if (! __bro_val_write((BroVal *) mv, bc))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_write_char(bc->tx_buf, mv->props))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_write_string(bc->tx_buf, (mv->id ? &mv->id->name : NULL)))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


static int
__bro_mutable_val_clone(BroMutableVal *dst, BroMutableVal *src)
{
  D_ENTER;
  
  if (! __bro_val_clone((BroVal *) dst, (BroVal *) src))
    D_RETURN_(FALSE);
  
  if (src->id && ! (dst->id = (BroID *) __bro_sobject_copy((BroSObject *) src->id)))
    D_RETURN_(FALSE);
  
  src->props = dst->props;
  
  D_RETURN_(TRUE);
}


static uint32
__bro_mutable_val_hash(BroMutableVal *mv)
{
  uint32 result;

  D_ENTER;

  if (! mv)
    D_RETURN_(0);

  result = __bro_id_hash(mv->id) ^ mv->props;

  D_RETURN_(result);
}


static int
__bro_mutable_val_cmp(BroMutableVal *mv1, BroMutableVal *mv2)
{
  D_ENTER;

  if (! mv1 || ! mv2)
    D_RETURN_(FALSE);

  if (! __bro_id_cmp(mv1->id, mv2->id))
    D_RETURN_(FALSE);

  if (mv1->props != mv2->props)
    D_RETURN_(FALSE);

  D_RETURN_(TRUE);
}


BroRecordVal *
__bro_record_val_new(void)
{
  BroRecordVal *val;

  D_ENTER;

  if (! (val = calloc(1, sizeof(BroRecordVal))))
    D_RETURN_(NULL);

  __bro_record_val_init(val);

  D_RETURN_(val);
}


static void
__bro_record_val_init(BroRecordVal *rv)
{
  BroSObject *sobj = (BroSObject *) rv;
  BroVal *val = (BroVal *) rv;

  D_ENTER;
  
  __bro_mutable_val_init((BroMutableVal *) rv);
  
  sobj->read  = (BroSObjectRead) __bro_record_val_read;
  sobj->write = (BroSObjectWrite) __bro_record_val_write;
  sobj->free  = (BroSObjectFree) __bro_record_val_free;
  sobj->clone = (BroSObjectClone) __bro_record_val_clone;
  sobj->hash  = (BroSObjectHash) __bro_record_val_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_record_val_cmp;

  sobj->type_id = SER_RECORD_VAL;

  val->get_data = (BroValAccessor) __bro_record_val_get;
  
  D_RETURN;
}


static void
__bro_record_val_free(BroRecordVal *rv)
{
  D_ENTER;

  if (! rv)
    D_RETURN;
  
  __bro_record_free(rv->rec);
  __bro_mutable_val_free((BroMutableVal *) rv);

  D_RETURN;
}


static int
__bro_record_val_read(BroRecordVal *rv, BroConn *bc)
{
  char opt;
  uint32 i, len;
  BroVal *val;
  
  D_ENTER;
  
  if (! __bro_mutable_val_read((BroMutableVal *) rv, bc))
    D_RETURN_(FALSE);

  /* Clean out old vals, if any */
  __bro_record_free(rv->rec);
  
  if (! (rv->rec = __bro_record_new()))
    D_RETURN_(FALSE);
  
  /* Read in new vals */

  if (! __bro_buf_read_int(bc->rx_buf, &len))
    goto error_return;
  
  for (i = 0; i < len; i++)
    {
      const char *field_name;
      BroVal *rv_val   = (BroVal *) rv;
      BroType *rv_type = rv_val->val_type;

      D(("Reading val %i/%i into record %p of val %p\n",
	 i+1, len, rv->rec, rv));

      if (! __bro_buf_read_char(bc->rx_buf, &opt))
	goto error_return;
      
      if (opt)
	{
	  if (! (val = (BroVal *) __bro_sobject_unserialize(SER_IS_VAL, bc)))
	    {
	      D(("WARNING -- unserializing record element failed.\n"));
	      goto error_return;
	    }
	}
      else
	{
	  /* We need an empty val if none was given in order to maintain
	   * a chain of vals nonetheless -- the missing type in this new
	   * val indicates that it is an unassigned val.
	   */
	  D(("WARNING -- unassigned val.\n"));
	  if (! (val = __bro_val_new()))
	    goto error_return;
	}
      
      __bro_record_add_val(rv->rec, val);
      
      if (! (field_name = __bro_record_type_get_nth_field((BroRecordType *) rv_type, i)))
	{
	  D(("WARNING -- record type field %i has no name.\n", i));
	  goto error_return;
	}

      __bro_record_set_nth_name(rv->rec, i, field_name);
    }
  
  D_RETURN_(TRUE);

 error_return:
  __bro_record_free(rv->rec);
  rv->rec = NULL;
  D_RETURN_(FALSE);
}


static int
__bro_record_val_write(BroRecordVal *rv, BroConn *bc)
{
  BroList *l;
  BroVal *val;
  int i;

  D_ENTER;

  if (! __bro_mutable_val_write((BroMutableVal *) rv, bc))
    D_RETURN_(FALSE);
  
  if (! __bro_buf_write_int(bc->tx_buf, rv->rec->val_len))
    D_RETURN_(FALSE);
  
  if (! rv->rec && rv->rec->val_len > 0)
    D_RETURN_(FALSE);
  
  D(("Writing out %i vals in record %p.\n", rv->rec->val_len, rv->rec));

  for (i = 0, l = rv->rec->val_list; l; i++, l = __bro_list_next(l))
    {
      val = __bro_list_data(l);
      
      D(("Val %i/%p's type: %p\n", i, val, val->val_type));
      
      if (! __bro_buf_write_char(bc->tx_buf, (val->val_type ? 1 :0)))
	D_RETURN_(FALSE);
      
      if (val->val_type)
	{	  
	  if (! __bro_sobject_serialize((BroSObject *) val, bc))
	    D_RETURN_(FALSE);
	}
    }
  
  D_RETURN_(TRUE);
}


static int
__bro_record_val_clone(BroRecordVal *dst, BroRecordVal *src)
{
  D_ENTER;
  
  if (! __bro_mutable_val_clone((BroMutableVal *) dst, (BroMutableVal *) src))
    D_RETURN_(FALSE);
  
  if (src->rec && ! (dst->rec = __bro_record_copy(src->rec)))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}


static uint32
__bro_record_val_hash(BroRecordVal *rv)
{
  uint32 result;
  
  D_ENTER;
  
  if (! rv)
    D_RETURN_(0);

  result = __bro_record_hash(rv->rec);

  D_RETURN_(result);

}


static int
__bro_record_val_cmp(BroRecordVal *rv1, BroRecordVal *rv2)
{
  D_ENTER;

  if (! rv1 || ! rv2)
    D_RETURN_(FALSE);
  
  if (! __bro_record_cmp(rv1->rec, rv2->rec))
    D_RETURN_(FALSE);

  D_RETURN_(TRUE);

}


static void *
__bro_record_val_get(BroRecordVal *rv)
{
  return rv->rec;
}


BroTableVal *
__bro_table_val_new(void)
{
  BroTableVal *val;

  D_ENTER;
  
  if (! (val = calloc(1, sizeof(BroTableVal))))
    D_RETURN_(NULL);

  __bro_table_val_init(val);
  
  D_RETURN_(val);
}

static void
__bro_table_val_init(BroTableVal *tbl)
{
  BroSObject *sobj = (BroSObject *) tbl;
  BroVal *val = (BroVal *) tbl;

  D_ENTER;
  
  __bro_mutable_val_init((BroMutableVal *) tbl);
  
  sobj->read  = (BroSObjectRead) __bro_table_val_read;
  sobj->write = (BroSObjectWrite) __bro_table_val_write;
  sobj->free  = (BroSObjectFree) __bro_table_val_free;
  sobj->clone = (BroSObjectClone) __bro_table_val_clone;
  sobj->hash  = (BroSObjectHash) __bro_table_val_hash;
  sobj->cmp   = (BroSObjectCmp) __bro_table_val_cmp;
  
  sobj->type_id = SER_TABLE_VAL;
  
  val->get_data = (BroValAccessor) __bro_table_val_get;  

  D_RETURN;
}

static void
__bro_table_val_free(BroTableVal *tbl)
{
  D_ENTER;
  
  if (! tbl)
    D_RETURN;
  
  __bro_table_free(tbl->table);
  __bro_mutable_val_free((BroMutableVal *) tbl);
  
  D_RETURN;
}

static int
__bro_table_val_read(BroTableVal *tbl, BroConn *bc)
{
  double d;
  char opt;
  int num_keys = 0, num_vals = 0;

  D_ENTER;
  
  if (! __bro_mutable_val_read((BroMutableVal *) tbl, bc))
    D_RETURN_(FALSE);
  
  /* Clean out old vals, if any */
  __bro_table_free(tbl->table);
  
  if (! (tbl->table = __bro_table_new()))
    D_RETURN_(FALSE);
  
  /* expire_time, currently unused */
  if (! __bro_buf_read_double(bc->rx_buf, &d))
    goto error_return;

  if (! __bro_buf_read_char(bc->rx_buf, &opt))
    goto error_return;
  if (opt)
    {
      if (! (tbl->attrs = (BroAttrs *) __bro_sobject_unserialize(SER_ATTRIBUTES, bc)))
	{
	  D(("WARNING -- unserializing table attributes failed.\n"));
	  goto error_return;
	}
    }
  
  if (! __bro_buf_read_char(bc->rx_buf, &opt))
    goto error_return;
  if (opt)
    {
      D(("WARNING -- cannot unserialize expression, try to use table without expiration expression.\n"));
      goto error_return;
    }

  /* Table entries are next: */
  for ( ; ; )
    {
      BroType *type;
      BroListVal *keys = NULL;
      BroVal *val = NULL;
      BroIndexType *itype = NULL;
      int i, len, key_type = 0, val_type = 0;
      double d;

      if (! __bro_buf_read_char(bc->rx_buf, &opt))
	goto error_return;

      /* End of set members is announced if opt is 0: */
      if (! opt)
	break;

      if (! (keys = (BroListVal *) __bro_sobject_unserialize(SER_LIST_VAL, bc)))
	goto error_return;

      /* If this isn't a set, we have a value associated with the keys too. */
      type = ((BroVal *) tbl)->val_type;
      itype = (BroIndexType*) type;
      num_vals++;

      if (itype->yield_type)
	{
	  if (! (val = (BroVal *) __bro_sobject_unserialize(SER_IS_VAL, bc)))
	    goto error_return;

	  val_type = val->val_type->tag;
	  num_keys++;
	}

      /* If the key is a composite, we report BRO_TYPE_LIST to the user,
       * so the user can access the individual values via a record. If
       * the key is atomic, we extract its type and use it directly.
       */

      if (keys->len > 1)
	key_type = BRO_TYPE_LIST;
      else if (keys->len == 1)
	key_type = __bro_list_val_get_front(keys)->val_type->tag;
      else
	goto error_return;
      
      if (tbl->table->tbl_key_type != BRO_TYPE_UNKNOWN &&
	  tbl->table->tbl_key_type != key_type)
	{
	  D(("Type mismatch when unserializing key of type %d, expecting %d\n",
	     key_type, tbl->table->tbl_key_type));
	  goto error_return;
	}

      tbl->table->tbl_key_type = key_type;
      
      if (tbl->table->tbl_val_type != BRO_TYPE_UNKNOWN &&
	  tbl->table->tbl_val_type != val_type)
	{
	  D(("Type mismatch when unserializing val of type %d, expecting %d\n",
	     val_type, tbl->table->tbl_val_type));
	  goto error_return;
	}

      tbl->table->tbl_val_type = val_type;	
      
      /* Eat two doubles -- one for the last access time and
       * one for when the item is supposed to expire.
       * XXX: currently unimplemented.
       */
      if (! __bro_buf_read_double(bc->rx_buf, &d) ||
	  ! __bro_buf_read_double(bc->rx_buf, &d))
	goto error_return;

      /* The key type of a BroTable is always a BroListVal, even
       * though it might well have only a single element.
       *
       * Since we just unserialized it, we pass on ownership of
       * both key and value to the table.
       */
      __bro_table_insert(tbl->table, (BroVal*) keys, val);
    }

  D_RETURN_(TRUE);

 error_return:
  __bro_table_free(tbl->table);
  tbl->table = NULL;
  D_RETURN_(FALSE);
}

static int
__bro_table_val_write_cb_direct(BroVal *key, BroVal *val, BroConn *bc)
{
  if (! __bro_sobject_serialize((BroSObject *) key, bc))
    return FALSE;
  
  if (val && ! __bro_sobject_serialize((BroSObject *) val, bc))
    return FALSE;
  
  return TRUE;
}

static int
__bro_table_val_write_cb_unpack(BroVal *key, BroRecordVal *val, BroConn *bc)
{
  BroRecord *rec = val->rec;
  BroListVal *lv = __bro_list_val_new();
  
  /* Just hook the list into the list val, we unhook below. */
  lv->list = rec->val_list;
  lv->len = rec->val_len;
  
  if (! __bro_sobject_serialize((BroSObject *) lv, bc))
    goto error_return;
  
  if (val && ! __bro_sobject_serialize((BroSObject *) val, bc))
    goto error_return;
  
  lv->list = NULL;
  __bro_list_val_free(lv);
  
  return TRUE;

 error_return:
  lv->list = NULL;
  __bro_list_val_free(lv);
  return FALSE;
}

static int
__bro_table_val_write(BroTableVal *tbl, BroConn *bc)
{
  double d = 0;
  char opt = 0;

  D_ENTER;

  if (! __bro_mutable_val_write((BroMutableVal *) tbl, bc))
    D_RETURN_(FALSE);

  if (! __bro_buf_write_double(bc->tx_buf, d))
    D_RETURN_(FALSE);

  /* XXX For now we neever send any attributes, nor an expire expr */
  if (! __bro_buf_write_char(bc->tx_buf, opt))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_char(bc->tx_buf, opt))
    D_RETURN_(FALSE);

  /* How we iterate depends on whether the index type is atomic or not.
   * If atomic, we use __bro_table_val_write_cb_direct(), otherwise
   * we use ..._unpack(), which converts the elements of the RecordVal
   * into a ListVal before sending.
   */
  if (__bro_table_val_has_atomic_key(tbl))
    __bro_table_foreach(tbl->table, (BroTableCallback) __bro_table_val_write_cb_direct, bc);
  else
    __bro_table_foreach(tbl->table, (BroTableCallback) __bro_table_val_write_cb_unpack, bc);

  D_RETURN_(TRUE);
}

static int
__bro_table_val_clone(BroTableVal *dst, BroTableVal *src)
{
  D_ENTER;

  if (! __bro_mutable_val_clone((BroMutableVal *) dst, (BroMutableVal *) src))
    D_RETURN_(FALSE);

  if (src->table && ! (dst->table = __bro_table_copy(src->table)))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}

static uint32
__bro_table_val_hash(BroTableVal *tv)
{
  uint32 result;

  D_ENTER;
  
  if (! tv)
    D_RETURN_(0);
  
  result = __bro_sobject_hash((BroSObject*) tv->table_type);
  result ^= __bro_sobject_hash((BroSObject*) tv->attrs);
  result ^= __bro_table_hash(tv->table);
  
  D_RETURN_(result);

}

static int
__bro_table_val_cmp(BroTableVal *tv1, BroTableVal *tv2)
{
  D_ENTER;

  if (! tv1 || ! tv2)
    D_RETURN_(FALSE);

  if (! __bro_sobject_cmp((BroSObject*) tv1->table_type,
			  (BroSObject*) tv2->table_type))
    D_RETURN_(FALSE);
  
  if (! __bro_table_cmp(tv1->table, tv2->table))
    D_RETURN_(FALSE);
  
  D_RETURN_(TRUE);
}

static void *
__bro_table_val_get(BroTableVal *tbl)
{
  return tbl->table;
}

int
__bro_table_val_has_atomic_key(BroTableVal *tbl)
{
  if (! tbl || ! tbl->table_type) 
    return FALSE;

  return ((BroIndexType *) tbl->table_type)->indices->num_types == 1;
}
