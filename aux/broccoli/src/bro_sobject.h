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
#ifndef broccoli_serial_object_h
#define broccoli_serial_object_h

#include <broccoli.h>
#include <bro_types.h>

/* A whole bunch of definitons taken straight out of Bro and run through cpp :)
 * These are type tags -- see explanation in SerialTypes.h in the Bro tree. We use
 * these tags to map to the default constructor implementation for an
 * object upon unserialization.
 */
#define SER_TYPE_MASK                 0xff00
#define SER_NONE                      0


/* "Abstract" parent classes, not used directly */
#define SER_IS_OBJ                    0x8000
#define SER_IS_CONNECTION            (0x0100 | SER_IS_OBJ)
#define SER_IS_TIMER                  0x0200
#define SER_IS_TCP_ENDPOINT           0x0300
#define SER_IS_TCP_ANALYZER          (0x0400 | SER_IS_OBJ)
#define SER_IS_TCP_ENDPOINT_ANALYZER (0x0500 | SER_IS_OBJ)
#define SER_IS_TCP_CONTENTS           0x0600
#define SER_IS_REASSEMBLER            0x0700
#define SER_IS_VAL                   (0x0800 | SER_IS_OBJ)
#define SER_IS_EXPR                  (0x0900 | SER_IS_OBJ)
#define SER_IS_TYPE                  (0x0a00 | SER_IS_OBJ)
#define SER_IS_STMT                  (0x0b00 | SER_IS_OBJ)
#define SER_IS_ATTRIBUTES            (0x0c00 | SER_IS_OBJ)
#define SER_IS_EVENT_HANDLER          0x0d00
#define SER_IS_FILE                  (0x0e00 | SER_IS_OBJ)
#define SER_IS_FUNC                  (0x0f00 | SER_IS_OBJ)
#define SER_IS_ID                    (0x1000 | SER_IS_OBJ)
#define SER_IS_STATE_ACCESS           0x1100
#define SER_IS_CASE                  (0x1200 | SER_IS_OBJ)
#define SER_IS_LOCATION               0x1300
#define SER_IS_RE_MATCHER             0x1400

/* Usable derivations */
#define SER_OBJ                      (1  | SER_IS_OBJ)
#define SER_VAL                      (1  | SER_IS_VAL)
#define SER_INTERVAL_VAL             (2  | SER_IS_VAL)
#define SER_PORT_VAL                 (3  | SER_IS_VAL)
#define SER_ADDR_VAL                 (4  | SER_IS_VAL)
#define SER_NET_VAL                  (5  | SER_IS_VAL)
#define SER_SUBNET_VAL               (6  | SER_IS_VAL)
#define SER_STRING_VAL               (7  | SER_IS_VAL)
#define SER_PATTERN_VAL              (8  | SER_IS_VAL)
#define SER_LIST_VAL                 (9  | SER_IS_VAL)
#define SER_TABLE_VAL                (10 | SER_IS_VAL)
#define SER_RECORD_VAL               (11 | SER_IS_VAL)
#define SER_ENUM_VAL                 (12 | SER_IS_VAL)
#define SER_VECTOR_VAL               (13 | SER_IS_VAL)
#define SER_MUTABLE_VAL              (14 | SER_IS_VAL)

#define SER_EXPR                     (1  | SER_IS_EXPR)
#define SER_NAME_EXPR                (2  | SER_IS_EXPR)
#define SER_CONST_EXPR               (3  | SER_IS_EXPR)
#define SER_UNARY_EXPR               (4  | SER_IS_EXPR)
#define SER_BINARY_EXPR              (5  | SER_IS_EXPR)
#define SER_INCR_EXPR                (6  | SER_IS_EXPR)
#define SER_NOT_EXPR                 (7  | SER_IS_EXPR)
#define SER_POS_EXPR                 (8  | SER_IS_EXPR)
#define SER_NEG_EXPR                 (9  | SER_IS_EXPR)
#define SER_ADD_EXPR                 (10 | SER_IS_EXPR)
#define SER_SUB_EXPR                 (11 | SER_IS_EXPR)
#define SER_TIMES_EXPR               (12 | SER_IS_EXPR)
#define SER_DIVIDE_EXPR              (13 | SER_IS_EXPR)
#define SER_MOD_EXPR                 (14 | SER_IS_EXPR)
#define SER_BOOL_EXPR                (15 | SER_IS_EXPR)
#define SER_EQ_EXPR                  (16 | SER_IS_EXPR)
#define SER_REL_EXPR                 (17 | SER_IS_EXPR)
#define SER_COND_EXPR                (18 | SER_IS_EXPR)
#define SER_REF_EXPR                 (19 | SER_IS_EXPR)
#define SER_ASSIGN_EXPR              (20 | SER_IS_EXPR)
#define SER_INDEX_EXPR               (21 | SER_IS_EXPR)
#define SER_FIELD_EXPR               (22 | SER_IS_EXPR)
#define SER_HAS_FIELD_EXPR           (23 | SER_IS_EXPR)
#define SER_RECORD_CONSTRUCTOR_EXPR  (24 | SER_IS_EXPR)
#define SER_FIELD_ASSIGN_EXPR        (25 | SER_IS_EXPR)
#define SER_RECORD_MATCH_EXPR        (26 | SER_IS_EXPR)
#define SER_ARITH_COERCE_EXPR        (27 | SER_IS_EXPR)
#define SER_RECORD_COERCE_EXPR       (28 | SER_IS_EXPR)
#define SER_FLATTEN_EXPR             (29 | SER_IS_EXPR)
#define SER_SCHEDULE_EXPR            (30 | SER_IS_EXPR)
#define SER_IN_EXPR                  (31 | SER_IS_EXPR)
#define SER_CALL_EXPR                (32 | SER_IS_EXPR)
#define SER_EVENT_EXPR               (33 | SER_IS_EXPR)
#define SER_LIST_EXPR                (34 | SER_IS_EXPR)
#define SER_RECORD_ASSIGN_EXPR       (35 | SER_IS_EXPR)

#define SER_TYPE                     (1  | SER_IS_TYPE)
#define SER_TYPE_LIST                (2  | SER_IS_TYPE)
#define SER_INDEX_TYPE               (3  | SER_IS_TYPE)
#define SER_TABLE_TYPE               (4  | SER_IS_TYPE)
#define SER_SET_TYPE                 (5  | SER_IS_TYPE)
#define SER_FUNC_TYPE                (6  | SER_IS_TYPE)
#define SER_RECORD_TYPE              (7  | SER_IS_TYPE)
#define SER_SUBNET_TYPE              (8  | SER_IS_TYPE)
#define SER_FILE_TYPE                (9  | SER_IS_TYPE)
#define SER_ENUM_TYPE                (10 | SER_IS_TYPE)
#define SER_VECTOR_TYPE              (11 | SER_IS_TYPE)

#define SER_ATTRIBUTES               (1  | SER_IS_ATTRIBUTES)

#define SER_EVENT_HANDLER            (1  | SER_IS_EVENT_HANDLER)
#define SER_FILE                     (1  | SER_IS_FILE)

#define SER_FUNC                     (1  | SER_IS_FUNC)
#define SER_BRO_FUNC                 (2  | SER_IS_FUNC)
#define SER_DEBUG_FUNC               (3  | SER_IS_FUNC)
#define SER_BUILTIN_FUNC             (4  | SER_IS_FUNC)

#define SER_ID                       (1  | SER_IS_ID)
#define SER_STATE_ACCESS             (1  | SER_IS_STATE_ACCESS)
#define SER_CASE                     (1  | SER_IS_CASE)
#define SER_LOCATION                 (1  | SER_IS_LOCATION)
#define SER_RE_MATCHER               (1  | SER_IS_RE_MATCHER)

typedef struct bro_serial_object BroSObject;

typedef BroSObject *(* BroSObjectNew) (void);

/* Signatures for all functions which we virtualize. */
typedef int (* BroSObjectRead) (BroSObject *obj, BroConn *bc);
typedef int (* BroSObjectWrite) (BroSObject *obj, BroConn *bc);
typedef void (* BroSObjectFree) (BroSObject *obj);
typedef int (* BroSObjectClone) (BroSObject *dst, BroSObject *src);
typedef uint32 (* BroSObjectHash) (BroSObject *obj);
typedef int (* BroSObjectCmp) (BroSObject *obj1, BroSObject *obj2);

/* BroSObjects are the base "class" of objects that can be serialized.
 * They mirror SerialObj in Bro. The way Broccoli realizes classes,
 * objects, and inheritance is as follows:
 *
 * (1) There is no distinction between classes and the objects that
 *     are created from them. That means that each object carries with
 *     it all the function pointers needed to implement polymorphism.
 *     Yes, this wastes space, but for now I don't think it wastes
 *     enough to justify the additional complexity of explicit-class,
 *     Gtk-style object orientation in C.
 *
 * (2) Currently, the only virtualized functions are the ones defined
 *     in BroSObject below, though this may change in the future.
 *     These functions implement reading/writing from/to a buffer,
 *     cleanup, cloning, hashing to a uint32, and strcmp()-style
 *     instance comparison.
 *
 *     Implementations of these functions need to work in typical OO
 *     fashion, i.e., they may need to call the implementation of the
 *     parent "class" explicitly. This is the case for the (un)seriali-
 *     zation functions (which need to read/write all elements of the
 *     inheritance chain. It is not the case for the virtual ..._hash()
 *     and ..._cmp() implementations, which usually define equality
 *     and the computed hash value exclusively from the most derived
 *     type's values.
 *
 * (3) Instances of BroSObject are usually created either by
 *     unserializing them from a buffer (via __bro_sobject_unserialize())
 *     or by specialized "constructors" in inherited classes. The
 *     main constructor of this sort if __bro_val_new_of_type(), which
 *     initializes BroVals with correct type information.
 *     
 *     Instances of BroSObject are to be deallocated via
 *     __bro_sobject_release(). Since BroSObjects may be referenced
 *     in multiple locations (the serialization cache being a main
 *     example), you must not explicitly release the memory associated
 *     with a BroSObject but let the BroSObject implementation decide
 *     when to do so.
 */
struct bro_serial_object
{
  /* The value by which the object is identified in the
   * serialization cache.
   */
  uint32           perm_id;

  /* One of the SER_xxx values above to identify the type
   * of object upon (un)serialization.
   */
  uint16           type_id;

  /* Reference count, used for unserialized objects that
   * sit in the connection's serialization cache and may
   * be referenced by multiple SObjects.
   */
  int              ref_count;

  /* Storage for arbitrary user data:
   */
  BroHT           *data;

  BroSObjectRead   read;
  BroSObjectWrite  write;
  BroSObjectFree   free;
  BroSObjectClone  clone;
  BroSObjectHash   hash;
  BroSObjectCmp    cmp;
};

BroSObject      *__bro_sobject_create(uint16 type_id);
void             __bro_sobject_release(BroSObject *obj);
void             __bro_sobject_ref(BroSObject *obj);
BroSObject      *__bro_sobject_copy(BroSObject *obj);

BroSObject      *__bro_sobject_new(void);

void             __bro_sobject_init(BroSObject *obj);
void             __bro_sobject_free(BroSObject *obj);

/* We need the connection handle for the next two and not just
 * a buffer because we might need the cache associated with the
 * connection.
 */
int              __bro_sobject_serialize(BroSObject *obj, BroConn *bc);
BroSObject      *__bro_sobject_unserialize(uint16 type_id, BroConn *bc);

/* Hash a SObject or compare them. These are the virtualized
 * functions -- the actual implementation of these functions
 * for SObjects themselves are static in bro_sobject.c.
 */
uint32           __bro_sobject_hash(BroSObject *obj);
int              __bro_sobject_cmp(BroSObject *obj1, BroSObject *obj2);

int              __bro_sobject_read(BroSObject *obj, BroConn *bc);
int              __bro_sobject_write(BroSObject *obj, BroConn *bc);
int              __bro_sobject_clone(BroSObject *dst, BroSObject *src);

/* Our base class has a facility for associating arbitrary stuff
 * with each instance. Make sure to clean up the associated items
 * before releasing the instance, because the object doesn't know
 * how to do this.
 */
void             __bro_sobject_data_set(BroSObject *obj, const char *key, void *val);
void            *__bro_sobject_data_get(BroSObject *obj, const char *key);
void            *__bro_sobject_data_del(BroSObject *obj, const char *key);

#endif
