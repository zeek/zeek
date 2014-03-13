// See the file "COPYING" in the main distribution directory for copyright.

#ifndef val_h
#define val_h

// BRO values.

#include <vector>
#include <list>

#include "net_util.h"
#include "Type.h"
#include "Dict.h"
#include "CompHash.h"
#include "BroString.h"
#include "Attr.h"
#include "Timer.h"
#include "ID.h"
#include "Scope.h"
#include "StateAccess.h"
#include "IPAddr.h"

class Val;
class Func;
class BroFile;
class RE_Matcher;
class PrefixTable;
class SerialInfo;

class PortVal;
class AddrVal;
class SubNetVal;

class IntervalVal;
class PatternVal;
class TableVal;
class RecordVal;
class ListVal;
class StringVal;
class EnumVal;
class MutableVal;

class StateAccess;

class VectorVal;

class TableEntryVal;
declare(PDict,TableEntryVal);

typedef union {
	// Used for bool, int, enum.
	bro_int_t int_val;

	// Used for count, counter, port, subnet.
	bro_uint_t uint_val;

	// Used for addr
	IPAddr* addr_val;

	// Used for subnet
	IPPrefix* subnet_val;

	// Used for double, time, interval.
	double double_val;

	BroString* string_val;
	Func* func_val;
	BroFile* file_val;
	RE_Matcher* re_val;
	PDict(TableEntryVal)* table_val;
	val_list* val_list_val;

	vector<Val*>* vector_val;

} BroValUnion;

class Val : public BroObj {
public:
	Val(bool b, TypeTag t)
		{
		val.int_val = b;
		type = base_type(t);
		attribs = 0;
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	Val(int32 i, TypeTag t)
		{
		val.int_val = bro_int_t(i);
		type = base_type(t);
		attribs = 0;
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	Val(uint32 u, TypeTag t)
		{
		val.uint_val = bro_uint_t(u);
		type = base_type(t);
		attribs = 0;
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	Val(int64 i, TypeTag t)
		{
		val.int_val = i;
		type = base_type(t);
		attribs = 0;
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	Val(uint64 u, TypeTag t)
		{
		val.uint_val = u;
		type = base_type(t);
		attribs = 0;
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	Val(double d, TypeTag t)
		{
		val.double_val = d;
		type = base_type(t);
		attribs = 0;
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	Val(Func* f);

	// Note, will unref 'f' when it's done, closing it unless
	// class has ref'd it.
	Val(BroFile* f);

	Val(BroType* t, bool type_type) // Extra arg to differentiate from protected version.
		{
		type = new TypeType(t->Ref());
		attribs = 0;
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	Val()
		{
		val.int_val = 0;
		type = base_type(TYPE_ERROR);
		attribs = 0;
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	virtual ~Val();

	Val* Ref()			{ ::Ref(this); return this; }
	virtual Val* Clone() const;

	int IsZero() const;
	int IsOne() const;

	bro_int_t InternalInt() const;
	bro_uint_t InternalUnsigned() const;
	double InternalDouble() const;

	bro_int_t CoerceToInt() const;
	bro_uint_t CoerceToUnsigned() const;
	double CoerceToDouble() const;

	// Returns a new Val with the "size" of this Val.  What constitutes
	// size depends on the Val's type.
	virtual Val* SizeVal() const;

	// Bytes in total value object.
	virtual unsigned int MemoryAllocation() const;

	// Add this value to the given value (if appropriate).
	// Returns true if succcessful.  is_first_init is true only if
	// this is the *first* initialization of the value, not
	// if it's a subsequent += initialization.
	virtual int AddTo(Val* v, int is_first_init) const;

	// Remove this value from the given value (if appropriate).
	virtual int RemoveFrom(Val* v) const;

	BroType* Type()			{ return type; }
	const BroType* Type() const	{ return type; }

#define CONST_ACCESSOR(tag, ctype, accessor, name) \
	const ctype name() const \
		{ \
		CHECK_TAG(type->Tag(), tag, "Val::CONST_ACCESSOR", type_name) \
		return val.accessor; \
		}

	// Needed for g++ 4.3's pickiness.
#define CONST_ACCESSOR2(tag, ctype, accessor, name) \
	ctype name() const \
		{ \
		CHECK_TAG(type->Tag(), tag, "Val::CONST_ACCESSOR", type_name) \
		return val.accessor; \
		}

	CONST_ACCESSOR2(TYPE_BOOL, bool, int_val, AsBool)
	CONST_ACCESSOR2(TYPE_INT, bro_int_t, int_val, AsInt)
	CONST_ACCESSOR2(TYPE_COUNT, bro_uint_t, uint_val, AsCount)
	CONST_ACCESSOR2(TYPE_COUNTER, bro_uint_t, uint_val, AsCounter)
	CONST_ACCESSOR2(TYPE_DOUBLE, double, double_val, AsDouble)
	CONST_ACCESSOR2(TYPE_TIME, double, double_val, AsTime)
	CONST_ACCESSOR2(TYPE_INTERVAL, double, double_val, AsInterval)
	CONST_ACCESSOR2(TYPE_ENUM, int, int_val, AsEnum)
	CONST_ACCESSOR(TYPE_STRING, BroString*, string_val, AsString)
	CONST_ACCESSOR(TYPE_FUNC, Func*, func_val, AsFunc)
	CONST_ACCESSOR(TYPE_TABLE, PDict(TableEntryVal)*, table_val, AsTable)
	CONST_ACCESSOR(TYPE_RECORD, val_list*, val_list_val, AsRecord)
	CONST_ACCESSOR(TYPE_FILE, BroFile*, file_val, AsFile)
	CONST_ACCESSOR(TYPE_PATTERN, RE_Matcher*, re_val, AsPattern)
	CONST_ACCESSOR(TYPE_VECTOR, vector<Val*>*, vector_val, AsVector)

	const IPPrefix& AsSubNet() const
		{
		CHECK_TAG(type->Tag(), TYPE_SUBNET, "Val::SubNet", type_name)
		return *val.subnet_val;
		}

	BroType* AsType() const
		{
		CHECK_TAG(type->Tag(), TYPE_TYPE, "Val::Type", type_name)
		return type;
		}

	const IPAddr& AsAddr() const
		{
		if ( type->Tag() != TYPE_ADDR )
			BadTag("Val::AsAddr", type_name(type->Tag()));
		return *val.addr_val;
		}

#define ACCESSOR(tag, ctype, accessor, name) \
	ctype name() \
		{ \
		CHECK_TAG(type->Tag(), tag, "Val::ACCESSOR", type_name) \
		return val.accessor; \
		}

	// Accessors for mutable values are called AsNonConst* and
	// are protected to avoid external state changes.
	// ACCESSOR(TYPE_STRING, BroString*, string_val, AsString)
	ACCESSOR(TYPE_FUNC, Func*, func_val, AsFunc)
	ACCESSOR(TYPE_FILE, BroFile*, file_val, AsFile)
	ACCESSOR(TYPE_PATTERN, RE_Matcher*, re_val, AsPattern)
	ACCESSOR(TYPE_VECTOR, vector<Val*>*, vector_val, AsVector)

	const IPPrefix& AsSubNet()
		{
		CHECK_TAG(type->Tag(), TYPE_SUBNET, "Val::SubNet", type_name)
		return *val.subnet_val;
		}

	const IPAddr& AsAddr()
		{
		if ( type->Tag() != TYPE_ADDR )
			BadTag("Val::AsAddr", type_name(type->Tag()));
		return *val.addr_val;
		}

	// Gives fast access to the bits of something that is one of
	// bool, int, count, or counter.
	bro_int_t ForceAsInt() const		{ return val.int_val; }
	bro_uint_t ForceAsUInt() const		{ return val.uint_val; }

#define CONVERTER(tag, ctype, name) \
	ctype name() \
		{ \
		CHECK_TAG(type->Tag(), tag, "Val::CONVERTER", type_name) \
		return (ctype)(this); \
		}

	CONVERTER(TYPE_PATTERN, PatternVal*, AsPatternVal)
	CONVERTER(TYPE_PORT, PortVal*, AsPortVal)
	CONVERTER(TYPE_SUBNET, SubNetVal*, AsSubNetVal)
	CONVERTER(TYPE_ADDR, AddrVal*, AsAddrVal)
	CONVERTER(TYPE_TABLE, TableVal*, AsTableVal)
	CONVERTER(TYPE_RECORD, RecordVal*, AsRecordVal)
	CONVERTER(TYPE_LIST, ListVal*, AsListVal)
	CONVERTER(TYPE_STRING, StringVal*, AsStringVal)
	CONVERTER(TYPE_VECTOR, VectorVal*, AsVectorVal)
	CONVERTER(TYPE_ENUM, EnumVal*, AsEnumVal)

#define CONST_CONVERTER(tag, ctype, name) \
	const ctype name() const \
		{ \
		CHECK_TAG(type->Tag(), tag, "Val::CONVERTER", type_name) \
		return (const ctype)(this); \
		}

	CONST_CONVERTER(TYPE_PATTERN, PatternVal*, AsPatternVal)
	CONST_CONVERTER(TYPE_PORT, PortVal*, AsPortVal)
	CONST_CONVERTER(TYPE_SUBNET, SubNetVal*, AsSubNetVal)
	CONST_CONVERTER(TYPE_ADDR, AddrVal*, AsAddrVal)
	CONST_CONVERTER(TYPE_TABLE, TableVal*, AsTableVal)
	CONST_CONVERTER(TYPE_RECORD, RecordVal*, AsRecordVal)
	CONST_CONVERTER(TYPE_LIST, ListVal*, AsListVal)
	CONST_CONVERTER(TYPE_STRING, StringVal*, AsStringVal)
	CONST_CONVERTER(TYPE_VECTOR, VectorVal*, AsVectorVal)

	bool IsMutableVal() const
		{
		return IsMutable(type->Tag());
		}

	const MutableVal* AsMutableVal() const
		{
		if ( ! IsMutableVal() )
			BadTag("Val::AsMutableVal", type_name(type->Tag()));
		return (MutableVal*) this;
		}

	MutableVal* AsMutableVal()
		{
		if ( ! IsMutableVal() )
			BadTag("Val::AsMutableVal", type_name(type->Tag()));
		return (MutableVal*) this;
		}

	void Describe(ODesc* d) const;
	virtual void DescribeReST(ODesc* d) const;

	bool Serialize(SerialInfo* info) const;
	static Val* Unserialize(UnserialInfo* info, TypeTag type = TYPE_ANY)
		{ return Unserialize(info, type, 0); }
	static Val* Unserialize(UnserialInfo* info, const BroType* exact_type)
		{ return Unserialize(info, exact_type->Tag(), exact_type); }

	DECLARE_SERIAL(Val);

#ifdef DEBUG
	// For debugging, we keep a reference to the global ID to which a
	// value has been bound *last*.
	ID* GetID() const
		{
		return bound_id ? global_scope()->Lookup(bound_id) : 0;
		}

	void SetID(ID* id)
		{
		delete [] bound_id;
		bound_id = id ? copy_string(id->Name()) : 0;
		}
#endif

protected:
	Val(BroString* s, TypeTag t)
		{
		val.string_val = s;
		type = base_type(t);
		attribs = 0;
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	virtual void ValDescribe(ODesc* d) const;
	virtual void ValDescribeReST(ODesc* d) const;

	Val(TypeTag t)
		{
		type = base_type(t);
		attribs = 0;
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	Val(BroType* t)
		{
		type = t->Ref();
		attribs = 0;
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	ACCESSOR(TYPE_TABLE, PDict(TableEntryVal)*, table_val, AsNonConstTable)
	ACCESSOR(TYPE_RECORD, val_list*, val_list_val, AsNonConstRecord)

	// Just an internal helper.
	static Val* Unserialize(UnserialInfo* info, TypeTag type,
			const BroType* exact_type);

	BroValUnion val;
	BroType* type;
	RecordVal* attribs;

#ifdef DEBUG
	// For debugging, we keep the name of the ID to which a Val is bound.
	const char* bound_id;
#endif

};

class MutableVal : public Val {
public:
	// Each MutableVal gets a globally unique ID that can be used to
	// reference it no matter if it's directly bound to any user-visible
	// ID. This ID is inserted into the global namespace.
	ID* UniqueID() const	{ return id ? id : Bind(); }

	// Returns true if we've already generated a unique ID.
	bool HasUniqueID() const	{ return id; }

	// Transfers the unique ID of the given value to this value. We keep our
	// old ID as an alias.
	void TransferUniqueID(MutableVal* mv);

	// MutableVals can have properties (let's refrain from calling them
	// attributes!).  Most properties are recursive.  If a derived object
	// can contain MutableVals itself, the object has to override
	// {Add,Remove}Properties(). RecursiveProp(state) masks out all non-
	// recursive properties. If this is non-null, an overriden method must
	// call itself with RecursiveProp(state) as argument for all contained
	// values.  (In any case, don't forget to call the parent's method.)
	typedef char Properties;

	static const int PERSISTENT = 0x01;
	static const int SYNCHRONIZED = 0x02;

	// Tracked by NotifierRegistry, not recursive.
	static const int TRACKED = 0x04;

	int RecursiveProps(int prop) const	{ return prop & ~TRACKED; }

	Properties GetProperties() const	{ return props; }
	virtual bool AddProperties(Properties state);
	virtual bool RemoveProperties(Properties state);

	// Whether StateAccess:LogAccess needs to be called.
	bool LoggingAccess() const
		{
#ifndef DEBUG
		return props & (SYNCHRONIZED|PERSISTENT|TRACKED);
#else
		return debug_logger.IsVerbose() ||
			(props & (SYNCHRONIZED|PERSISTENT|TRACKED));
#endif
		}

	virtual uint64 LastModified() const 	{ return last_modified; }

	// Mark value as changed.
	void Modified()
		{
		last_modified = IncreaseTimeCounter();
		}

protected:
	MutableVal(BroType* t) : Val(t)
		{ props = 0; id = 0; last_modified = SerialObj::ALWAYS; }
	MutableVal()	{ props = 0; id = 0; last_modified = SerialObj::ALWAYS; }
	~MutableVal();

	friend class ID;
	friend class Val;

	void SetID(ID* arg_id)	{ Unref(id); id = arg_id; }

	DECLARE_SERIAL(MutableVal);

private:
	ID* Bind() const;

	mutable ID* id;
	list<ID*> aliases;
	Properties props;
	uint64 last_modified;
};

#define Microseconds 1e-6
#define Milliseconds 1e-3
#define Seconds 1.0
#define Minutes (60*Seconds)
#define Hours (60*Minutes)
#define Days (24*Hours)

class IntervalVal : public Val {
public:
	IntervalVal(double quantity, double units);

protected:
	IntervalVal()	{}

	void ValDescribe(ODesc* d) const;

	DECLARE_SERIAL(IntervalVal);
};


// We have four different port name spaces: TCP, UDP, ICMP, and UNKNOWN.
// We distinguish between them based on the bits specified in the *_PORT_MASK
// entries specified below.
#define NUM_PORT_SPACES 4
#define PORT_SPACE_MASK 0x30000

#define TCP_PORT_MASK	0x10000
#define UDP_PORT_MASK	0x20000
#define ICMP_PORT_MASK	0x30000

class PortVal : public Val {
public:
	// Constructors - both take the port number in host order.
	PortVal(uint32 p, TransportProto port_type);
	PortVal(uint32 p);	// used for already-massaged port value.

	Val* SizeVal() const	{ return new Val(val.uint_val, TYPE_INT); }

	// Returns the port number in host order (not including the mask).
	uint32 Port() const;

	// Tests for protocol types.
	int IsTCP() const;
	int IsUDP() const;
	int IsICMP() const;

	TransportProto PortType() const
		{
		if ( IsTCP() )
			return TRANSPORT_TCP;
		else if ( IsUDP() )
			return TRANSPORT_UDP;
		else if ( IsICMP() )
			return TRANSPORT_ICMP;
		else
			return TRANSPORT_UNKNOWN;
		}

protected:
	friend class Val;
	PortVal()	{}

	void ValDescribe(ODesc* d) const;

	DECLARE_SERIAL(PortVal);
};

class AddrVal : public Val {
public:
	AddrVal(const char* text);
	~AddrVal();

	Val* SizeVal() const;

	// Constructor for address already in network order.
	AddrVal(uint32 addr);          // IPv4.
	AddrVal(const uint32 addr[4]); // IPv6.
	AddrVal(const IPAddr& addr);

	unsigned int MemoryAllocation() const;

protected:
	friend class Val;
	AddrVal()	{}
	AddrVal(TypeTag t) : Val(t)	{ }
	AddrVal(BroType* t) : Val(t)	{ }

	DECLARE_SERIAL(AddrVal);
};

class SubNetVal : public Val {
public:
	SubNetVal(const char* text);
	SubNetVal(const char* text, int width);
	SubNetVal(uint32 addr, int width); // IPv4.
	SubNetVal(const uint32 addr[4], int width); // IPv6.
	SubNetVal(const IPAddr& addr, int width);
	SubNetVal(const IPPrefix& prefix);
	~SubNetVal();

	Val* SizeVal() const;

	const IPAddr& Prefix() const;
	int Width() const;
	IPAddr Mask() const;

	bool Contains(const IPAddr& addr) const;

	unsigned int MemoryAllocation() const;

protected:
	friend class Val;
	SubNetVal()	{}

	void ValDescribe(ODesc* d) const;

	DECLARE_SERIAL(SubNetVal);
};

class StringVal : public Val {
public:
	StringVal(BroString* s);
	StringVal(const char* s);
	StringVal(const string& s);
	StringVal(int length, const char* s);

	Val* SizeVal() const
		{ return new Val(val.string_val->Len(), TYPE_COUNT); }

	int Len()		{ return AsString()->Len(); }
	const u_char* Bytes()	{ return AsString()->Bytes(); }
	const char* CheckString() { return AsString()->CheckString(); }

	// Note that one needs to de-allocate the return value of
	// ExpandedString() to avoid a memory leak.
	// char* ExpandedString(int format = BroString::EXPANDED_STRING)
	// 	{ return AsString()->ExpandedString(format); }

	StringVal* ToUpper();

	unsigned int MemoryAllocation() const;

protected:
	friend class Val;
	StringVal()	{}

	void ValDescribe(ODesc* d) const;

	DECLARE_SERIAL(StringVal);
};

class PatternVal : public Val {
public:
	PatternVal(RE_Matcher* re);
	~PatternVal();

	int AddTo(Val* v, int is_first_init) const;

	void SetMatcher(RE_Matcher* re);

	unsigned int MemoryAllocation() const;

protected:
	friend class Val;
	PatternVal()	{}

	void ValDescribe(ODesc* d) const;

	DECLARE_SERIAL(PatternVal);
};

// ListVals are mainly used to index tables that have more than one 
// element in their index.
class ListVal : public Val {
public:
	ListVal(TypeTag t);
	~ListVal();

	TypeTag BaseTag() const		{ return tag; }

	Val* SizeVal() const	{ return new Val(vals.length(), TYPE_COUNT); }

	int Length() const		{ return vals.length(); }
	Val* Index(const int n)		{ return vals[n]; }
	const Val* Index(const int n) const	{ return vals[n]; }

	// Returns an RE_Matcher() that will match any string that
	// includes embedded within it one of the patterns listed
	// (as a string, e.g., "foo|bar") in this ListVal.
	//
	// Assumes that all of the strings in the list are NUL-terminated
	// and do not have any embedded NULs.
	//
	// The return RE_Matcher has not yet been compiled.
	RE_Matcher* BuildRE() const;

	void Append(Val* v);

	// Returns a Set representation of the list (which must be homogeneous).
	TableVal* ConvertToSet() const;

	const val_list* Vals() const	{ return &vals; }
	val_list* Vals()		{ return &vals; }

	void Describe(ODesc* d) const;

	unsigned int MemoryAllocation() const;

protected:
	friend class Val;
	ListVal()	{}

	DECLARE_SERIAL(ListVal);

	val_list vals;
	TypeTag tag;
};

extern double bro_start_network_time;

class TableEntryVal {
public:
	TableEntryVal(Val* v)
		{
		val = v;
		last_access_time = network_time;
		expire_access_time = last_read_update =
			int(network_time - bro_start_network_time);
		}
	~TableEntryVal()	{ }

	Val* Value()	{ return val; }
	void Ref()	{ val->Ref(); }
	void Unref()	{ ::Unref(val); }

	// Returns/sets time of last expiration relevant access to this value.
	double ExpireAccessTime() const
		{ return bro_start_network_time + expire_access_time; }
	void SetExpireAccess(double time)
		{ expire_access_time = int(time - bro_start_network_time); }

	// Returns/sets time of when we propagated the last OP_READ_IDX
	// for this item.
	double LastReadUpdate() const
		{ return bro_start_network_time + last_read_update; }
	void SetLastReadUpdate(double time)
		{ last_read_update = int(time - bro_start_network_time); }

protected:
	friend class TableVal;

	Val* val;
	double last_access_time;

	// The next two entries store seconds since Bro's start.  We use
	// ints here to save a few bytes, as we do not need a high resolution
	// for these anyway.
	int expire_access_time;
	int last_read_update;
};

class TableValTimer : public Timer {
public:
	TableValTimer(TableVal* val, double t);
	~TableValTimer();

	virtual void Dispatch(double t, int is_expire);

	TableVal* Table()	{ return table; }

protected:
	TableVal* table;
};

class CompositeHash;
class TableVal : public MutableVal {
public:
	TableVal(TableType* t, Attributes* attrs = 0);
	~TableVal();

	// Returns true if the assignment typechecked, false if not.
	// Second version takes a HashKey and Unref()'s it when done.
	// If we're a set, new_val has to be nil.
	// If we aren't a set, index may be nil in the second version.
	int Assign(Val* index, Val* new_val, Opcode op = OP_ASSIGN);
	int Assign(Val* index, HashKey* k, Val* new_val, Opcode op = OP_ASSIGN);

	Val* SizeVal() const	{ return new Val(Size(), TYPE_COUNT); }

	// Add the entire contents of the table to the given value,
	// which must also be a TableVal.
	// Returns true if the addition typechecked, false if not.
	// If is_first_init is true, then this is the *first* initialization
	// (and so should be strictly adding new elements).
	int AddTo(Val* v, int is_first_init) const;

	// Same but allows suppression of state operations.
	int AddTo(Val* v, int is_first_init, bool propagate_ops) const;

	// Remove the entire contents.
	void RemoveAll();

	// Remove the entire contents of the table from the given value.
	// which must also be a TableVal.
	// Returns true if the addition typechecked, false if not.
	int RemoveFrom(Val* v) const;

	// Expands any lists in the index into multiple initializations.
	// Returns true if the initializations typecheck, false if not.
	int ExpandAndInit(Val* index, Val* new_val);

	// Returns the element's value if it exists in the table,
	// nil otherwise.  Note, "index" is not const because we
	// need to Ref/Unref it when calling the default function.
	Val* Lookup(Val* index, bool use_default_val = true);

	// Sets the timestamp for the given index to network time.
	// Returns false if index does not exist.
	bool UpdateTimestamp(Val* index);

	// Returns the index corresponding to the given HashKey.
	ListVal* RecoverIndex(const HashKey* k) const;

	// Returns the element if it was in the table, false otherwise.
	Val* Delete(const Val* index);
	Val* Delete(const HashKey* k);

	// Returns a ListVal representation of the table (which must be a set).
	ListVal* ConvertToList(TypeTag t=TYPE_ANY) const;
	ListVal* ConvertToPureList() const;	// must be single index type

	void SetAttrs(Attributes* attrs);
	Attr* FindAttr(attr_tag t) const
		{ return attrs ? attrs->FindAttr(t) : 0; }
	Attributes* Attrs()	{ return attrs; }

	// Returns the size of the table.
	int Size() const	{ return AsTable()->Length(); }
	int RecursiveSize() const;

	void Describe(ODesc* d) const;

	void InitTimer(double delay);
	void DoExpire(double t);

	unsigned int MemoryAllocation() const;

	void ClearTimer(Timer* t)
		{
		if ( timer == t )
			timer = 0;
		}

	HashKey* ComputeHash(const Val* index) const
		{ return table_hash->ComputeHash(index, 1); }

protected:
	friend class Val;
	friend class StateAccess;
	TableVal()	{}

	void Init(TableType* t);

	void CheckExpireAttr(attr_tag at);
	int ExpandCompoundAndInit(val_list* vl, int k, Val* new_val);
	int CheckAndAssign(Val* index, Val* new_val, Opcode op = OP_ASSIGN);

	bool AddProperties(Properties arg_state);
	bool RemoveProperties(Properties arg_state);

	// Calculates default value for index.  Returns 0 if none.
	Val* Default(Val* index);

	// Calls &expire_func and returns its return interval;
	// takes ownership of the reference.
	double CallExpireFunc(Val *idx);

	// Propagates a read operation if necessary.
	void ReadOperation(Val* index, TableEntryVal *v);

	DECLARE_SERIAL(TableVal);

	TableType* table_type;
	CompositeHash* table_hash;
	Attributes* attrs;
	double expire_time;
	Expr* expire_expr;
	TableValTimer* timer;
	IterCookie* expire_cookie;
	PrefixTable* subnets;
	Val* def_val;
};

class RecordVal : public MutableVal {
public:
	RecordVal(RecordType* t);
	~RecordVal();

	Val* SizeVal() const
		{ return new Val(record_type->NumFields(), TYPE_COUNT); }

	void Assign(int field, Val* new_val, Opcode op = OP_ASSIGN);
	Val* Lookup(int field) const;	// Does not Ref() value.
	Val* LookupWithDefault(int field) const;	// Does Ref() value.

	/**
	 * Looks up the value of a field by field name.  If the field doesn't
	 * exist in the record type, it's an internal error: abort.
	 * @param field name of field to lookup.
	 * @param with_default whether to rely on field's &default attribute when
	 * the field has yet to be initialized.
	 * @return the value in field \a field.  It is Ref()'d only if
	 * \a with_default is true.
	 */
	Val* Lookup(const char* field, bool with_default = false) const;

	void Describe(ODesc* d) const;

	// This is an experiment to associate a BroObj within the
	// event engine to a record value in bro script.
	void SetOrigin(BroObj* o)	{ origin = o; }
	BroObj* GetOrigin() const	{ return origin; }

	// Returns a new value representing the value coerced to the given
	// type. If coercion is not possible, returns 0. The non-const
	// version may return the current value ref'ed if its type matches
	// directly.
	//
	// *aggr* is optional; if non-zero, we add to it. See
	// Expr::InitVal(). We leave it out in the non-const version to make
	// the choice unambigious.
	//
	// The *allow_orphaning* parameter allows for a record to be demoted
	// down to a record type that contains less fields.
	RecordVal* CoerceTo(const RecordType* other, Val* aggr, bool allow_orphaning = false) const;
	RecordVal* CoerceTo(RecordType* other, bool allow_orphaning = false);

	unsigned int MemoryAllocation() const;
	void DescribeReST(ODesc* d) const;

protected:
	friend class Val;
	RecordVal()	{}

	bool AddProperties(Properties arg_state);
	bool RemoveProperties(Properties arg_state);

	DECLARE_SERIAL(RecordVal);

	RecordType* record_type;
	BroObj* origin;
};

class EnumVal : public Val {
public:
	EnumVal(int i, EnumType* t) : Val(t)
		{
		val.int_val = i;
		type = t;
		attribs = 0;
		}

	Val* SizeVal() const	{ return new Val(val.int_val, TYPE_INT); }

protected:
	friend class Val;
	EnumVal()	{}

	void ValDescribe(ODesc* d) const;

	DECLARE_SERIAL(EnumVal);
};


class VectorVal : public MutableVal {
public:
	VectorVal(VectorType* t);
	~VectorVal();

	Val* SizeVal() const
		{ return new Val(uint32(val.vector_val->size()), TYPE_COUNT); }

	// Returns false if the type of the argument was wrong.
	// The vector will automatically grow to accomodate the index.
	// 'assigner" is the expression that is doing the assignment;
	// it's just used for pinpointing errors.
	//
	// Note: does NOT Ref() the element! Remember to do so unless
	//       the element was just created and thus has refcount 1.
	//
	bool Assign(unsigned int index, Val* element, Opcode op = OP_ASSIGN);
	bool Assign(Val* index, Val* element, Opcode op = OP_ASSIGN)
		{
		return Assign(index->AsListVal()->Index(0)->CoerceToUnsigned(),
				element, op);
		}

	// Assigns the value to how_many locations starting at index.
	bool AssignRepeat(unsigned int index, unsigned int how_many,
			  Val* element);

	// Returns nil if no element was at that value.
	// Lookup does NOT grow the vector to this size.
	// The Val* variant assumes that the index Val* has been type-checked.
	Val* Lookup(unsigned int index) const;
	Val* Lookup(Val* index)
		{
		bro_uint_t i = index->AsListVal()->Index(0)->CoerceToUnsigned();
		return Lookup(static_cast<unsigned int>(i));
		}

	unsigned int Size() const { return val.vector_val->size(); }

	// Is there any way to reclaim previously-allocated memory when you
	// shrink a vector?  The return value is the old size.
	unsigned int Resize(unsigned int new_num_elements);

	// Won't shrink size.
	unsigned int ResizeAtLeast(unsigned int new_num_elements);

protected:
	friend class Val;
	VectorVal()	{ }

	bool AddProperties(Properties arg_state);
	bool RemoveProperties(Properties arg_state);
	void ValDescribe(ODesc* d) const;

	DECLARE_SERIAL(VectorVal);

	VectorType* vector_type;
};

// Base class for values with types that are managed completely internally,
// with no further script-level operators provided (other than bif
// functions). See OpaqueVal.h for derived classes.
class OpaqueVal : public Val {
public:
	OpaqueVal(OpaqueType* t);
	virtual ~OpaqueVal();

protected:
	friend class Val;
	OpaqueVal() { }

	DECLARE_SERIAL(OpaqueVal);
};

// Checks the given value for consistency with the given type.  If an
// exact match, returns it.  If promotable, returns the promoted version,
// Unref()'ing the original.  If not a match, generates an error message
// and returns nil, also Unref()'ing v.  If is_init is true, then
// the checking is done in the context of an initialization.
extern Val* check_and_promote(Val* v, const BroType* t, int is_init);

// Given a pointer to where a Val's core (i.e., its BRO value) resides,
// returns a corresponding newly-created or Ref()'d Val.  ptr must already
// be properly aligned.  Returns the size of the core in bytes in 'n'.
// If t corresponds to a variable-length type, n must give the size on entry.
Val* recover_val(void* ptr, BroType* t, int& n);

extern int same_val(const Val* v1, const Val* v2);
extern int same_atomic_val(const Val* v1, const Val* v2);
extern bool is_atomic_val(const Val* v);
extern void describe_vals(const val_list* vals, ODesc* d, int offset=0);
extern void delete_vals(val_list* vals);

// True if the given Val* has a vector type.
inline bool is_vector(Val* v)	{ return  v->Type()->Tag() == TYPE_VECTOR; }

#endif
