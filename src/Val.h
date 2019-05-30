// See the file "COPYING" in the main distribution directory for copyright.

#ifndef val_h
#define val_h

// BRO values.

#include <vector>
#include <list>
#include <array>

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

// We have four different port name spaces: TCP, UDP, ICMP, and UNKNOWN.
// We distinguish between them based on the bits specified in the *_PORT_MASK
// entries specified below.
#define NUM_PORT_SPACES 4
#define PORT_SPACE_MASK 0x30000

#define TCP_PORT_MASK	0x10000
#define UDP_PORT_MASK	0x20000
#define ICMP_PORT_MASK	0x30000

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

	// Used for count, counter, port.
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
	BRO_DEPRECATED("use val_mgr->GetBool, GetFalse/GetTrue, GetInt, or GetCount instead")
	Val(bool b, TypeTag t)
		{
		val.int_val = b;
		type = base_type(t);
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	BRO_DEPRECATED("use val_mgr->GetBool, GetFalse/GetTrue, GetInt, or GetCount instead")
	Val(int32 i, TypeTag t)
		{
		val.int_val = bro_int_t(i);
		type = base_type(t);
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	BRO_DEPRECATED("use val_mgr->GetBool, GetFalse/GetTrue, GetInt, or GetCount instead")
	Val(uint32 u, TypeTag t)
		{
		val.uint_val = bro_uint_t(u);
		type = base_type(t);
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	BRO_DEPRECATED("use val_mgr->GetBool, GetFalse/GetTrue, GetInt, or GetCount instead")
	Val(int64 i, TypeTag t)
		{
		val.int_val = i;
		type = base_type(t);
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	BRO_DEPRECATED("use val_mgr->GetBool, GetFalse/GetTrue, GetInt, or GetCount instead")
	Val(uint64 u, TypeTag t)
		{
		val.uint_val = u;
		type = base_type(t);
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	Val(double d, TypeTag t)
		{
		val.double_val = d;
		type = base_type(t);
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	explicit Val(Func* f);

	// Note, will unref 'f' when it's done, closing it unless
	// class has ref'd it.
	explicit Val(BroFile* f);

	Val(BroType* t, bool type_type) // Extra arg to differentiate from protected version.
		{
		type = new TypeType(t->Ref());
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	Val()
		{
		val.int_val = 0;
		type = base_type(TYPE_ERROR);
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	~Val() override;

	Val* Ref()			{ ::Ref(this); return this; }
	Val* Clone();

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

	void Describe(ODesc* d) const override;
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

	friend class EnumType;
	friend class ListVal;
	friend class RecordVal;
	friend class VectorVal;
	friend class ValManager;

	virtual void ValDescribe(ODesc* d) const;
	virtual void ValDescribeReST(ODesc* d) const;

	static Val* MakeBool(bool b)
		{
		auto rval = new Val(TYPE_BOOL);
		rval->val.int_val = b;
		return rval;
		}

	static Val* MakeInt(bro_int_t i)
		{
		auto rval = new Val(TYPE_INT);
		rval->val.int_val = i;
		return rval;
		}

	static Val* MakeCount(bro_uint_t u)
		{
		auto rval = new Val(TYPE_COUNT);
		rval->val.uint_val = u;
		return rval;
		}

	explicit Val(TypeTag t)
		{
		type = base_type(t);
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	explicit Val(BroType* t)
		{
		type = t->Ref();
#ifdef DEBUG
		bound_id = 0;
#endif
		}

	ACCESSOR(TYPE_TABLE, PDict(TableEntryVal)*, table_val, AsNonConstTable)
	ACCESSOR(TYPE_RECORD, val_list*, val_list_val, AsNonConstRecord)

	// Just an internal helper.
	static Val* Unserialize(UnserialInfo* info, TypeTag type,
			const BroType* exact_type);

	// For internal use by the Val::Clone() methods.
	struct CloneState {
	    std::unordered_map<const Val*, Val*> clones;
	};

	Val* Clone(CloneState* state);
	virtual Val* DoClone(CloneState* state);

	BroValUnion val;
	BroType* type;

#ifdef DEBUG
	// For debugging, we keep the name of the ID to which a Val is bound.
	const char* bound_id;
#endif

};

class PortManager {
public:
	// Port number given in host order.
	BRO_DEPRECATED("use val_mgr->GetPort() instead")
	PortVal* Get(uint32 port_num, TransportProto port_type) const;

	// Host-order port number already masked with port space protocol mask.
	BRO_DEPRECATED("use val_mgr->GetPort() instead")
	PortVal* Get(uint32 port_num) const;

	// Returns a masked port number
	BRO_DEPRECATED("use PortVal::Mask() instead")
	uint32 Mask(uint32 port_num, TransportProto port_type) const;
};

extern PortManager* port_mgr;

// Holds pre-allocated Val objects for those where it's more optimal to
// re-use existing ones rather than allocate anew.
class ValManager {
public:

	static constexpr bro_uint_t PREALLOCATED_COUNTS = 4096;
	static constexpr bro_uint_t PREALLOCATED_INTS = 512;
	static constexpr bro_int_t PREALLOCATED_INT_LOWEST = -255;
	static constexpr bro_int_t PREALLOCATED_INT_HIGHEST =
            PREALLOCATED_INT_LOWEST + PREALLOCATED_INTS - 1;

	ValManager();

	~ValManager();

	inline Val* GetTrue() const
		{ return b_true->Ref(); }

	inline Val* GetFalse() const
		{ return b_false->Ref(); }

	inline Val* GetBool(bool b) const
		{ return b ? b_true->Ref() : b_false->Ref(); }

	inline Val* GetInt(int64 i) const
		{
		return i < PREALLOCATED_INT_LOWEST || i > PREALLOCATED_INT_HIGHEST ?
		    Val::MakeInt(i) : ints[i - PREALLOCATED_INT_LOWEST]->Ref();
		}

	inline Val* GetCount(uint64 i) const
		{
		return i >= PREALLOCATED_COUNTS ? Val::MakeCount(i) : counts[i]->Ref();
		}

	StringVal* GetEmptyString() const;

	// Port number given in host order.
	PortVal* GetPort(uint32 port_num, TransportProto port_type) const;

	// Host-order port number already masked with port space protocol mask.
	PortVal* GetPort(uint32 port_num) const;

private:

	std::array<std::array<PortVal*, 65536>, NUM_PORT_SPACES> ports;
	StringVal* empty_string;
	Val* b_true;
	Val* b_false;
	Val** counts;
	Val** ints;
};

extern ValManager* val_mgr;

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
		return props & TRACKED;
#else
		return debug_logger.IsVerbose() ||
			(props & TRACKED);
#endif
		}

	uint64 LastModified() const override	{ return last_modified; }

	// Mark value as changed.
	void Modified()
		{
		last_modified = IncreaseTimeCounter();
		}

protected:
	explicit MutableVal(BroType* t) : Val(t)
		{ props = 0; id = 0; last_modified = SerialObj::ALWAYS; }
	MutableVal()	{ props = 0; id = 0; last_modified = SerialObj::ALWAYS; }
	~MutableVal() override;

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

	void ValDescribe(ODesc* d) const override;

	DECLARE_SERIAL(IntervalVal);
};


class PortVal : public Val {
public:
	// Port number given in host order.
	BRO_DEPRECATED("use val_mgr->GetPort() instead")
	PortVal(uint32 p, TransportProto port_type);

	// Host-order port number already masked with port space protocol mask.
	BRO_DEPRECATED("use val_mgr->GetPort() instead")
	explicit PortVal(uint32 p);

	Val* SizeVal() const override	{ return val_mgr->GetInt(val.uint_val); }

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

	// Returns a masked port number
	static uint32 Mask(uint32 port_num, TransportProto port_type);

protected:
	friend class Val;
	friend class ValManager;
	PortVal()	{}
	PortVal(uint32 p, bool unused);

	void ValDescribe(ODesc* d) const override;
	Val* DoClone(CloneState* state) override;

	DECLARE_SERIAL(PortVal);
};

class AddrVal : public Val {
public:
	explicit AddrVal(const char* text);
	explicit AddrVal(const std::string& text);
	~AddrVal() override;

	Val* SizeVal() const override;

	// Constructor for address already in network order.
	explicit AddrVal(uint32 addr);          // IPv4.
	explicit AddrVal(const uint32 addr[4]); // IPv6.
	explicit AddrVal(const IPAddr& addr);

	unsigned int MemoryAllocation() const override;

protected:
	friend class Val;
	AddrVal()	{}
	explicit AddrVal(TypeTag t) : Val(t)	{ }
	explicit AddrVal(BroType* t) : Val(t)	{ }

	Val* DoClone(CloneState* state) override;

	DECLARE_SERIAL(AddrVal);
};

class SubNetVal : public Val {
public:
	explicit SubNetVal(const char* text);
	SubNetVal(const char* text, int width);
	SubNetVal(uint32 addr, int width); // IPv4.
	SubNetVal(const uint32 addr[4], int width); // IPv6.
	SubNetVal(const IPAddr& addr, int width);
	explicit SubNetVal(const IPPrefix& prefix);
	~SubNetVal() override;

	Val* SizeVal() const override;

	const IPAddr& Prefix() const;
	int Width() const;
	IPAddr Mask() const;

	bool Contains(const IPAddr& addr) const;

	unsigned int MemoryAllocation() const override;

protected:
	friend class Val;
	SubNetVal()	{}

	void ValDescribe(ODesc* d) const override;
	Val* DoClone(CloneState* state) override;

	DECLARE_SERIAL(SubNetVal);
};

class StringVal : public Val {
public:
	explicit StringVal(BroString* s);
	explicit StringVal(const char* s);
	explicit StringVal(const string& s);
	StringVal(int length, const char* s);

	Val* SizeVal() const override
		{ return val_mgr->GetCount(val.string_val->Len()); }

	int Len()		{ return AsString()->Len(); }
	const u_char* Bytes()	{ return AsString()->Bytes(); }
	const char* CheckString() { return AsString()->CheckString(); }

	// Note that one needs to de-allocate the return value of
	// ExpandedString() to avoid a memory leak.
	// char* ExpandedString(int format = BroString::EXPANDED_STRING)
	// 	{ return AsString()->ExpandedString(format); }

	StringVal* ToUpper();

	unsigned int MemoryAllocation() const override;

protected:
	friend class Val;
	StringVal()	{}

	void ValDescribe(ODesc* d) const override;
	Val* DoClone(CloneState* state) override;

	DECLARE_SERIAL(StringVal);
};

class PatternVal : public Val {
public:
	explicit PatternVal(RE_Matcher* re);
	~PatternVal() override;

	int AddTo(Val* v, int is_first_init) const override;

	void SetMatcher(RE_Matcher* re);

	unsigned int MemoryAllocation() const override;

protected:
	friend class Val;
	PatternVal()	{}

	void ValDescribe(ODesc* d) const override;
	Val* DoClone(CloneState* state) override;

	DECLARE_SERIAL(PatternVal);
};

// ListVals are mainly used to index tables that have more than one
// element in their index.
class ListVal : public Val {
public:
	explicit ListVal(TypeTag t);
	~ListVal() override;

	TypeTag BaseTag() const		{ return tag; }

	Val* SizeVal() const override	{ return val_mgr->GetCount(vals.length()); }

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

	void Describe(ODesc* d) const override;

	unsigned int MemoryAllocation() const override;

protected:
	friend class Val;
	ListVal()	{}

	Val* DoClone(CloneState* state) override;

	DECLARE_SERIAL(ListVal);

	val_list vals;
	TypeTag tag;
};

extern double bro_start_network_time;

class TableEntryVal {
public:
	explicit TableEntryVal(Val* v)
		{
		val = v;
		last_access_time = network_time;
		expire_access_time = last_read_update =
			int(network_time - bro_start_network_time);
		}

	TableEntryVal* Clone()
		{
		auto rval = new TableEntryVal(val ? val->Clone() : nullptr);
		rval->last_access_time = last_access_time;
		rval->expire_access_time = expire_access_time;
		rval->last_read_update = last_read_update;
		return rval;
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
	~TableValTimer() override;

	void Dispatch(double t, int is_expire) override;

	TableVal* Table()	{ return table; }

protected:
	TableVal* table;
};

class CompositeHash;
class TableVal : public MutableVal {
public:
	explicit TableVal(TableType* t, Attributes* attrs = 0);
	~TableVal() override;

	// Returns true if the assignment typechecked, false if not. The
	// methods take ownership of new_val, but not of the index. Second
	// version takes a HashKey and Unref()'s it when done. If we're a
	// set, new_val has to be nil. If we aren't a set, index may be nil
	// in the second version.
	int Assign(Val* index, Val* new_val, Opcode op = OP_ASSIGN);
	int Assign(Val* index, HashKey* k, Val* new_val, Opcode op = OP_ASSIGN);

	Val* SizeVal() const override	{ return val_mgr->GetCount(Size()); }

	// Add the entire contents of the table to the given value,
	// which must also be a TableVal.
	// Returns true if the addition typechecked, false if not.
	// If is_first_init is true, then this is the *first* initialization
	// (and so should be strictly adding new elements).
	int AddTo(Val* v, int is_first_init) const override;

	// Same but allows suppression of state operations.
	int AddTo(Val* v, int is_first_init, bool propagate_ops) const;

	// Remove the entire contents.
	void RemoveAll();

	// Remove the entire contents of the table from the given value.
	// which must also be a TableVal.
	// Returns true if the addition typechecked, false if not.
	int RemoveFrom(Val* v) const override;

	// Returns a new table that is the intersection of this
	// table and the given table.  Intersection is just done
	// on index, not on yield value, so this really only makes
	// sense for sets.
	TableVal* Intersect(const TableVal* v) const;

	// Returns true if this set contains the same members as the
	// given set.  Note that comparisons are done using hash keys,
	// so errors can arise for compound sets such as sets-of-sets.
	// See https://bro-tracker.atlassian.net/browse/BIT-1949.
	bool EqualTo(const TableVal* v) const;

	// Returns true if this set is a subset (not necessarily proper)
	// of the given set.
	bool IsSubsetOf(const TableVal* v) const;

	// Expands any lists in the index into multiple initializations.
	// Returns true if the initializations typecheck, false if not.
	int ExpandAndInit(Val* index, Val* new_val);

	// Returns the element's value if it exists in the table,
	// nil otherwise.  Note, "index" is not const because we
	// need to Ref/Unref it when calling the default function.
	Val* Lookup(Val* index, bool use_default_val = true);

	// For a table[subnet]/set[subnet], return all subnets that cover
	// the given subnet.
	// Causes an internal error if called for any other kind of table.
	VectorVal* LookupSubnets(const SubNetVal* s);

	// For a set[subnet]/table[subnet], return a new table that only contains
	// entries that cover the given subnet.
	// Causes an internal error if called for any other kind of table.
	TableVal* LookupSubnetValues(const SubNetVal* s);

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

	// Returns the Prefix table used inside the table (if present).
	// This allows us to do more direct queries to this specialized
	// type that the general Table API does not allow.
	const PrefixTable* Subnets() const { return subnets; }

	void Describe(ODesc* d) const override;

	void InitTimer(double delay);
	void DoExpire(double t);

	unsigned int MemoryAllocation() const override;

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

	bool AddProperties(Properties arg_state) override;
	bool RemoveProperties(Properties arg_state) override;

	// Calculates default value for index.  Returns 0 if none.
	Val* Default(Val* index);

	// Returns true if item expiration is enabled.
	bool ExpirationEnabled()	{ return expire_time != 0; }

	// Returns the expiration time defined by %{create,read,write}_expire
	// attribute, or -1 for unset/invalid values. In the invalid case, an
	// error will have been reported.
	double GetExpireTime();

	// Calls &expire_func and returns its return interval;
	// takes ownership of the reference.
	double CallExpireFunc(Val *idx);

	// Propagates a read operation if necessary.
	void ReadOperation(Val* index, TableEntryVal *v);

	Val* DoClone(CloneState* state) override;

	DECLARE_SERIAL(TableVal);

	TableType* table_type;
	CompositeHash* table_hash;
	Attributes* attrs;
	Expr* expire_time;
	Expr* expire_func;
	TableValTimer* timer;
	IterCookie* expire_cookie;
	PrefixTable* subnets;
	Val* def_val;
};

class RecordVal : public MutableVal {
public:
	explicit RecordVal(RecordType* t, bool init_fields = true);
	~RecordVal() override;

	Val* SizeVal() const override
		{ return val_mgr->GetCount(Type()->AsRecordType()->NumFields()); }

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

	void Describe(ODesc* d) const override;

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

	unsigned int MemoryAllocation() const override;
	void DescribeReST(ODesc* d) const override;

	// Extend the underlying arrays of record instances created during
	// parsing to match the number of fields in the record type (they may
	// mismatch as a result of parse-time record type redefinitions.
	static void ResizeParseTimeRecords();

protected:
	friend class Val;
	RecordVal()	{}

	bool AddProperties(Properties arg_state) override;
	bool RemoveProperties(Properties arg_state) override;

	Val* DoClone(CloneState* state) override;

	DECLARE_SERIAL(RecordVal);

	BroObj* origin;

	static vector<RecordVal*> parse_time_records;
};

class EnumVal : public Val {
public:

	BRO_DEPRECATED("use t->GetVal(i) instead")
	EnumVal(int i, EnumType* t) : Val(t)
		{
		val.int_val = i;
		}

	Val* SizeVal() const override	{ return val_mgr->GetInt(val.int_val); }

protected:
	friend class Val;
	friend class EnumType;

	EnumVal(EnumType* t, int i) : Val(t)
		{
		val.int_val = i;
		}

	EnumVal()	{}

	void ValDescribe(ODesc* d) const override;
	Val* DoClone(CloneState* state) override;

	DECLARE_SERIAL(EnumVal);
};


class VectorVal : public MutableVal {
public:
	explicit VectorVal(VectorType* t);
	~VectorVal() override;

	Val* SizeVal() const override
		{ return val_mgr->GetCount(uint32(val.vector_val->size())); }

	// Returns false if the type of the argument was wrong.
	// The vector will automatically grow to accomodate the index.
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

	// Add this value to the given value (if appropriate).
	// Returns true if succcessful.
	int AddTo(Val* v, int is_first_init) const override;

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

	bool AddProperties(Properties arg_state) override;
	bool RemoveProperties(Properties arg_state) override;
	void ValDescribe(ODesc* d) const override;
	Val* DoClone(CloneState* state) override;

	DECLARE_SERIAL(VectorVal);

	VectorType* vector_type;
};

// Base class for values with types that are managed completely internally,
// with no further script-level operators provided (other than bif
// functions). See OpaqueVal.h for derived classes.
class OpaqueVal : public Val {
public:
	explicit OpaqueVal(OpaqueType* t);
	~OpaqueVal() override;

protected:
	friend class Val;
	OpaqueVal() { }

	Val* DoClone(CloneState* state) override;

	DECLARE_SERIAL(OpaqueVal);
};

// Checks the given value for consistency with the given type.  If an
// exact match, returns it.  If promotable, returns the promoted version,
// Unref()'ing the original.  If not a match, generates an error message
// and returns nil, also Unref()'ing v.  If is_init is true, then
// the checking is done in the context of an initialization.
extern Val* check_and_promote(Val* v, const BroType* t, int is_init, const Location* expr_location = nullptr);

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

// Returns v casted to type T if the type supports that. Returns null if not.
// The returned value will be ref'ed.
//
// Note: This implements the script-level cast operator.
extern Val* cast_value_to_type(Val* v, BroType* t);

// Returns true if v can be casted to type T. If so, check_and_cast() will
// succeed as well.
//
// Note: This implements the script-level type comparision operator.
extern bool can_cast_value_to_type(const Val* v, BroType* t);

// Returns true if values of type s may support casting to type t. This is
// purely static check to weed out cases early on that will never succeed.
// However, even this function returns true, casting may still fail for a
// specific instance later.
extern bool can_cast_value_to_type(const BroType* s, BroType* t);

#endif
