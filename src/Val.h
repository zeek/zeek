// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "IntrusivePtr.h"
#include "Type.h"
#include "Timer.h"
#include "Notifier.h"
#include "net_util.h"

#include <vector>
#include <list>
#include <array>
#include <unordered_map>

#include <sys/types.h> // for u_char

// We have four different port name spaces: TCP, UDP, ICMP, and UNKNOWN.
// We distinguish between them based on the bits specified in the *_PORT_MASK
// entries specified below.
#define NUM_PORT_SPACES 4
#define PORT_SPACE_MASK 0x30000

#define TCP_PORT_MASK	0x10000
#define UDP_PORT_MASK	0x20000
#define ICMP_PORT_MASK	0x30000

template<typename T> class PDict;
class IterCookie;

class Val;
class BroString;
class BroFunc;
class Func;
class BroFile;
class PrefixTable;

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
class OpaqueVal;

class IPAddr;
class IPPrefix;

class StateAccess;

class VectorVal;

class TableEntryVal;

class RE_Matcher;

union BroValUnion {
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
	PDict<TableEntryVal>* table_val;
	val_list* val_list_val;

	std::vector<Val*>* vector_val;

	BroValUnion() = default;

	constexpr BroValUnion(bro_int_t value) noexcept
		: int_val(value) {}

	constexpr BroValUnion(bro_uint_t value) noexcept
		: uint_val(value) {}

	constexpr BroValUnion(IPAddr* value) noexcept
		: addr_val(value) {}

	constexpr BroValUnion(IPPrefix* value) noexcept
		: subnet_val(value) {}

	constexpr BroValUnion(double value) noexcept
		: double_val(value) {}

	constexpr BroValUnion(BroString* value) noexcept
		: string_val(value) {}

	constexpr BroValUnion(Func* value) noexcept
		: func_val(value) {}

	constexpr BroValUnion(BroFile* value) noexcept
		: file_val(value) {}

	constexpr BroValUnion(RE_Matcher* value) noexcept
		: re_val(value) {}

	constexpr BroValUnion(PDict<TableEntryVal>* value) noexcept
		: table_val(value) {}

	constexpr BroValUnion(val_list* value) noexcept
		: val_list_val(value) {}

	constexpr BroValUnion(std::vector<Val*> *value) noexcept
		: vector_val(value) {}
};

class Val : public BroObj {
public:
	Val(double d, TypeTag t)
		: val(d), type(base_type(t))
		{}

	explicit Val(Func* f);

	// Note, will unref 'f' when it's done, closing it unless
	// class has ref'd it.
	explicit Val(BroFile* f);

	// Extra arg to differentiate from protected version.
	Val(IntrusivePtr<BroType> t, bool type_type)
		: type(make_intrusive<TypeType>(std::move(t)))
		{}

	[[deprecated("Remove in v4.1.  Construct from IntrusivePtr instead.")]]
	Val(BroType* t, bool type_type) : Val({NewRef{}, t}, type_type)
		{}

	Val()
		: val(bro_int_t(0)), type(base_type(TYPE_ERROR))
		{}

	~Val() override;

	Val* Ref()			{ ::Ref(this); return this; }
	IntrusivePtr<Val> Clone();

	bool IsZero() const;
	bool IsOne() const;

	bro_int_t InternalInt() const;
	bro_uint_t InternalUnsigned() const;
	double InternalDouble() const;

	bro_int_t CoerceToInt() const;
	bro_uint_t CoerceToUnsigned() const;
	double CoerceToDouble() const;

	// Returns a new Val with the "size" of this Val.  What constitutes
	// size depends on the Val's type.
	virtual IntrusivePtr<Val> SizeVal() const;

	// Bytes in total value object.
	virtual unsigned int MemoryAllocation() const;

	// Add this value to the given value (if appropriate).
	// Returns true if succcessful.  is_first_init is true only if
	// this is the *first* initialization of the value, not
	// if it's a subsequent += initialization.
	virtual bool AddTo(Val* v, bool is_first_init) const;

	// Remove this value from the given value (if appropriate).
	virtual bool RemoveFrom(Val* v) const;

	[[deprecated("Remove in v4.1.  Use GetType().")]]
	BroType* Type()			{ return type.get(); }
	[[deprecated("Remove in v4.1.  Use GetType().")]]
	const BroType* Type() const	{ return type.get(); }

	const IntrusivePtr<BroType>& GetType() const
		{ return type; }

	template <class T>
	IntrusivePtr<T> GetType() const
		{ return cast_intrusive<T>(type); }

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
	CONST_ACCESSOR(TYPE_TABLE, PDict<TableEntryVal>*, table_val, AsTable)
	CONST_ACCESSOR(TYPE_RECORD, val_list*, val_list_val, AsRecord)
	CONST_ACCESSOR(TYPE_FILE, BroFile*, file_val, AsFile)
	CONST_ACCESSOR(TYPE_PATTERN, RE_Matcher*, re_val, AsPattern)
	CONST_ACCESSOR(TYPE_VECTOR, std::vector<Val*>*, vector_val, AsVector)

	const IPPrefix& AsSubNet() const
		{
		CHECK_TAG(type->Tag(), TYPE_SUBNET, "Val::SubNet", type_name)
		return *val.subnet_val;
		}

	BroType* AsType() const
		{
		CHECK_TAG(type->Tag(), TYPE_TYPE, "Val::Type", type_name)
		return type.get();
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
	ACCESSOR(TYPE_VECTOR, std::vector<Val*>*, vector_val, AsVector)

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
	CONVERTER(TYPE_OPAQUE, OpaqueVal*, AsOpaqueVal)

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
	CONST_CONVERTER(TYPE_OPAQUE, OpaqueVal*, AsOpaqueVal)

	void Describe(ODesc* d) const override;
	virtual void DescribeReST(ODesc* d) const;

	// To be overridden by mutable derived class to enable change
	// notification.
	virtual notifier::Modifiable* Modifiable()	{ return nullptr; }

#ifdef DEBUG
	// For debugging, we keep a reference to the global ID to which a
	// value has been bound *last*.
	ID* GetID() const;

	void SetID(ID* id);
#endif

	static bool WouldOverflow(const BroType* from_type, const BroType* to_type, const Val* val);

	IntrusivePtr<TableVal> GetRecordFields();

	IntrusivePtr<StringVal> ToJSON(bool only_loggable=false, RE_Matcher* re=nullptr);

protected:

	friend class EnumType;
	friend class ListVal;
	friend class RecordVal;
	friend class VectorVal;
	friend class ValManager;
	friend class TableEntryVal;

	virtual void ValDescribe(ODesc* d) const;
	virtual void ValDescribeReST(ODesc* d) const;

	static IntrusivePtr<Val> MakeBool(bool b);
	static IntrusivePtr<Val> MakeInt(bro_int_t i);
	static IntrusivePtr<Val> MakeCount(bro_uint_t u);

	template<typename V>
	Val(V&& v, TypeTag t) noexcept
		: val(std::forward<V>(v)), type(base_type(t))
		{}

	template<typename V>
	Val(V&& v, IntrusivePtr<BroType> t) noexcept
		: val(std::forward<V>(v)), type(std::move(t))
		{}

	explicit Val(IntrusivePtr<BroType> t) noexcept
		: type(std::move(t))
		{}

	ACCESSOR(TYPE_TABLE, PDict<TableEntryVal>*, table_val, AsNonConstTable)
	ACCESSOR(TYPE_RECORD, val_list*, val_list_val, AsNonConstRecord)

	// For internal use by the Val::Clone() methods.
	struct CloneState {
		// Caches a cloned value for later reuse during the same
		// cloning operation. For recursive types, call this *before*
		// descending down.
		IntrusivePtr<Val> NewClone(Val* src, IntrusivePtr<Val> dst);

		std::unordered_map<Val*, Val*> clones;
	};

	IntrusivePtr<Val> Clone(CloneState* state);
	virtual IntrusivePtr<Val> DoClone(CloneState* state);

	BroValUnion val;
	IntrusivePtr<BroType> type;

#ifdef DEBUG
	// For debugging, we keep the name of the ID to which a Val is bound.
	const char* bound_id = nullptr;
#endif

};

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

	[[deprecated("Remove in v4.1.  Use val_mgr->True() instead.")]]
	inline Val* GetTrue() const
		{ return b_true->Ref(); }

	inline const IntrusivePtr<Val>& True() const
		{ return b_true; }

	[[deprecated("Remove in v4.1.  Use val_mgr->False() instead.")]]
	inline Val* GetFalse() const
		{ return b_false->Ref(); }

	inline const IntrusivePtr<Val>& False() const
		{ return b_false; }

	[[deprecated("Remove in v4.1.  Use val_mgr->Bool() instead.")]]
	inline Val* GetBool(bool b) const
		{ return b ? b_true->Ref() : b_false->Ref(); }

	inline const IntrusivePtr<Val>& Bool(bool b) const
		{ return b ? b_true : b_false; }

	[[deprecated("Remove in v4.1.  Use val_mgr->Int() instead.")]]
	inline Val* GetInt(int64_t i) const
		{
		return i < PREALLOCATED_INT_LOWEST || i > PREALLOCATED_INT_HIGHEST ?
		    Val::MakeInt(i).release() : ints[i - PREALLOCATED_INT_LOWEST]->Ref();
		}

	inline IntrusivePtr<Val> Int(int64_t i) const
		{
		return i < PREALLOCATED_INT_LOWEST || i > PREALLOCATED_INT_HIGHEST ?
		    Val::MakeInt(i) : ints[i - PREALLOCATED_INT_LOWEST];
		}

	[[deprecated("Remove in v4.1.  Use val_mgr->Count() instead.")]]
	inline Val* GetCount(uint64_t i) const
		{
		return i >= PREALLOCATED_COUNTS ? Val::MakeCount(i).release() : counts[i]->Ref();
		}

	inline IntrusivePtr<Val> Count(uint64_t i) const
		{
		return i >= PREALLOCATED_COUNTS ? Val::MakeCount(i) : counts[i];
		}

	[[deprecated("Remove in v4.1.  Use val_mgr->EmptyString() instead.")]]
	StringVal* GetEmptyString() const;

	inline const IntrusivePtr<StringVal>& EmptyString() const
		{ return empty_string; }

	// Port number given in host order.
	[[deprecated("Remove in v4.1.  Use val_mgr->Port() instead.")]]
	PortVal* GetPort(uint32_t port_num, TransportProto port_type) const;

	// Port number given in host order.
	const IntrusivePtr<PortVal>& Port(uint32_t port_num, TransportProto port_type) const;

	// Host-order port number already masked with port space protocol mask.
	[[deprecated("Remove in v4.1.  Use val_mgr->Port() instead.")]]
	PortVal* GetPort(uint32_t port_num) const;

	// Host-order port number already masked with port space protocol mask.
	const IntrusivePtr<PortVal>& Port(uint32_t port_num) const;

private:

	std::array<std::array<IntrusivePtr<PortVal>, 65536>, NUM_PORT_SPACES> ports;
	std::array<IntrusivePtr<Val>, PREALLOCATED_COUNTS> counts;
	std::array<IntrusivePtr<Val>, PREALLOCATED_INTS> ints;
	IntrusivePtr<StringVal> empty_string;
	IntrusivePtr<Val> b_true;
	IntrusivePtr<Val> b_false;
};

extern ValManager* val_mgr;

#define Microseconds 1e-6
#define Milliseconds 1e-3
#define Seconds 1.0
#define Minutes (60*Seconds)
#define Hours (60*Minutes)
#define Days (24*Hours)

class IntervalVal final : public Val {
public:
	IntervalVal(double quantity, double units);

protected:
	IntervalVal()	{}

	void ValDescribe(ODesc* d) const override;
};


class PortVal final : public Val {
public:
	IntrusivePtr<Val> SizeVal() const override;

	// Returns the port number in host order (not including the mask).
	uint32_t Port() const;
	std::string Protocol() const;

	// Tests for protocol types.
	bool IsTCP() const;
	bool IsUDP() const;
	bool IsICMP() const;

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
	static uint32_t Mask(uint32_t port_num, TransportProto port_type);

protected:
	friend class ValManager;
	PortVal(uint32_t p);

	void ValDescribe(ODesc* d) const override;
	IntrusivePtr<Val> DoClone(CloneState* state) override;
};

class AddrVal final : public Val {
public:
	explicit AddrVal(const char* text);
	explicit AddrVal(const std::string& text);
	~AddrVal() override;

	IntrusivePtr<Val> SizeVal() const override;

	// Constructor for address already in network order.
	explicit AddrVal(uint32_t addr);          // IPv4.
	explicit AddrVal(const uint32_t addr[4]); // IPv6.
	explicit AddrVal(const IPAddr& addr);

	unsigned int MemoryAllocation() const override;

protected:
	IntrusivePtr<Val> DoClone(CloneState* state) override;
};

class SubNetVal final : public Val {
public:
	explicit SubNetVal(const char* text);
	SubNetVal(const char* text, int width);
	SubNetVal(uint32_t addr, int width); // IPv4.
	SubNetVal(const uint32_t addr[4], int width); // IPv6.
	SubNetVal(const IPAddr& addr, int width);
	explicit SubNetVal(const IPPrefix& prefix);
	~SubNetVal() override;

	IntrusivePtr<Val> SizeVal() const override;

	const IPAddr& Prefix() const;
	int Width() const;
	IPAddr Mask() const;

	bool Contains(const IPAddr& addr) const;

	unsigned int MemoryAllocation() const override;

protected:
	void ValDescribe(ODesc* d) const override;
	IntrusivePtr<Val> DoClone(CloneState* state) override;
};

class StringVal final : public Val {
public:
	explicit StringVal(BroString* s);
	explicit StringVal(const char* s);
	explicit StringVal(const std::string& s);
	StringVal(int length, const char* s);

	IntrusivePtr<Val> SizeVal() const override;

	int Len();
	const u_char* Bytes();
	const char* CheckString();

	// Note that one needs to de-allocate the return value of
	// ExpandedString() to avoid a memory leak.
	// char* ExpandedString(int format = BroString::EXPANDED_STRING)
	// 	{ return AsString()->ExpandedString(format); }

	std::string ToStdString() const;
	StringVal* ToUpper();

	unsigned int MemoryAllocation() const override;

	IntrusivePtr<StringVal> Substitute(RE_Matcher* re, StringVal* repl, bool do_all);

protected:
	void ValDescribe(ODesc* d) const override;
	IntrusivePtr<Val> DoClone(CloneState* state) override;
};

class PatternVal final : public Val {
public:
	explicit PatternVal(RE_Matcher* re);
	~PatternVal() override;

	bool AddTo(Val* v, bool is_first_init) const override;

	void SetMatcher(RE_Matcher* re);

	unsigned int MemoryAllocation() const override;

protected:
	void ValDescribe(ODesc* d) const override;
	IntrusivePtr<Val> DoClone(CloneState* state) override;
};

// ListVals are mainly used to index tables that have more than one
// element in their index.
class ListVal final : public Val {
public:
	explicit ListVal(TypeTag t);
	~ListVal() override;

	TypeTag BaseTag() const		{ return tag; }

	IntrusivePtr<Val> SizeVal() const override;

	int Length() const		{ return vals.size(); }

	const IntrusivePtr<Val>& Idx(size_t i) const	{ return vals[i]; }

	[[deprecated("Remove in v4.1.  Use Idx() instead")]]
	Val* Index(const int n)		{ return vals[n].get(); }
	[[deprecated("Remove in v4.1.  Use Idx() instead")]]
	const Val* Index(const int n) const	{ return vals[n].get(); }

	// Returns an RE_Matcher() that will match any string that
	// includes embedded within it one of the patterns listed
	// (as a string, e.g., "foo|bar") in this ListVal.
	//
	// Assumes that all of the strings in the list are NUL-terminated
	// and do not have any embedded NULs.
	//
	// The return RE_Matcher has not yet been compiled.
	RE_Matcher* BuildRE() const;

	/**
	 * Appends a value to the list.
	 * @param v  the value to append.
	 */
	void Append(IntrusivePtr<Val> v);

	[[deprecated("Remove in v4.1.  Use Append(IntrusivePtr) instead.")]]
	void Append(Val* v);

	// Returns a Set representation of the list (which must be homogeneous).
	IntrusivePtr<TableVal> ToSetVal() const;

	[[deprecated("Remove in v4.1.  Use ToSetVal() instead.")]]
	TableVal* ConvertToSet() const;

	const std::vector<IntrusivePtr<Val>>& Vals() const	{ return vals; }

	void Describe(ODesc* d) const override;

	unsigned int MemoryAllocation() const override;

protected:
	IntrusivePtr<Val> DoClone(CloneState* state) override;

	std::vector<IntrusivePtr<Val>> vals;
	TypeTag tag;
};

extern double bro_start_network_time;

class TableEntryVal {
public:
	template<typename V>
	explicit TableEntryVal(V&& v)
		: val(std::forward<V>(v))
		{
		last_access_time = network_time;
		expire_access_time =
			int(network_time - bro_start_network_time);
		}

	TableEntryVal* Clone(Val::CloneState* state);

	Val* Value()	{ return val.get(); }

	// Returns/sets time of last expiration relevant access to this value.
	double ExpireAccessTime() const
		{ return bro_start_network_time + expire_access_time; }
	void SetExpireAccess(double time)
		{ expire_access_time = int(time - bro_start_network_time); }

protected:
	friend class TableVal;

	IntrusivePtr<Val> val;
	double last_access_time;

	// The next entry stores seconds since Bro's start.  We use ints here
	// to save a few bytes, as we do not need a high resolution for these
	// anyway.
	int expire_access_time;
};

class TableValTimer final : public Timer {
public:
	TableValTimer(TableVal* val, double t);
	~TableValTimer() override;

	void Dispatch(double t, bool is_expire) override;

	TableVal* Table()	{ return table; }

protected:
	TableVal* table;
};

class CompositeHash;
class HashKey;
class Frame;

class TableVal final : public Val, public notifier::Modifiable {
public:
	explicit TableVal(IntrusivePtr<TableType> t, IntrusivePtr<Attributes> attrs = nullptr);
	~TableVal() override;

	// Returns true if the assignment typechecked, false if not. The
	// methods take ownership of new_val, but not of the index. Second
	// version takes a HashKey and Unref()'s it when done. If we're a
	// set, new_val has to be nil. If we aren't a set, index may be nil
	// in the second version.
	bool Assign(Val* index, IntrusivePtr<Val> new_val);
	bool Assign(Val* index, Val* new_val);
	bool Assign(Val* index, HashKey* k, IntrusivePtr<Val> new_val);
	bool Assign(Val* index, HashKey* k, Val* new_val);

	IntrusivePtr<Val> SizeVal() const override;

	// Add the entire contents of the table to the given value,
	// which must also be a TableVal.
	// Returns true if the addition typechecked, false if not.
	// If is_first_init is true, then this is the *first* initialization
	// (and so should be strictly adding new elements).
	bool AddTo(Val* v, bool is_first_init) const override;

	// Same but allows suppression of state operations.
	bool AddTo(Val* v, bool is_first_init, bool propagate_ops) const;

	// Remove the entire contents.
	void RemoveAll();

	// Remove the entire contents of the table from the given value.
	// which must also be a TableVal.
	// Returns true if the addition typechecked, false if not.
	bool RemoveFrom(Val* v) const override;

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
	bool ExpandAndInit(IntrusivePtr<Val> index, IntrusivePtr<Val> new_val);

	// Returns the element's value if it exists in the table,
	// nil otherwise.  Note, "index" is not const because we
	// need to Ref/Unref it when calling the default function.
	IntrusivePtr<Val> Lookup(Val* index, bool use_default_val = true);

	// For a table[subnet]/set[subnet], return all subnets that cover
	// the given subnet.
	// Causes an internal error if called for any other kind of table.
	IntrusivePtr<VectorVal> LookupSubnets(const SubNetVal* s);

	// For a set[subnet]/table[subnet], return a new table that only contains
	// entries that cover the given subnet.
	// Causes an internal error if called for any other kind of table.
	IntrusivePtr<TableVal> LookupSubnetValues(const SubNetVal* s);

	// Sets the timestamp for the given index to network time.
	// Returns false if index does not exist.
	bool UpdateTimestamp(Val* index);

	// Returns the index corresponding to the given HashKey.
	IntrusivePtr<ListVal> RecoverIndex(const HashKey* k) const;

	// Returns the element if it was in the table, false otherwise.
	IntrusivePtr<Val> Delete(const Val* index);
	IntrusivePtr<Val> Delete(const HashKey* k);

	// Returns a ListVal representation of the table (which must be a set).
	IntrusivePtr<ListVal> ToListVal(TypeTag t = TYPE_ANY) const;

	// Returns a ListVal representation of the table (which must be a set
	// with non-composite index type).
	IntrusivePtr<ListVal> ToPureListVal() const;

	[[deprecated("Remove in v4.1.  Use ToListVal() instead.")]]
	ListVal* ConvertToList(TypeTag t=TYPE_ANY) const;
	[[deprecated("Remove in v4.1.  Use ToPureListVal() instead.")]]
	ListVal* ConvertToPureList() const;	// must be single index type

	void SetAttrs(IntrusivePtr<Attributes> attrs);
	Attr* FindAttr(attr_tag t) const;
	Attributes* Attrs()	{ return attrs.get(); }

	// Returns the size of the table.
	int Size() const;
	int RecursiveSize() const;

	// Returns the Prefix table used inside the table (if present).
	// This allows us to do more direct queries to this specialized
	// type that the general Table API does not allow.
	const PrefixTable* Subnets() const { return subnets; }

	void Describe(ODesc* d) const override;

	void InitTimer(double delay);
	void DoExpire(double t);

	// If the &default attribute is not a function, or the functon has
	// already been initialized, this does nothing. Otherwise, evaluates
	// the function in the frame allowing it to capture its closure.
	void InitDefaultFunc(Frame* f);

	unsigned int MemoryAllocation() const override;

	void ClearTimer(Timer* t)
		{
		if ( timer == t )
			timer = nullptr;
		}

	HashKey* ComputeHash(const Val* index) const;

	notifier::Modifiable* Modifiable() override	{ return this; }

	// Retrieves and saves all table state (key-value pairs) for
	// tables whose index type depends on the given RecordType.
	static void SaveParseTimeTableState(RecordType* rt);

	// Rebuilds all TableVals whose state was previously saved by
	// SaveParseTimeTableState().  This is used to re-recreate the tables
	// in the event that a record type gets redefined while parsing.
	static void RebuildParseTimeTables();

	// Clears all state that was used to track TableVals that depending
	// on RecordTypes.
	static void DoneParsing();

protected:
	void Init(IntrusivePtr<TableType> t);

	using TableRecordDependencies = std::unordered_map<RecordType*, std::vector<IntrusivePtr<TableVal>>>;

	using ParseTimeTableState = std::vector<std::pair<IntrusivePtr<Val>, IntrusivePtr<Val>>>;
	using ParseTimeTableStates = std::unordered_map<TableVal*, ParseTimeTableState>;

	ParseTimeTableState DumpTableState();
	void RebuildTable(ParseTimeTableState ptts);

	void CheckExpireAttr(attr_tag at);
	bool ExpandCompoundAndInit(ListVal* lv, int k, IntrusivePtr<Val> new_val);
	bool CheckAndAssign(Val* index, IntrusivePtr<Val> new_val);

	// Calculates default value for index.  Returns 0 if none.
	IntrusivePtr<Val> Default(Val* index);

	// Returns true if item expiration is enabled.
	bool ExpirationEnabled()	{ return expire_time != nullptr; }

	// Returns the expiration time defined by %{create,read,write}_expire
	// attribute, or -1 for unset/invalid values. In the invalid case, an
	// error will have been reported.
	double GetExpireTime();

	// Calls &expire_func and returns its return interval;
	double CallExpireFunc(IntrusivePtr<ListVal> idx);

	// Enum for the different kinds of changes an &on_change handler can see
	enum OnChangeType { ELEMENT_NEW, ELEMENT_CHANGED, ELEMENT_REMOVED, ELEMENT_EXPIRED };

	// Calls &change_func. Does not take ownership of values. (Refs if needed).
	void CallChangeFunc(const Val* index, Val* old_value, OnChangeType tpe);

	IntrusivePtr<Val> DoClone(CloneState* state) override;

	IntrusivePtr<TableType> table_type;
	CompositeHash* table_hash;
	IntrusivePtr<Attributes> attrs;
	IntrusivePtr<Expr> expire_time;
	IntrusivePtr<Expr> expire_func;
	TableValTimer* timer;
	IterCookie* expire_cookie;
	PrefixTable* subnets;
	IntrusivePtr<Val> def_val;
	IntrusivePtr<Expr> change_func;
	// prevent recursion of change functions
	bool in_change_func = false;

	static TableRecordDependencies parse_time_table_record_dependencies;
	static ParseTimeTableStates parse_time_table_states;
};

class RecordVal final : public Val, public notifier::Modifiable {
public:
	explicit RecordVal(RecordType* t, bool init_fields = true);
	explicit RecordVal(IntrusivePtr<RecordType> t, bool init_fields = true);

	~RecordVal() override;

	IntrusivePtr<Val> SizeVal() const override;

	void Assign(int field, IntrusivePtr<Val> new_val);
	void Assign(int field, Val* new_val);
	Val* Lookup(int field) const;	// Does not Ref() value.
	IntrusivePtr<Val> LookupWithDefault(int field) const;

	/**
	 * Looks up the value of a field by field name.  If the field doesn't
	 * exist in the record type, it's an internal error: abort.
	 * @param field name of field to lookup.
	 * @param with_default whether to rely on field's &default attribute when
	 * the field has yet to be initialized.
	 * @return the value in field \a field.
	 */
	IntrusivePtr<Val> Lookup(const char* field, bool with_default = false) const;

	void Describe(ODesc* d) const override;

	/**
	 * Returns a "record_field_table" value for introspection purposes.
	 */
	IntrusivePtr<TableVal> GetRecordFieldsVal() const;

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
	IntrusivePtr<RecordVal> CoerceTo(const RecordType* other, Val* aggr, bool allow_orphaning = false) const;
	IntrusivePtr<RecordVal> CoerceTo(RecordType* other, bool allow_orphaning = false);

	unsigned int MemoryAllocation() const override;
	void DescribeReST(ODesc* d) const override;

	notifier::Modifiable* Modifiable() override	{ return this; }

	// Extend the underlying arrays of record instances created during
	// parsing to match the number of fields in the record type (they may
	// mismatch as a result of parse-time record type redefinitions.
	static void ResizeParseTimeRecords(RecordType* rt);

	static void DoneParsing();

protected:
	IntrusivePtr<Val> DoClone(CloneState* state) override;

	BroObj* origin;

	using RecordTypeValMap = std::unordered_map<RecordType*, std::vector<IntrusivePtr<RecordVal>>>;
	static RecordTypeValMap parse_time_records;
};

class EnumVal final : public Val {
public:
	IntrusivePtr<Val> SizeVal() const override;

protected:
	friend class Val;
	friend class EnumType;

	template<class T, class... Ts>
	friend IntrusivePtr<T> make_intrusive(Ts&&... args);

	EnumVal(EnumType* t, int i) : Val(bro_int_t(i), {NewRef{}, t})
		{
		}

	void ValDescribe(ODesc* d) const override;
	IntrusivePtr<Val> DoClone(CloneState* state) override;
};


class VectorVal final : public Val, public notifier::Modifiable {
public:
	[[deprecated("Remove in v4.1.  Construct from IntrusivePtr instead.")]]
	explicit VectorVal(VectorType* t);
	explicit VectorVal(IntrusivePtr<VectorType> t);
	~VectorVal() override;

	IntrusivePtr<Val> SizeVal() const override;

	// Returns false if the type of the argument was wrong.
	// The vector will automatically grow to accomodate the index.
	//
	// Note: does NOT Ref() the element! Remember to do so unless
	//       the element was just created and thus has refcount 1.
	//
	bool Assign(unsigned int index, IntrusivePtr<Val> element);
	bool Assign(unsigned int index, Val* element);

	template<typename E>
	bool Assign(Val* index, E&& element)
		{
		return Assign(index->AsListVal()->Idx(0)->CoerceToUnsigned(),
		              std::forward<E>(element));
		}

	// Assigns the value to how_many locations starting at index.
	bool AssignRepeat(unsigned int index, unsigned int how_many,
			  Val* element);

	// Add this value to the given value (if appropriate).
	// Returns true if succcessful.
	bool AddTo(Val* v, bool is_first_init) const override;

	// Returns nil if no element was at that value.
	// Lookup does NOT grow the vector to this size.
	// The Val* variant assumes that the index Val* has been type-checked.
	Val* Lookup(unsigned int index) const;
	Val* Lookup(Val* index)
		{
		bro_uint_t i = index->AsListVal()->Idx(0)->CoerceToUnsigned();
		return Lookup(static_cast<unsigned int>(i));
		}

	unsigned int Size() const { return val.vector_val->size(); }

	// Is there any way to reclaim previously-allocated memory when you
	// shrink a vector?  The return value is the old size.
	unsigned int Resize(unsigned int new_num_elements);

	// Won't shrink size.
	unsigned int ResizeAtLeast(unsigned int new_num_elements);

	notifier::Modifiable* Modifiable() override	{ return this; }

	// Insert an element at a specific position into the underlying vector.
	bool Insert(unsigned int index, Val* element);

	// Removes an element at a specific position.
	bool Remove(unsigned int index);

protected:
	void ValDescribe(ODesc* d) const override;
	IntrusivePtr<Val> DoClone(CloneState* state) override;
};

// Checks the given value for consistency with the given type.  If an
// exact match, returns it.  If promotable, returns the promoted version,
// Unref()'ing the original.  If not a match, generates an error message
// and returns nil, also Unref()'ing v.  If is_init is true, then
// the checking is done in the context of an initialization.
extern IntrusivePtr<Val> check_and_promote(IntrusivePtr<Val> v,
                                           const BroType* t, bool is_init,
                                           const Location* expr_location = nullptr);

extern bool same_val(const Val* v1, const Val* v2);
extern bool same_atomic_val(const Val* v1, const Val* v2);
extern bool is_atomic_val(const Val* v);
extern void describe_vals(const val_list* vals, ODesc* d, int offset=0);
extern void describe_vals(const std::vector<IntrusivePtr<Val>>& vals,
                          ODesc* d, size_t offset = 0);
extern void delete_vals(val_list* vals);

// True if the given Val* has a vector type.
inline bool is_vector(Val* v)	{ return  v->GetType()->Tag() == TYPE_VECTOR; }

// Returns v casted to type T if the type supports that. Returns null if not.
//
// Note: This implements the script-level cast operator.
extern IntrusivePtr<Val> cast_value_to_type(Val* v, BroType* t);

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
