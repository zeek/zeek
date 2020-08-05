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

namespace zeek {
template<typename T> class PDict;
class String;
}
template<typename T> using PDict [[deprecated("Remove in v4.1. Use zeek::PDict instead.")]] = zeek::PDict<T>;
using BroString [[deprecated("Remove in v4.1. Use zeek::String instead.")]] = zeek::String;

ZEEK_FORWARD_DECLARE_NAMESPACED(IterCookie, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Frame, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Func, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(IPAddr, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(IPPrefix, zeek);
namespace zeek {
class File;
using FilePtr = zeek::IntrusivePtr<File>;
}
using BroFile [[deprecated("Remove in v4.1. Use zeek::File.")]] = zeek::File;
using BroFilePtr [[deprecated("Remove in v4.1. Use zeek::FilePtr.")]] = zeek::FilePtr;

namespace zeek::detail { class ScriptFunc; }
using BroFunc [[deprecated("Remove in v4.1. Use zeek::detail::ScriptFunc instead.")]] = zeek::detail::ScriptFunc;

ZEEK_FORWARD_DECLARE_NAMESPACED(PrefixTable, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(RE_Matcher, zeek);

ZEEK_FORWARD_DECLARE_NAMESPACED(CompositeHash, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(HashKey, zeek::detail);

namespace zeek {
namespace net {
	extern double network_time;
	extern double zeek_start_network_time;
}

using FuncPtr = zeek::IntrusivePtr<Func>;
using FilePtr = zeek::IntrusivePtr<File>;

class Val;
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
class VectorVal;
class TableEntryVal;

using AddrValPtr = zeek::IntrusivePtr<AddrVal>;
using EnumValPtr = zeek::IntrusivePtr<EnumVal>;
using ListValPtr = zeek::IntrusivePtr<ListVal>;
using PortValPtr = zeek::IntrusivePtr<PortVal>;
using RecordValPtr = zeek::IntrusivePtr<RecordVal>;
using StringValPtr = zeek::IntrusivePtr<StringVal>;
using TableValPtr = zeek::IntrusivePtr<TableVal>;
using ValPtr = zeek::IntrusivePtr<Val>;
using VectorValPtr = zeek::IntrusivePtr<VectorVal>;

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

	String* string_val;
	zeek::Func* func_val;
	File* file_val;
	RE_Matcher* re_val;
	zeek::PDict<TableEntryVal>* table_val;
	std::vector<ValPtr>* record_val;
	std::vector<ValPtr>* vector_val;

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

	constexpr BroValUnion(String* value) noexcept
		: string_val(value) {}

	constexpr BroValUnion(zeek::Func* value) noexcept
		: func_val(value) {}

	constexpr BroValUnion(File* value) noexcept
		: file_val(value) {}

	constexpr BroValUnion(RE_Matcher* value) noexcept
		: re_val(value) {}

	constexpr BroValUnion(zeek::PDict<TableEntryVal>* value) noexcept
		: table_val(value) {}
};

class Val : public Obj {
public:
	static inline const ValPtr nil;

	[[deprecated("Remove in v4.1.  Use IntervalVal(), TimeVal(), or DoubleVal() constructors.")]]
	Val(double d, zeek::TypeTag t)
		: val(d), type(zeek::base_type(t))
		{}

	[[deprecated("Remove in v4.1.  Construct from IntrusivePtr instead.")]]
	explicit Val(zeek::Func* f);
	explicit Val(zeek::FuncPtr f);

	[[deprecated("Remove in v4.1.  Construct from IntrusivePtr instead.")]]
	explicit Val(File* f);
	// Note, the file will be closed after this Val is destructed if there's
	// no other remaining references.
	explicit Val(FilePtr f);

	// Extra arg to differentiate from protected version.
	Val(zeek::TypePtr t, bool type_type)
		: type(zeek::make_intrusive<zeek::TypeType>(std::move(t)))
		{}

	[[deprecated("Remove in v4.1.  Construct from IntrusivePtr instead.")]]
	Val(zeek::Type* t, bool type_type) : Val({zeek::NewRef{}, t}, type_type)
		{}

	Val()
		: val(bro_int_t(0)), type(zeek::base_type(zeek::TYPE_ERROR))
		{}

	~Val() override;

	Val* Ref()			{ zeek::Ref(this); return this; }
	ValPtr Clone();

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
	virtual ValPtr SizeVal() const;

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
	zeek::Type* Type()			{ return type.get(); }
	[[deprecated("Remove in v4.1.  Use GetType().")]]
	const zeek::Type* Type() const	{ return type.get(); }

	const zeek::TypePtr& GetType() const
		{ return type; }

	template <class T>
	zeek::IntrusivePtr<T> GetType() const
		{ return zeek::cast_intrusive<T>(type); }

#define CONST_ACCESSOR(tag, ctype, accessor, name) \
	const ctype name() const \
		{ \
		CHECK_TAG(type->Tag(), tag, "Val::CONST_ACCESSOR", zeek::type_name) \
		return val.accessor; \
		}

	// Needed for g++ 4.3's pickiness.
#define CONST_ACCESSOR2(tag, ctype, accessor, name) \
	ctype name() const \
		{ \
		CHECK_TAG(type->Tag(), tag, "Val::CONST_ACCESSOR", zeek::type_name) \
		return val.accessor; \
		}

	CONST_ACCESSOR2(zeek::TYPE_BOOL, bool, int_val, AsBool)
	CONST_ACCESSOR2(zeek::TYPE_INT, bro_int_t, int_val, AsInt)
	CONST_ACCESSOR2(zeek::TYPE_COUNT, bro_uint_t, uint_val, AsCount)
	CONST_ACCESSOR2(zeek::TYPE_DOUBLE, double, double_val, AsDouble)
	CONST_ACCESSOR2(zeek::TYPE_TIME, double, double_val, AsTime)
	CONST_ACCESSOR2(zeek::TYPE_INTERVAL, double, double_val, AsInterval)
	CONST_ACCESSOR2(zeek::TYPE_ENUM, int, int_val, AsEnum)
	CONST_ACCESSOR(zeek::TYPE_STRING, String*, string_val, AsString)
	CONST_ACCESSOR(zeek::TYPE_FUNC, zeek::Func*, func_val, AsFunc)
	CONST_ACCESSOR(zeek::TYPE_TABLE, zeek::PDict<TableEntryVal>*, table_val, AsTable)
	CONST_ACCESSOR(zeek::TYPE_RECORD, std::vector<ValPtr>*, record_val, AsRecord)
	CONST_ACCESSOR(zeek::TYPE_FILE, File*, file_val, AsFile)
	CONST_ACCESSOR(zeek::TYPE_PATTERN, RE_Matcher*, re_val, AsPattern)
	CONST_ACCESSOR(zeek::TYPE_VECTOR, std::vector<ValPtr>*, vector_val, AsVector)

	const IPPrefix& AsSubNet() const
		{
		CHECK_TAG(type->Tag(), zeek::TYPE_SUBNET, "Val::SubNet", zeek::type_name)
		return *val.subnet_val;
		}

	zeek::Type* AsType() const
		{
		CHECK_TAG(type->Tag(), zeek::TYPE_TYPE, "Val::Type", zeek::type_name)
		return type.get();
		}

	const IPAddr& AsAddr() const
		{
		if ( type->Tag() != zeek::TYPE_ADDR )
			BadTag("Val::AsAddr", zeek::type_name(type->Tag()));
		return *val.addr_val;
		}

#define ACCESSOR(tag, ctype, accessor, name) \
	ctype name() \
		{ \
		CHECK_TAG(type->Tag(), tag, "Val::ACCESSOR", zeek::type_name) \
		return val.accessor; \
		}

	// Accessors for mutable values are called AsNonConst* and
	// are protected to avoid external state changes.
	// ACCESSOR(zeek::TYPE_STRING, String*, string_val, AsString)
	ACCESSOR(zeek::TYPE_FUNC, zeek::Func*, func_val, AsFunc)
	ACCESSOR(zeek::TYPE_FILE, File*, file_val, AsFile)
	ACCESSOR(zeek::TYPE_PATTERN, RE_Matcher*, re_val, AsPattern)
	ACCESSOR(zeek::TYPE_VECTOR, std::vector<ValPtr>*, vector_val, AsVector)

	zeek::FuncPtr AsFuncPtr() const;

	const IPPrefix& AsSubNet()
		{
		CHECK_TAG(type->Tag(), zeek::TYPE_SUBNET, "Val::SubNet", zeek::type_name)
		return *val.subnet_val;
		}

	const IPAddr& AsAddr()
		{
		if ( type->Tag() != zeek::TYPE_ADDR )
			BadTag("Val::AsAddr", zeek::type_name(type->Tag()));
		return *val.addr_val;
		}

	// Gives fast access to the bits of something that is one of
	// bool, int, count, or counter.
	bro_int_t ForceAsInt() const		{ return val.int_val; }
	bro_uint_t ForceAsUInt() const		{ return val.uint_val; }

	PatternVal* AsPatternVal();
	const PatternVal* AsPatternVal() const;

	PortVal* AsPortVal();
	const PortVal* AsPortVal() const;

	SubNetVal* AsSubNetVal();
	const SubNetVal* AsSubNetVal() const;

	AddrVal* AsAddrVal();
	const AddrVal* AsAddrVal() const;

	TableVal* AsTableVal();
	const TableVal* AsTableVal() const;

	RecordVal* AsRecordVal();
	const RecordVal* AsRecordVal() const;

	ListVal* AsListVal();
	const ListVal* AsListVal() const;

	StringVal* AsStringVal();
	const StringVal* AsStringVal() const;

	VectorVal* AsVectorVal();
	const VectorVal* AsVectorVal() const;

	EnumVal* AsEnumVal();
	const EnumVal* AsEnumVal() const;

	OpaqueVal* AsOpaqueVal();
	const OpaqueVal* AsOpaqueVal() const;

	void Describe(ODesc* d) const override;
	virtual void DescribeReST(ODesc* d) const;

	// To be overridden by mutable derived class to enable change
	// notification.
	virtual zeek::notifier::detail::Modifiable* Modifiable()	{ return nullptr; }

#ifdef DEBUG
	// For debugging, we keep a reference to the global ID to which a
	// value has been bound *last*.
	zeek::detail::ID* GetID() const;

	void SetID(zeek::detail::ID* id);
#endif

	static bool WouldOverflow(const zeek::Type* from_type, const zeek::Type* to_type, const Val* val);

	TableValPtr GetRecordFields();

	StringValPtr ToJSON(bool only_loggable=false, RE_Matcher* re=nullptr);

protected:

	friend class zeek::EnumType;
	friend class ListVal;
	friend class RecordVal;
	friend class VectorVal;
	friend class ValManager;
	friend class TableEntryVal;

	virtual void ValDescribe(ODesc* d) const;
	virtual void ValDescribeReST(ODesc* d) const;

	static ValPtr MakeBool(bool b);
	static ValPtr MakeInt(bro_int_t i);
	static ValPtr MakeCount(bro_uint_t u);

	template<typename V>
	Val(V&& v, zeek::TypeTag t) noexcept
		: val(std::forward<V>(v)), type(zeek::base_type(t))
		{}

	template<typename V>
	Val(V&& v, zeek::TypePtr t) noexcept
		: val(std::forward<V>(v)), type(std::move(t))
		{}

	explicit Val(zeek::TypePtr t) noexcept
		: type(std::move(t))
		{}

	ACCESSOR(zeek::TYPE_TABLE, zeek::PDict<TableEntryVal>*, table_val, AsNonConstTable)
	ACCESSOR(zeek::TYPE_RECORD, std::vector<ValPtr>*, record_val, AsNonConstRecord)

	// For internal use by the Val::Clone() methods.
	struct CloneState {
		// Caches a cloned value for later reuse during the same
		// cloning operation. For recursive types, call this *before*
		// descending down.
		ValPtr NewClone(Val* src, ValPtr dst);

		std::unordered_map<Val*, Val*> clones;
	};

	ValPtr Clone(CloneState* state);
	virtual ValPtr DoClone(CloneState* state);

	BroValUnion val;
	zeek::TypePtr type;

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

	[[deprecated("Remove in v4.1.  Use zeek::val_mgr->True() instead.")]]
	inline Val* GetTrue() const
		{ return b_true->Ref(); }

	inline const ValPtr& True() const
		{ return b_true; }

	[[deprecated("Remove in v4.1.  Use zeek::val_mgr->False() instead.")]]
	inline Val* GetFalse() const
		{ return b_false->Ref(); }

	inline const ValPtr& False() const
		{ return b_false; }

	[[deprecated("Remove in v4.1.  Use zeek::val_mgr->Bool() instead.")]]
	inline Val* GetBool(bool b) const
		{ return b ? b_true->Ref() : b_false->Ref(); }

	inline const ValPtr& Bool(bool b) const
		{ return b ? b_true : b_false; }

	[[deprecated("Remove in v4.1.  Use zeek::val_mgr->Int() instead.")]]
	inline Val* GetInt(int64_t i) const
		{
		return i < PREALLOCATED_INT_LOWEST || i > PREALLOCATED_INT_HIGHEST ?
		    Val::MakeInt(i).release() : ints[i - PREALLOCATED_INT_LOWEST]->Ref();
		}

	inline ValPtr Int(int64_t i) const
		{
		return i < PREALLOCATED_INT_LOWEST || i > PREALLOCATED_INT_HIGHEST ?
		    Val::MakeInt(i) : ints[i - PREALLOCATED_INT_LOWEST];
		}

	[[deprecated("Remove in v4.1.  Use zeek::val_mgr->Count() instead.")]]
	inline Val* GetCount(uint64_t i) const
		{
		return i >= PREALLOCATED_COUNTS ? Val::MakeCount(i).release() : counts[i]->Ref();
		}

	inline ValPtr Count(uint64_t i) const
		{
		return i >= PREALLOCATED_COUNTS ? Val::MakeCount(i) : counts[i];
		}

	[[deprecated("Remove in v4.1.  Use zeek::val_mgr->EmptyString() instead.")]]
	StringVal* GetEmptyString() const;

	inline const StringValPtr& EmptyString() const
		{ return empty_string; }

	// Port number given in host order.
	[[deprecated("Remove in v4.1.  Use zeek::val_mgr->Port() instead.")]]
	PortVal* GetPort(uint32_t port_num, TransportProto port_type) const;

	// Port number given in host order.
	const PortValPtr& Port(uint32_t port_num, TransportProto port_type) const;

	// Host-order port number already masked with port space protocol mask.
	[[deprecated("Remove in v4.1.  Use zeek::val_mgr->Port() instead.")]]
	PortVal* GetPort(uint32_t port_num) const;

	// Host-order port number already masked with port space protocol mask.
	const PortValPtr& Port(uint32_t port_num) const;

private:

	std::array<std::array<PortValPtr, 65536>, NUM_PORT_SPACES> ports;
	std::array<ValPtr, PREALLOCATED_COUNTS> counts;
	std::array<ValPtr, PREALLOCATED_INTS> ints;
	StringValPtr empty_string;
	ValPtr b_true;
	ValPtr b_false;
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
	IntervalVal(double quantity, double units = Seconds)
		: Val(quantity * units, zeek::base_type(zeek::TYPE_INTERVAL))
		{}

protected:
	void ValDescribe(ODesc* d) const override;
};

class TimeVal final : public Val {
public:
	TimeVal(double t)
		: Val(t, zeek::base_type(zeek::TYPE_TIME))
		{}
};

class DoubleVal final : public Val {
public:
	DoubleVal(double v)
		: Val(v, zeek::base_type(zeek::TYPE_DOUBLE))
		{}
};

class PortVal final : public Val {
public:
	ValPtr SizeVal() const override;

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
	ValPtr DoClone(CloneState* state) override;
};

class AddrVal final : public Val {
public:
	explicit AddrVal(const char* text);
	explicit AddrVal(const std::string& text);
	~AddrVal() override;

	ValPtr SizeVal() const override;

	// Constructor for address already in network order.
	explicit AddrVal(uint32_t addr);          // IPv4.
	explicit AddrVal(const uint32_t addr[4]); // IPv6.
	explicit AddrVal(const IPAddr& addr);

	unsigned int MemoryAllocation() const override;

protected:
	ValPtr DoClone(CloneState* state) override;
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

	ValPtr SizeVal() const override;

	const IPAddr& Prefix() const;
	int Width() const;
	IPAddr Mask() const;

	bool Contains(const IPAddr& addr) const;

	unsigned int MemoryAllocation() const override;

protected:
	void ValDescribe(ODesc* d) const override;
	ValPtr DoClone(CloneState* state) override;
};

class StringVal final : public Val {
public:
	explicit StringVal(String* s);
	explicit StringVal(const char* s);
	explicit StringVal(const std::string& s);
	StringVal(int length, const char* s);

	ValPtr SizeVal() const override;

	int Len();
	const u_char* Bytes();
	const char* CheckString();

	// Note that one needs to de-allocate the return value of
	// ExpandedString() to avoid a memory leak.
	// char* ExpandedString(int format = String::EXPANDED_STRING)
	// 	{ return AsString()->ExpandedString(format); }

	std::string ToStdString() const;
	StringVal* ToUpper();

	unsigned int MemoryAllocation() const override;

	StringValPtr Replace(RE_Matcher* re, const String& repl,
	                                      bool do_all);

	[[deprecated("Remove in v4.1.  Use Replace().")]]
	Val* Substitute(RE_Matcher* re, StringVal* repl, bool do_all)
		{ return Replace(re, *repl->AsString(), do_all).release(); }

protected:
	void ValDescribe(ODesc* d) const override;
	ValPtr DoClone(CloneState* state) override;
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
	ValPtr DoClone(CloneState* state) override;
};

// ListVals are mainly used to index tables that have more than one
// element in their index.
class ListVal final : public Val {
public:
	explicit ListVal(zeek::TypeTag t);

	~ListVal() override;

	zeek::TypeTag BaseTag() const		{ return tag; }

	ValPtr SizeVal() const override;

	int Length() const		{ return vals.size(); }

	const ValPtr& Idx(size_t i) const	{ return vals[i]; }

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
	void Append(ValPtr v);

	[[deprecated("Remove in v4.1.  Use Append(IntrusivePtr) instead.")]]
	void Append(Val* v);

	// Returns a Set representation of the list (which must be homogeneous).
	TableValPtr ToSetVal() const;

	[[deprecated("Remove in v4.1.  Use ToSetVal() instead.")]]
	TableVal* ConvertToSet() const;

	const std::vector<ValPtr>& Vals() const	{ return vals; }

	void Describe(ODesc* d) const override;

	unsigned int MemoryAllocation() const override;

protected:
	ValPtr DoClone(CloneState* state) override;

	std::vector<ValPtr> vals;
	zeek::TypeTag tag;
};

class TableEntryVal {
public:
	explicit TableEntryVal(ValPtr v)
		: val(std::move(v))
		{
		expire_access_time =
			int(net::network_time - net::zeek_start_network_time);
		}

	TableEntryVal* Clone(Val::CloneState* state);

	[[deprecated("Remove in v4.1.  Use GetVal().")]]
	Val* Value()	{ return val.get(); }

	const ValPtr& GetVal() const
		{ return val; }

	// Returns/sets time of last expiration relevant access to this value.
	double ExpireAccessTime() const
		{ return net::zeek_start_network_time + expire_access_time; }
	void SetExpireAccess(double time)
		{ expire_access_time = int(time - net::zeek_start_network_time); }

protected:
	friend class TableVal;

	ValPtr val;

	// The next entry stores seconds since Bro's start.  We use ints here
	// to save a few bytes, as we do not need a high resolution for these
	// anyway.
	int expire_access_time;
};

class TableValTimer final : public zeek::detail::Timer {
public:
	TableValTimer(TableVal* val, double t);
	~TableValTimer() override;

	void Dispatch(double t, bool is_expire) override;

	TableVal* Table()	{ return table; }

protected:
	TableVal* table;
};

class TableVal final : public Val, public zeek::notifier::detail::Modifiable {
public:
	explicit TableVal(zeek::TableTypePtr t, zeek::detail::AttributesPtr attrs = nullptr);

	[[deprecated("Remove in v4.1.  Construct from IntrusivePtrs instead.")]]
	explicit TableVal(zeek::TableType* t, zeek::detail::Attributes* attrs = nullptr)
		: TableVal({zeek::NewRef{}, t}, {zeek::NewRef{}, attrs})
		{}

	~TableVal() override;

	/**
	 * Assigns a value at an associated index in the table (or in the
	 * case of a set, just adds the index).
	 * @param index  The key to assign.
	 * @param new_val  The value to assign at the index.  For a set, this
	 * must be nullptr.
	 * @param broker_forward Controls if the value will be forwarded to attached
	 *        Broker stores.
	 * @return  True if the assignment type-checked.
	 */
	bool Assign(ValPtr index, ValPtr new_val, bool broker_forward = true);

	/**
	 * Assigns a value at an associated index in the table (or in the
	 * case of a set, just adds the index).
	 * @param index  The key to assign.  For tables, this is allowed to be null
	 * (if needed, the index val can be recovered from the hash key).
	 * @param k  A precomputed hash key to use.
	 * @param new_val  The value to assign at the index.  For a set, this
	 * must be nullptr.
	 * @param broker_forward Controls if the value will be forwarded to attached
	 *        Broker stores.
	 * @return  True if the assignment type-checked.
	 */
	bool Assign(ValPtr index, std::unique_ptr<zeek::detail::HashKey> k,
	            ValPtr new_val, bool broker_forward = true);

	// Returns true if the assignment typechecked, false if not. The
	// methods take ownership of new_val, but not of the index.  If we're
	// a set, new_val has to be nil.
	[[deprecated("Remove in v4.1.  Use IntrusivePtr overload instead.")]]
	bool Assign(Val* index, Val* new_val);

	// Same as other Assign() method, but takes a precomuted zeek::detail::HashKey and
	// deletes it when done.
	[[deprecated("Remove in v4.1.  Use IntrusivePtr overload instead.")]]
	bool Assign(Val* index, zeek::detail::HashKey* k, Val* new_val);

	ValPtr SizeVal() const override;

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

	/**
	 * Returns a new table that is the intersection of this table
	 * and the given table.  Intersection is done only on index, not on
	 * yield value, so this generally makes most sense to use for sets,
	 * not tables.
	 * @param v  The intersecting table.
	 * @return  The intersection of this table and the given one.
	 */
	TableValPtr Intersection(const TableVal& v) const;

	[[deprecated("Remove in v4.1.  Use Intersection() instead.")]]
	TableVal* Intersect(const TableVal* v) const
		{ return Intersection(*v).release(); }

	// Returns true if this set contains the same members as the
	// given set.  Note that comparisons are done using hash keys,
	// so errors can arise for compound sets such as sets-of-sets.
	// See https://bro-tracker.atlassian.net/browse/BIT-1949.
	bool EqualTo(const TableVal& v) const;

	[[deprecated("Remove in v4.1.  Pass TableVal& instead.")]]
	bool EqualTo(const TableVal* v) const
		{ return EqualTo(*v); }

	// Returns true if this set is a subset (not necessarily proper)
	// of the given set.
	bool IsSubsetOf(const TableVal& v) const;

	[[deprecated("Remove in v4.1.  Pass TableVal& instead.")]]
	bool IsSubsetOf(const TableVal* v) const
		{ return IsSubsetOf(*v); }

	// Expands any lists in the index into multiple initializations.
	// Returns true if the initializations typecheck, false if not.
	bool ExpandAndInit(ValPtr index, ValPtr new_val);

	/**
	 * Finds an index in the table and returns its associated value.
	 * @param index  The index to lookup in the table.
	 * @return  The value associated with the index.  If the index doesn't
	 * exist, this is a nullptr.  For sets that don't really contain associated
	 * values, a placeholder value is returned to differentiate it from
	 * non-existent index (nullptr), but otherwise has no meaning in relation
	 * to the set's contents.
	 */
	const ValPtr& Find(const ValPtr& index);

	/**
	 * Finds an index in the table and returns its associated value or else
	 * the &default value.
	 * @param index  The index to lookup in the table.
	 * @return  The value associated with the index.  If the index doesn't
	 * exist, instead returns the &default value.  If there's no &default
	 * attribute, then nullptr is still returned for non-existent index.
	 */
	ValPtr FindOrDefault(const ValPtr& index);

	// Returns the element's value if it exists in the table,
	// nil otherwise.  Note, "index" is not const because we
	// need to Ref/Unref it when calling the default function.
	[[deprecated("Remove in v4.1.  Use Find() or FindOrDefault().")]]
	Val* Lookup(Val* index, bool use_default_val = true);

	// For a table[subnet]/set[subnet], return all subnets that cover
	// the given subnet.
	// Causes an internal error if called for any other kind of table.
	VectorValPtr LookupSubnets(const SubNetVal* s);

	// For a set[subnet]/table[subnet], return a new table that only contains
	// entries that cover the given subnet.
	// Causes an internal error if called for any other kind of table.
	TableValPtr LookupSubnetValues(const SubNetVal* s);

	// Sets the timestamp for the given index to network time.
	// Returns false if index does not exist.
	bool UpdateTimestamp(Val* index);

	/**
	 * @return  The index corresponding to the given HashKey.
	 */
	ListValPtr RecreateIndex(const zeek::detail::HashKey& k) const;

	[[deprecated("Remove in v4.1.  Use RecreateIndex().")]]
	ListVal* RecoverIndex(const zeek::detail::HashKey* k) const
		{ return RecreateIndex(*k).release(); }

	/**
	 * Remove an element from the table and return it.
	 * @param index  The index to remove.
	 * @param broker_forward Controls if the remove operation will be forwarded to attached
	 *        Broker stores.
	 * @return  The value associated with the index if it exists, else nullptr.
	 * For a sets that don't really contain associated values, a placeholder
	 * value is returned to differentiate it from non-existent index (nullptr),
	 * but otherwise has no meaning in relation to the set's contents.
	 */
	ValPtr Remove(const Val& index, bool broker_forward = true);

	/**
	 * Same as Remove(const Val&), but uses a precomputed hash key.
	 * @param k  The hash key to lookup.
	 * @return  Same as Remove(const Val&).
	 */
	ValPtr Remove(const zeek::detail::HashKey& k);

	[[deprecated("Remove in v4.1.  Use Remove().")]]
	Val* Delete(const Val* index)
		{ return Remove(*index).release(); }

	[[deprecated("Remove in v4.1.  Use Remove().")]]
	Val* Delete(const zeek::detail::HashKey* k)
		{ return Remove(*k).release(); }

	// Returns a ListVal representation of the table (which must be a set).
	ListValPtr ToListVal(zeek::TypeTag t = zeek::TYPE_ANY) const;

	// Returns a ListVal representation of the table (which must be a set
	// with non-composite index type).
	ListValPtr ToPureListVal() const;

	[[deprecated("Remove in v4.1.  Use ToListVal() instead.")]]
	ListVal* ConvertToList(zeek::TypeTag t=zeek::TYPE_ANY) const;
	[[deprecated("Remove in v4.1.  Use ToPureListVal() instead.")]]
	ListVal* ConvertToPureList() const;	// must be single index type

	void SetAttrs(zeek::detail::AttributesPtr attrs);

	const zeek::detail::AttrPtr& GetAttr(zeek::detail::AttrTag t) const;

	[[deprecated("Remove in v4.1.  Use GetAttrs().")]]
	zeek::detail::Attributes* Attrs()	{ return attrs.get(); }

	const zeek::detail::AttributesPtr& GetAttrs() const
		{ return attrs; }

	// Returns the size of the table.
	int Size() const;
	int RecursiveSize() const;

	// Returns the Prefix table used inside the table (if present).
	// This allows us to do more direct queries to this specialized
	// type that the general Table API does not allow.
	const zeek::detail::PrefixTable* Subnets() const { return subnets; }

	void Describe(ODesc* d) const override;

	void InitTimer(double delay);
	void DoExpire(double t);

	// If the &default attribute is not a function, or the functon has
	// already been initialized, this does nothing. Otherwise, evaluates
	// the function in the frame allowing it to capture its closure.
	void InitDefaultFunc(zeek::detail::Frame* f);

	unsigned int MemoryAllocation() const override;

	void ClearTimer(zeek::detail::Timer* t)
		{
		if ( timer == t )
			timer = nullptr;
		}

	/**
	 * @param  The index value to hash.
	 * @return  The hash of the index value or nullptr if
	 * type-checking failed.
	 */
	std::unique_ptr<zeek::detail::HashKey> MakeHashKey(const Val& index) const;

	[[deprecated("Remove in v4.1.  Use MakeHashKey().")]]
	zeek::detail::HashKey* ComputeHash(const Val* index) const;

	zeek::notifier::detail::Modifiable* Modifiable() override	{ return this; }

	// Retrieves and saves all table state (key-value pairs) for
	// tables whose index type depends on the given zeek::RecordType.
	static void SaveParseTimeTableState(zeek::RecordType* rt);

	// Rebuilds all TableVals whose state was previously saved by
	// SaveParseTimeTableState().  This is used to re-recreate the tables
	// in the event that a record type gets redefined while parsing.
	static void RebuildParseTimeTables();

	// Clears all state that was used to track TableVals that depending
	// on zeek::RecordTypes.
	static void DoneParsing();

	/**
	 * Sets the name of the Broker store that is backing this table.
	 * @param store store that is backing this table.
	 */
	void SetBrokerStore(const std::string& store) { broker_store = store; }

	/**
	 * Disable change notification processing of &on_change until re-enabled.
	 */
	void DisableChangeNotifications() { in_change_func = true; }

	/**
	 * Re-enables change notifcations after being disabled by DisableChangeNotifications.
	 */
	void EnableChangeNotifications() { in_change_func = false; }

protected:
	void Init(zeek::TableTypePtr t);

	using TableRecordDependencies = std::unordered_map<zeek::RecordType*, std::vector<TableValPtr>>;

	using ParseTimeTableState = std::vector<std::pair<ValPtr, ValPtr>>;
	using ParseTimeTableStates = std::unordered_map<TableVal*, ParseTimeTableState>;

	ParseTimeTableState DumpTableState();
	void RebuildTable(ParseTimeTableState ptts);

	void CheckExpireAttr(zeek::detail::AttrTag at);
	bool ExpandCompoundAndInit(ListVal* lv, int k, ValPtr new_val);
	bool CheckAndAssign(ValPtr index, ValPtr new_val);

	// Calculates default value for index.  Returns nullptr if none.
	ValPtr Default(const ValPtr& index);

	// Returns true if item expiration is enabled.
	bool ExpirationEnabled()	{ return expire_time != nullptr; }

	// Returns the expiration time defined by %{create,read,write}_expire
	// attribute, or -1 for unset/invalid values. In the invalid case, an
	// error will have been reported.
	double GetExpireTime();

	// Calls &expire_func and returns its return interval;
	double CallExpireFunc(ListValPtr idx);

	// Enum for the different kinds of changes an &on_change handler can see
	enum OnChangeType { ELEMENT_NEW, ELEMENT_CHANGED, ELEMENT_REMOVED, ELEMENT_EXPIRED };

	// Calls &change_func.
	void CallChangeFunc(const ValPtr& index, const ValPtr& old_value,
	                    OnChangeType tpe);

	// Sends data on to backing Broker Store
	void SendToStore(const Val* index, const TableEntryVal* new_entry_val, OnChangeType tpe);

	ValPtr DoClone(CloneState* state) override;

	zeek::TableTypePtr table_type;
	zeek::detail::CompositeHash* table_hash;
	zeek::detail::AttributesPtr attrs;
	zeek::detail::ExprPtr expire_time;
	zeek::detail::ExprPtr expire_func;
	TableValTimer* timer;
	IterCookie* expire_cookie;
	zeek::detail::PrefixTable* subnets;
	ValPtr def_val;
	zeek::detail::ExprPtr change_func;
	std::string broker_store;
	// prevent recursion of change functions
	bool in_change_func = false;

	static TableRecordDependencies parse_time_table_record_dependencies;
	static ParseTimeTableStates parse_time_table_states;
};

class RecordVal final : public Val, public zeek::notifier::detail::Modifiable {
public:
	[[deprecated("Remove in v4.1.  Construct from IntrusivePtr instead.")]]
	explicit RecordVal(zeek::RecordType* t, bool init_fields = true);
	explicit RecordVal(zeek::RecordTypePtr t, bool init_fields = true);

	~RecordVal() override;

	ValPtr SizeVal() const override;

	/**
	 * Assign a value to a record field.
	 * @param field  The field index to assign.
	 * @param new_val  The value to assign.
	 */
	void Assign(int field, ValPtr new_val);

	/**
	 * Assign a value of type @c T to a record field, as constructed from
	 * the provided arguments.
	 * @param field  The field index to assign.
	 * @param args  A variable number of arguments to pass to constructor of
	 * type @c T.
	 */
	template <class T, class... Ts>
	void Assign(int field, Ts&&... args)
		{ Assign(field, zeek::make_intrusive<T>(std::forward<Ts>(args)...)); }

	[[deprecated("Remove in v4.1.  Assign an IntrusivePtr instead.")]]
	void Assign(int field, Val* new_val);
	// Note: the following nullptr method can also go upon removing the above.
	void Assign(int field, std::nullptr_t)
		{ Assign(field, ValPtr{}); }

	[[deprecated("Remove in v4.1.  Use GetField().")]]
	Val* Lookup(int field) const	// Does not Ref() value.
		{ return (*AsRecord())[field].get(); }

	/**
	 * Returns the value of a given field index.
	 * @param field  The field index to retrieve.
	 * @return  The value at the given field index.
	 */
	const ValPtr& GetField(int field) const
		{ return (*AsRecord())[field]; }

	/**
	 * Returns the value of a given field index as cast to type @c T.
	 * @param field  The field index to retrieve.
	 * @return  The value at the given field index cast to type @c T.
	 */
	template <class T>
	zeek::IntrusivePtr<T> GetField(int field) const
		{ return zeek::cast_intrusive<T>(GetField(field)); }

	/**
	 * Returns the value of a given field index if it's previously been
	 * assigned, * or else returns the value created from evaluating the
	 * record field's &default expression.
	 * @param field  The field index to retrieve.
	 * @return  The value at the given field index or the default value if
	 * the field hasn't been assigned yet.
	 */
	ValPtr GetFieldOrDefault(int field) const;

	[[deprecated("Remove in v4.1.  Use GetFieldOrDefault().")]]
	Val* LookupWithDefault(int field) const
		{ return GetFieldOrDefault(field).release(); }

	/**
	 * Returns the value of a given field name.
	 * @param field  The name of a field to retrieve.
	 * @return  The value of the given field.  If no such field name exists,
	 * a fatal error occurs.
	 */
	const ValPtr& GetField(const char* field) const;

	/**
	 * Returns the value of a given field name as cast to type @c T.
	 * @param field  The name of a field to retrieve.
	 * @return  The value of the given field cast to type @c T.  If no such
	 * field name exists, a fatal error occurs.
	 */
	template <class T>
	zeek::IntrusivePtr<T> GetField(const char* field) const
		{ return zeek::cast_intrusive<T>(GetField(field)); }

	/**
	 * Returns the value of a given field name if it's previously been
	 * assigned, or else returns the value created from evaluating the record
	 * fields' &default expression.
	 * @param field  The name of a field to retrieve.
	 * @return  The value of the given field.  or the default value
	 * if the field hasn't been assigned yet.  If no such field name exists,
	 * a fatal error occurs.
	 */
	ValPtr GetFieldOrDefault(const char* field) const;

	/**
	 * Returns the value of a given field name or its default value
	 * as cast to type @c T.
	 * @param field  The name of a field to retrieve.
	 * @return  The value of the given field or its default value cast to
	 * type @c T.  If no such field name exists, a fatal error occurs.
	 */
	template <class T>
	zeek::IntrusivePtr<T> GetFieldOrDefault(const char* field) const
		{ return zeek::cast_intrusive<T>(GetField(field)); }

	/**
	 * Looks up the value of a field by field name.  If the field doesn't
	 * exist in the record type, it's an internal error: abort.
	 * @param field name of field to lookup.
	 * @param with_default whether to rely on field's &default attribute when
	 * the field has yet to be initialized.
	 * @return the value in field \a field.
	 */
	[[deprecated("Remove in v4.1.  Use GetField() or GetFieldOrDefault().")]]
	Val* Lookup(const char* field, bool with_default = false) const
		{ return with_default ? GetFieldOrDefault(field).release() : GetField(field).get(); }

	void Describe(ODesc* d) const override;

	/**
	 * Returns a "record_field_table" value for introspection purposes.
	 */
	TableValPtr GetRecordFieldsVal() const;

	// This is an experiment to associate a Obj within the
	// event engine to a record value in bro script.
	void SetOrigin(Obj* o)	{ origin = o; }
	Obj* GetOrigin() const	{ return origin; }

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
	RecordValPtr CoerceTo(zeek::RecordTypePtr other,
	                      RecordValPtr aggr,
	                      bool allow_orphaning = false) const;
	RecordValPtr CoerceTo(zeek::RecordTypePtr other,
	                      bool allow_orphaning = false);

	unsigned int MemoryAllocation() const override;
	void DescribeReST(ODesc* d) const override;

	zeek::notifier::detail::Modifiable* Modifiable() override	{ return this; }

	// Extend the underlying arrays of record instances created during
	// parsing to match the number of fields in the record type (they may
	// mismatch as a result of parse-time record type redefinitions.
	static void ResizeParseTimeRecords(zeek::RecordType* rt);

	static void DoneParsing();

protected:
	ValPtr DoClone(CloneState* state) override;

	Obj* origin;

	using RecordTypeValMap = std::unordered_map<zeek::RecordType*, std::vector<RecordValPtr>>;
	static RecordTypeValMap parse_time_records;
};

class EnumVal final : public Val {
public:
	ValPtr SizeVal() const override;

protected:
	friend class Val;
	friend class zeek::EnumType;

	template<class T, class... Ts>
	friend zeek::IntrusivePtr<T> zeek::make_intrusive(Ts&&... args);

	EnumVal(zeek::EnumTypePtr t, bro_int_t i) : Val(i, std::move(t))
		{}

	void ValDescribe(ODesc* d) const override;
	ValPtr DoClone(CloneState* state) override;
};


class VectorVal final : public Val, public zeek::notifier::detail::Modifiable {
public:
	[[deprecated("Remove in v4.1.  Construct from IntrusivePtr instead.")]]
	explicit VectorVal(zeek::VectorType* t);
	explicit VectorVal(zeek::VectorTypePtr t);
	~VectorVal() override;

	ValPtr SizeVal() const override;

	/**
	 * Assigns an element to a given vector index.
	 * @param index  The index to assign.
	 * @param element  The element value to assign.
	 * @return  True if the element was successfully assigned, or false if
	 * the element was the wrong type.
	 */
	bool Assign(unsigned int index, ValPtr element);

	// Note: does NOT Ref() the element! Remember to do so unless
	//       the element was just created and thus has refcount 1.
	[[deprecated("Remove in v4.1.  Assign an IntrusivePtr instead.")]]
	bool Assign(unsigned int index, Val* element)
		{ return Assign(index, {zeek::AdoptRef{}, element}); }
	// Note: the following nullptr method can also go upon removing the above.
	void Assign(unsigned int index, std::nullptr_t)
		{ Assign(index, ValPtr{}); }

	[[deprecated("Remove in v4.1.  Assign using integer index and IntrusivePtr element.")]]
	bool Assign(Val* index, Val* element)
		{
		return Assign(index->AsListVal()->Idx(0)->CoerceToUnsigned(),
		              {zeek::AdoptRef{}, element});
		}

	/**
	 * Assigns a given value to multiple indices in the vector.
	 * @param index  The starting index to assign to.
	 * @param how_many  The number of indices to assign, counting from *index*.
	 * @return  True if the elements were successfully assigned, or false if
	 * the element was the wrong type.
	 */
	bool AssignRepeat(unsigned int index, unsigned int how_many,
	                  ValPtr element);

	[[deprecated("Remove in v4.1.  Assign an IntrusivePtr instead.")]]
	bool AssignRepeat(unsigned int index, unsigned int how_many, Val* element)
		{ return AssignRepeat(index, how_many, {zeek::NewRef{}, element}); }

	// Add this value to the given value (if appropriate).
	// Returns true if succcessful.
	bool AddTo(Val* v, bool is_first_init) const override;

	/**
	 * Returns the element at a given index or nullptr if it does not exist.
	 * @param index  The position in the vector of the element to return.
	 * @return  The element at the given index or nullptr if the index
	 * does not exist (it's greater than or equal to vector's current size).
	 */
	const ValPtr& At(unsigned int index) const;

	[[deprecated("Remove in v4.1.  Use At().")]]
	Val* Lookup(unsigned int index) const
		{ return At(index).get(); }

	[[deprecated("Remove in v4.1.  Use At().")]]
	Val* Lookup(Val* index)
		{
		bro_uint_t i = index->AsListVal()->Idx(0)->CoerceToUnsigned();
		return At(static_cast<unsigned int>(i)).get();
		}

	unsigned int Size() const { return val.vector_val->size(); }

	// Is there any way to reclaim previously-allocated memory when you
	// shrink a vector?  The return value is the old size.
	unsigned int Resize(unsigned int new_num_elements);

	// Won't shrink size.
	unsigned int ResizeAtLeast(unsigned int new_num_elements);

	zeek::notifier::detail::Modifiable* Modifiable() override	{ return this; }

	/**
	 * Inserts an element at the given position in the vector.  All elements
	 * at that original position and higher are shifted up by one.
	 * @param index  The index to insert the element at.
	 * @param element  The value to insert into the vector.
	 * @return  True if the element was inserted or false if the element was
	 * the wrong type.
	 */
	bool Insert(unsigned int index, ValPtr element);

	[[deprecated("Remove in v4.1.  Insert an IntrusivePtr instead.")]]
	bool Insert(unsigned int index, Val* element)
		{ return Insert(index, {zeek::AdoptRef{}, element}); }

	// Removes an element at a specific position.
	bool Remove(unsigned int index);

protected:
	void ValDescribe(ODesc* d) const override;
	ValPtr DoClone(CloneState* state) override;
};

// Checks the given value for consistency with the given type.  If an
// exact match, returns it.  If promotable, returns the promoted version.
// If not a match, generates an error message and return nil.  If is_init is
// true, then the checking is done in the context of an initialization.
extern ValPtr check_and_promote(
	ValPtr v, const zeek::Type* t, bool is_init,
	const zeek::detail::Location* expr_location = nullptr);

extern bool same_val(const Val* v1, const Val* v2);
extern bool same_atomic_val(const Val* v1, const Val* v2);
extern bool is_atomic_val(const Val* v);
extern void describe_vals(const val_list* vals, ODesc* d, int offset=0);
extern void describe_vals(const std::vector<ValPtr>& vals,
                          ODesc* d, size_t offset = 0);
extern void delete_vals(val_list* vals);

// True if the given Val* has a vector type.
inline bool is_vector(Val* v)	{ return  v->GetType()->Tag() == zeek::TYPE_VECTOR; }
inline bool is_vector(const ValPtr& v)	{ return is_vector(v.get()); }

// Returns v casted to type T if the type supports that. Returns null if not.
//
// Note: This implements the script-level cast operator.
extern ValPtr cast_value_to_type(Val* v, zeek::Type* t);

// Returns true if v can be casted to type T. If so, check_and_cast() will
// succeed as well.
//
// Note: This implements the script-level type comparision operator.
extern bool can_cast_value_to_type(const Val* v, zeek::Type* t);

// Returns true if values of type s may support casting to type t. This is
// purely static check to weed out cases early on that will never succeed.
// However, even this function returns true, casting may still fail for a
// specific instance later.
extern bool can_cast_value_to_type(const zeek::Type* s, zeek::Type* t);

}

using Val [[deprecated("Remove in v4.1. Use zeek::Val instead.")]] = zeek::Val;
using PortVal [[deprecated("Remove in v4.1. Use zeek::PortVal instead.")]] = zeek::PortVal;
using AddrVal [[deprecated("Remove in v4.1. Use zeek::AddrVal instead.")]] = zeek::AddrVal;
using SubNetVal [[deprecated("Remove in v4.1. Use zeek::SubNetVal instead.")]] = zeek::SubNetVal;
using PatternVal [[deprecated("Remove in v4.1. Use zeek::PatternVal instead.")]] = zeek::PatternVal;
using TableVal [[deprecated("Remove in v4.1. Use zeek::TableVal instead.")]] = zeek::TableVal;
using TableValTimer [[deprecated("Remove in v4.1. Use zeek::TableVal instead.")]] = zeek::TableValTimer;
using RecordVal [[deprecated("Remove in v4.1. Use zeek::RecordVal instead.")]] = zeek::RecordVal;
using ListVal [[deprecated("Remove in v4.1. Use zeek::ListVal instead.")]] = zeek::ListVal;
using StringVal [[deprecated("Remove in v4.1. Use zeek::StringVal instead.")]] = zeek::StringVal;
using EnumVal [[deprecated("Remove in v4.1. Use zeek::EnumVal instead.")]] = zeek::EnumVal;
using VectorVal [[deprecated("Remove in v4.1. Use zeek::VectorVal instead.")]] = zeek::VectorVal;
using TableEntryVal [[deprecated("Remove in v4.1. Use zeek::TableEntryVal instead.")]] = zeek::TableEntryVal;
using TimeVal [[deprecated("Remove in v4.1. Use zeek::TimeVal instead.")]] = zeek::TimeVal;
using DoubleVal [[deprecated("Remove in v4.1. Use zeek::DoubleVal instead.")]] = zeek::DoubleVal;
using IntervalVal [[deprecated("Remove in v4.1. Use zeek::IntervalVal instead.")]] = zeek::IntervalVal;
using ValManager [[deprecated("Remove in v4.1. Use zeek::ValManager instead.")]] = zeek::ValManager;

// Alias for zeek::val_mgr.
extern zeek::ValManager*& val_mgr [[deprecated("Remove in v4.1. Use zeek::val_mgr instead.")]];
