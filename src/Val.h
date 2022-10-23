// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char
#include <array>
#include <list>
#include <unordered_map>
#include <vector>

#include "zeek/IntrusivePtr.h"
#include "zeek/Notifier.h"
#include "zeek/Reporter.h"
#include "zeek/Timer.h"
#include "zeek/Type.h"
#include "zeek/ZVal.h"
#include "zeek/net_util.h"

// We have four different port name spaces: TCP, UDP, ICMP, and UNKNOWN.
// We distinguish between them based on the bits specified in the *_PORT_MASK
// entries specified below.
#define NUM_PORT_SPACES 4
#define PORT_SPACE_MASK 0x30000

#define TCP_PORT_MASK 0x10000
#define UDP_PORT_MASK 0x20000
#define ICMP_PORT_MASK 0x30000

namespace zeek
	{

class String;
class Func;
class IPAddr;
class IPPrefix;
class RE_Matcher;
class File;
using FilePtr = zeek::IntrusivePtr<File>;

template <typename T> class RobustDictIterator;
template <typename T> class Dictionary;
template <typename T> using PDict = Dictionary<T>;

namespace detail
	{

class ScriptFunc;
class Frame;
class PrefixTable;
class CompositeHash;
class HashKey;

class ValTrace;
class ZBody;

	} // namespace detail

namespace run_state
	{

extern double network_time;
extern double zeek_start_network_time;

	} // namespace run_state

using FuncPtr = IntrusivePtr<Func>;
using FilePtr = IntrusivePtr<File>;

class Val;
class PortVal;
class AddrVal;
class SubNetVal;
class IntervalVal;
class FuncVal;
class FileVal;
class PatternVal;
class TableVal;
class RecordVal;
class ListVal;
class StringVal;
class EnumVal;
class OpaqueVal;
class VectorVal;
class TableEntryVal;
class TypeVal;

using AddrValPtr = IntrusivePtr<AddrVal>;
using EnumValPtr = IntrusivePtr<EnumVal>;
using FuncValPtr = IntrusivePtr<FuncVal>;
using ListValPtr = IntrusivePtr<ListVal>;
using PortValPtr = IntrusivePtr<PortVal>;
using RecordValPtr = IntrusivePtr<RecordVal>;
using StringValPtr = IntrusivePtr<StringVal>;
using TableValPtr = IntrusivePtr<TableVal>;
using ValPtr = IntrusivePtr<Val>;
using VectorValPtr = IntrusivePtr<VectorVal>;

class Val : public Obj
	{
public:
	static inline const ValPtr nil;

	~Val() override;

	Val* Ref()
		{
		zeek::Ref(this);
		return this;
		}
	ValPtr Clone();

	bool IsZero() const;
	bool IsOne() const;

	zeek_int_t InternalInt() const;
	zeek_uint_t InternalUnsigned() const;
	double InternalDouble() const;

	zeek_int_t CoerceToInt() const;
	zeek_uint_t CoerceToUnsigned() const;
	double CoerceToDouble() const;

	// Returns a new Val with the "size" of this Val.  What constitutes
	// size depends on the Val's type.
	virtual ValPtr SizeVal() const;

	/**
	 * Returns the Val's "footprint", i.e., how many elements / Val
	 * objects the value includes, either directly or indirectly.
	 * The number is not meant to be precise, but rather comparable:
	 * larger footprint correlates with more memory consumption.
	 *
	 * @return  The total footprint.
	 */
	unsigned int Footprint() const
		{
		std::unordered_set<const Val*> analyzed_vals;
		return Footprint(&analyzed_vals);
		}

	// Add this value to the given value (if appropriate).
	// Returns true if succcessful.  is_first_init is true only if
	// this is the *first* initialization of the value, not
	// if it's a subsequent += initialization.
	virtual bool AddTo(Val* v, bool is_first_init) const;

	// Remove this value from the given value (if appropriate).
	virtual bool RemoveFrom(Val* v) const;

	const TypePtr& GetType() const { return type; }

	template <class T> IntrusivePtr<T> GetType() const { return cast_intrusive<T>(type); }

#define UNDERLYING_ACCESSOR_DECL(ztype, ctype, name) ctype name() const;

	UNDERLYING_ACCESSOR_DECL(detail::IntValImplementation, zeek_int_t, AsInt)
	UNDERLYING_ACCESSOR_DECL(BoolVal, bool, AsBool)
	UNDERLYING_ACCESSOR_DECL(EnumVal, int, AsEnum)
	UNDERLYING_ACCESSOR_DECL(detail::UnsignedValImplementation, zeek_uint_t, AsCount)
	UNDERLYING_ACCESSOR_DECL(detail::DoubleValImplementation, double, AsDouble)
	UNDERLYING_ACCESSOR_DECL(TimeVal, double, AsTime)
	UNDERLYING_ACCESSOR_DECL(IntervalVal, double, AsInterval)
	UNDERLYING_ACCESSOR_DECL(AddrVal, const IPAddr&, AsAddr)
	UNDERLYING_ACCESSOR_DECL(SubNetVal, const IPPrefix&, AsSubNet)
	UNDERLYING_ACCESSOR_DECL(StringVal, const String*, AsString)
	UNDERLYING_ACCESSOR_DECL(FuncVal, Func*, AsFunc)
	UNDERLYING_ACCESSOR_DECL(FileVal, File*, AsFile)
	UNDERLYING_ACCESSOR_DECL(PatternVal, const RE_Matcher*, AsPattern)
	UNDERLYING_ACCESSOR_DECL(TableVal, const PDict<TableEntryVal>*, AsTable)
	UNDERLYING_ACCESSOR_DECL(TypeVal, zeek::Type*, AsType)

	FuncVal* AsFuncVal();
	const FuncVal* AsFuncVal() const;

	FileVal* AsFileVal();
	const FileVal* AsFileVal() const;

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

	TypeVal* AsTypeVal();
	const TypeVal* AsTypeVal() const;

	void Describe(ODesc* d) const override;
	virtual void DescribeReST(ODesc* d) const;

	// To be overridden by mutable derived class to enable change
	// notification.
	virtual notifier::detail::Modifiable* Modifiable() { return nullptr; }

#ifdef DEBUG
	// For debugging, we keep a reference to the global ID to which a
	// value has been bound *last*.
	detail::ID* GetID() const;

	void SetID(detail::ID* id);
#endif

	TableValPtr GetRecordFields();

	StringValPtr ToJSON(bool only_loggable = false, RE_Matcher* re = nullptr);

	template <typename T> T As()
		{
		// Since we're converting from "this", make sure the type requested is a pointer.
		static_assert(std::is_pointer<T>());
		return static_cast<T>(this);
		}

protected:
	// Friends with access to Clone().
	friend class EnumType;
	friend class ListVal;
	friend class RecordVal;
	friend class TableVal;
	friend class VectorVal;
	friend class ValManager;
	friend class TableEntryVal;

	virtual void ValDescribe(ODesc* d) const;
	virtual void ValDescribeReST(ODesc* d) const;

	static ValPtr MakeBool(bool b);
	static ValPtr MakeInt(zeek_int_t i);
	static ValPtr MakeCount(zeek_uint_t u);

	explicit Val(TypePtr t) noexcept : type(std::move(t)) { }

	/**
	 * Internal function for computing a Val's "footprint".
	 *
	 * @param analyzed_vals  A pointer to a set used to track which values
	 * have been analyzed to date, used to prevent infinite recursion.
	 * The set should be empty (but not nil) on the first call.
	 *
	 * @return  The total footprint.
	 */
	unsigned int Footprint(std::unordered_set<const Val*>* analyzed_vals) const;
	virtual unsigned int ComputeFootprint(std::unordered_set<const Val*>* analyzed_vals) const
		{
		return 1;
		}

	// For internal use by the Val::Clone() methods.
	struct CloneState
		{
		// Caches a cloned value for later reuse during the same
		// cloning operation. For recursive types, call this *before*
		// descending down.
		ValPtr NewClone(Val* src, ValPtr dst);

		std::unordered_map<Val*, Val*> clones;
		};

	ValPtr Clone(CloneState* state);
	virtual ValPtr DoClone(CloneState* state);

	TypePtr type;

#ifdef DEBUG
	// For debugging, we keep the name of the ID to which a Val is bound.
	const char* bound_id = nullptr;
#endif
	};

// Holds pre-allocated Val objects for those where it's more optimal to
// re-use existing ones rather than allocate anew.
class ValManager
	{
public:
	static constexpr zeek_uint_t PREALLOCATED_COUNTS = 4096;
	static constexpr zeek_uint_t PREALLOCATED_INTS = 512;
	static constexpr zeek_int_t PREALLOCATED_INT_LOWEST = -255;
	static constexpr zeek_int_t PREALLOCATED_INT_HIGHEST = PREALLOCATED_INT_LOWEST +
	                                                       PREALLOCATED_INTS - 1;

	ValManager();

	inline const ValPtr& True() const { return b_true; }

	inline const ValPtr& False() const { return b_false; }

	inline const ValPtr& Bool(bool b) const { return b ? b_true : b_false; }

	inline ValPtr Int(int64_t i) const
		{
		return i < PREALLOCATED_INT_LOWEST || i > PREALLOCATED_INT_HIGHEST
		           ? Val::MakeInt(i)
		           : ints[i - PREALLOCATED_INT_LOWEST];
		}

	inline ValPtr Count(uint64_t i) const
		{
		return i >= PREALLOCATED_COUNTS ? Val::MakeCount(i) : counts[i];
		}

	inline const StringValPtr& EmptyString() const { return empty_string; }

	// Port number given in host order.
	const PortValPtr& Port(uint32_t port_num, TransportProto port_type) const;

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

namespace detail
	{

// These are *internal* classes used to allow different publicly visible
// classes to share the same low-level value (per Type::InternalType).
// They may change or go away in the future.

class IntValImplementation : public Val
	{
public:
	IntValImplementation(TypePtr t, zeek_int_t v) : Val(std::move(t)), int_val(v) { }

	zeek_int_t Get() const { return int_val; }

protected:
	zeek_int_t int_val;
	};

class UnsignedValImplementation : public Val
	{
public:
	UnsignedValImplementation(TypePtr t, zeek_uint_t v) : Val(std::move(t)), uint_val(v) { }

	zeek_uint_t Get() const { return uint_val; }

protected:
	zeek_uint_t uint_val;
	};

class DoubleValImplementation : public Val
	{
public:
	DoubleValImplementation(TypePtr t, double v) : Val(std::move(t)), double_val(v) { }

	double Get() const { return double_val; }

protected:
	double double_val;
	};

	} // namespace detail

class IntVal final : public detail::IntValImplementation
	{
public:
	IntVal(zeek_int_t v) : detail::IntValImplementation(base_type(TYPE_INT), v) { }

	// No Get() method since in the current implementation the
	// inherited one serves that role.
	};

class BoolVal final : public detail::IntValImplementation
	{
public:
	BoolVal(zeek_int_t v) : detail::IntValImplementation(base_type(TYPE_BOOL), v) { }

	bool Get() const { return static_cast<bool>(int_val); }
	};

class CountVal : public detail::UnsignedValImplementation
	{
public:
	CountVal(zeek_uint_t v) : detail::UnsignedValImplementation(base_type(TYPE_COUNT), v) { }

	// Same as for IntVal: no Get() method needed.
	};

class DoubleVal : public detail::DoubleValImplementation
	{
public:
	DoubleVal(double v) : detail::DoubleValImplementation(base_type(TYPE_DOUBLE), v) { }

	// Same as for IntVal: no Get() method needed.
	};

#define Microseconds 1e-6
#define Milliseconds 1e-3
#define Seconds 1.0
#define Minutes (60 * Seconds)
#define Hours (60 * Minutes)
#define Days (24 * Hours)

class IntervalVal final : public detail::DoubleValImplementation
	{
public:
	IntervalVal(double quantity, double units = Seconds)
		: detail::DoubleValImplementation(base_type(TYPE_INTERVAL), quantity * units)
		{
		}

	// Same as for IntVal: no Get() method needed.

protected:
	void ValDescribe(ODesc* d) const override;
	};

class TimeVal final : public detail::DoubleValImplementation
	{
public:
	TimeVal(double t) : detail::DoubleValImplementation(base_type(TYPE_TIME), t) { }

	// Same as for IntVal: no Get() method needed.
	};

class PortVal final : public detail::UnsignedValImplementation
	{
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

	// Only meant for use by ValManager and compiled-to-C++ script
	// functions.
	PortVal(uint32_t p);

protected:
	void ValDescribe(ODesc* d) const override;
	ValPtr DoClone(CloneState* state) override;

private:
	// This method is just here to trick the interface in
	// `RecordVal::GetFieldAs` into returning the right type.
	// It shouldn't actually be used for anything.
	friend class RecordVal;
	PortValPtr Get() { return {NewRef{}, this}; }
	};

class AddrVal final : public Val
	{
public:
	explicit AddrVal(const char* text);
	explicit AddrVal(const std::string& text);
	~AddrVal() override;

	ValPtr SizeVal() const override;

	// Constructor for address already in network order.
	explicit AddrVal(uint32_t addr); // IPv4.
	explicit AddrVal(const uint32_t addr[4]); // IPv6.
	explicit AddrVal(const IPAddr& addr);

	const IPAddr& Get() const { return *addr_val; }

protected:
	ValPtr DoClone(CloneState* state) override;

private:
	IPAddr* addr_val;
	};

class SubNetVal final : public Val
	{
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

	const IPPrefix& Get() const { return *subnet_val; }

protected:
	void ValDescribe(ODesc* d) const override;
	ValPtr DoClone(CloneState* state) override;

private:
	IPPrefix* subnet_val;
	};

class StringVal final : public Val
	{
public:
	explicit StringVal(String* s);
	StringVal(std::string_view s);
	StringVal(int length, const char* s);
	~StringVal() override;

	ValPtr SizeVal() const override;

	int Len() const;
	const u_char* Bytes() const;
	const char* CheckString() const;

	// Note that one needs to de-allocate the return value of
	// ExpandedString() to avoid a memory leak.
	// char* ExpandedString(int format = String::EXPANDED_STRING)
	// 	{ return AsString()->ExpandedString(format); }

	std::string ToStdString() const;
	std::string_view ToStdStringView() const;
	StringVal* ToUpper();

	const String* Get() const { return string_val; }

	StringValPtr Replace(RE_Matcher* re, const String& repl, bool do_all);

protected:
	void ValDescribe(ODesc* d) const override;
	ValPtr DoClone(CloneState* state) override;

private:
	String* string_val;
	};

class FuncVal final : public Val
	{
public:
	explicit FuncVal(FuncPtr f);

	FuncPtr AsFuncPtr() const;

	ValPtr SizeVal() const override;

	Func* Get() const { return func_val.get(); }

protected:
	void ValDescribe(ODesc* d) const override;
	ValPtr DoClone(CloneState* state) override;

private:
	FuncPtr func_val;
	};

class FileVal final : public Val
	{
public:
	explicit FileVal(FilePtr f);

	ValPtr SizeVal() const override;

	File* Get() const { return file_val.get(); }

protected:
	void ValDescribe(ODesc* d) const override;
	ValPtr DoClone(CloneState* state) override;

private:
	FilePtr file_val;
	};

class PatternVal final : public Val
	{
public:
	explicit PatternVal(RE_Matcher* re);
	~PatternVal() override;

	bool AddTo(Val* v, bool is_first_init) const override;

	void SetMatcher(RE_Matcher* re);

	bool MatchExactly(const String* s) const;
	bool MatchAnywhere(const String* s) const;

	const RE_Matcher* Get() const { return re_val; }

protected:
	void ValDescribe(ODesc* d) const override;
	ValPtr DoClone(CloneState* state) override;

private:
	RE_Matcher* re_val;
	};

// ListVals are mainly used to index tables that have more than one
// element in their index.
class ListVal final : public Val
	{
public:
	explicit ListVal(TypeTag t);

	~ListVal() override;

	TypeTag BaseTag() const { return tag; }

	ValPtr SizeVal() const override;

	int Length() const { return vals.size(); }

	const ValPtr& Idx(size_t i) const { return vals[i]; }

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

	// Returns a Set representation of the list (which must be homogeneous).
	TableValPtr ToSetVal() const;

	const std::vector<ValPtr>& Vals() const { return vals; }

	void Describe(ODesc* d) const override;

protected:
	unsigned int ComputeFootprint(std::unordered_set<const Val*>* analyzed_vals) const override;

	ValPtr DoClone(CloneState* state) override;

	std::vector<ValPtr> vals;
	TypeTag tag;
	};

class TableEntryVal
	{
public:
	explicit TableEntryVal(ValPtr v) : val(std::move(v))
		{
		expire_access_time = int(run_state::network_time - run_state::zeek_start_network_time);
		}

	TableEntryVal* Clone(Val::CloneState* state);

	const ValPtr& GetVal() const { return val; }

	// Returns/sets time of last expiration relevant access to this value.
	double ExpireAccessTime() const
		{
		return run_state::zeek_start_network_time + expire_access_time;
		}
	void SetExpireAccess(double time)
		{
		expire_access_time = int(time - run_state::zeek_start_network_time);
		}

protected:
	friend class TableVal;

	ValPtr val;

	// The next entry stores seconds since Zeek's start.  We use ints here
	// to save a few bytes, as we do not need a high resolution for these
	// anyway.
	int expire_access_time;
	};

class TableValTimer final : public detail::Timer
	{
public:
	TableValTimer(TableVal* val, double t);
	~TableValTimer() override;

	void Dispatch(double t, bool is_expire) override;

	TableVal* Table() { return table; }

protected:
	TableVal* table;
	};

class TableVal final : public Val, public notifier::detail::Modifiable
	{
public:
	explicit TableVal(TableTypePtr t, detail::AttributesPtr attrs = nullptr);

	~TableVal() override;

	/**
	 * Assigns a value at an associated index in the table (or in the
	 * case of a set, just adds the index).
	 * @param index  The key to assign.
	 * @param new_val  The value to assign at the index.  For a set, this
	 * must be nullptr.
	 * @param broker_forward Controls if the value will be forwarded to attached
	 *        Broker stores.
	 * @param iterators_invalidated  if supplied, gets set to true if the operation
	 *        may have invalidated existing iterators.
	 * @return  True if the assignment type-checked.
	 */
	bool Assign(ValPtr index, ValPtr new_val, bool broker_forward = true,
	            bool* iterators_invalidated = nullptr);

	/**
	 * Assigns a value at an associated index in the table (or in the
	 * case of a set, just adds the index).
	 * @param index  The key to assign.  For tables, this is allowed to be null
	 * (if needed, the index val can be recovered from the hash key).
	 * @param k  A precomputed hash key to use.
	 * @param new_val  The value to assign at the index.  For a set, this
	 * @param iterators_invalidated  if supplied, gets set to true if the operation
	 *        may have invalidated existing iterators.
	 * must be nullptr.
	 * @param broker_forward Controls if the value will be forwarded to attached
	 *        Broker stores.
	 * @return  True if the assignment type-checked.
	 */
	bool Assign(ValPtr index, std::unique_ptr<detail::HashKey> k, ValPtr new_val,
	            bool broker_forward = true, bool* iterators_invalidated = nullptr);

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

	/**
	 * Returns a new table that is the union of this table and the
	 * given table.  Union is done only on index, so this generally
	 * makes most sense to use for sets, not tables.
	 * @param v  The union'ing table.
	 * @return  The union of this table and the given one.
	 */
	TableValPtr Union(TableVal* v) const
		{
		auto v_clone = cast_intrusive<TableVal>(v->Clone());
		AddTo(v_clone.get(), false, false);
		return v_clone;
		}

	/**
	 * Returns a copy of this table with the given table removed.
	 * @param v  The table to remove.
	 * @return  The subset of this table that doesn't include v.
	 */
	TableValPtr TakeOut(TableVal* v)
		{
		auto clone = cast_intrusive<TableVal>(Clone());
		v->RemoveFrom(clone.get());
		return clone;
		}

	// Returns true if this set contains the same members as the
	// given set.  Note that comparisons are done using hash keys,
	// so errors can arise for compound sets such as sets-of-sets.
	// See https://github.com/zeek/zeek/issues/151.
	bool EqualTo(const TableVal& v) const;
	bool EqualTo(const TableValPtr& v) const { return EqualTo(*(v.get())); }

	// Returns true if this set is a subset (not necessarily proper)
	// of the given set.
	bool IsSubsetOf(const TableVal& v) const;

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

	/**
	 * Returns true if this is a table[subnet]/set[subnet] and the
	 * given address was found in the table. Otherwise returns false.
	 * @param addr  The address to look for.
	 * @return  Boolean value to indicate if addr is in the table or set. If
	 * self is not a table[subnet]/set[subnet] an internal error will be
	 * generated and false will be returned.
	 */
	bool Contains(const IPAddr& addr) const;

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
	ListValPtr RecreateIndex(const detail::HashKey& k) const;

	/**
	 * Remove an element from the table and return it.
	 * @param index  The index to remove.
	 * @param broker_forward Controls if the remove operation will be forwarded to attached
	 *        Broker stores.
	 * @param iterators_invalidated  if supplied, gets set to true if the operation
	 *        may have invalidated existing iterators.
	 * @return  The value associated with the index if it exists, else nullptr.
	 * For a sets that don't really contain associated values, a placeholder
	 * value is returned to differentiate it from non-existent index (nullptr),
	 * but otherwise has no meaning in relation to the set's contents.
	 */
	ValPtr Remove(const Val& index, bool broker_forward = true,
	              bool* iterators_invalidated = nullptr);

	/**
	 * Same as Remove(const Val&), but uses a precomputed hash key.
	 * @param k  The hash key to lookup.
	 * @param iterators_invalidated  if supplied, gets set to true if the operation
	 *        may have invalidated existing iterators.
	 * @return  Same as Remove(const Val&).
	 */
	ValPtr Remove(const detail::HashKey& k, bool* iterators_invalidated = nullptr);

	// Returns a ListVal representation of the table (which must be a set).
	ListValPtr ToListVal(TypeTag t = TYPE_ANY) const;

	// Returns a ListVal representation of the table (which must be a set
	// with non-composite index type).
	ListValPtr ToPureListVal() const;

	// Returns a map of index-to-value's.  The value is nil for sets.
	std::unordered_map<ValPtr, ValPtr> ToMap() const;

	void SetAttrs(detail::AttributesPtr attrs);

	const detail::AttrPtr& GetAttr(detail::AttrTag t) const;

	const detail::AttributesPtr& GetAttrs() const { return attrs; }

	const PDict<TableEntryVal>* Get() const { return table_val; }

	const detail::CompositeHash* GetTableHash() const { return table_hash; }

	// Returns the size of the table.
	int Size() const;
	int RecursiveSize() const;

	// Returns the Prefix table used inside the table (if present).
	// This allows us to do more direct queries to this specialized
	// type that the general Table API does not allow.
	const detail::PrefixTable* Subnets() const { return subnets; }

	void Describe(ODesc* d) const override;

	void InitTimer(double delay);
	void DoExpire(double t);

	// If the &default attribute is not a function, or the function has
	// already been initialized, this does nothing. Otherwise, evaluates
	// the function in the frame allowing it to capture its closure.
	void InitDefaultFunc(detail::Frame* f);

	void ClearTimer(detail::Timer* t)
		{
		if ( timer == t )
			timer = nullptr;
		}

	/**
	 * @param  The index value to hash.
	 * @return  The hash of the index value or nullptr if
	 * type-checking failed.
	 */
	std::unique_ptr<detail::HashKey> MakeHashKey(const Val& index) const;

	notifier::detail::Modifiable* Modifiable() override { return this; }

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
	void Init(TableTypePtr t, bool ordered = false);

	using TableRecordDependencies = std::unordered_map<RecordType*, std::vector<TableValPtr>>;

	using ParseTimeTableState = std::vector<std::pair<ValPtr, ValPtr>>;
	using ParseTimeTableStates = std::unordered_map<TableVal*, ParseTimeTableState>;

	ParseTimeTableState DumpTableState();
	void RebuildTable(ParseTimeTableState ptts);

	void CheckExpireAttr(detail::AttrTag at);

	// Calculates default value for index.  Returns nullptr if none.
	ValPtr Default(const ValPtr& index);

	// Returns true if item expiration is enabled.
	bool ExpirationEnabled() { return expire_time != nullptr; }

	// Returns the expiration time defined by %{create,read,write}_expire
	// attribute, or -1 for unset/invalid values. In the invalid case, an
	// error will have been reported.
	double GetExpireTime();

	// Calls &expire_func and returns its return interval;
	double CallExpireFunc(ListValPtr idx);

	// Enum for the different kinds of changes an &on_change handler can see
	enum OnChangeType
		{
		ELEMENT_NEW,
		ELEMENT_CHANGED,
		ELEMENT_REMOVED,
		ELEMENT_EXPIRED
		};

	// Calls &change_func.
	void CallChangeFunc(const ValPtr& index, const ValPtr& old_value, OnChangeType tpe);

	// Sends data on to backing Broker Store
	void SendToStore(const Val* index, const TableEntryVal* new_entry_val, OnChangeType tpe);

	unsigned int ComputeFootprint(std::unordered_set<const Val*>* analyzed_vals) const override;

	ValPtr DoClone(CloneState* state) override;

	TableTypePtr table_type;
	detail::CompositeHash* table_hash;
	detail::AttributesPtr attrs;
	detail::ExprPtr expire_time;
	detail::ExprPtr expire_func;
	TableValTimer* timer;
	RobustDictIterator<TableEntryVal>* expire_iterator;
	detail::PrefixTable* subnets;
	ValPtr def_val;
	detail::ExprPtr change_func;
	std::string broker_store;
	// prevent recursion of change functions
	bool in_change_func = false;

	static TableRecordDependencies parse_time_table_record_dependencies;
	static ParseTimeTableStates parse_time_table_states;

private:
	PDict<TableEntryVal>* table_val;
	};

// This would be way easier with is_convertible_v, but sadly that won't
// work here because Obj has deleted copy constructors (and for good
// reason). Instead we make up our own type trait here that basically
// combines a bunch of is_same traits into a single trait to make life
// easier in the definitions of GetFieldAs().
template <typename T> struct is_zeek_val
	{
	static const bool value = std::disjunction_v<
		std::is_same<AddrVal, T>, std::is_same<BoolVal, T>, std::is_same<CountVal, T>,
		std::is_same<DoubleVal, T>, std::is_same<EnumVal, T>, std::is_same<FileVal, T>,
		std::is_same<FuncVal, T>, std::is_same<IntVal, T>, std::is_same<IntervalVal, T>,
		std::is_same<ListVal, T>, std::is_same<OpaqueVal, T>, std::is_same<PatternVal, T>,
		std::is_same<PortVal, T>, std::is_same<RecordVal, T>, std::is_same<StringVal, T>,
		std::is_same<SubNetVal, T>, std::is_same<TableVal, T>, std::is_same<TimeVal, T>,
		std::is_same<TypeVal, T>, std::is_same<VectorVal, T>>;
	};
template <typename T> inline constexpr bool is_zeek_val_v = is_zeek_val<T>::value;

class RecordVal final : public Val, public notifier::detail::Modifiable
	{
public:
	explicit RecordVal(RecordTypePtr t, bool init_fields = true);

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
	template <class T, class... Ts> void Assign(int field, Ts&&... args)
		{
		Assign(field, make_intrusive<T>(std::forward<Ts>(args)...));
		}

	/**
	 * Sets the given record field to not-in-record.  Equivalent to
	 * Assign using a nil ValPtr.
	 * @param field  The field index to remove.
	 */
	void Remove(int field);

	// The following provide efficient record field assignments.
	void Assign(int field, bool new_val)
		{
		(*record_val)[field] = ZVal(zeek_int_t(new_val));
		AddedField(field);
		}

	void Assign(int field, int new_val)
		{
		(*record_val)[field] = ZVal(zeek_int_t(new_val));
		AddedField(field);
		}

	// For unsigned, we provide both uint32_t and uint64_t versions
	// for convenience, since sometimes the caller has one rather
	// than the other.
	void Assign(int field, uint32_t new_val)
		{
		(*record_val)[field] = ZVal(zeek_uint_t(new_val));
		AddedField(field);
		}
	void Assign(int field, uint64_t new_val)
		{
		(*record_val)[field] = ZVal(zeek_uint_t(new_val));
		AddedField(field);
		}

	void Assign(int field, double new_val)
		{
		(*record_val)[field] = ZVal(new_val);
		AddedField(field);
		}

	// The following two are the same as the previous method,
	// but we use the names so that in the future if it would
	// be helpful, we can track the intent of the underlying
	// value representing a time or an interval.
	void AssignTime(int field, double new_val) { Assign(field, new_val); }
	void AssignInterval(int field, double new_val) { Assign(field, new_val); }

	void Assign(int field, StringVal* new_val)
		{
		if ( HasField(field) )
			ZVal::DeleteManagedType(*(*record_val)[field]);
		(*record_val)[field] = ZVal(new_val);
		AddedField(field);
		}
	void Assign(int field, const char* new_val) { Assign(field, new StringVal(new_val)); }
	void Assign(int field, const std::string& new_val) { Assign(field, new StringVal(new_val)); }
	void Assign(int field, String* new_val) { Assign(field, new StringVal(new_val)); }

	/**
	 * Assign a value of type @c T to a record field of the given name.
	 * A fatal error occurs if the no such field name exists.
	 */
	template <class T> void AssignField(const char* field_name, T&& val)
		{
		int idx = GetType()->AsRecordType()->FieldOffset(field_name);
		if ( idx < 0 )
			reporter->InternalError("missing record field: %s", field_name);
		Assign(idx, std::forward<T>(val));
		}

	/**
	 * Returns the number of fields in the record.
	 * @return  The number of fields in the record.
	 */
	unsigned int NumFields() const { return record_val->size(); }

	/**
	 * Returns true if the given field is in the record, false if
	 * it's missing.
	 * @param field  The field index to retrieve.
	 * @return  Whether there's a value for the given field index.
	 */
	bool HasField(int field) const { return (*record_val)[field] ? true : false; }

	/**
	 * Returns true if the given field is in the record, false if
	 * it's missing.
	 * @param field  The field name to retrieve.
	 * @return  Whether there's a value for the given field name.
	 */
	bool HasField(const char* field) const
		{
		int idx = GetType()->AsRecordType()->FieldOffset(field);
		return (idx != -1) && HasField(idx);
		}

	/**
	 * Returns the value of a given field index.
	 * @param field  The field index to retrieve.
	 * @return  The value at the given field index.
	 */
	ValPtr GetField(int field) const
		{
		if ( ! HasField(field) )
			return nullptr;

		return (*record_val)[field]->ToVal(rt->GetFieldType(field));
		}

	/**
	 * Returns the value of a given field index as cast to type @c T.
	 * @param field  The field index to retrieve.
	 * @return  The value at the given field index cast to type @c T.
	 */
	template <class T> IntrusivePtr<T> GetField(int field) const
		{
		return cast_intrusive<T>(GetField(field));
		}

	/**
	 * Returns the value of a given field index if it's previously been
	 * assigned, * or else returns the value created from evaluating the
	 * record field's &default expression.
	 * @param field  The field index to retrieve.
	 * @return  The value at the given field index or the default value if
	 * the field hasn't been assigned yet.
	 */
	ValPtr GetFieldOrDefault(int field) const;

	/**
	 * Returns the value of a given field name.
	 * @param field  The name of a field to retrieve.
	 * @return  The value of the given field.  If no such field name exists,
	 * a fatal error occurs.
	 */
	ValPtr GetField(const char* field) const;

	/**
	 * Returns the value of a given field name as cast to type @c T.
	 * @param field  The name of a field to retrieve.
	 * @return  The value of the given field cast to type @c T.  If no such
	 * field name exists, a fatal error occurs.
	 */
	template <class T> IntrusivePtr<T> GetField(const char* field) const
		{
		return cast_intrusive<T>(GetField(field));
		}

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
	template <class T> IntrusivePtr<T> GetFieldOrDefault(const char* field) const
		{
		return cast_intrusive<T>(GetField(field));
		}

	// The following return the given field converted to a particular
	// underlying value.  We provide these to enable efficient
	// access to record fields (without requiring an intermediary Val).
	// It is up to the caller to ensure that the field exists in the
	// record (using HasField(), if necessary).
	template <typename T, typename std::enable_if_t<is_zeek_val_v<T>, bool> = true>
	auto GetFieldAs(int field) const -> std::invoke_result_t<decltype(&T::Get), T>
		{
		if constexpr ( std::is_same_v<T, BoolVal> || std::is_same_v<T, IntVal> ||
		               std::is_same_v<T, EnumVal> )
			return record_val->operator[](field)->int_val;
		else if constexpr ( std::is_same_v<T, CountVal> )
			return record_val->operator[](field)->uint_val;
		else if constexpr ( std::is_same_v<T, DoubleVal> || std::is_same_v<T, TimeVal> ||
		                    std::is_same_v<T, IntervalVal> )
			return record_val->operator[](field)->double_val;
		else if constexpr ( std::is_same_v<T, PortVal> )
			return val_mgr->Port(record_val->at(field)->uint_val);
		else if constexpr ( std::is_same_v<T, StringVal> )
			return record_val->operator[](field)->string_val->Get();
		else if constexpr ( std::is_same_v<T, AddrVal> )
			return record_val->operator[](field)->addr_val->Get();
		else if constexpr ( std::is_same_v<T, SubNetVal> )
			return record_val->operator[](field)->subnet_val->Get();
		else if constexpr ( std::is_same_v<T, File> )
			return *(record_val->operator[](field)->file_val);
		else if constexpr ( std::is_same_v<T, Func> )
			return *(record_val->operator[](field)->func_val);
		else if constexpr ( std::is_same_v<T, PatternVal> )
			return record_val->operator[](field)->re_val->Get();
		else if constexpr ( std::is_same_v<T, RecordVal> )
			return record_val->operator[](field)->record_val;
		else if constexpr ( std::is_same_v<T, VectorVal> )
			return record_val->operator[](field)->vector_val;
		else if constexpr ( std::is_same_v<T, TableVal> )
			return record_val->operator[](field)->table_val->Get();
		else
			{
			// It's an error to reach here, although because of
			// the type trait we really shouldn't ever wind up
			// here.
			reporter->InternalError("bad type in GetFieldAs");
			}
		}

	template <typename T, typename std::enable_if_t<! is_zeek_val_v<T>, bool> = true>
	T GetFieldAs(int field) const
		{
		if constexpr ( std::is_integral_v<T> && std::is_signed_v<T> )
			return record_val->operator[](field)->int_val;
		else if constexpr ( std::is_integral_v<T> && std::is_unsigned_v<T> )
			return record_val->operator[](field)->uint_val;
		else if constexpr ( std::is_floating_point_v<T> )
			return record_val->operator[](field)->double_val;

		// Note: we could add other types here using type traits,
		// such as is_same_v<T, std::string>, etc.

		return T{};
		}

	template <typename T> auto GetFieldAs(const char* field) const
		{
		int idx = GetType()->AsRecordType()->FieldOffset(field);

		if ( idx < 0 )
			reporter->InternalError("missing record field: %s", field);

		return GetFieldAs<T>(idx);
		}

	void Describe(ODesc* d) const override;

	/**
	 * Returns a "record_field_table" value for introspection purposes.
	 */
	TableValPtr GetRecordFieldsVal() const;

	// This is an experiment to associate a Obj within the
	// event engine to a record value in Zeek script.
	void SetOrigin(Obj* o) { origin = o; }
	Obj* GetOrigin() const { return origin; }

	// Returns a new value representing the value coerced to the given
	// type. If coercion is not possible, returns nil. The non-const
	// version may return the current value ref'ed if its type matches
	// directly.
	//
	// The *allow_orphaning* parameter allows for a record to be demoted
	// down to a record type that contains less fields.
	RecordValPtr CoerceTo(RecordTypePtr other, bool allow_orphaning = false) const
		{
		return DoCoerceTo(other, allow_orphaning);
		}
	RecordValPtr CoerceTo(RecordTypePtr other, bool allow_orphaning = false);

	void DescribeReST(ODesc* d) const override;

	notifier::detail::Modifiable* Modifiable() override { return this; }

	// Extend the underlying arrays of record instances created during
	// parsing to match the number of fields in the record type (they may
	// mismatch as a result of parse-time record type redefinitions).
	static void ResizeParseTimeRecords(RecordType* rt);

	static void DoneParsing();

protected:
	friend class zeek::detail::ValTrace;
	friend class zeek::detail::ZBody;

	RecordValPtr DoCoerceTo(RecordTypePtr other, bool allow_orphaning) const;

	/**
	 * Appends a value to the record's fields.  The caller is responsible
	 * for ensuring that fields are appended in the correct order and
	 * with the correct type.  The type needs to be passed in because
	 * it's unsafe to take it from v when the field's type is "any" while
	 * v is a concrete type.
	 * @param v  The value to append.
	 * @param t  The type associated with the field.
	 */
	void AppendField(ValPtr v, const TypePtr& t)
		{
		if ( v )
			record_val->emplace_back(ZVal(v, t));
		else
			record_val->emplace_back(std::nullopt);
		}

	// For internal use by low-level ZAM instructions and event tracing.
	// Caller assumes responsibility for memory management.  The first
	// version allows manipulation of whether the field is present at all.
	// The second version ensures that the optional value is present.
	std::optional<ZVal>& RawOptField(int field) { return (*record_val)[field]; }

	ZVal& RawField(int field)
		{
		auto& f = RawOptField(field);
		if ( ! f )
			f = ZVal();
		return *f;
		}

	ValPtr DoClone(CloneState* state) override;

	void AddedField(int field) { Modified(); }

	Obj* origin;

	using RecordTypeValMap = std::unordered_map<RecordType*, std::vector<RecordValPtr>>;
	static RecordTypeValMap parse_time_records;

private:
	void DeleteFieldIfManaged(unsigned int field)
		{
		if ( HasField(field) && IsManaged(field) )
			ZVal::DeleteManagedType(*(*record_val)[field]);
		}

	bool IsManaged(unsigned int offset) const { return is_managed[offset]; }

	// Just for template inferencing.
	RecordVal* Get() { return this; }

	unsigned int ComputeFootprint(std::unordered_set<const Val*>* analyzed_vals) const override;

	// Keep this handy for quick access during low-level operations.
	RecordTypePtr rt;

	// Low-level values of each of the fields.
	std::vector<std::optional<ZVal>>* record_val;

	// Whether a given field requires explicit memory management.
	const std::vector<bool>& is_managed;
	};

class EnumVal final : public detail::IntValImplementation
	{
public:
	ValPtr SizeVal() const override;

protected:
	friend class Val;
	friend class EnumType;

	friend EnumValPtr make_enum__CPP(TypePtr t, int i);

	template <class T, class... Ts> friend IntrusivePtr<T> make_intrusive(Ts&&... args);

	EnumVal(EnumTypePtr t, zeek_int_t i) : detail::IntValImplementation(std::move(t), i) { }

	void ValDescribe(ODesc* d) const override;
	ValPtr DoClone(CloneState* state) override;
	};

class TypeVal final : public Val
	{
public:
	TypeVal(TypePtr t) : Val(std::move(t)) { }

	// Extra arg to differentiate from previous version.
	TypeVal(TypePtr t, bool type_type) : Val(make_intrusive<TypeType>(std::move(t))) { }

	zeek::Type* Get() const { return type.get(); }

protected:
	void ValDescribe(ODesc* d) const override;
	ValPtr DoClone(CloneState* state) override;
	};

class VectorVal final : public Val, public notifier::detail::Modifiable
	{
public:
	explicit VectorVal(VectorTypePtr t);
	VectorVal(VectorTypePtr t, std::vector<std::optional<ZVal>>* vals);

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

	/**
	 * Assigns a given value to multiple indices in the vector.
	 * @param index  The starting index to assign to.
	 * @param how_many  The number of indices to assign, counting from *index*.
	 * @return  True if the elements were successfully assigned, or false if
	 * the element was the wrong type.
	 */
	bool AssignRepeat(unsigned int index, unsigned int how_many, ValPtr element);

	// Add this value to the given value (if appropriate).
	// Returns true if succcessful.
	bool AddTo(Val* v, bool is_first_init) const override;

	unsigned int Size() const { return vector_val->size(); }

	// Is there any way to reclaim previously-allocated memory when you
	// shrink a vector?  The return value is the old size.
	unsigned int Resize(unsigned int new_num_elements);

	// Won't shrink size.
	unsigned int ResizeAtLeast(unsigned int new_num_elements);

	// Reserves storage for at least the number of elements.
	void Reserve(unsigned int num_elements);

	notifier::detail::Modifiable* Modifiable() override { return this; }

	/**
	 * Inserts an element at the given position in the vector.  All elements
	 * at that original position and higher are shifted up by one.
	 * @param index  The index to insert the element at.
	 * @param element  The value to insert into the vector.
	 * @return  True if the element was inserted or false if the element was
	 * the wrong type.
	 */
	bool Insert(unsigned int index, ValPtr element);

	/**
	 * Inserts an element at the end of the vector.
	 * @param element  The value to insert into the vector.
	 * @return  True if the element was inserted or false if the element was
	 * the wrong type.
	 */
	bool Append(ValPtr element) { return Insert(Size(), element); }

	// Removes an element at a specific position.
	bool Remove(unsigned int index);

	/**
	 * Sorts the vector in place, using the given optional
	 * comparison function.
	 * @param cmp_func  Comparison function for vector elements.
	 */
	void Sort(Func* cmp_func = nullptr);

	/**
	 * Returns a "vector of count" holding the indices of this
	 * vector when sorted using the given (optional) comparison function.
	 * @param cmp_func  Comparison function for vector elements.  If
	 *                  nullptr, then the vector must be internally
	 *                  of a numeric, and the usual '<' comparison
	 *                  will be used.
	 */
	VectorValPtr Order(Func* cmp_func = nullptr);

	/**
	 * Ensures that the vector can be used as a "vector of t".  In
	 * general, this is only relevant for objects that are typed as
	 * "vector of any", making sure that each element is in fact
	 * of type "t", and is internally represented as such so that
	 * this object can be used directly without any special-casing.
	 *
	 * Returns true if the object is compatible with "vector of t"
	 * (including if it's not a vector-of-any but instead already a
	 * vector-of-t), false if not compatible.
	 * @param t  The yield type to concretize to.
	 * @return  True if the object is compatible with vector-of-t, false
	 * if not.
	 */
	bool Concretize(const TypePtr& t);

	ValPtr ValAt(unsigned int index) const { return At(index); }

	bool Has(unsigned int index) const
		{
		return index < vector_val->size() && (*vector_val)[index];
		}

	/**
	 * Returns the given element in a given underlying representation.
	 * Enables efficient vector access.  Caller must ensure that the
	 * index lies within the vector's range, and does not point to
	 * a "hole".
	 * @param index  The position in the vector of the element to return.
	 * @return  The element's underlying value.
	 */
	zeek_int_t IntAt(unsigned int index) const { return (*vector_val)[index]->int_val; }
	zeek_uint_t CountAt(unsigned int index) const { return (*vector_val)[index]->uint_val; }
	double DoubleAt(unsigned int index) const { return (*vector_val)[index]->double_val; }
	const RecordVal* RecordValAt(unsigned int index) const
		{
		return (*vector_val)[index]->record_val;
		}
	bool BoolAt(unsigned int index) const
		{
		return static_cast<bool>((*vector_val)[index]->uint_val);
		}
	const StringVal* StringValAt(unsigned int index) const
		{
		return (*vector_val)[index]->string_val;
		}
	const String* StringAt(unsigned int index) const { return StringValAt(index)->AsString(); }

	// Only intended for low-level access by internal or compiled code.
	const auto& RawVec() const { return vector_val; }
	auto& RawVec() { return vector_val; }

	const auto& RawYieldType() const { return yield_type; }
	const auto& RawYieldTypes() const { return yield_types; }

protected:
	/**
	 * Returns the element at a given index or nullptr if it does not exist.
	 * @param index  The position in the vector of the element to return.
	 * @return  The element at the given index or nullptr if the index
	 * does not exist.
	 *
	 * Protected to ensure callers pick one of the differentiated accessors
	 * above, as appropriate, with ValAt() providing the original semantics.
	 */
	ValPtr At(unsigned int index) const;

	void ValDescribe(ODesc* d) const override;

	unsigned int ComputeFootprint(std::unordered_set<const Val*>* analyzed_vals) const override;

	ValPtr DoClone(CloneState* state) override;

private:
	// Just for template inferencing.
	friend class RecordVal;
	VectorVal* Get() { return this; }

	// Check the type of the given element against our current
	// yield type and adjust as necessary.  Returns whether the
	// element type-checked.
	bool CheckElementType(const ValPtr& element);

	// Add the given number of "holes" to the end of a vector.
	void AddHoles(int nholes);

	std::vector<std::optional<ZVal>>* vector_val;

	// For homogeneous vectors (the usual case), the type of the
	// elements.  Will be TYPE_VOID for empty vectors created using
	// "vector()".
	TypePtr yield_type;

	// True if this is a vector-of-any, or potentially one (which is
	// the case for empty vectors created using "vector()").
	bool any_yield;

	// True if this is a vector-of-managed-types, requiring explicit
	// memory management.
	bool managed_yield;

	// For heterogeneous vectors, the individual type of each element,
	// parallel to vector_val.  Heterogeneous vectors can arise for
	// "vector of any" when disparate elements are stored in the vector.
	//
	// Thus, if yield_types is non-nil, then we know this is a
	// vector-of-any.
	std::vector<TypePtr>* yield_types = nullptr;
	};

#define UNDERLYING_ACCESSOR_DEF(ztype, ctype, name)                                                \
	inline ctype Val::name() const { return static_cast<const ztype*>(this)->Get(); }

UNDERLYING_ACCESSOR_DEF(detail::IntValImplementation, zeek_int_t, AsInt)
UNDERLYING_ACCESSOR_DEF(BoolVal, bool, AsBool)
UNDERLYING_ACCESSOR_DEF(EnumVal, int, AsEnum)
UNDERLYING_ACCESSOR_DEF(detail::UnsignedValImplementation, zeek_uint_t, AsCount)
UNDERLYING_ACCESSOR_DEF(detail::DoubleValImplementation, double, AsDouble)
UNDERLYING_ACCESSOR_DEF(TimeVal, double, AsTime)
UNDERLYING_ACCESSOR_DEF(IntervalVal, double, AsInterval)
UNDERLYING_ACCESSOR_DEF(SubNetVal, const IPPrefix&, AsSubNet)
UNDERLYING_ACCESSOR_DEF(AddrVal, const IPAddr&, AsAddr)
UNDERLYING_ACCESSOR_DEF(StringVal, const String*, AsString)
UNDERLYING_ACCESSOR_DEF(FuncVal, Func*, AsFunc)
UNDERLYING_ACCESSOR_DEF(FileVal, File*, AsFile)
UNDERLYING_ACCESSOR_DEF(PatternVal, const RE_Matcher*, AsPattern)
UNDERLYING_ACCESSOR_DEF(TableVal, const PDict<TableEntryVal>*, AsTable)
UNDERLYING_ACCESSOR_DEF(TypeVal, zeek::Type*, AsType)

// Checks the given value for consistency with the given type.  If an
// exact match, returns it.  If promotable, returns the promoted version.
// If not a match, generates an error message and return nil.  If is_init is
// true, then the checking is done in the context of an initialization.
extern ValPtr check_and_promote(ValPtr v, const TypePtr& new_type, bool is_init,
                                const detail::Location* expr_location = nullptr);

extern bool same_val(const Val* v1, const Val* v2);
extern bool same_atomic_val(const Val* v1, const Val* v2);
extern bool is_atomic_val(const Val* v);
extern void describe_vals(const ValPList* vals, ODesc* d, int offset = 0);
extern void describe_vals(const std::vector<ValPtr>& vals, ODesc* d, size_t offset = 0);
extern void delete_vals(ValPList* vals);

// True if the given Val* has a vector type.
inline bool is_vector(Val* v)
	{
	return v->GetType()->Tag() == TYPE_VECTOR;
	}
inline bool is_vector(const ValPtr& v)
	{
	return is_vector(v.get());
	}

// Returns v casted to type T if the type supports that. Returns null if not.
//
// Note: This implements the script-level cast operator.
extern ValPtr cast_value_to_type(Val* v, Type* t);

// Returns true if v can be casted to type T. If so, check_and_cast() will
// succeed as well.
//
// Note: This implements the script-level type comparison operator.
extern bool can_cast_value_to_type(const Val* v, Type* t);

// Returns true if values of type s may support casting to type t. This is
// purely static check to weed out cases early on that will never succeed.
// However, even this function returns true, casting may still fail for a
// specific instance later.
extern bool can_cast_value_to_type(const Type* s, Type* t);

	} // namespace zeek
