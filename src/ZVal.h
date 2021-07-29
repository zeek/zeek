// See the file "COPYING" in the main distribution directory for copyright.

// Low-level representation of Zeek scripting values.

#pragma once

#include "zeek/zeek-config.h"

namespace zeek {

class AddrVal;
class File;
class Func;
class ListVal;
class OpaqueVal;
class PatternVal;
class RecordVal;
class StringVal;
class SubNetVal;
class TableVal;
class TypeVal;
class Val;
class VectorVal;

using AddrValPtr = IntrusivePtr<AddrVal>;
using EnumValPtr = IntrusivePtr<EnumVal>;
using ListValPtr = IntrusivePtr<ListVal>;
using OpaqueValPtr = IntrusivePtr<OpaqueVal>;
using PatternValPtr = IntrusivePtr<PatternVal>;
using RecordValPtr = IntrusivePtr<RecordVal>;
using StringValPtr = IntrusivePtr<StringVal>;
using SubNetValPtr = IntrusivePtr<SubNetVal>;
using TableValPtr = IntrusivePtr<TableVal>;
using TypeValPtr = IntrusivePtr<TypeVal>;
using ValPtr = IntrusivePtr<Val>;
using VectorValPtr = IntrusivePtr<VectorVal>;

namespace detail {
	class ZBody;
}

// Note that a ZVal by itself is ambiguous: it doesn't track its type.
// This makes them consume less memory and cheaper to copy.  It does
// however require a separate way to determine the type.  Generally
// this is doable using surrounding context, or can be statically
// determined in the case of optimization/compilation.
//
// An alternative would be to use std::variant, but it will be larger
// due to needing to track the variant type, and it won't allow access
// to the managed_val member, which both simplifies memory management
// and is also required for sharing of ZAM frame slots.

union ZVal {
	// Constructor for hand-populating the values.
	ZVal() { managed_val = nullptr; }

	// Construct from a given higher-level script value with a given type.
	ZVal(ValPtr v, const TypePtr& t);

	// Construct an empty value compatible with the given type.
	ZVal(const TypePtr& t);

	// Construct directly.
	ZVal(bro_int_t v)	{ int_val = v; }
	ZVal(bro_uint_t v)	{ uint_val = v; }
	ZVal(double v)		{ double_val = v; }

	ZVal(StringVal* v)	{ string_val = v; }
	ZVal(AddrVal* v)	{ addr_val = v; }
	ZVal(SubNetVal* v)	{ subnet_val = v; }
	ZVal(File* v)		{ file_val = v; }
	ZVal(Func* v)		{ func_val = v; }
	ZVal(ListVal* v)	{ list_val = v; }
	ZVal(OpaqueVal* v)	{ opaque_val = v; }
	ZVal(PatternVal* v)	{ re_val = v; }
	ZVal(TableVal* v)	{ table_val = v; }
	ZVal(RecordVal* v)	{ record_val = v; }
	ZVal(VectorVal* v)	{ vector_val = v; }
	ZVal(TypeVal* v)	{ type_val = v; }
	ZVal(Val* v)		{ any_val = v; }

	ZVal(StringValPtr v)	{ string_val = v.release(); }
	ZVal(AddrValPtr v)	{ addr_val = v.release(); }
	ZVal(SubNetValPtr v)	{ subnet_val = v.release(); }
	ZVal(ListValPtr v)	{ list_val = v.release(); }
	ZVal(OpaqueValPtr v)	{ opaque_val = v.release(); }
	ZVal(PatternValPtr v)	{ re_val = v.release(); }
	ZVal(TableValPtr v)	{ table_val = v.release(); }
	ZVal(RecordValPtr v)	{ record_val = v.release(); }
	ZVal(VectorValPtr v)	{ vector_val = v.release(); }
	ZVal(TypeValPtr v)	{ type_val = v.release(); }

	// Convert to a higher-level script value.  The caller needs to
	// ensure that they're providing the correct type.
	ValPtr ToVal(const TypePtr& t) const;

	bro_int_t AsInt() const		{ return int_val; }
	bro_uint_t AsCount() const	{ return uint_val; }
	double AsDouble() const		{ return double_val; }

	StringVal* AsString() const	{ return string_val; }
	AddrVal* AsAddr() const		{ return addr_val; }
	SubNetVal* AsSubNet() const	{ return subnet_val; }
	File* AsFile() const		{ return file_val; }
	Func* AsFunc() const		{ return func_val; }
	ListVal* AsList() const		{ return list_val; }
	OpaqueVal* AsOpaque() const	{ return opaque_val; }
	PatternVal* AsPattern() const	{ return re_val; }
	TableVal* AsTable() const	{ return table_val; }
	RecordVal* AsRecord() const	{ return record_val; }
	VectorVal* AsVector() const	{ return vector_val; }
	TypeVal* AsType() const		{ return type_val; }
	Val* AsAny() const		{ return any_val; }

	Obj* ManagedVal() const		{ return managed_val; }
	void ClearManagedVal()		{ managed_val = nullptr; }

	// The following return references that can be used to
	// populate the ZVal.  Handy for compiled ZAM code.
	bro_int_t& AsIntRef()		{ return int_val; }
	bro_uint_t& AsCountRef()	{ return uint_val; }
	double& AsDoubleRef()		{ return double_val; }
	StringVal*& AsStringRef()	{ return string_val; }
	AddrVal*& AsAddrRef()		{ return addr_val; }
	SubNetVal*& AsSubNetRef()	{ return subnet_val; }
	File*& AsFileRef()		{ return file_val; }
	Func*& AsFuncRef()		{ return func_val; }
	ListVal*& AsListRef()		{ return list_val; }
	OpaqueVal*& AsOpaqueRef()	{ return opaque_val; }
	PatternVal*& AsPatternRef()	{ return re_val; }
	TableVal*& AsTableRef()		{ return table_val; }
	RecordVal*& AsRecordRef()	{ return record_val; }
	VectorVal*& AsVectorRef()	{ return vector_val; }
	TypeVal*& AsTypeRef()		{ return type_val; }
	Val*& AsAnyRef()		{ return any_val; }
	Obj*& ManagedValRef()		{ return managed_val; }

	// True if a given type is one for which we manage the associated
	// memory internally.
	static bool IsManagedType(const TypePtr& t);

	// Deletes a managed value.  Caller needs to ensure that the ZVal
	// indeed holds such.
	static void DeleteManagedType(ZVal& v)
		{
		Unref(v.ManagedVal());
		}

	// Deletes a possibly-managed value.
	static void DeleteIfManaged(ZVal& v, const TypePtr& t)
		{
		if ( IsManagedType(t) )
			DeleteManagedType(v);
		}

	// Specifies the address of a flag to set if a ZVal is accessed
	// that was missing (a nil pointer).  Used to generate run-time
	// error messages.  We use an address-based interface so that
	// this flag can be combined with a general-purpose error flag,
	// allowing inner loops to only have to test a single flag.
	static void SetZValNilStatusAddr(bool* _zval_was_nil_addr)
		{ zval_was_nil_addr = _zval_was_nil_addr; }

private:
	friend class RecordVal;
	friend class VectorVal;
	friend class zeek::detail::ZBody;

	// Used for bool, int, enum.
	bro_int_t int_val;

	// Used for count and port.
	bro_uint_t uint_val;

	// Used for double, time, interval.
	double double_val;

	// The types are all variants of Val, or more fundamentally Obj.
	// They are raw pointers rather than IntrusivePtr's because
	// unions can't contain the latter.  For memory management, we use
	// Ref/Unref.
	StringVal* string_val;
	AddrVal* addr_val;
	SubNetVal* subnet_val;
	File* file_val;
	Func* func_val;
	ListVal* list_val;
	OpaqueVal* opaque_val;
	PatternVal* re_val;
	TableVal* table_val;
	RecordVal* record_val;
	VectorVal* vector_val;
	TypeVal* type_val;

	// Used for "any" values.
	Val* any_val;

	// Used for generic access to managed (derived-from-Obj) objects.
	Obj* managed_val;

	// A class-wide status variable set to true when a missing
	// value was accessed.  Only germane for managed types, since
	// we don't track the presence of non-managed types.  Static
	// because often the caller won't have direct access to the
	// particular ZVal that produces the issue, and just wants to
	// know whether it occurred at some point.
	static bool* zval_was_nil_addr;
};

} // zeek
