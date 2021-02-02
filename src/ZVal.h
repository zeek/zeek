// See the file "COPYING" in the main distribution directory for copyright.

// Low-level representation of Zeek scripting values.

#pragma once

#include <unordered_set>

#include "zeek/Dict.h"
#include "zeek/Expr.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(StringVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(AddrVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(SubNetVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(File, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Func, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(ListVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(OpaqueVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(PatternVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(TableVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(RecordVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(VectorVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Type, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);

namespace zeek {

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

	// Convert to a higher-level script value.  The caller needs to
	// ensure that they're providing the correct type.
	ValPtr ToVal(const TypePtr& t) const;

	// Whether a ZVal was accessed that was missing (a nil pointer).
	// Used to generate run-time error messages.
	static bool ZValNilStatus()		{ return zval_was_nil; }

	// Resets the notion of low-level-error-occurred.
	static void ClearZValNilStatus()	{ zval_was_nil = false; }

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
	Type* AsType() const		{ return type_val; }
	Val* AsAny() const		{ return any_val; }

	Obj* ManagedVal() const		{ return managed_val; }

private:
	// Used for bool, int, enum.
	bro_int_t int_val;

	// Used for count and port.
	bro_uint_t uint_val;

	// Used for double, time, interval.
	double double_val;

	// The types are all variants of Val, Type, or more fundamentally
	// Obj.  They are raw pointers rather than IntrusivePtr's because
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
	Type* type_val;

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
	static bool zval_was_nil;
};

// True if a given type is one for which we manage the associated
// memory internally.
bool IsManagedType(const TypePtr& t);

// Deletes a managed value.  Caller needs to ensure that the ZVal
// indeed holds such.
inline void DeleteManagedType(ZVal& v)
	{
	Unref(v.ManagedVal());
	}

// Deletes a possibly-managed value.
inline void DeleteIfManaged(ZVal& v, const TypePtr& t)
	{
	if ( IsManagedType(t) )
		DeleteManagedType(v);
	}

} // zeek
