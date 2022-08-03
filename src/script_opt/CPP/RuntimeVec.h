// See the file "COPYING" in the main distribution directory for copyright.

// Run-time support for vector-oriented operations in C++-compiled scripts.
// The scope is unary (including appending), binary, and conditional
// operations.  It does not include operations common to other aggregates,
// such as indexing and explicit coercion (but does include low-level
// coercion needed to support unary and binary operations).

#pragma once

#include "zeek/Val.h"

namespace zeek::detail
	{

// Appends v2 to the vector v1.  A separate function because of the
// need to support assignment cascades.
inline ValPtr vector_append__CPP(VectorValPtr v1, const ValPtr& v2)
	{
	v1->Assign(v1->Size(), v2);
	return v1;
	}

// Appends vector v2 to the vector v1.
inline ValPtr vector_vec_append__CPP(VectorValPtr v1, const VectorValPtr& v2)
	{
	v2->AddTo(v1.get(), false);
	return v1;
	}

// Unary vector operations.
extern VectorValPtr vec_op_pos__CPP(const VectorValPtr& v, const TypePtr& t);
extern VectorValPtr vec_op_neg__CPP(const VectorValPtr& v, const TypePtr& t);
extern VectorValPtr vec_op_not__CPP(const VectorValPtr& v, const TypePtr& t);
extern VectorValPtr vec_op_comp__CPP(const VectorValPtr& v, const TypePtr& t);

// Binary vector operations.
extern VectorValPtr vec_op_add__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_sub__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_mul__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_div__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_mod__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_and__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_or__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_xor__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_andand__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_oror__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_lshift__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_rshift__CPP(const VectorValPtr& v1, const VectorValPtr& v2);

// Vector relational operations.
extern VectorValPtr vec_op_lt__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_gt__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_eq__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_ne__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_le__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_ge__CPP(const VectorValPtr& v1, const VectorValPtr& v2);

// The following are to support ++/-- operations on vectors ...
extern VectorValPtr vec_op_add__CPP(VectorValPtr v, int incr);
extern VectorValPtr vec_op_sub__CPP(VectorValPtr v, int i);

// ... and these for vector-plus-scalar and vector-plus-vector string
// operations.
extern VectorValPtr str_vec_op_add__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr str_vec_op_add__CPP(const VectorValPtr& v1, const StringValPtr& v2);
extern VectorValPtr str_vec_op_add__CPP(const StringValPtr& v1, const VectorValPtr& v2);

// String vector relationals.
extern VectorValPtr str_vec_op_lt__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr str_vec_op_le__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr str_vec_op_eq__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr str_vec_op_ne__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr str_vec_op_gt__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr str_vec_op_ge__CPP(const VectorValPtr& v1, const VectorValPtr& v2);

// Support for vector conditional ('?:') expressions.  Using the boolean
// vector v1 as a selector, returns a new vector populated with the
// elements selected out of v2 and v3.
extern VectorValPtr vector_select__CPP(const VectorValPtr& v1, VectorValPtr v2, VectorValPtr v3);

// Returns a new vector reflecting the given vector coerced to the given
// type.  Assumes v already has the correct internal type.  This can go
// away after we finish migrating to ZVal's.
extern VectorValPtr vector_coerce_to__CPP(const VectorValPtr& v, const TypePtr& targ);

// Similar coercion, but works for v having perhaps not the correct type.
extern VectorValPtr vec_coerce_to_zeek_int_t__CPP(const VectorValPtr& v, TypePtr targ);
extern VectorValPtr vec_coerce_to_zeek_uint_t__CPP(const VectorValPtr& v, TypePtr targ);
extern VectorValPtr vec_coerce_to_double__CPP(const VectorValPtr& v, TypePtr targ);

// A dummy function used during code generation for unsupported operations
// that mix vector and scalar arguments.
extern VectorValPtr vec_scalar_mixed_with_vector();

	} // namespace zeek::detail
