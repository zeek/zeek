// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/RuntimeVec.h"

#include "zeek/Overflow.h"
#include "zeek/ZeekString.h"

namespace zeek::detail
	{

using namespace std;

// Helper function for ensuring that two vectors have matching sizes.
static bool check_vec_sizes__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	if ( v1->Size() == v2->Size() )
		return true;

	reporter->CPPRuntimeError("vector operands are of different sizes");
	return false;
	}

// Helper function that returns a VectorTypePtr apt for use with the
// the given yield type.  We don't just use the yield type directly
// because here we're supporting low-level arithmetic operations
// (for example, adding one vector of "interval" to another), which
// we want to do using the low-level representations.  We'll later
// convert the vector to the high-level representation if needed.
static VectorTypePtr base_vector_type__CPP(const VectorTypePtr& vt)
	{
	switch ( vt->Yield()->InternalType() )
		{
		case TYPE_INTERNAL_INT:
			return make_intrusive<VectorType>(base_type(TYPE_INT));

		case TYPE_INTERNAL_UNSIGNED:
			return make_intrusive<VectorType>(base_type(TYPE_COUNT));

		case TYPE_INTERNAL_DOUBLE:
			return make_intrusive<VectorType>(base_type(TYPE_DOUBLE));

		default:
			return nullptr;
		}
	}

// The kernel used for unary vector operations.
#define VEC_OP1_KERNEL(accessor, type, op)                                                         \
	for ( unsigned int i = 0; i < v->Size(); ++i )                                                 \
		{                                                                                          \
		auto v_i = v->ValAt(i);                                                                    \
		if ( v_i )                                                                                 \
			v_result->Assign(i, make_intrusive<type>(op v_i->accessor()));                         \
		}

// A macro (since it's beyond my templating skillz to deal with the
// "op" operator) for unary vector operations, invoking the kernel
// per the underlying representation used by the vector.  "double_kernel"
// is an optional kernel to use for vectors whose underlying type
// is "double".  It needs to be optional because C++ will (rightfully)
// complain about applying certain C++ unary operations to doubles.
#define VEC_OP1(name, op, double_kernel)                                                           \
	VectorValPtr vec_op_##name##__CPP(const VectorValPtr& v, const TypePtr& t)                     \
		{                                                                                          \
		auto vt = base_vector_type__CPP(cast_intrusive<VectorType>(t));                            \
		auto v_result = make_intrusive<VectorVal>(vt);                                             \
                                                                                                   \
		switch ( vt->Yield()->InternalType() )                                                     \
			{                                                                                      \
			case TYPE_INTERNAL_INT:                                                                \
				{                                                                                  \
				VEC_OP1_KERNEL(AsInt, IntVal, op)                                                  \
				break;                                                                             \
				}                                                                                  \
                                                                                                   \
			case TYPE_INTERNAL_UNSIGNED:                                                           \
				{                                                                                  \
				VEC_OP1_KERNEL(AsCount, CountVal, op)                                              \
				break;                                                                             \
				}                                                                                  \
                                                                                                   \
				double_kernel                                                                      \
                                                                                                   \
					default : break;                                                               \
			}                                                                                      \
                                                                                                   \
		return v_result;                                                                           \
		}

// Instantiates a double_kernel for a given operation.
#define VEC_OP1_WITH_DOUBLE(name, op)                                                              \
	VEC_OP1(                                                                                       \
		name, op, case TYPE_INTERNAL_DOUBLE                                                        \
		: {                                                                                        \
			VEC_OP1_KERNEL(AsDouble, DoubleVal, op)                                                \
			break;                                                                                 \
		})

// The unary operations supported for vectors.
VEC_OP1_WITH_DOUBLE(pos, +)
VEC_OP1_WITH_DOUBLE(neg, -)
VEC_OP1(not, !, )
VEC_OP1(comp, ~, )

// A kernel for applying a binary operation element-by-element to two
// vectors of a given low-level type.
#define VEC_OP2_KERNEL(accessor, type, op, zero_check)                                             \
	for ( unsigned int i = 0; i < v1->Size(); ++i )                                                \
		{                                                                                          \
		auto v1_i = v1->ValAt(i);                                                                  \
		auto v2_i = v2->ValAt(i);                                                                  \
		if ( v1_i && v2_i )                                                                        \
			{                                                                                      \
			if ( zero_check && v2_i->IsZero() )                                                    \
				reporter->CPPRuntimeError("division/modulo by zero");                              \
			else                                                                                   \
				v_result->Assign(i, make_intrusive<type>(v1_i->accessor() op v2_i->accessor()));   \
			}                                                                                      \
		}

// Analogous to VEC_OP1, instantiates a function for a given binary operation,
// which might-or-might-not be supported for low-level "double" types.
// This version is for operations whose result type is the same as the
// operand type.
#define VEC_OP2(name, op, double_kernel, zero_check)                                               \
	VectorValPtr vec_op_##name##__CPP(const VectorValPtr& v1, const VectorValPtr& v2)              \
		{                                                                                          \
		if ( ! check_vec_sizes__CPP(v1, v2) )                                                      \
			return nullptr;                                                                        \
                                                                                                   \
		auto vt = base_vector_type__CPP(v1->GetType<VectorType>());                                \
		auto v_result = make_intrusive<VectorVal>(vt);                                             \
                                                                                                   \
		switch ( vt->Yield()->InternalType() )                                                     \
			{                                                                                      \
			case TYPE_INTERNAL_INT:                                                                \
				{                                                                                  \
				if ( vt->Yield()->Tag() == TYPE_BOOL )                                             \
					VEC_OP2_KERNEL(AsBool, BoolVal, op, zero_check)                                \
				else                                                                               \
					VEC_OP2_KERNEL(AsInt, IntVal, op, zero_check)                                  \
				break;                                                                             \
				}                                                                                  \
                                                                                                   \
			case TYPE_INTERNAL_UNSIGNED:                                                           \
				{                                                                                  \
				VEC_OP2_KERNEL(AsCount, CountVal, op, zero_check)                                  \
				break;                                                                             \
				}                                                                                  \
                                                                                                   \
				double_kernel                                                                      \
                                                                                                   \
					default : break;                                                               \
			}                                                                                      \
                                                                                                   \
		return v_result;                                                                           \
		}

// Instantiates a double_kernel for a binary operation.
#define VEC_OP2_WITH_DOUBLE(name, op, zero_check)                                                  \
	VEC_OP2(                                                                                       \
		name, op, case TYPE_INTERNAL_DOUBLE                                                        \
		: {                                                                                        \
			VEC_OP2_KERNEL(AsDouble, DoubleVal, op, zero_check)                                    \
			break;                                                                                 \
		},                                                                                         \
		zero_check)

// The binary operations supported for vectors.
VEC_OP2_WITH_DOUBLE(add, +, 0)
VEC_OP2_WITH_DOUBLE(sub, -, 0)
VEC_OP2_WITH_DOUBLE(mul, *, 0)
VEC_OP2_WITH_DOUBLE(div, /, 1)
VEC_OP2(mod, %, , 1)
VEC_OP2(and, &, , 0)
VEC_OP2(or, |, , 0)
VEC_OP2(xor, ^, , 0)
VEC_OP2(andand, &&, , 0)
VEC_OP2(oror, ||, , 0)
VEC_OP2(lshift, <<, , 0)
VEC_OP2(rshift, >>, , 0)

// A version of VEC_OP2 that instead supports relational operations, so
// the result type is always vector-of-bool.
#define VEC_REL_OP(name, op)                                                                       \
	VectorValPtr vec_op_##name##__CPP(const VectorValPtr& v1, const VectorValPtr& v2)              \
		{                                                                                          \
		if ( ! check_vec_sizes__CPP(v1, v2) )                                                      \
			return nullptr;                                                                        \
                                                                                                   \
		auto vt = v1->GetType<VectorType>();                                                       \
		auto res_type = make_intrusive<VectorType>(base_type(TYPE_BOOL));                          \
		auto v_result = make_intrusive<VectorVal>(res_type);                                       \
                                                                                                   \
		switch ( vt->Yield()->InternalType() )                                                     \
			{                                                                                      \
			case TYPE_INTERNAL_INT:                                                                \
				{                                                                                  \
				VEC_OP2_KERNEL(AsInt, BoolVal, op, 0)                                              \
				break;                                                                             \
				}                                                                                  \
                                                                                                   \
			case TYPE_INTERNAL_UNSIGNED:                                                           \
				{                                                                                  \
				VEC_OP2_KERNEL(AsCount, BoolVal, op, 0)                                            \
				break;                                                                             \
				}                                                                                  \
                                                                                                   \
			case TYPE_INTERNAL_DOUBLE:                                                             \
				{                                                                                  \
				VEC_OP2_KERNEL(AsDouble, BoolVal, op, 0)                                           \
				break;                                                                             \
				}                                                                                  \
                                                                                                   \
			default:                                                                               \
				break;                                                                             \
			}                                                                                      \
                                                                                                   \
		return v_result;                                                                           \
		}

// The relational operations supported for vectors.
VEC_REL_OP(lt, <)
VEC_REL_OP(gt, >)
VEC_REL_OP(eq, ==)
VEC_REL_OP(ne, !=)
VEC_REL_OP(le, <=)
VEC_REL_OP(ge, >=)

VectorValPtr vec_op_add__CPP(VectorValPtr v, int incr)
	{
	const auto& yt = v->GetType()->Yield();
	auto is_signed = yt->InternalType() == TYPE_INTERNAL_INT;
	auto n = v->Size();

	for ( unsigned int i = 0; i < n; ++i )
		{
		auto v_i = v->ValAt(i);
		ValPtr new_v_i;

		if ( is_signed )
			new_v_i = val_mgr->Int(v_i->AsInt() + incr);
		else
			new_v_i = val_mgr->Count(v_i->AsCount() + incr);

		v->Assign(i, new_v_i);
		}

	return v;
	}

VectorValPtr vec_op_sub__CPP(VectorValPtr v, int i)
	{
	return vec_op_add__CPP(std::move(v), -i);
	}

// This function provides the core functionality.  The arguments
// are applied as though they appeared left-to-right in a statement
// "s1 + v2 + v3 + s4".  For any invocation, v2 will always be
// non-nil, and one-and-only-one of s1, v3, or s4 will be non-nil.
static VectorValPtr str_vec_op_str_vec_add__CPP(const StringValPtr& s1, const VectorValPtr& v2,
                                                const VectorValPtr& v3, const StringValPtr& s4)
	{
	auto vt = v2->GetType<VectorType>();
	auto v_result = make_intrusive<VectorVal>(vt);
	auto n = v2->Size();

	for ( unsigned int i = 0; i < n; ++i )
		{
		vector<const String*> strings;

		auto v2_i = v2->ValAt(i);
		if ( ! v2_i )
			continue;

		auto s2 = v2_i->AsString();
		const String* s3 = nullptr;

		if ( v3 )
			{
			auto v3_i = v3->ValAt(i);
			if ( ! v3_i )
				continue;
			s3 = v3_i->AsString();
			}

		if ( s1 )
			strings.push_back(s1->AsString());
		strings.push_back(s2);
		if ( s3 )
			strings.push_back(s3);
		if ( s4 )
			strings.push_back(s4->AsString());

		auto res = make_intrusive<StringVal>(concatenate(strings));
		v_result->Assign(i, res);
		}

	return v_result;
	}

VectorValPtr str_vec_op_add__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	return str_vec_op_str_vec_add__CPP(nullptr, v1, v2, nullptr);
	}

VectorValPtr str_vec_op_add__CPP(const VectorValPtr& v1, const StringValPtr& s2)
	{
	return str_vec_op_str_vec_add__CPP(nullptr, v1, nullptr, s2);
	}

VectorValPtr str_vec_op_add__CPP(const StringValPtr& s1, const VectorValPtr& v2)
	{
	return str_vec_op_str_vec_add__CPP(s1, v2, nullptr, nullptr);
	}

// Kernel for element-by-element string relationals.  "rel1" and "rel2"
// codify which relational (</<=/==/!=/>=/>) we're aiming to support,
// in terms of how a Bstr_cmp() comparison should be assessed.
static VectorValPtr str_vec_op_kernel__CPP(const VectorValPtr& v1, const VectorValPtr& v2, int rel1,
                                           int rel2)
	{
	auto res_type = make_intrusive<VectorType>(base_type(TYPE_BOOL));
	auto v_result = make_intrusive<VectorVal>(res_type);
	auto n = v1->Size();

	for ( unsigned int i = 0; i < n; ++i )
		{
		auto v1_i = v1->ValAt(i);
		auto v2_i = v2->ValAt(i);
		if ( ! v1_i || ! v2_i )
			continue;

		auto s1 = v1_i->AsString();
		auto s2 = v2_i->AsString();

		auto cmp = Bstr_cmp(s1, s2);
		auto rel = (cmp == rel1) || (cmp == rel2);

		v_result->Assign(i, val_mgr->Bool(rel));
		}

	return v_result;
	}

VectorValPtr str_vec_op_lt__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	return str_vec_op_kernel__CPP(v1, v2, -1, -1);
	}
VectorValPtr str_vec_op_le__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	return str_vec_op_kernel__CPP(v1, v2, -1, 0);
	}
VectorValPtr str_vec_op_eq__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	return str_vec_op_kernel__CPP(v1, v2, 0, 0);
	}
VectorValPtr str_vec_op_ne__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	return str_vec_op_kernel__CPP(v1, v2, -1, 1);
	}
VectorValPtr str_vec_op_gt__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	return str_vec_op_kernel__CPP(v1, v2, 1, 1);
	}
VectorValPtr str_vec_op_ge__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	return str_vec_op_kernel__CPP(v1, v2, 0, 1);
	}

VectorValPtr vector_select__CPP(const VectorValPtr& v1, VectorValPtr v2, VectorValPtr v3)
	{
	auto vt = v2->GetType<VectorType>();
	auto v_result = make_intrusive<VectorVal>(vt);

	if ( ! check_vec_sizes__CPP(v1, v2) || ! check_vec_sizes__CPP(v1, v3) )
		return nullptr;

	auto n = v1->Size();

	for ( unsigned int i = 0; i < n; ++i )
		{
		auto vr_i = v1->BoolAt(i) ? v2->ValAt(i) : v3->ValAt(i);
		v_result->Assign(i, std::move(vr_i));
		}

	return v_result;
	}

VectorValPtr vector_coerce_to__CPP(const VectorValPtr& v, const TypePtr& targ)
	{
	auto res_t = cast_intrusive<VectorType>(targ);
	auto v_result = make_intrusive<VectorVal>(std::move(res_t));
	auto n = v->Size();
	auto yt = targ->Yield();
	auto ytag = yt->Tag();

	for ( unsigned int i = 0; i < n; ++i )
		{
		ValPtr v_i = v->ValAt(i);
		if ( ! v_i )
			continue;

		// We compute these for each element to cover the case where
		// the coerced vector is of type "any".
		auto& t_i = v_i->GetType();
		auto it = t_i->InternalType();

		ValPtr r_i;
		switch ( ytag )
			{
			case TYPE_BOOL:
				r_i = val_mgr->Bool(v_i->CoerceToInt() != 0);
				break;

			case TYPE_INT:
				if ( (it == TYPE_INTERNAL_UNSIGNED || it == TYPE_INTERNAL_DOUBLE) &&
				     would_overflow(t_i.get(), yt.get(), v_i.get()) )
					reporter->CPPRuntimeError(
						"overflow promoting from unsigned/double to signed arithmetic value");
				else
					r_i = val_mgr->Int(v_i->CoerceToInt());
				break;

			case TYPE_COUNT:
				if ( (it == TYPE_INTERNAL_INT || it == TYPE_INTERNAL_DOUBLE) &&
				     would_overflow(t_i.get(), yt.get(), v_i.get()) )
					reporter->CPPRuntimeError(
						"overflow promoting from signed/double to signed arithmetic value");
				else
					r_i = val_mgr->Count(v_i->CoerceToUnsigned());
				break;

			case TYPE_ENUM:
				r_i = yt->AsEnumType()->GetEnumVal(v_i->CoerceToInt());
				break;

			case TYPE_PORT:
				r_i = make_intrusive<PortVal>(v_i->CoerceToUnsigned());
				break;

			case TYPE_DOUBLE:
				r_i = make_intrusive<DoubleVal>(v_i->CoerceToDouble());
				break;

			case TYPE_INTERVAL:
				r_i = make_intrusive<IntervalVal>(v_i->CoerceToDouble());
				break;

			case TYPE_TIME:
				r_i = make_intrusive<TimeVal>(v_i->CoerceToDouble());
				break;

			default:
				reporter->InternalError("bad vector type in vector_coerce_to__CPP");
			}

		v_result->Assign(i, std::move(r_i));
		}

	return v_result;
	}

VectorValPtr vec_scalar_mixed_with_vector()
	{
	reporter->CPPRuntimeError("vector-mixed-with-scalar operations not supported");
	return nullptr;
	}

	} // namespace zeek::detail
