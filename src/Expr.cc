// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"

#include "zeek/Expr.h"
#include "zeek/Event.h"
#include "zeek/Desc.h"
#include "zeek/Frame.h"
#include "zeek/Func.h"
#include "zeek/RE.h"
#include "zeek/Scope.h"
#include "zeek/Stmt.h"
#include "zeek/EventRegistry.h"
#include "zeek/RunState.h"
#include "zeek/Traverse.h"
#include "zeek/Trigger.h"
#include "zeek/IPAddr.h"
#include "zeek/digest.h"
#include "zeek/module_util.h"
#include "zeek/DebugLogger.h"
#include "zeek/Hash.h"
#include "zeek/script_opt/ExprOptInfo.h"

#include "zeek/broker/Data.h"

namespace zeek::detail {

static bool init_tag_check(const Expr* expr, const char* name,
                           TypeTag expect_tag, TypeTag init_tag)
	{
	if ( expect_tag == init_tag )
		return true;

	auto msg = util::fmt("unexpected use of %s in '%s' initialization",
	                     name, type_name(init_tag));
	expr->Error(msg);
	return false;
	}

const char* expr_name(BroExprTag t)
	{
	static const char* expr_names[int(NUM_EXPRS)] = {
		"name", "const",
		"(*)",
		"++", "--", "!", "~", "+", "-",
		"+", "-", "+=", "-=", "*", "/", "%",
		"&", "|", "^",
		"&&", "||",
		"<", "<=", "==", "!=", ">=", ">", "?:", "ref",
		"=", "[]", "$", "?$", "[=]",
		"table()", "set()", "vector()",
		"$=", "in", "<<>>",
		"()", "function()", "event", "schedule",
		"coerce", "record_coerce", "table_coerce", "vector_coerce",
		"sizeof", "cast", "is", "[:]=",
		"inline()",
		"[]=", "$=",
		"vec+=",
		"to_any_coerce", "from_any_coerce", "from_any_vec_coerce",
		"any[]",
		"nop",

	};

	if ( int(t) >= NUM_EXPRS )
		{
		static char errbuf[512];

		// This isn't quite right - we return a static buffer,
		// so multiple calls to expr_name() could lead to confusion
		// by overwriting the buffer.  But oh well.
		snprintf(errbuf, sizeof(errbuf),
				"%d: not an expression tag", int(t));
		return errbuf;
		}

	return expr_names[int(t)];
	}

Expr::Expr(BroExprTag arg_tag) : tag(arg_tag), paren(false), type(nullptr)
	{
	SetLocationInfo(&start_location, &end_location);
	opt_info = new ExprOptInfo();
	}

Expr::~Expr()
	{
	delete opt_info;
	}

const ListExpr* Expr::AsListExpr() const
	{
	CHECK_TAG(tag, EXPR_LIST, "Expr::AsListExpr", expr_name)
	return (const ListExpr*) this;
	}

ListExpr* Expr::AsListExpr()
	{
	CHECK_TAG(tag, EXPR_LIST, "Expr::AsListExpr", expr_name)
	return (ListExpr*) this;
	}

ListExprPtr Expr::AsListExprPtr()
	{
	CHECK_TAG(tag, EXPR_LIST, "Expr::AsListExpr", expr_name)
	return {NewRef{}, (ListExpr*) this};
	}

const NameExpr* Expr::AsNameExpr() const
	{
	CHECK_TAG(tag, EXPR_NAME, "Expr::AsNameExpr", expr_name)
	return (const NameExpr*) this;
	}

NameExpr* Expr::AsNameExpr()
	{
	CHECK_TAG(tag, EXPR_NAME, "Expr::AsNameExpr", expr_name)
	return (NameExpr*) this;
	}

NameExprPtr Expr::AsNameExprPtr()
	{
	CHECK_TAG(tag, EXPR_NAME, "Expr::AsNameExpr", expr_name)
	return {NewRef{}, (NameExpr*) this};
	}

const ConstExpr* Expr::AsConstExpr() const
	{
	CHECK_TAG(tag, EXPR_CONST, "Expr::AsConstExpr", expr_name)
	return (const ConstExpr*) this;
	}

ConstExprPtr Expr::AsConstExprPtr()
	{
	CHECK_TAG(tag, EXPR_CONST, "Expr::AsConstExpr", expr_name)
	return {NewRef{}, (ConstExpr*) this};
	}

const CallExpr* Expr::AsCallExpr() const
	{
	CHECK_TAG(tag, EXPR_CALL, "Expr::AsCallExpr", expr_name)
	return (const CallExpr*) this;
	}

const AssignExpr* Expr::AsAssignExpr() const
	{
	CHECK_TAG(tag, EXPR_ASSIGN, "Expr::AsAssignExpr", expr_name)
	return (const AssignExpr*) this;
	}

AssignExpr* Expr::AsAssignExpr()
	{
	CHECK_TAG(tag, EXPR_ASSIGN, "Expr::AsAssignExpr", expr_name)
	return (AssignExpr*) this;
	}

const IndexExpr* Expr::AsIndexExpr() const
	{
	CHECK_TAG(tag, EXPR_INDEX, "Expr::AsIndexExpr", expr_name)
	return (const IndexExpr*) this;
	}

IndexExpr* Expr::AsIndexExpr()
	{
	CHECK_TAG(tag, EXPR_INDEX, "Expr::AsIndexExpr", expr_name)
	return (IndexExpr*) this;
	}

const EventExpr* Expr::AsEventExpr() const
	{
	CHECK_TAG(tag, EXPR_EVENT, "Expr::AsEventExpr", expr_name)
	return (const EventExpr*) this;
	}

EventExprPtr Expr::AsEventExprPtr()
	{
	CHECK_TAG(tag, EXPR_EVENT, "Expr::AsEventExpr", expr_name)
	return {NewRef{}, (EventExpr*) this};
	}

const RefExpr* Expr::AsRefExpr() const
	{
	CHECK_TAG(tag, EXPR_REF, "Expr::AsRefExpr", expr_name)
	return (const RefExpr*) this;
	}

RefExprPtr Expr::AsRefExprPtr()
	{
	CHECK_TAG(tag, EXPR_REF, "Expr::AsRefExpr", expr_name)
	return {NewRef{}, (RefExpr*) this};
	}

bool Expr::CanAdd() const
	{
	return false;
	}

bool Expr::CanDel() const
	{
	return false;
	}

void Expr::Add(Frame* /* f */)
	{
	Internal("Expr::Add called");
	}

void Expr::Delete(Frame* /* f */)
	{
	Internal("Expr::Delete called");
	}

ExprPtr Expr::MakeLvalue()
	{
	if ( ! IsError() )
		ExprError("can't be assigned to");

	return {NewRef{}, this};
	}

bool Expr::InvertSense()
	{
	return false;
	}

void Expr::EvalIntoAggregate(const zeek::Type* /* t */, Val* /* aggr */,
                             Frame* /* f */) const
	{
	Internal("Expr::EvalIntoAggregate called");
	}

void Expr::Assign(Frame* /* f */, ValPtr /* v */)
	{
	Internal("Expr::Assign called");
	}

void Expr::AssignToIndex(ValPtr v1, ValPtr v2, ValPtr v3) const
	{
	bool iterators_invalidated;

	auto error_msg = assign_to_index(std::move(v1), std::move(v2), std::move(v3),
	                                 iterators_invalidated);

	if ( iterators_invalidated )
		{
		ODesc d;
		Describe(&d);
		reporter->PushLocation(GetLocationInfo());
		reporter->Warning("possible loop/iterator invalidation caused by expression: %s", d.Description());
		reporter->PopLocation();
		}

	if ( error_msg )
		RuntimeErrorWithCallStack(error_msg);
	}

static int get_slice_index(int idx, int len)
	{
	if ( abs(idx) > len )
		idx = idx > 0 ? len : 0; // Clamp maximum positive/negative indices.
	else if ( idx < 0 )
		idx += len;  // Map to a positive index.

	return idx;
	}

const char* assign_to_index(ValPtr v1, ValPtr v2, ValPtr v3,
				bool& iterators_invalidated)
	{
	iterators_invalidated = false;

	if ( ! v1 || ! v2 || ! v3 )
		return nullptr;

	// Hold an extra reference in case the ownership transfer
	// to the table/vector goes wrong and we still want to obtain
	// diagnostic info from the original value after the assignment
	// already unref'd.
	auto v_extra = v3;

	switch ( v1->GetType()->Tag() ) {
	case TYPE_VECTOR:
		{
		const ListVal* lv = v2->AsListVal();
		VectorVal* v1_vect = v1->AsVectorVal();

		if ( lv->Length() > 1 )
			{
			auto len = v1_vect->Size();
			bro_int_t first = get_slice_index(lv->Idx(0)->CoerceToInt(), len);
			bro_int_t last = get_slice_index(lv->Idx(1)->CoerceToInt(), len);

			// Remove the elements from the vector within the slice.
			for ( auto idx = first; idx < last; idx++ )
				v1_vect->Remove(first);

			// Insert the new elements starting at the first
			// position.

			VectorVal* v_vect = v3->AsVectorVal();

			for ( auto idx = 0u; idx < v_vect->Size();
			      idx++, first++ )
				v1_vect->Insert(first, v_vect->ValAt(idx));
			}

		else if ( ! v1_vect->Assign(lv->Idx(0)->CoerceToUnsigned(), std::move(v3)) )
			{
			v3 = std::move(v_extra);

			if ( v3 )
				{
				ODesc d;
				v3->Describe(&d);
				const auto& vt = v3->GetType();
				auto vtt = vt->Tag();
				std::string tn = vtt == TYPE_RECORD ?
					vt->GetName() : type_name(vtt);
				return util::fmt("vector index assignment failed for invalid type '%s', value: %s",
					tn.data(), d.Description());
				}
			else
				return "assignment failed with null value";
			}
		break;
		}

	case TYPE_TABLE:
		{
		if ( ! v1->AsTableVal()->Assign(std::move(v2), std::move(v3), true, &iterators_invalidated) )
			{
			v3 = std::move(v_extra);

			if ( v3 )
				{
				ODesc d;
				v3->Describe(&d);
				const auto& vt = v3->GetType();
				auto vtt = vt->Tag();
				std::string tn = vtt == TYPE_RECORD ?
					vt->GetName() : type_name(vtt);
				return util::fmt("table index assignment failed for invalid type '%s', value: %s",
					tn.data(), d.Description());
				}
			else
				return "assignment failed with null value";
			}

		break;
		}

	case TYPE_STRING:
		return "assignment via string index accessor not allowed";
		break;

	default:
		return "bad index expression type in assignment";
		break;
	}

	return nullptr;
	}

TypePtr Expr::InitType() const
	{
	return type;
	}

bool Expr::IsRecordElement(TypeDecl* /* td */) const
	{
	return false;
	}

bool Expr::IsPure() const
	{
	return true;
	}

ValPtr Expr::InitVal(const zeek::Type* t, ValPtr aggr) const
	{
	if ( aggr )
		{
		Error("bad initializer");
		return nullptr;
		}

	if ( IsError() )
		return nullptr;

	return check_and_promote(Eval(nullptr), t, true);
	}

bool Expr::IsError() const
	{
	return type && type->Tag() == TYPE_ERROR;
	}

void Expr::SetError()
	{
	SetType(error_type());
	}

void Expr::SetError(const char* msg)
	{
	Error(msg);
	SetError();
	}

bool Expr::IsZero() const
	{
	return IsConst() && ExprVal()->IsZero();
	}

bool Expr::IsOne() const
	{
	return IsConst() && ExprVal()->IsOne();
	}

void Expr::Describe(ODesc* d) const
	{
	if ( IsParen() && ! d->IsBinary() )
		d->Add("(");

	if ( d->IsPortable() || d->IsBinary() )
		AddTag(d);

	ExprDescribe(d);

	if ( IsParen() && ! d->IsBinary() )
		d->Add(")");
	}

void Expr::AddTag(ODesc* d) const
	{
	if ( d->IsBinary() )
		d->Add(int(Tag()));
	else
		d->AddSP(expr_name(Tag()));
	}

void Expr::Canonicize()
	{
	}

void Expr::SetType(TypePtr t)
	{
	if ( ! type || type->Tag() != TYPE_ERROR )
		type = std::move(t);
	}

void Expr::ExprError(const char msg[])
	{
	Error(msg);
	SetError();
	}

void Expr::RuntimeError(const std::string& msg) const
	{
	reporter->ExprRuntimeError(this, "%s", msg.data());
	}

void Expr::RuntimeErrorWithCallStack(const std::string& msg) const
	{
	auto rcs = render_call_stack();

	if ( rcs.empty() )
		reporter->ExprRuntimeError(this, "%s", msg.data());
	else
		{
		ODesc d;
		d.SetShort();
		Describe(&d);
		reporter->RuntimeError(GetLocationInfo(),
					"%s, expression: %s, call stack: %s",
					msg.data(), d.Description(), rcs.data());
		}
	}

NameExpr::NameExpr(IDPtr arg_id, bool const_init)
	: Expr(EXPR_NAME), id(std::move(arg_id))
	{
	in_const_init = const_init;

	if ( id->IsType() )
		SetType(make_intrusive<TypeType>(id->GetType()));
	else
		SetType(id->GetType());

	EventHandler* h = event_registry->Lookup(id->Name());
	if ( h )
		h->SetUsed();
	}

// This isn't in-lined to avoid needing to pull in ID.h.
const IDPtr& NameExpr::IdPtr() const
	{
	return id;
	}

ValPtr NameExpr::Eval(Frame* f) const
	{
	ValPtr v;

	if ( id->IsType() )
		return make_intrusive<TypeVal>(id->GetType(), true);

	if ( id->IsGlobal() )
		v = id->GetVal();

	else if ( f )
		v = f->GetElementByID(id);

	else
		// No frame - evaluating for purposes of resolving a
		// compile-time constant.
		return nullptr;

	if ( v )
		return v;
	else
		{
		RuntimeError("value used but not set");
		return nullptr;
		}
	}

ExprPtr NameExpr::MakeLvalue()
	{
	if ( id->IsType() )
		ExprError("Type name is not an lvalue");

	if ( id->IsConst() && ! in_const_init )
		ExprError("const is not a modifiable lvalue");

	if ( id->IsOption() && ! in_const_init )
		ExprError("option is not a modifiable lvalue");

	return make_intrusive<RefExpr>(IntrusivePtr{NewRef{}, this});
	}

void NameExpr::Assign(Frame* f, ValPtr v)
	{
	if ( id->IsGlobal() )
		id->SetVal(std::move(v));
	else
		f->SetElement(id, std::move(v));
	}

bool NameExpr::IsPure() const
	{
	return id->IsConst();
	}

TraversalCode NameExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	tc = id->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}


void NameExpr::ExprDescribe(ODesc* d) const
	{
	if ( d->IsReadable() )
		d->Add(id->Name());
	else
		{
		if ( d->IsPortable() )
			d->Add(id->Name());
		else
			d->AddCS(id->Name());
		}
	}

ConstExpr::ConstExpr(ValPtr arg_val)
	: Expr(EXPR_CONST), val(std::move(arg_val))
	{
	if ( val )
		{
		if ( val->GetType()->Tag() == TYPE_LIST &&
		     val->AsListVal()->Length() == 1 )
			val = val->AsListVal()->Idx(0);

		SetType(val->GetType());
		}
	else
		SetError();
	}

void ConstExpr::ExprDescribe(ODesc* d) const
	{
	val->Describe(d);
	}

ValPtr ConstExpr::Eval(Frame* /* f */) const
	{
	return {NewRef{}, Value()};
	}

TraversalCode ConstExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}

UnaryExpr::UnaryExpr(BroExprTag arg_tag, ExprPtr arg_op)
	: Expr(arg_tag), op(std::move(arg_op))
	{
	if ( op->IsError() )
		SetError();
	}

ValPtr UnaryExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return nullptr;

	auto v = op->Eval(f);

	if ( ! v )
		return nullptr;

	if ( is_vector(v) && Tag() != EXPR_IS && Tag() != EXPR_CAST &&
	     // The following allows passing vectors-by-reference to
	     // functions that use vector-of-any for generic vector
	     // manipulation ...
	     Tag() != EXPR_TO_ANY_COERCE &&
	     // ... and the following to avoid vectorizing operations
	     // on vector-of-any's
	     Tag() != EXPR_FROM_ANY_COERCE )
		{
		VectorVal* v_op = v->AsVectorVal();
		VectorTypePtr out_t;

		if ( GetType()->Tag() == TYPE_ANY )
			out_t = v->GetType<VectorType>();
		else
			out_t = GetType<VectorType>();

		auto result = make_intrusive<VectorVal>(std::move(out_t));

		for ( unsigned int i = 0; i < v_op->Size(); ++i )
			{
			auto vop = v_op->ValAt(i);
			if ( vop )
				result->Assign(i, Fold(vop.get()));
			else
				result->Assign(i, nullptr);
			}

		return result;
		}
	else
		return Fold(v.get());
	}

bool UnaryExpr::IsPure() const
	{
	return op->IsPure();
	}

TraversalCode UnaryExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	tc = op->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}

ValPtr UnaryExpr::Fold(Val* v) const
	{
	return {NewRef{}, v};
	}

void UnaryExpr::ExprDescribe(ODesc* d) const
	{
	bool is_coerce =
		Tag() == EXPR_ARITH_COERCE || Tag() == EXPR_RECORD_COERCE ||
		Tag() == EXPR_TABLE_COERCE;

	if ( d->IsReadable() )
		{
		if ( is_coerce )
			d->Add("(coerce ");
		else if ( Tag() != EXPR_REF )
			d->Add(expr_name(Tag()));
		}

	op->Describe(d);

	if ( d->IsReadable() && is_coerce )
		{
		d->Add(" to ");
		GetType()->Describe(d);
		d->Add(")");
		}
	}

ValPtr BinaryExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return nullptr;

	auto v1 = op1->Eval(f);

	if ( ! v1 )
		return nullptr;

	auto v2 = op2->Eval(f);

	if ( ! v2 )
		return nullptr;

	bool is_vec1 = is_vector(v1);
	bool is_vec2 = is_vector(v2);

	if ( is_vec1 && is_vec2 )
		{ // fold pairs of elements
		VectorVal* v_op1 = v1->AsVectorVal();
		VectorVal* v_op2 = v2->AsVectorVal();

		if ( v_op1->Size() != v_op2->Size() )
			{
			RuntimeError("vector operands are of different sizes");
			return nullptr;
			}

		auto v_result = make_intrusive<VectorVal>(GetType<VectorType>());

		for ( unsigned int i = 0; i < v_op1->Size(); ++i )
			{
			auto v1_i = v_op1->ValAt(i);
			auto v2_i = v_op2->ValAt(i);
			if ( v1_i && v2_i )
				v_result->Assign(i, Fold(v_op1->ValAt(i).get(), v_op2->ValAt(i).get()));
			else
				v_result->Assign(i, nullptr);
			}

		return v_result;
		}

	if ( IsVector(GetType()->Tag()) && (is_vec1 || is_vec2) )
		{ // fold vector against scalar
		VectorVal* vv = (is_vec1 ? v1 : v2)->AsVectorVal();
		auto v_result = make_intrusive<VectorVal>(GetType<VectorType>());

		for ( unsigned int i = 0; i < vv->Size(); ++i )
			{
			auto vv_i = vv->ValAt(i);
			if ( vv_i )
				v_result->Assign(i, is_vec1 ? Fold(vv_i.get(), v2.get())
				                            : Fold(v1.get(), vv_i.get()));
			else
				v_result->Assign(i, nullptr);
			}

		return v_result;
		}

	// scalar op scalar
	return Fold(v1.get(), v2.get());
	}

bool BinaryExpr::IsPure() const
	{
	return op1->IsPure() && op2->IsPure();
	}

TraversalCode BinaryExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	tc = op1->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = op2->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}

void BinaryExpr::ExprDescribe(ODesc* d) const
	{
	op1->Describe(d);

	d->SP();
	if ( d->IsReadable() )
		d->AddSP(expr_name(Tag()));

	op2->Describe(d);
	}

ValPtr BinaryExpr::Fold(Val* v1, Val* v2) const
	{
	InternalTypeTag it = v1->GetType()->InternalType();

	if ( it == TYPE_INTERNAL_STRING )
		return StringFold(v1, v2);

	if ( v1->GetType()->Tag() == TYPE_PATTERN )
		return PatternFold(v1, v2);

	if ( v1->GetType()->IsSet() )
		return SetFold(v1, v2);

	if ( it == TYPE_INTERNAL_ADDR )
		return AddrFold(v1, v2);

	if ( it == TYPE_INTERNAL_SUBNET )
		return SubNetFold(v1, v2);

	bro_int_t i1 = 0, i2 = 0, i3 = 0;
	bro_uint_t u1 = 0, u2 = 0, u3 = 0;
	double d1 = 0.0, d2 = 0.0, d3 = 0.0;
	bool is_integral = false;
	bool is_unsigned = false;

	if ( it == TYPE_INTERNAL_INT )
		{
		i1 = v1->InternalInt();
		i2 = v2->InternalInt();
		is_integral = true;
		}
	else if ( it == TYPE_INTERNAL_UNSIGNED )
		{
		u1 = v1->InternalUnsigned();
		u2 = v2->InternalUnsigned();
		is_unsigned = true;
		}
	else if ( it == TYPE_INTERNAL_DOUBLE )
		{
		d1 = v1->InternalDouble();
		d2 = v2->InternalDouble();
		}
	else
		RuntimeErrorWithCallStack("bad type in BinaryExpr::Fold");

	switch ( tag ) {
#define DO_INT_FOLD(op) \
	if ( is_integral ) \
		i3 = i1 op i2; \
	else if ( is_unsigned ) \
		u3 = u1 op u2; \
	else \
		RuntimeErrorWithCallStack("bad type in BinaryExpr::Fold");

#define DO_UINT_FOLD(op) \
	if ( is_unsigned ) \
		u3 = u1 op u2; \
	else \
		RuntimeErrorWithCallStack("bad type in BinaryExpr::Fold");

#define DO_FOLD(op) \
	if ( is_integral ) \
		i3 = i1 op i2; \
	else if ( is_unsigned ) \
		u3 = u1 op u2; \
	else \
		d3 = d1 op d2;

#define DO_INT_VAL_FOLD(op) \
	if ( is_integral ) \
		i3 = i1 op i2; \
	else if ( is_unsigned ) \
		i3 = u1 op u2; \
	else \
		i3 = d1 op d2;

	case EXPR_ADD:
	case EXPR_ADD_TO:	DO_FOLD(+); break;
	case EXPR_SUB:
	case EXPR_REMOVE_FROM:	DO_FOLD(-); break;
	case EXPR_TIMES:	DO_FOLD(*); break;
	case EXPR_DIVIDE:
		{
		if ( is_integral )
			{
			if ( i2 == 0 )
				RuntimeError("division by zero");

			i3 = i1 / i2;
			}

		else if ( is_unsigned )
			{
			if ( u2 == 0 )
				RuntimeError("division by zero");

			u3 = u1 / u2;
			}
		else
			{
			if ( d2 == 0 )
				RuntimeError("division by zero");

			d3 = d1 / d2;
			}

		}
		break;

	case EXPR_MOD:
		{
		if ( is_integral )
			{
			if ( i2 == 0 )
				RuntimeError("modulo by zero");

			i3 = i1 % i2;
			}

		else if ( is_unsigned )
			{
			if ( u2 == 0 )
				RuntimeError("modulo by zero");

			u3 = u1 % u2;
			}

		else
			RuntimeErrorWithCallStack("bad type in BinaryExpr::Fold");
		}

		break;

	case EXPR_AND:		DO_UINT_FOLD(&); break;
	case EXPR_OR:		DO_UINT_FOLD(|); break;
	case EXPR_XOR:		DO_UINT_FOLD(^); break;

	case EXPR_AND_AND:	DO_INT_FOLD(&&); break;
	case EXPR_OR_OR:	DO_INT_FOLD(||); break;

	case EXPR_LT:		DO_INT_VAL_FOLD(<); break;
	case EXPR_LE:		DO_INT_VAL_FOLD(<=); break;
	case EXPR_EQ:		DO_INT_VAL_FOLD(==); break;
	case EXPR_NE:		DO_INT_VAL_FOLD(!=); break;
	case EXPR_GE:		DO_INT_VAL_FOLD(>=); break;
	case EXPR_GT:		DO_INT_VAL_FOLD(>); break;

	default:
		BadTag("BinaryExpr::Fold", expr_name(tag));
	}

	const auto& ret_type = IsVector(GetType()->Tag()) ? GetType()->Yield() : GetType();

	if ( ret_type->Tag() == TYPE_INTERVAL )
		return make_intrusive<IntervalVal>(d3);
	else if ( ret_type->Tag() == TYPE_TIME )
		return make_intrusive<TimeVal>(d3);
	else if ( ret_type->Tag() == TYPE_DOUBLE )
		return make_intrusive<DoubleVal>(d3);
	else if ( ret_type->InternalType() == TYPE_INTERNAL_UNSIGNED )
		return val_mgr->Count(u3);
	else if ( ret_type->Tag() == TYPE_BOOL )
		return val_mgr->Bool(i3);
	else
		return val_mgr->Int(i3);
	}

ValPtr BinaryExpr::StringFold(Val* v1, Val* v2) const
	{
	const String* s1 = v1->AsString();
	const String* s2 = v2->AsString();
	int result = 0;

	switch ( tag ) {
#undef DO_FOLD
#define DO_FOLD(sense) { result = Bstr_cmp(s1, s2) sense 0; break; }

	case EXPR_LT:		DO_FOLD(<)
	case EXPR_LE:		DO_FOLD(<=)
	case EXPR_EQ:		DO_FOLD(==)
	case EXPR_NE:		DO_FOLD(!=)
	case EXPR_GE:		DO_FOLD(>=)
	case EXPR_GT:		DO_FOLD(>)

	case EXPR_ADD:
	case EXPR_ADD_TO:
		{
		std::vector<const String*> strings;
		strings.push_back(s1);
		strings.push_back(s2);

		return make_intrusive<StringVal>(concatenate(strings));
		}

	default:
		BadTag("BinaryExpr::StringFold", expr_name(tag));
	}

	return val_mgr->Bool(result);
	}


ValPtr BinaryExpr::PatternFold(Val* v1, Val* v2) const
	{
	const RE_Matcher* re1 = v1->AsPattern();
	const RE_Matcher* re2 = v2->AsPattern();

	if ( tag != EXPR_AND && tag != EXPR_OR )
		BadTag("BinaryExpr::PatternFold");

	RE_Matcher* res = tag == EXPR_AND ?
		RE_Matcher_conjunction(re1, re2) :
		RE_Matcher_disjunction(re1, re2);

	return make_intrusive<PatternVal>(res);
	}

ValPtr BinaryExpr::SetFold(Val* v1, Val* v2) const
	{
	TableVal* tv1 = v1->AsTableVal();
	TableVal* tv2 = v2->AsTableVal();
	bool res = false;

	switch ( tag ) {
	case EXPR_AND:
		return tv1->Intersection(*tv2);

	case EXPR_OR:
		{
		auto rval = v1->Clone();

		if ( ! tv2->AddTo(rval.get(), false, false) )
			reporter->InternalError("set union failed to type check");

		return rval;
		}

	case EXPR_SUB:
		{
		auto rval = v1->Clone();

		if ( ! tv2->RemoveFrom(rval.get()) )
			reporter->InternalError("set difference failed to type check");

		return rval;
		}

	case EXPR_EQ:
		res = tv1->EqualTo(*tv2);
		break;

	case EXPR_NE:
		res = ! tv1->EqualTo(*tv2);
		break;

	case EXPR_LT:
		res = tv1->IsSubsetOf(*tv2) && tv1->Size() < tv2->Size();
		break;

	case EXPR_LE:
		res = tv1->IsSubsetOf(*tv2);
		break;

	case EXPR_GE:
	case EXPR_GT:
		// These should't happen due to canonicalization.
		reporter->InternalError("confusion over canonicalization in set comparison");
		break;

	default:
		BadTag("BinaryExpr::SetFold", expr_name(tag));
		return nullptr;
	}

	return val_mgr->Bool(res);
	}

ValPtr BinaryExpr::AddrFold(Val* v1, Val* v2) const
	{
	IPAddr a1 = v1->AsAddr();
	IPAddr a2 = v2->AsAddr();
	bool result = false;

	switch ( tag ) {

	case EXPR_LT:
		result = a1 < a2;
		break;
	case EXPR_LE:
		result = a1 < a2 || a1 == a2;
		break;
	case EXPR_EQ:
		result = a1 == a2;
		break;
	case EXPR_NE:
		result = a1 != a2;
		break;
	case EXPR_GE:
		result = ! ( a1 < a2 );
		break;
	case EXPR_GT:
		result = ( ! ( a1 < a2 ) ) && ( a1 != a2 );
		break;

	default:
		BadTag("BinaryExpr::AddrFold", expr_name(tag));
	}

	return val_mgr->Bool(result);
	}

ValPtr BinaryExpr::SubNetFold(Val* v1, Val* v2) const
	{
	const IPPrefix& n1 = v1->AsSubNet();
	const IPPrefix& n2 = v2->AsSubNet();

	bool result = n1 == n2;

	if ( tag == EXPR_NE )
		result = ! result;

	return val_mgr->Bool(result);
	}

void BinaryExpr::SwapOps()
	{
	// We could check here whether the operator is commutative.
	using std::swap;
	swap(op1, op2);
	}

void BinaryExpr::PromoteOps(TypeTag t)
	{
	TypeTag bt1 = op1->GetType()->Tag();
	TypeTag bt2 = op2->GetType()->Tag();

	bool is_vec1 = IsVector(bt1);
	bool is_vec2 = IsVector(bt2);

	if ( is_vec1 )
		bt1 = op1->GetType()->AsVectorType()->Yield()->Tag();
	if ( is_vec2 )
		bt2 = op2->GetType()->AsVectorType()->Yield()->Tag();

	if ( (is_vec1 || is_vec2) && ! (is_vec1 && is_vec2) )
		reporter->Warning("mixing vector and scalar operands is deprecated");

	if ( bt1 != t )
		op1 = make_intrusive<ArithCoerceExpr>(op1, t);
	if ( bt2 != t )
		op2 = make_intrusive<ArithCoerceExpr>(op2, t);
	}

void BinaryExpr::PromoteType(TypeTag t, bool is_vector)
	{
	PromoteOps(t);

	if ( is_vector )
		SetType(make_intrusive<VectorType>(base_type(t)));
	else
		SetType(base_type(t));
	}

void BinaryExpr::PromoteForInterval(ExprPtr& op)
	{
	if ( is_vector(op1) || is_vector(op2) )
		SetType(make_intrusive<VectorType>(base_type(TYPE_INTERVAL)));
	else
		SetType(base_type(TYPE_INTERVAL));

	if ( op->GetType()->Tag() != TYPE_DOUBLE )
		op = make_intrusive<ArithCoerceExpr>(op, TYPE_DOUBLE);
	}

CloneExpr::CloneExpr(ExprPtr arg_op)
	: UnaryExpr(EXPR_CLONE, std::move(arg_op))
	{
	if ( IsError() )
		return;

	SetType(op->GetType());
	}

ValPtr CloneExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return nullptr;

	if ( auto v = op->Eval(f) )
		return Fold(v.get());

	return nullptr;
	}

ValPtr CloneExpr::Fold(Val* v) const
	{
	return v->Clone();
	}

IncrExpr::IncrExpr(BroExprTag arg_tag, ExprPtr arg_op)
	: UnaryExpr(arg_tag, arg_op->MakeLvalue())
	{
	if ( IsError() )
		return;

	const auto& t = op->GetType();

	if ( IsVector(t->Tag()) )
		{
		if ( ! IsIntegral(t->AsVectorType()->Yield()->Tag()) )
			ExprError("vector elements must be integral for increment operator");
		else
			{
			reporter->Warning("increment/decrement operations for vectors deprecated");
			SetType(t);
			}
		}
	else
		{
		if ( ! IsIntegral(t->Tag()) )
			ExprError("requires an integral operand");
		else
			SetType(t);
		}
	}

ValPtr IncrExpr::DoSingleEval(Frame* f, Val* v) const
	{
	bro_int_t k = v->CoerceToInt();

	if ( Tag() == EXPR_INCR )
		++k;
	else
		{
		--k;

		if ( k < 0 &&
		     v->GetType()->InternalType() == TYPE_INTERNAL_UNSIGNED )
			RuntimeError("count underflow");
		}

	const auto& ret_type = IsVector(GetType()->Tag()) ? GetType()->Yield() : GetType();

	if ( ret_type->Tag() == TYPE_INT )
		return val_mgr->Int(k);
	else
		return val_mgr->Count(k);
	}


ValPtr IncrExpr::Eval(Frame* f) const
	{
	auto v = op->Eval(f);

	if ( ! v )
		return nullptr;

	if ( is_vector(v) )
		{
		VectorValPtr v_vec{NewRef{}, v->AsVectorVal()};

		for ( unsigned int i = 0; i < v_vec->Size(); ++i )
			{
			auto elt = v_vec->ValAt(i);
			if ( elt )
				v_vec->Assign(i, DoSingleEval(f, elt.get()));
			}

		op->Assign(f, std::move(v_vec));
		return v;
		}
	else
		{
		auto new_v = DoSingleEval(f, v.get());
		op->Assign(f, new_v);
		return new_v;
		}
	}

bool IncrExpr::IsPure() const
	{
	return false;
	}

ComplementExpr::ComplementExpr(ExprPtr arg_op)
	: UnaryExpr(EXPR_COMPLEMENT, std::move(arg_op))
	{
	if ( IsError() )
		return;

	const auto& t = op->GetType();
	TypeTag bt = t->Tag();

	if ( bt != TYPE_COUNT )
		ExprError("requires \"count\" operand");
	else
		SetType(base_type(TYPE_COUNT));
	}

ValPtr ComplementExpr::Fold(Val* v) const
	{
	return val_mgr->Count(~ v->InternalUnsigned());
	}

NotExpr::NotExpr(ExprPtr arg_op)
	: UnaryExpr(EXPR_NOT, std::move(arg_op))
	{
	if ( IsError() )
		return;

	TypeTag bt = op->GetType()->Tag();

	if ( ! IsIntegral(bt) && bt != TYPE_BOOL )
		ExprError("requires an integral or boolean operand");
	else
		SetType(base_type(TYPE_BOOL));
	}

ValPtr NotExpr::Fold(Val* v) const
	{
	return val_mgr->Bool(! v->InternalInt());
	}

PosExpr::PosExpr(ExprPtr arg_op)
	: UnaryExpr(EXPR_POSITIVE, std::move(arg_op))
	{
	if ( IsError() )
		return;

	const auto& t = IsVector(op->GetType()->Tag()) ? op->GetType()->Yield() : op->GetType();

	TypeTag bt = t->Tag();
	TypePtr base_result_type;

	if ( IsIntegral(bt) )
		// Promote count and counter to int.
		base_result_type = base_type(TYPE_INT);
	else if ( bt == TYPE_INTERVAL || bt == TYPE_DOUBLE )
		base_result_type = t;
	else
		ExprError("requires an integral or double operand");

	if ( is_vector(op) )
		SetType(make_intrusive<VectorType>(std::move(base_result_type)));
	else
		SetType(std::move(base_result_type));
	}

ValPtr PosExpr::Fold(Val* v) const
	{
	TypeTag t = v->GetType()->Tag();

	if ( t == TYPE_DOUBLE || t == TYPE_INTERVAL || t == TYPE_INT )
		return {NewRef{}, v};
	else
		return val_mgr->Int(v->CoerceToInt());
	}

NegExpr::NegExpr(ExprPtr arg_op)
	: UnaryExpr(EXPR_NEGATE, std::move(arg_op))
	{
	if ( IsError() )
		return;

	const auto& t = IsVector(op->GetType()->Tag()) ? op->GetType()->Yield() : op->GetType();

	TypeTag bt = t->Tag();
	TypePtr base_result_type;

	if ( IsIntegral(bt) )
		// Promote count and counter to int.
		base_result_type = base_type(TYPE_INT);
	else if ( bt == TYPE_INTERVAL || bt == TYPE_DOUBLE )
		base_result_type = t;
	else
		ExprError("requires an integral or double operand");

	if ( is_vector(op) )
		SetType(make_intrusive<VectorType>(std::move(base_result_type)));
	else
		SetType(std::move(base_result_type));
	}

ValPtr NegExpr::Fold(Val* v) const
	{
	if ( v->GetType()->Tag() == TYPE_DOUBLE )
		return make_intrusive<DoubleVal>(- v->InternalDouble());
	else if ( v->GetType()->Tag() == TYPE_INTERVAL )
		return make_intrusive<IntervalVal>(- v->InternalDouble());
	else
		return val_mgr->Int(- v->CoerceToInt());
	}

SizeExpr::SizeExpr(ExprPtr arg_op)
	: UnaryExpr(EXPR_SIZE, std::move(arg_op))
	{
	if ( IsError() )
		return;

	auto& t = op->GetType();

	if ( t->Tag() == TYPE_ANY )
		SetType(base_type(TYPE_ANY));
	else if ( t->Tag() == TYPE_FILE || t->Tag() == TYPE_SUBNET ||
	          t->InternalType() == TYPE_INTERNAL_DOUBLE )
		SetType(base_type(TYPE_DOUBLE));
	else
		SetType(base_type(TYPE_COUNT));
	}

ValPtr SizeExpr::Eval(Frame* f) const
	{
	auto v = op->Eval(f);

	if ( ! v )
		return nullptr;

	return Fold(v.get());
	}

ValPtr SizeExpr::Fold(Val* v) const
	{
	return v->SizeVal();
	}

AddExpr::AddExpr(ExprPtr arg_op1, ExprPtr arg_op2)
    : BinaryExpr(EXPR_ADD, std::move(arg_op1), std::move(arg_op2))
	{
	if ( IsError() )
		return;

	TypeTag bt1 = op1->GetType()->Tag();

	if ( IsVector(bt1) )
		bt1 = op1->GetType()->AsVectorType()->Yield()->Tag();

	TypeTag bt2 = op2->GetType()->Tag();

	if ( IsVector(bt2) )
		bt2 = op2->GetType()->AsVectorType()->Yield()->Tag();

	TypePtr base_result_type;

	if ( bt2 == TYPE_INTERVAL && ( bt1 == TYPE_TIME || bt1 == TYPE_INTERVAL ) )
		base_result_type = base_type(bt1);
	else if ( bt2 == TYPE_TIME && bt1 == TYPE_INTERVAL )
		base_result_type = base_type(bt2);
	else if ( BothArithmetic(bt1, bt2) )
		PromoteType(max_type(bt1, bt2), is_vector(op1) || is_vector(op2));
	else if ( BothString(bt1, bt2) )
		base_result_type = base_type(bt1);
	else
		ExprError("requires arithmetic operands");

	if ( base_result_type )
		{
		if ( is_vector(op1) || is_vector(op2) )
			SetType(make_intrusive<VectorType>(std::move(base_result_type)));
		else
			SetType(std::move(base_result_type));
		}
	}

void AddExpr::Canonicize()
	{
	if ( expr_greater(op2.get(), op1.get()) ||
	     (op1->GetType()->Tag() == TYPE_INTERVAL &&
	      op2->GetType()->Tag() == TYPE_TIME) ||
	     (op2->IsConst() && ! is_vector(op2->ExprVal()) && ! op1->IsConst()))
		SwapOps();
	}

AddToExpr::AddToExpr(ExprPtr arg_op1, ExprPtr arg_op2)
	: BinaryExpr(EXPR_ADD_TO, is_vector(arg_op1) ?
	             std::move(arg_op1) : arg_op1->MakeLvalue(),
	             std::move(arg_op2))
	{
	if ( IsError() )
		return;

	TypeTag bt1 = op1->GetType()->Tag();
	TypeTag bt2 = op2->GetType()->Tag();

	if ( BothArithmetic(bt1, bt2) )
		PromoteType(max_type(bt1, bt2), is_vector(op1) || is_vector(op2));
	else if ( BothString(bt1, bt2) || BothInterval(bt1, bt2) )
		SetType(base_type(bt1));

	else if ( IsVector(bt1) )
		{
		bt1 = op1->GetType()->AsVectorType()->Yield()->Tag();

		if ( IsArithmetic(bt1) )
			{
			if ( IsArithmetic(bt2) )
				{
				if ( bt2 != bt1 )
					op2 = make_intrusive<ArithCoerceExpr>(std::move(op2), bt1);

				SetType(op1->GetType());
				}

			else
				ExprError("appending non-arithmetic to arithmetic vector");
			}

		else if ( bt1 != bt2 && bt1 != TYPE_ANY )
			ExprError(util::fmt("incompatible vector append: %s and %s",
			                          type_name(bt1), type_name(bt2)));

		else
			SetType(op1->GetType());
		}

	else
		ExprError("requires two arithmetic or two string operands");
	}

ValPtr AddToExpr::Eval(Frame* f) const
	{
	auto v1 = op1->Eval(f);

	if ( ! v1 )
		return nullptr;

	auto v2 = op2->Eval(f);

	if ( ! v2 )
		return nullptr;

	if ( is_vector(v1) )
		{
		VectorVal* vv = v1->AsVectorVal();

		if ( ! vv->Assign(vv->Size(), v2) )
			RuntimeError("type-checking failed in vector append");

		return v1;
		}

	if ( auto result = Fold(v1.get(), v2.get()) )
		{
		op1->Assign(f, result);
		return result;
		}
	else
		return nullptr;
	}

SubExpr::SubExpr(ExprPtr arg_op1, ExprPtr arg_op2)
	: BinaryExpr(EXPR_SUB, std::move(arg_op1), std::move(arg_op2))
	{
	if ( IsError() )
		return;

	const auto& t1 = op1->GetType();
	const auto& t2 = op2->GetType();

	TypeTag bt1 = t1->Tag();
	if ( IsVector(bt1) )
		bt1 = t1->AsVectorType()->Yield()->Tag();

	TypeTag bt2 = t2->Tag();
	if ( IsVector(bt2) )
		bt2 = t2->AsVectorType()->Yield()->Tag();

	TypePtr base_result_type;

	if ( bt2 == TYPE_INTERVAL && ( bt1 == TYPE_TIME || bt1 == TYPE_INTERVAL ) )
		base_result_type = base_type(bt1);

	else if ( bt1 == TYPE_TIME && bt2 == TYPE_TIME )
		SetType(base_type(TYPE_INTERVAL));

	else if ( t1->IsSet() && t2->IsSet() )
		{
		if ( same_type(t1, t2) )
			SetType(op1->GetType());
		else
			ExprError("incompatible \"set\" operands");
		}

	else if ( BothArithmetic(bt1, bt2) )
		PromoteType(max_type(bt1, bt2), is_vector(op1) || is_vector(op2));

	else
		ExprError("requires arithmetic operands");

	if ( base_result_type )
		{
		if ( is_vector(op1) || is_vector(op2) )
			SetType(make_intrusive<VectorType>(std::move(base_result_type)));
		else
			SetType(std::move(base_result_type));
		}
	}

RemoveFromExpr::RemoveFromExpr(ExprPtr arg_op1, ExprPtr arg_op2)
	: BinaryExpr(EXPR_REMOVE_FROM, arg_op1->MakeLvalue(), std::move(arg_op2))
	{
	if ( IsError() )
		return;

	TypeTag bt1 = op1->GetType()->Tag();
	TypeTag bt2 = op2->GetType()->Tag();

	if ( BothArithmetic(bt1, bt2) )
		PromoteType(max_type(bt1, bt2), is_vector(op1) || is_vector(op2));
	else if ( BothInterval(bt1, bt2) )
		SetType(base_type(bt1));
	else
		ExprError("requires two arithmetic operands");
	}

ValPtr RemoveFromExpr::Eval(Frame* f) const
	{
	auto v1 = op1->Eval(f);

	if ( ! v1 )
		return nullptr;

	auto v2 = op2->Eval(f);

	if ( ! v2 )
		return nullptr;

	if ( auto result = Fold(v1.get(), v2.get()) )
		{
		op1->Assign(f, result);
		return result;
		}
	else
		return nullptr;
	}

TimesExpr::TimesExpr(ExprPtr arg_op1, ExprPtr arg_op2)
	: BinaryExpr(EXPR_TIMES, std::move(arg_op1), std::move(arg_op2))
	{
	if ( IsError() )
		return;

	Canonicize();

	TypeTag bt1 = op1->GetType()->Tag();

	if ( IsVector(bt1) )
		bt1 = op1->GetType()->AsVectorType()->Yield()->Tag();

	TypeTag bt2 = op2->GetType()->Tag();

	if ( IsVector(bt2) )
		bt2 = op2->GetType()->AsVectorType()->Yield()->Tag();

	if ( bt1 == TYPE_INTERVAL || bt2 == TYPE_INTERVAL )
		{
		if ( IsArithmetic(bt1) || IsArithmetic(bt2) )
			PromoteForInterval(IsArithmetic(bt1) ? op1 : op2);
		else
			ExprError("multiplication with interval requires arithmetic operand");
		}
	else if ( BothArithmetic(bt1, bt2) )
		PromoteType(max_type(bt1, bt2), is_vector(op1) || is_vector(op2));
	else
		ExprError("requires arithmetic operands");
	}

void TimesExpr::Canonicize()
	{
	if ( expr_greater(op2.get(), op1.get()) || op2->GetType()->Tag() == TYPE_INTERVAL ||
	     (op2->IsConst() && ! is_vector(op2->ExprVal()) && ! op1->IsConst()) )
		SwapOps();
	}

DivideExpr::DivideExpr(ExprPtr arg_op1, ExprPtr arg_op2)
	: BinaryExpr(EXPR_DIVIDE, std::move(arg_op1), std::move(arg_op2))
	{
	if ( IsError() )
		return;

	TypeTag bt1 = op1->GetType()->Tag();

	if ( IsVector(bt1) )
		bt1 = op1->GetType()->AsVectorType()->Yield()->Tag();

	TypeTag bt2 = op2->GetType()->Tag();

	if ( IsVector(bt2) )
		bt2 = op2->GetType()->AsVectorType()->Yield()->Tag();

	if ( bt1 == TYPE_INTERVAL || bt2 == TYPE_INTERVAL )
		{
		if ( IsArithmetic(bt1) || IsArithmetic(bt2) )
			PromoteForInterval(IsArithmetic(bt1) ? op1 : op2);
		else if ( bt1 == TYPE_INTERVAL && bt2 == TYPE_INTERVAL )
			{
			if ( is_vector(op1) || is_vector(op2) )
				SetType(make_intrusive<VectorType>(base_type(TYPE_DOUBLE)));
			else
				SetType(base_type(TYPE_DOUBLE));
			}
		else
			ExprError("division of interval requires arithmetic operand");
		}

	else if ( BothArithmetic(bt1, bt2) )
		PromoteType(max_type(bt1, bt2), is_vector(op1) || is_vector(op2));

	else if ( bt1 == TYPE_ADDR && ! is_vector(op2) &&
		  (bt2 == TYPE_COUNT || bt2 == TYPE_INT) )
		SetType(base_type(TYPE_SUBNET));

	else
		ExprError("requires arithmetic operands");
	}

ValPtr DivideExpr::AddrFold(Val* v1, Val* v2) const
	{
	uint32_t mask;

	if ( v2->GetType()->Tag() == TYPE_COUNT )
		mask = static_cast<uint32_t>(v2->InternalUnsigned());
	else
		mask = static_cast<uint32_t>(v2->InternalInt());

	auto& a = v1->AsAddr();

	if ( a.GetFamily() == IPv4 )
		{
		if ( mask > 32 )
			RuntimeError(util::fmt("bad IPv4 subnet prefix length: %" PRIu32, mask));
		}
	else
		{
		if ( mask > 128 )
			RuntimeError(util::fmt("bad IPv6 subnet prefix length: %" PRIu32, mask));
		}

	return make_intrusive<SubNetVal>(a, mask);
	}

ModExpr::ModExpr(ExprPtr arg_op1, ExprPtr arg_op2)
	: BinaryExpr(EXPR_MOD, std::move(arg_op1), std::move(arg_op2))
	{
	if ( IsError() )
		return;

	TypeTag bt1 = op1->GetType()->Tag();

	if ( IsVector(bt1) )
		bt1 = op1->GetType()->AsVectorType()->Yield()->Tag();

	TypeTag bt2 = op2->GetType()->Tag();

	if ( IsVector(bt2) )
		bt2 = op2->GetType()->AsVectorType()->Yield()->Tag();

	if ( BothIntegral(bt1, bt2) )
		PromoteType(max_type(bt1, bt2), is_vector(op1) || is_vector(op2));
	else
		ExprError("requires integral operands");
	}

BoolExpr::BoolExpr(BroExprTag arg_tag, ExprPtr arg_op1, ExprPtr arg_op2)
	: BinaryExpr(arg_tag, std::move(arg_op1), std::move(arg_op2))
	{
	if ( IsError() )
		return;

	TypeTag bt1 = op1->GetType()->Tag();

	if ( IsVector(bt1) )
		bt1 = op1->GetType()->AsVectorType()->Yield()->Tag();

	TypeTag bt2 = op2->GetType()->Tag();

	if ( IsVector(bt2) )
		bt2 = op2->GetType()->AsVectorType()->Yield()->Tag();

	if ( BothBool(bt1, bt2) )
		{
		if ( is_vector(op1) || is_vector(op2) )
			{
			if ( ! (is_vector(op1) && is_vector(op2)) )
				reporter->Warning("mixing vector and scalar operands is deprecated");
			SetType(make_intrusive<VectorType>(base_type(TYPE_BOOL)));
			}
		else
			SetType(base_type(TYPE_BOOL));
		}
	else
		ExprError("requires boolean operands");
	}

ValPtr BoolExpr::DoSingleEval(Frame* f, ValPtr v1, Expr* op2) const
	{
	if ( ! v1 )
		return nullptr;

	if ( tag == EXPR_AND_AND )
		{
		if ( v1->IsZero() )
			return v1;
		else
			return op2->Eval(f);
		}

	else
		{
		if ( v1->IsZero() )
			return op2->Eval(f);
		else
			return v1;
		}
	}

ValPtr BoolExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return nullptr;

	auto v1 = op1->Eval(f);

	if ( ! v1 )
		return nullptr;

	bool is_vec1 = is_vector(op1);
	bool is_vec2 = is_vector(op2);

	// Handle scalar op scalar
	if ( ! is_vec1 && ! is_vec2 )
		return DoSingleEval(f, std::move(v1), op2.get());

	// Handle scalar op vector  or  vector op scalar
	// We can't short-circuit everything since we need to eval
	// a vector in order to find out its length.
	if ( ! (is_vec1 && is_vec2) )
		{ // Only one is a vector.
		ValPtr scalar_v;
		VectorValPtr vector_v;

		if ( is_vec1 )
			{
			scalar_v = op2->Eval(f);
			vector_v = {AdoptRef{}, v1.release()->AsVectorVal()};
			}
		else
			{
			scalar_v = std::move(v1);
			vector_v = {AdoptRef{}, op2->Eval(f).release()->AsVectorVal()};
			}

		if ( ! scalar_v || ! vector_v )
			return nullptr;

		VectorValPtr result;

		// It's either an EXPR_AND_AND or an EXPR_OR_OR.
		bool is_and = (tag == EXPR_AND_AND);

		if ( scalar_v->IsZero() == is_and )
			{
			result = make_intrusive<VectorVal>(GetType<VectorType>());
			result->Resize(vector_v->Size());
			result->AssignRepeat(0, result->Size(), std::move(scalar_v));
			}
		else
			result = std::move(vector_v);

		return result;
		}

	// Only case remaining: both are vectors.
	auto v2 = op2->Eval(f);

	if ( ! v2 )
		return nullptr;

	VectorVal* vec_v1 = v1->AsVectorVal();
	VectorVal* vec_v2 = v2->AsVectorVal();

	if ( vec_v1->Size() != vec_v2->Size() )
		{
		RuntimeError("vector operands have different sizes");
		return nullptr;
		}

	auto result = make_intrusive<VectorVal>(GetType<VectorType>());
	result->Resize(vec_v1->Size());

	for ( unsigned int i = 0; i < vec_v1->Size(); ++i )
		{
		const auto op1 = vec_v1->BoolAt(i);
		const auto op2 = vec_v2->BoolAt(i);

		bool local_result =
			(tag == EXPR_AND_AND) ? (op1 && op2) : (op1 || op2);

		result->Assign(i, val_mgr->Bool(local_result));
		}

	return result;
	}

BitExpr::BitExpr(BroExprTag arg_tag, ExprPtr arg_op1, ExprPtr arg_op2)
	: BinaryExpr(arg_tag, std::move(arg_op1), std::move(arg_op2))
	{
	if ( IsError() )
		return;

	const auto& t1 = op1->GetType();
	const auto& t2 = op2->GetType();

	TypeTag bt1 = t1->Tag();

	if ( IsVector(bt1) )
		bt1 = t1->AsVectorType()->Yield()->Tag();

	TypeTag bt2 = t2->Tag();

	if ( IsVector(bt2) )
		bt2 = t2->AsVectorType()->Yield()->Tag();

	if ( (bt1 == TYPE_COUNT) && (bt2 == TYPE_COUNT) )
		{
		if ( is_vector(op1) || is_vector(op2) )
			SetType(make_intrusive<VectorType>(base_type(TYPE_COUNT)));
		else
			SetType(base_type(TYPE_COUNT));
		}

	else if ( bt1 == TYPE_PATTERN )
		{
		if ( bt2 != TYPE_PATTERN )
			ExprError("cannot mix pattern and non-pattern operands");
		else if ( tag == EXPR_XOR )
			ExprError("'^' operator does not apply to patterns");
		else
			SetType(base_type(TYPE_PATTERN));
		}

	else if ( t1->IsSet() && t2->IsSet() )
		{
		if ( same_type(t1, t2) )
			SetType(op1->GetType());
		else
			ExprError("incompatible \"set\" operands");
		}

	else
		ExprError("requires \"count\" or compatible \"set\" operands");
	}

EqExpr::EqExpr(BroExprTag arg_tag, ExprPtr arg_op1, ExprPtr arg_op2)
	: BinaryExpr(arg_tag, std::move(arg_op1), std::move(arg_op2))
	{
	if ( IsError() )
		return;

	Canonicize();

	const auto& t1 = op1->GetType();
	const auto& t2 = op2->GetType();

	TypeTag bt1 = t1->Tag();
	if ( IsVector(bt1) )
		bt1 = t1->AsVectorType()->Yield()->Tag();

	TypeTag bt2 = t2->Tag();
	if ( IsVector(bt2) )
		bt2 = t2->AsVectorType()->Yield()->Tag();

	if ( is_vector(op1) || is_vector(op2) )
		SetType(make_intrusive<VectorType>(base_type(TYPE_BOOL)));
	else
		SetType(base_type(TYPE_BOOL));

	if ( BothArithmetic(bt1, bt2) )
		PromoteOps(max_type(bt1, bt2));

	else if ( EitherArithmetic(bt1, bt2) &&
		// Allow comparisons with zero.
		  ((bt1 == TYPE_TIME && op2->IsZero()) ||
		   (bt2 == TYPE_TIME && op1->IsZero())) )
		PromoteOps(TYPE_TIME);

	else if ( bt1 == bt2 )
		{
		switch ( bt1 ) {
		case TYPE_BOOL:
		case TYPE_TIME:
		case TYPE_INTERVAL:
		case TYPE_STRING:
		case TYPE_PORT:
		case TYPE_ADDR:
		case TYPE_SUBNET:
		case TYPE_ERROR:
		case TYPE_FUNC:
			break;

		case TYPE_ENUM:
			if ( ! same_type(t1, t2) )
				ExprError("illegal enum comparison");
			break;

		case TYPE_TABLE:
			if ( t1->IsSet() && t2->IsSet() )
				{
				if ( ! same_type(t1, t2) )
					ExprError("incompatible sets in comparison");
				break;
				}

			// FALL THROUGH

		default:
			ExprError("illegal comparison");
		}
		}

	else if ( bt1 == TYPE_PATTERN && bt2 == TYPE_STRING )
		;

	else
		ExprError("type clash in comparison");
	}

void EqExpr::Canonicize()
	{
	if ( op2->GetType()->Tag() == TYPE_PATTERN )
		SwapOps();

	else if ( op1->GetType()->Tag() == TYPE_PATTERN )
		;

	else if ( expr_greater(op2.get(), op1.get()) )
		SwapOps();
	}

ValPtr EqExpr::Fold(Val* v1, Val* v2) const
	{
	if ( op1->GetType()->Tag() == TYPE_PATTERN )
		{
		auto re = v1->As<PatternVal*>();
		const String* s = v2->AsString();
		if ( tag == EXPR_EQ )
			return val_mgr->Bool(re->MatchExactly(s));
		else
			return val_mgr->Bool(! re->MatchExactly(s));
		}
	else if ( op1->GetType()->Tag() == TYPE_FUNC )
		{
		auto res = v1->AsFunc() == v2->AsFunc();
		return val_mgr->Bool(tag == EXPR_EQ ? res : ! res);
		}

	else
		return BinaryExpr::Fold(v1, v2);
	}

bool EqExpr::InvertSense()
	{
	tag = (tag == EXPR_EQ ? EXPR_NE : EXPR_EQ);
	return true;
	}

RelExpr::RelExpr(BroExprTag arg_tag, ExprPtr arg_op1, ExprPtr arg_op2)
	: BinaryExpr(arg_tag, std::move(arg_op1), std::move(arg_op2))
	{
	if ( IsError() )
		return;

	Canonicize();

	const auto& t1 = op1->GetType();
	const auto& t2 = op2->GetType();

	TypeTag bt1 = t1->Tag();
	if ( IsVector(bt1) )
		bt1 = t1->AsVectorType()->Yield()->Tag();

	TypeTag bt2 = t2->Tag();
	if ( IsVector(bt2) )
		bt2 = t2->AsVectorType()->Yield()->Tag();

	if ( is_vector(op1) || is_vector(op2) )
		SetType(make_intrusive<VectorType>(base_type(TYPE_BOOL)));
	else
		SetType(base_type(TYPE_BOOL));

	if ( BothArithmetic(bt1, bt2) )
		PromoteOps(max_type(bt1, bt2));

	else if ( t1->IsSet() && t2->IsSet() )
		{
		if ( ! same_type(t1, t2) )
			ExprError("incompatible sets in comparison");
		}

	else if ( bt1 != bt2 )
		ExprError("operands must be of the same type");

	else if ( bt1 != TYPE_TIME && bt1 != TYPE_INTERVAL &&
		  bt1 != TYPE_PORT && bt1 != TYPE_ADDR &&
		  bt1 != TYPE_STRING )
		ExprError("illegal comparison");
	}

void RelExpr::Canonicize()
	{
	if ( tag == EXPR_GT )
		{
		SwapOps();
		tag = EXPR_LT;
		}

	else if ( tag == EXPR_GE )
		{
		SwapOps();
		tag = EXPR_LE;
		}
	}

bool RelExpr::InvertSense()
	{
	switch ( tag ) {
	case EXPR_LT:   tag = EXPR_GE; return true;
	case EXPR_LE:   tag = EXPR_GT; return true;
	case EXPR_GE:   tag = EXPR_LT; return true;
	case EXPR_GT:   tag = EXPR_LE; return true;

	default:
		return false;
	}
	}

CondExpr::CondExpr(ExprPtr arg_op1, ExprPtr arg_op2, ExprPtr arg_op3)
	: Expr(EXPR_COND),
	  op1(std::move(arg_op1)), op2(std::move(arg_op2)), op3(std::move(arg_op3))
	{
	TypeTag bt1 = op1->GetType()->Tag();

	if ( IsVector(bt1) )
		bt1 = op1->GetType()->AsVectorType()->Yield()->Tag();

	if ( op1->IsError() || op2->IsError() || op3->IsError() )
		SetError();

	else if ( bt1 != TYPE_BOOL )
		ExprError("requires boolean conditional");

	else
		{
		TypeTag bt2 = op2->GetType()->Tag();
		TypeTag bt3 = op3->GetType()->Tag();

		if ( is_vector(op1) )
			{
			if ( ! (is_vector(op2) && is_vector(op3)) )
				{
				ExprError("vector conditional requires vector alternatives");
				return;
				}

			bt2 = op2->GetType()->AsVectorType()->Yield()->Tag();
			bt3 = op3->GetType()->AsVectorType()->Yield()->Tag();
			}

		if ( BothArithmetic(bt2, bt3) )
			{
			TypeTag t = max_type(bt2, bt3);
			if ( bt2 != t )
				op2 = make_intrusive<ArithCoerceExpr>(std::move(op2), t);
			if ( bt3 != t )
				op3 = make_intrusive<ArithCoerceExpr>(std::move(op3), t);

			if ( is_vector(op1) )
				SetType(make_intrusive<VectorType>(base_type(t)));
			else
				SetType(base_type(t));
			}

		else if ( bt2 != bt3 )
			ExprError("operands must be of the same type");

		else
			{
			if ( is_vector(op1) )
				{
				ExprError("vector conditional type clash between alternatives");
				return;
				}

			if ( bt2 == zeek::TYPE_TABLE )
				{
				auto tt2 = op2->GetType<TableType>();
				auto tt3 = op3->GetType<TableType>();

				if ( tt2->IsUnspecifiedTable() )
					op2 = make_intrusive<TableCoerceExpr>(std::move(op2), std::move(tt3));
				else if( tt3->IsUnspecifiedTable() )
					op3 = make_intrusive<TableCoerceExpr>(std::move(op3), std::move(tt2));
				else if ( ! same_type(op2->GetType(), op3->GetType()) )
					ExprError("operands must be of the same type");
				}
			else if ( bt2 == zeek::TYPE_VECTOR )
				{
				auto vt2 = op2->GetType<VectorType>();
				auto vt3 = op3->GetType<VectorType>();

				if ( vt2->IsUnspecifiedVector() )
					op2 = make_intrusive<VectorCoerceExpr>(std::move(op2), std::move(vt3));
				else if( vt3->IsUnspecifiedVector() )
					op3 = make_intrusive<VectorCoerceExpr>(std::move(op3), std::move(vt2));
				else if ( ! same_type(op2->GetType(), op3->GetType()) )
					ExprError("operands must be of the same type");
				}
			else if ( ! same_type(op2->GetType(), op3->GetType()) )
				// Records could potentially also coerce, but may have some cases
				// where the coercion direction is ambiguous.
				ExprError("operands must be of the same type");

			if ( ! IsError() )
				SetType(op2->GetType());
			}
		}
	}

ValPtr CondExpr::Eval(Frame* f) const
	{
	if ( ! is_vector(op1) )
		{
		// Scalar case
		auto false_eval = op1->Eval(f)->IsZero();
		return (false_eval ? op3 : op2)->Eval(f);
		}

	// Vector case: no mixed scalar/vector cases allowed
	auto v1 = op1->Eval(f);

	if ( ! v1 )
		return nullptr;

	auto v2 = op2->Eval(f);

	if ( ! v2 )
		return nullptr;

	auto v3 = op3->Eval(f);

	if ( ! v3 )
		return nullptr;

	VectorVal* cond = v1->AsVectorVal();
	VectorVal* a = v2->AsVectorVal();
	VectorVal* b = v3->AsVectorVal();

	if ( cond->Size() != a->Size() || a->Size() != b->Size() )
		{
		RuntimeError("vectors in conditional expression have different sizes");
		return nullptr;
		}

	auto result = make_intrusive<VectorVal>(GetType<VectorType>());
	result->Resize(cond->Size());

	for ( unsigned int i = 0; i < cond->Size(); ++i )
		{
		auto local_cond = cond->BoolAt(i);
		auto v = local_cond ? a->ValAt(i) : b->ValAt(i);
		result->Assign(i, v);
		}

	return result;
	}

bool CondExpr::IsPure() const
	{
	return op1->IsPure() && op2->IsPure() && op3->IsPure();
	}

TraversalCode CondExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	tc = op1->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = op2->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = op3->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}

void CondExpr::ExprDescribe(ODesc* d) const
	{
	op1->Describe(d);
	d->AddSP(" ?");
	op2->Describe(d);
	d->AddSP(" :");
	op3->Describe(d);
	}

RefExpr::RefExpr(ExprPtr arg_op)
	: UnaryExpr(EXPR_REF, std::move(arg_op))
	{
	if ( IsError() )
		return;

	if ( ! is_assignable(op->GetType()->Tag()) )
		ExprError("illegal assignment target");
	else
		SetType(op->GetType());
	}

ExprPtr RefExpr::MakeLvalue()
	{
	return {NewRef{}, this};
	}

void RefExpr::Assign(Frame* f, ValPtr v)
	{
	op->Assign(f, std::move(v));
	}

AssignExpr::AssignExpr(ExprPtr arg_op1,
                       ExprPtr arg_op2,
                       bool arg_is_init, ValPtr arg_val,
                       const AttributesPtr& attrs,
                       bool typecheck)
	: BinaryExpr(EXPR_ASSIGN, arg_is_init ?
	             std::move(arg_op1) : arg_op1->MakeLvalue(),
	             std::move(arg_op2))
	{
	val = nullptr;
	is_init = arg_is_init;

	if ( IsError() )
		return;

	if ( arg_val )
		SetType(arg_val->GetType());
	else
		SetType(op1->GetType());

	if ( is_init )
		{
		SetLocationInfo(op1->GetLocationInfo(),
				op2->GetLocationInfo());
		return;
		}

	if ( typecheck )
		// We discard the status from TypeCheck since it has already
		// generated error messages.
		(void) TypeCheck(attrs);

	val = std::move(arg_val);

	SetLocationInfo(op1->GetLocationInfo(), op2->GetLocationInfo());
	}

bool AssignExpr::TypeCheck(const AttributesPtr& attrs)
	{
	TypeTag bt1 = op1->GetType()->Tag();
	TypeTag bt2 = op2->GetType()->Tag();

	if ( bt1 == TYPE_LIST && bt2 == TYPE_ANY )
		// This is ok because we cannot explicitly declare lists on
		// the script level.
		return true;

	// This should be one of them, but not both (i.e. XOR)
	if ( ((bt1 == TYPE_ENUM) ^ (bt2 == TYPE_ENUM)) )
		{
		ExprError("can't convert to/from enumerated type");
		return false;
		}

	if ( IsArithmetic(bt1) )
		return TypeCheckArithmetics(bt1, bt2);

	if ( bt1 == TYPE_TIME && IsArithmetic(bt2) && op2->IsZero() )
		{ // Allow assignments to zero as a special case.
		op2 = make_intrusive<ArithCoerceExpr>(std::move(op2), bt1);
		return true;
		}

	if ( bt1 == TYPE_TABLE && bt2 == bt1 &&
	     op2->GetType()->AsTableType()->IsUnspecifiedTable() )
		{
		op2 = make_intrusive<TableCoerceExpr>(std::move(op2), op1->GetType<TableType>());
		return true;
		}

	if ( bt1 == TYPE_TABLE && op2->Tag() == EXPR_LIST )
		{
		std::unique_ptr<std::vector<AttrPtr>> attr_copy;

		if ( attrs )
			attr_copy = std::make_unique<std::vector<AttrPtr>>(attrs->GetAttrs());

		if ( op1->GetType()->IsSet() )
			op2 = make_intrusive<SetConstructorExpr>(
			        cast_intrusive<ListExpr>(op2), std::move(attr_copy), op1->GetType());
		else
			op2 = make_intrusive<TableConstructorExpr>(
			        cast_intrusive<ListExpr>(op2), std::move(attr_copy), op1->GetType());

		// The constructor expressions are performing the type
		// checking and will set op2 to an error state on failure.
		return ! op2->IsError();
		}

	if ( bt1 == TYPE_VECTOR )
		{
		if ( bt2 == bt1 && op2->GetType()->AsVectorType()->IsUnspecifiedVector() )
			{
			op2 = make_intrusive<VectorCoerceExpr>(std::move(op2), op1->GetType<VectorType>());
			return true;
			}

		if ( op2->Tag() == EXPR_LIST )
			{
			op2 = make_intrusive<VectorConstructorExpr>(
				IntrusivePtr{AdoptRef{}, op2.release()->AsListExpr()},
				op1->GetType());
			return true;
			}
		}

	if ( op1->GetType()->Tag() == TYPE_RECORD &&
	     op2->GetType()->Tag() == TYPE_RECORD )
		{
		if ( same_type(op1->GetType(), op2->GetType()) )
			return true;

		// Need to coerce.
		op2 = make_intrusive<RecordCoerceExpr>(std::move(op2), op1->GetType<RecordType>());
		return true;
		}

	if ( ! same_type(op1->GetType(), op2->GetType()) )
		{
		if ( bt1 == TYPE_TABLE && bt2 == TYPE_TABLE )
			{
			if ( op2->Tag() == EXPR_SET_CONSTRUCTOR )
				{
				// Some elements in constructor list must not match, see if
				// we can create a new constructor now that the expected type
				// of LHS is known and let it do coercions where possible.
				SetConstructorExpr* sce = dynamic_cast<SetConstructorExpr*>(op2.get());

				if ( ! sce )
					{
					ExprError("Failed typecast to SetConstructorExpr");
					return false;
					}

				ListExpr* ctor_list = dynamic_cast<ListExpr*>(sce->Op());

				if ( ! ctor_list )
					{
					ExprError("Failed typecast to ListExpr");
					return false;
					}

				std::unique_ptr<std::vector<AttrPtr>> attr_copy;


				if ( sce->GetAttrs() )
					{
					const auto& a = sce->GetAttrs()->GetAttrs();
					attr_copy = std::make_unique<std::vector<AttrPtr>>(a);
					}

				int errors_before = reporter->Errors();
				op2 = make_intrusive<SetConstructorExpr>(
					IntrusivePtr{NewRef{}, ctor_list},
					std::move(attr_copy),
					op1->GetType());
				int errors_after = reporter->Errors();

				if ( errors_after > errors_before )
					{
					ExprError("type clash in assignment");
					return false;
					}

				return true;
				}
			}

		ExprError("type clash in assignment");
		return false;
		}

	return true;
	}

bool AssignExpr::TypeCheckArithmetics(TypeTag bt1, TypeTag bt2)
	{
	if ( ! IsArithmetic(bt2) )
		{
		ExprError(util::fmt("assignment of non-arithmetic value to arithmetic (%s/%s)",
		                          type_name(bt1), type_name(bt2)));
		return false;
		}

	if ( bt1 == TYPE_DOUBLE )
		{
		PromoteOps(TYPE_DOUBLE);
		return true;
		}

	if ( bt2 == TYPE_DOUBLE )
		{
		Warn("dangerous assignment of double to integral");
		op2 = make_intrusive<ArithCoerceExpr>(std::move(op2), bt1);
		bt2 = op2->GetType()->Tag();
		}

	if ( bt1 == TYPE_INT )
		PromoteOps(TYPE_INT);
	else
		{
		if ( bt2 == TYPE_INT )
			{
			Warn("dangerous assignment of integer to count");
			op2 = make_intrusive<ArithCoerceExpr>(std::move(op2), bt1);
			}

		// Assignment of count to counter or vice
		// versa is allowed, and requires no
		// coercion.
		}

	return true;
	}


ValPtr AssignExpr::Eval(Frame* f) const
	{
	if ( is_init )
		{
		RuntimeError("illegal assignment in initialization");
		return nullptr;
		}

	if ( auto v = op2->Eval(f) )
		{
		op1->Assign(f, v);

		if ( val )
			return val;

		return v;
		}
	else
		return nullptr;
	}

TypePtr AssignExpr::InitType() const
	{
	if ( op1->Tag() != EXPR_LIST )
		{
		Error("bad initializer");
		return nullptr;
		}

	const auto& tl = op1->GetType();
	if ( tl->Tag() != TYPE_LIST )
		Internal("inconsistent list expr in AssignExpr::InitType");

	return make_intrusive<TableType>(
		IntrusivePtr{NewRef{}, tl->AsTypeList()},
		op2->GetType());
	}

void AssignExpr::EvalIntoAggregate(const zeek::Type* t, Val* aggr, Frame* f) const
	{
	if ( IsError() )
		return;

	TypeDecl td;

	if ( IsRecordElement(&td) )
		{
		if ( t->Tag() != TYPE_RECORD )
			{
			RuntimeError("not a record initializer");
			return;
			}

		const RecordType* rt = t->AsRecordType();
		int field = rt->FieldOffset(td.id);

		if ( field < 0 )
			{
			RuntimeError("no such field");
			return;
			}

		RecordVal* aggr_r = aggr->AsRecordVal();

		auto v = op2->Eval(f);

		if ( v )
			aggr_r->Assign(field, std::move(v));

		return;
		}

	if ( op1->Tag() != EXPR_LIST )
		RuntimeError("bad table insertion");

	TableVal* tv = aggr->AsTableVal();

	auto index = op1->Eval(f);
	auto v = check_and_promote(op2->Eval(f), t->Yield().get(), true);

	if ( ! index || ! v )
		return;

	if ( ! tv->Assign(std::move(index), std::move(v)) )
		RuntimeError("type clash in table assignment");
	}

ValPtr AssignExpr::InitVal(const zeek::Type* t, ValPtr aggr) const
	{
	if ( ! aggr )
		{
		Error("assignment in initialization");
		return nullptr;
		}

	if ( IsError() )
		return nullptr;

	TypeDecl td;

	if ( IsRecordElement(&td) )
		{
		if ( t->Tag() != TYPE_RECORD )
			{
			Error("not a record initializer", t);
			return nullptr;
			}

		const RecordType* rt = t->AsRecordType();
		int field = rt->FieldOffset(td.id);

		if ( field < 0 )
			{
			Error("no such field");
			return nullptr;
			}

		if ( aggr->GetType()->Tag() != TYPE_RECORD )
			Internal("bad aggregate in AssignExpr::InitVal");

		RecordVal* aggr_r = aggr->AsRecordVal();

		auto v = op2->InitVal(rt->GetFieldType(td.id).get(), nullptr);

		if ( ! v )
			return nullptr;

		aggr_r->Assign(field, v);
		return v;
		}

	else if ( op1->Tag() == EXPR_LIST )
		{
		if ( t->Tag() != TYPE_TABLE )
			{
			Error("not a table initialization", t);
			return nullptr;
			}

		if ( aggr->GetType()->Tag() != TYPE_TABLE )
			Internal("bad aggregate in AssignExpr::InitVal");

		auto tv = cast_intrusive<TableVal>(std::move(aggr));
		const TableType* tt = tv->GetType()->AsTableType();
		const auto& yt = tv->GetType()->Yield();

		auto index = op1->InitVal(tt->GetIndices().get(), nullptr);

		if ( yt->Tag() == TYPE_RECORD )
			{
			if ( op2->GetType()->Tag() != TYPE_RECORD )
				{
				Error(util::fmt("type mismatch in table value initialization: "
				                "assigning '%s' to table with values of type '%s'",
				                type_name(op2->GetType()->Tag()), type_name(yt->Tag())));
				return nullptr;
				}

			if ( ! same_type(*yt, *op2->GetType()) &&
			     ! record_promotion_compatible(yt->AsRecordType(),
			                                   op2->GetType()->AsRecordType()) )
				{
				Error("type mismatch in table value initialization: "
				      "incompatible record types");
				return nullptr;
				}
			}
		else
			{
			if ( ! same_type(*yt, *op2->GetType(), true) )
				{
				Error(util::fmt("type mismatch in table value initialization: "
				                "assigning '%s' to table with values of type '%s'",
				                type_name(op2->GetType()->Tag()), type_name(yt->Tag())));
				return nullptr;
				}
			}

		auto v = op2->InitVal(yt.get(), nullptr);

		if ( ! index || ! v )
			return nullptr;

		if ( ! tv->ExpandAndInit(std::move(index), std::move(v)) )
			return nullptr;

		return tv;
		}

	else
		{
		Error("illegal initializer");
		return nullptr;
		}
	}

bool AssignExpr::IsRecordElement(TypeDecl* td) const
	{
	if ( op1->Tag() == EXPR_NAME )
		{
		if ( td )
			{
			const NameExpr* n = (const NameExpr*) op1.get();
			td->type = op2->GetType();
			td->id = util::copy_string(n->Id()->Name());
			}

		return true;
		}

	return false;
	}

bool AssignExpr::IsPure() const
	{
	return false;
	}

IndexSliceAssignExpr::IndexSliceAssignExpr(ExprPtr op1, ExprPtr op2, bool is_init)
	: AssignExpr(std::move(op1), std::move(op2), is_init)
	{
	}

ValPtr IndexSliceAssignExpr::Eval(Frame* f) const
	{
	if ( is_init )
		{
		RuntimeError("illegal assignment in initialization");
		return nullptr;
		}

	if ( auto v = op2->Eval(f) )
		op1->Assign(f, std::move(v));

	return nullptr;
	}

IndexExpr::IndexExpr(ExprPtr arg_op1, ListExprPtr arg_op2, bool arg_is_slice)
	: BinaryExpr(EXPR_INDEX, std::move(arg_op1), std::move(arg_op2)),
	  is_slice(arg_is_slice)
	{
	if ( IsError() )
		return;

	if ( is_slice )
		{
		if ( ! IsString(op1->GetType()->Tag()) && ! IsVector(op1->GetType()->Tag()) )
			ExprError("slice notation indexing only supported for strings and vectors currently");
		}

	else if ( IsString(op1->GetType()->Tag()) )
		{
		if ( op2->AsListExpr()->Exprs().length() != 1 )
			ExprError("invalid string index expression");
		}

	if ( IsError() )
		return;

	int match_type = op1->GetType()->MatchesIndex(op2->AsListExpr());

	if ( match_type == DOES_NOT_MATCH_INDEX )
		{
		std::string error_msg =
		    util::fmt("expression with type '%s' is not a type that can be indexed",
		                    type_name(op1->GetType()->Tag()));
		SetError(error_msg.data());
		}

	else if ( ! op1->GetType()->Yield() )
		{
		if ( IsString(op1->GetType()->Tag()) && match_type == MATCHES_INDEX_SCALAR )
			SetType(base_type(TYPE_STRING));
		else
			// It's a set - so indexing it yields void.  We don't
			// directly generate an error message, though, since this
			// expression might be part of an add/delete statement,
			// rather than yielding a value.
			SetType(base_type(TYPE_VOID));
		}

	else if ( match_type == MATCHES_INDEX_SCALAR )
		SetType(op1->GetType()->Yield());

	else if ( match_type == MATCHES_INDEX_VECTOR )
		SetType(make_intrusive<VectorType>(op1->GetType()->Yield()));

	else
		ExprError("Unknown MatchesIndex() return value");
	}

bool IndexExpr::CanAdd() const
	{
	if ( IsError() )
		return true;	// avoid cascading the error report

	// "add" only allowed if our type is "set".
	return op1->GetType()->IsSet();
	}

bool IndexExpr::CanDel() const
	{
	if ( IsError() )
		return true;	// avoid cascading the error report

	return op1->GetType()->Tag() == TYPE_TABLE;
	}

void IndexExpr::Add(Frame* f)
	{
	if ( IsError() )
		return;

	auto v1 = op1->Eval(f);

	if ( ! v1 )
		return;

	auto v2 = op2->Eval(f);

	if ( ! v2 )
		return;

	bool iterators_invalidated = false;
	v1->AsTableVal()->Assign(std::move(v2), nullptr, true, &iterators_invalidated);

	if ( iterators_invalidated )
		{
		ODesc d;
		Describe(&d);
		reporter->PushLocation(GetLocationInfo());
		reporter->Warning("possible loop/iterator invalidation caused by expression: %s", d.Description());
		reporter->PopLocation();
		}
	}

void IndexExpr::Delete(Frame* f)
	{
	if ( IsError() )
		return;

	auto v1 = op1->Eval(f);

	if ( ! v1 )
		return;

	auto v2 = op2->Eval(f);

	if ( ! v2 )
		return;

	bool iterators_invalidated = false;
	v1->AsTableVal()->Remove(*v2, true, &iterators_invalidated);

	if ( iterators_invalidated )
		{
		ODesc d;
		Describe(&d);
		reporter->PushLocation(GetLocationInfo());
		reporter->Warning("possible loop/iterator invalidation caused by expression: %s", d.Description());
		reporter->PopLocation();
		}
	}

ExprPtr IndexExpr::MakeLvalue()
	{
	if ( IsString(op1->GetType()->Tag()) )
		ExprError("cannot assign to string index expression");

	return make_intrusive<RefExpr>(IntrusivePtr{NewRef{}, this});
	}

ValPtr IndexExpr::Eval(Frame* f) const
	{
	auto v1 = op1->Eval(f);

	if ( ! v1 )
		return nullptr;

	auto v2 = op2->Eval(f);

	if ( ! v2 )
		return nullptr;

	Val* indv = v2->AsListVal()->Idx(0).get();

	if ( is_vector(indv) )
		{
		VectorVal* v_v1 = v1->AsVectorVal();
		VectorVal* v_v2 = indv->AsVectorVal();
		auto vt = cast_intrusive<VectorType>(GetType());

		// Booleans select each element (or not).
		if ( IsBool(v_v2->GetType()->Yield()->Tag()) )
			{
			if ( v_v1->Size() != v_v2->Size() )
				{
				RuntimeError("size mismatch, boolean index and vector");
				return nullptr;
				}

			return vector_bool_select(vt, v_v1, v_v2);
			}
		else
			// Elements are indices.
			return vector_int_select(vt, v_v1, v_v2);
		}
	else
		return Fold(v1.get(), v2.get());
	}

ValPtr IndexExpr::Fold(Val* v1, Val* v2) const
	{
	if ( IsError() )
		return nullptr;

	ValPtr v;

	switch ( v1->GetType()->Tag() ) {
	case TYPE_VECTOR:
		{
		VectorVal* vect = v1->AsVectorVal();
		const ListVal* lv = v2->AsListVal();

		if ( lv->Length() == 1 )
			v = vect->ValAt(lv->Idx(0)->CoerceToUnsigned());
		else
			return index_slice(vect, lv);
		}
		break;

	case TYPE_TABLE:
		v = v1->AsTableVal()->FindOrDefault({NewRef{}, v2});
		break;

	case TYPE_STRING:
		return index_string(v1->AsString(), v2->AsListVal());

	default:
		RuntimeError("type cannot be indexed");
		break;
	}

	if ( v )
		return v;

	RuntimeError("no such index");
	return nullptr;
	}

StringValPtr index_string(const String* s, const ListVal* lv)
	{
	int len = s->Len();
	String* substring = nullptr;

	if ( lv->Length() == 1 )
		{
		bro_int_t idx = lv->Idx(0)->AsInt();

		if ( idx < 0 )
			idx += len;

		// Out-of-range index will return null pointer.
		substring = s->GetSubstring(idx, 1);
		}
	else
		{
		bro_int_t first = get_slice_index(lv->Idx(0)->AsInt(), len);
		bro_int_t last = get_slice_index(lv->Idx(1)->AsInt(), len);
		bro_int_t substring_len = last - first;

		if ( substring_len < 0 )
			substring = nullptr;
		else
			substring = s->GetSubstring(first, substring_len);
		}

	return make_intrusive<StringVal>(substring ? substring : new String(""));
	}

VectorValPtr index_slice(VectorVal* vect, const ListVal* lv)
	{
	auto first = lv->Idx(0)->CoerceToInt();
	auto last = lv->Idx(1)->CoerceToInt();
	return index_slice(vect, first, last);
	}

VectorValPtr index_slice(VectorVal* vect, int _first, int _last)
	{
	size_t len = vect->Size();
	auto result = make_intrusive<VectorVal>(vect->GetType<VectorType>());

	bro_int_t first = get_slice_index(_first, len);
	bro_int_t last = get_slice_index(_last, len);
	bro_int_t sub_length = last - first;

	if ( sub_length >= 0 )
		{
		result->Resize(sub_length);

		for ( bro_int_t idx = first; idx < last; idx++ )
			result->Assign(idx - first, vect->ValAt(idx));
		}

	return result;
	}

VectorValPtr vector_bool_select(VectorTypePtr vt, const VectorVal* v1,
                                const VectorVal* v2)
	{
	auto v_result = make_intrusive<VectorVal>(std::move(vt));

	for ( unsigned int i = 0; i < v2->Size(); ++i )
		if ( v2->BoolAt(i) )
			v_result->Assign(v_result->Size() + 1, v1->ValAt(i));

	return v_result;
	}

VectorValPtr vector_int_select(VectorTypePtr vt, const VectorVal* v1,
                               const VectorVal* v2)
	{
	auto v_result = make_intrusive<VectorVal>(std::move(vt));

	// The elements are indices.
	//
	// ### Should handle negative indices here like S does, i.e.,
	// by excluding those elements.  Probably only do this if *all*
	// are negative.
	v_result->Resize(v2->Size());
	for ( unsigned int i = 0; i < v2->Size(); ++i )
		v_result->Assign(i, v1->ValAt(v2->ValAt(i)->CoerceToInt()));

	return v_result;
	}

void IndexExpr::Assign(Frame* f, ValPtr v)
	{
	if ( IsError() )
		return;

	auto v1 = op1->Eval(f);
	auto v2 = op2->Eval(f);

	AssignToIndex(v1, v2, v);
	}

void IndexExpr::ExprDescribe(ODesc* d) const
	{
	op1->Describe(d);
	if ( d->IsReadable() )
		d->Add("[");

	op2->Describe(d);
	if ( d->IsReadable() )
		d->Add("]");
	}

FieldExpr::FieldExpr(ExprPtr arg_op, const char* arg_field_name)
	: UnaryExpr(EXPR_FIELD, std::move(arg_op)),
	  field_name(util::copy_string(arg_field_name)), td(nullptr), field(0)
	{
	if ( IsError() )
		return;

	if ( ! IsRecord(op->GetType()->Tag()) )
		ExprError("not a record");
	else
		{
		RecordType* rt = op->GetType()->AsRecordType();
		field = rt->FieldOffset(field_name);

		if ( field < 0 )
			ExprError("no such field in record");
		else
			{
			SetType(rt->GetFieldType(field));
			td = rt->FieldDecl(field);

			if ( rt->IsFieldDeprecated(field) )
				reporter->Warning("%s", rt->GetFieldDeprecationWarning(field, false).c_str());
			}
		}
	}

FieldExpr::~FieldExpr()
	{
	delete [] field_name;
	}

ExprPtr FieldExpr::MakeLvalue()
	{
	return make_intrusive<RefExpr>(IntrusivePtr{NewRef{}, this});
	}

bool FieldExpr::CanDel() const
	{
	return td->GetAttr(ATTR_DEFAULT) || td->GetAttr(ATTR_OPTIONAL);
	}

void FieldExpr::Assign(Frame* f, ValPtr v)
	{
	if ( IsError() )
		return;

	if ( auto op_v = op->Eval(f) )
		{
		RecordVal* r = op_v->AsRecordVal();
		r->Assign(field, std::move(v));
		}
	}

void FieldExpr::Delete(Frame* f)
	{
	Assign(f, nullptr);
	}

ValPtr FieldExpr::Fold(Val* v) const
	{
	if ( const auto& result = v->AsRecordVal()->GetField(field) )
		return result;

	// Check for &default.
	const Attr* def_attr = td ? td->GetAttr(ATTR_DEFAULT).get() : nullptr;

	if ( def_attr )
		return def_attr->GetExpr()->Eval(nullptr);
	else
		{
		RuntimeError("field value missing");
		assert(false);
		return nullptr; // Will never get here, but compiler can't tell.
		}
	}

void FieldExpr::ExprDescribe(ODesc* d) const
	{
	op->Describe(d);
	if ( d->IsReadable() )
		d->Add("$");

	if ( IsError() )
		d->Add("<error>");
	else if ( d->IsReadable() )
		d->Add(field_name);
	else
		d->Add(field);
	}

HasFieldExpr::HasFieldExpr(ExprPtr arg_op, const char* arg_field_name)
	: UnaryExpr(EXPR_HAS_FIELD, std::move(arg_op)),
	  field_name(arg_field_name), field(0)
	{
	if ( IsError() )
		return;

	if ( ! IsRecord(op->GetType()->Tag()) )
		ExprError("not a record");
	else
		{
		RecordType* rt = op->GetType()->AsRecordType();
		field = rt->FieldOffset(field_name);

		if ( field < 0 )
			ExprError("no such field in record");
		else if ( rt->IsFieldDeprecated(field) )
			reporter->Warning("%s", rt->GetFieldDeprecationWarning(field, true).c_str());

		SetType(base_type(TYPE_BOOL));
		}
	}

HasFieldExpr::~HasFieldExpr()
	{
	delete field_name;
	}

ValPtr HasFieldExpr::Fold(Val* v) const
	{
	auto rv = v->AsRecordVal();
	return val_mgr->Bool(rv->HasField(field));
	}

void HasFieldExpr::ExprDescribe(ODesc* d) const
	{
	op->Describe(d);

	if ( d->IsReadable() )
		d->Add("?$");

	if ( IsError() )
		d->Add("<error>");
	else if ( d->IsReadable() )
		d->Add(field_name);
	else
		d->Add(field);
	}


RecordConstructorExpr::RecordConstructorExpr(ListExprPtr constructor_list)
	: Expr(EXPR_RECORD_CONSTRUCTOR), op(std::move(constructor_list)),
	  map(std::nullopt)
	{
	if ( IsError() )
		return;

	// Spin through the list, which should be comprised only of
	// record-field-assign expressions, and build up a
	// record type to associate with this constructor.
	const ExprPList& exprs = op->AsListExpr()->Exprs();
	type_decl_list* record_types = new type_decl_list(exprs.length());

	for ( const auto& e : exprs )
		{
		if ( e->Tag() != EXPR_FIELD_ASSIGN )
			{
			Error("bad type in record constructor", e);
			SetError();
			continue;
			}

		FieldAssignExpr* field = (FieldAssignExpr*) e;
		const auto& field_type = field->GetType();
		char* field_name = util::copy_string(field->FieldName());
		record_types->push_back(new TypeDecl(field_name, field_type));
		}

	SetType(make_intrusive<RecordType>(record_types));
	}

RecordConstructorExpr::RecordConstructorExpr(RecordTypePtr known_rt,
                                             ListExprPtr constructor_list)
: Expr(EXPR_RECORD_CONSTRUCTOR), op(std::move(constructor_list))
	{
	if ( IsError() )
		return;

	SetType(known_rt);

	const auto& exprs = op->AsListExpr()->Exprs();
	map = std::vector<int>(exprs.length());

	int i = 0;
	for ( const auto& e : exprs )
		{
		if ( e->Tag() != EXPR_FIELD_ASSIGN )
			{
			Error("bad type in record constructor", e);
			SetError();
			continue;
			}

		auto field = e->AsFieldAssignExpr();
		int index = known_rt->FieldOffset(field->FieldName());

		if ( index < 0 )
			{
			Error("no such field in record", e);
			SetError();
			continue;
			}

		auto known_ft = known_rt->GetFieldType(index);

		if ( ! field->PromoteTo(known_ft) )
			SetError();

		(*map)[i++] = index;
		}
	}

ValPtr RecordConstructorExpr::InitVal(const zeek::Type* t, ValPtr aggr) const
	{
	if ( IsError() )
		{
		Error("bad record initializer");
		return nullptr;
		}

	if ( ! init_tag_check(this, "record constructor", TYPE_RECORD, t->Tag()) )
		return nullptr;

	auto v = Eval(nullptr);

	if ( v )
		{
		RecordVal* rv = v->AsRecordVal();
		auto bt = const_cast<zeek::Type*>(t);
		RecordTypePtr rt{NewRef{}, bt->AsRecordType()};
		auto aggr_rec = cast_intrusive<RecordVal>(std::move(aggr));
		auto ar = rv->CoerceTo(std::move(rt), std::move(aggr_rec));

		if ( ar )
			return ar;
		}

	Error("bad record initializer");
	return nullptr;
	}

ValPtr RecordConstructorExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return nullptr;

	const auto& exprs = op->Exprs();
	auto rt = cast_intrusive<RecordType>(type);

	if ( ! map && exprs.length() != rt->NumFields() )
		RuntimeErrorWithCallStack("inconsistency evaluating record constructor");

	auto rv = make_intrusive<RecordVal>(std::move(rt));

	for ( int i = 0; i < exprs.length(); ++i )
		{
		int ind = map ? (*map)[i] : i;
		rv->Assign(ind, exprs[i]->Eval(f));
		}

	return rv;
	}

bool RecordConstructorExpr::IsPure() const
	{
	return op->IsPure();
	}

void RecordConstructorExpr::ExprDescribe(ODesc* d) const
	{
	auto& tn = type->GetName();

	if ( tn.size() > 0 )
		{
		d->Add(tn);
		d->Add("(");
		op->Describe(d);
		d->Add(")");
		}
	else
		{
		d->Add("[");
		op->Describe(d);
		d->Add("]");
		}
	}

TraversalCode RecordConstructorExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	tc = op->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}

TableConstructorExpr::TableConstructorExpr(ListExprPtr constructor_list,
                                           std::unique_ptr<std::vector<AttrPtr>> arg_attrs,
                                           TypePtr arg_type,
                                           AttributesPtr arg_attrs2)
	: UnaryExpr(EXPR_TABLE_CONSTRUCTOR, std::move(constructor_list))
	{
	if ( IsError() )
		return;

	if ( arg_type )
		{
		if ( ! arg_type->IsTable() )
			{
			Error("bad table constructor type", arg_type.get());
			SetError();
			return;
			}

		SetType(std::move(arg_type));
		}
	else
		{
		if ( op->AsListExpr()->Exprs().empty() )
			SetType(make_intrusive<TableType>(make_intrusive<TypeList>(base_type(TYPE_ANY)), nullptr));
		else
			{
			SetType(init_type(op.get()));

			if ( ! type )
				SetError();

			else if ( type->Tag() != TYPE_TABLE ||
				  type->AsTableType()->IsSet() )
				SetError("values in table(...) constructor do not specify a table");
			}
		}

	if ( arg_attrs )
		attrs = make_intrusive<Attributes>(std::move(*arg_attrs), type, false, false);
	else
		attrs = arg_attrs2;

	const auto& indices = type->AsTableType()->GetIndices()->GetTypes();
	const ExprPList& cle = op->AsListExpr()->Exprs();

	// check and promote all assign expressions in ctor list
	for ( const auto& expr : cle )
		{
		if ( expr->Tag() != EXPR_ASSIGN )
			continue;

		auto idx_expr = expr->AsAssignExpr()->GetOp1();
		auto val_expr = expr->AsAssignExpr()->GetOp2();
		auto yield_type = GetType()->AsTableType()->Yield();

		// Promote LHS
		assert(idx_expr->Tag() == EXPR_LIST);
		ExprPList& idx_exprs = idx_expr->AsListExpr()->Exprs();

		if ( idx_exprs.length() != static_cast<int>(indices.size()) )
			continue;

		loop_over_list(idx_exprs, j)
			{
			ExprPtr idx = {NewRef{}, idx_exprs[j]};

			auto promoted_idx = check_and_promote_expr(idx, indices[j]);

			if ( promoted_idx )
				{
				if ( promoted_idx != idx )
					Unref(idx_exprs.replace(j, promoted_idx.release()));

				continue;
				}

			ExprError("inconsistent types in table constructor");
			return;
			}

		// Promote RHS
		if ( auto promoted_val = check_and_promote_expr(val_expr, yield_type) )
			{
			if ( promoted_val != val_expr )
				expr->AsAssignExpr()->SetOp2(promoted_val);
			}
		else
			{
			ExprError("inconsistent types in table constructor");
			return;
			}
		}
	}

ValPtr TableConstructorExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return nullptr;

	auto aggr = make_intrusive<TableVal>(GetType<TableType>(), attrs);
	const ExprPList& exprs = op->AsListExpr()->Exprs();

	for ( const auto& expr : exprs )
		expr->EvalIntoAggregate(type.get(), aggr.get(), f);

	aggr->InitDefaultFunc(f);

	return aggr;
	}

ValPtr TableConstructorExpr::InitVal(const zeek::Type* t, ValPtr aggr) const
	{
	if ( IsError() )
		return nullptr;

	if ( ! init_tag_check(this, "table constructor", TYPE_TABLE, t->Tag()) )
		return nullptr;

	auto tt = GetType<TableType>();

	auto tval = aggr ?
	        TableValPtr{AdoptRef{}, aggr.release()->AsTableVal()} :
	        make_intrusive<TableVal>(std::move(tt), attrs);
	const ExprPList& exprs = op->AsListExpr()->Exprs();

	for ( const auto& expr : exprs )
		expr->EvalIntoAggregate(t, tval.get(), nullptr);

	return tval;
	}

void TableConstructorExpr::ExprDescribe(ODesc* d) const
	{
	d->Add("table(");
	op->Describe(d);
	d->Add(")");
	}

SetConstructorExpr::SetConstructorExpr(ListExprPtr constructor_list,
                                       std::unique_ptr<std::vector<AttrPtr>> arg_attrs,
                                       TypePtr arg_type,
                                       AttributesPtr arg_attrs2)
	: UnaryExpr(EXPR_SET_CONSTRUCTOR, std::move(constructor_list))
	{
	if ( IsError() )
		return;

	if ( arg_type )
		{
		if ( ! arg_type->IsSet() )
			{
			Error("bad set constructor type", arg_type.get());
			SetError();
			return;
			}

		SetType(std::move(arg_type));
		}
	else
		{
		if ( op->AsListExpr()->Exprs().empty() )
			SetType(make_intrusive<zeek::SetType>(make_intrusive<TypeList>(base_type(TYPE_ANY)), nullptr));
		else
			SetType(init_type(op.get()));
		}

	if ( ! type )
		SetError();

	else if ( type->Tag() != TYPE_TABLE || ! type->AsTableType()->IsSet() )
		SetError("values in set(...) constructor do not specify a set");

	if ( arg_attrs )
		attrs = make_intrusive<Attributes>(std::move(*arg_attrs), type, false, false);
	else
		attrs = arg_attrs2;

	const auto& indices = type->AsTableType()->GetIndices()->GetTypes();
	ExprPList& cle = op->AsListExpr()->Exprs();

	if ( indices.size() == 1 )
		{
		if ( ! check_and_promote_exprs_to_type(op->AsListExpr(),
		                                       indices[0]) )
			ExprError("inconsistent type in set constructor");
		}

	else if ( indices.size() > 1 )
		{
		// Check/promote each expression in composite index.
		loop_over_list(cle, i)
			{
			Expr* ce = cle[i];
			ListExpr* le = ce->AsListExpr();

			assert(ce->Tag() == EXPR_LIST);
			if ( check_and_promote_exprs(le, type->AsTableType()->GetIndices().get()) )
				{
				if ( le != cle[i] )
					cle.replace(i, le);

				continue;
				}

			ExprError("inconsistent types in set constructor");
			}
		}
	}

ValPtr SetConstructorExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return nullptr;

	auto aggr = make_intrusive<TableVal>(IntrusivePtr{NewRef{}, type->AsTableType()},
	                                     attrs);
	const ExprPList& exprs = op->AsListExpr()->Exprs();

	for ( const auto& expr : exprs )
		{
		auto element = expr->Eval(f);
		aggr->Assign(std::move(element), nullptr);
		}

	return aggr;
	}

ValPtr SetConstructorExpr::InitVal(const zeek::Type* t, ValPtr aggr) const
	{
	if ( IsError() )
		return nullptr;

	if ( ! init_tag_check(this, "set constructor", TYPE_TABLE, t->Tag()) )
		return nullptr;

	const auto& index_type = t->AsTableType()->GetIndices();
	auto tt = GetType<TableType>();
	auto tval = aggr ?
	        TableValPtr{AdoptRef{}, aggr.release()->AsTableVal()} :
	make_intrusive<TableVal>(std::move(tt), attrs);
	const ExprPList& exprs = op->AsListExpr()->Exprs();

	for ( const auto& e : exprs )
		{
		auto element = check_and_promote(e->Eval(nullptr), index_type.get(), true);

		if ( ! element || ! tval->Assign(std::move(element), nullptr) )
			{
			Error(util::fmt("initialization type mismatch in set"), e);
			return nullptr;
			}
		}

	return tval;
	}

void SetConstructorExpr::ExprDescribe(ODesc* d) const
	{
	d->Add("set(");
	op->Describe(d);
	d->Add(")");
	}

VectorConstructorExpr::VectorConstructorExpr(ListExprPtr constructor_list,
                                             TypePtr arg_type)
	: UnaryExpr(EXPR_VECTOR_CONSTRUCTOR, std::move(constructor_list))
	{
	if ( IsError() )
		return;

	if ( arg_type )
		{
		if ( arg_type->Tag() != TYPE_VECTOR )
			{
			Error("bad vector constructor type", arg_type.get());
			SetError();
			return;
			}

		SetType(std::move(arg_type));
		}
	else
		{
		if ( op->AsListExpr()->Exprs().empty() )
			{
			// vector().
			// By default, assign VOID type here. A vector with
			// void type set is seen as an unspecified vector.
			SetType(make_intrusive<VectorType>(base_type(TYPE_VOID)));
			return;
			}

		if ( auto t = merge_type_list(op->AsListExpr()) )
			SetType(make_intrusive<VectorType>(std::move(t)));
		else
			{
			SetError();
			return;
			}
		}

	if ( ! check_and_promote_exprs_to_type(op->AsListExpr(),
					       type->AsVectorType()->Yield()) )
		ExprError("inconsistent types in vector constructor");
	}

ValPtr VectorConstructorExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return nullptr;

	auto vec = make_intrusive<VectorVal>(GetType<VectorType>());
	const ExprPList& exprs = op->AsListExpr()->Exprs();

	loop_over_list(exprs, i)
		{
		Expr* e = exprs[i];

		if ( ! vec->Assign(i, e->Eval(f)) )
			{
			RuntimeError(util::fmt("type mismatch at index %d", i));
			return nullptr;
			}
		}

	return vec;
	}

ValPtr VectorConstructorExpr::InitVal(const zeek::Type* t, ValPtr aggr) const
	{
	if ( IsError() )
		return nullptr;

	if ( ! init_tag_check(this, "vector constructor", TYPE_VECTOR, t->Tag()) )
		return nullptr;

	auto vt = GetType<VectorType>();
	auto vec = aggr ?
	        VectorValPtr{AdoptRef{}, aggr.release()->AsVectorVal()} :
	make_intrusive<VectorVal>(std::move(vt));
	const ExprPList& exprs = op->AsListExpr()->Exprs();

	loop_over_list(exprs, i)
		{
		Expr* e = exprs[i];
		auto v = check_and_promote(e->Eval(nullptr), t->Yield().get(), true);

		if ( ! v || ! vec->Assign(i, std::move(v)) )
			{
			Error(util::fmt("initialization type mismatch at index %d", i), e);
			return nullptr;
			}
		}

	return vec;
	}

void VectorConstructorExpr::ExprDescribe(ODesc* d) const
	{
	d->Add("vector(");
	op->Describe(d);
	d->Add(")");
	}

FieldAssignExpr::FieldAssignExpr(const char* arg_field_name, ExprPtr value)
	: UnaryExpr(EXPR_FIELD_ASSIGN, std::move(value)), field_name(arg_field_name)
	{
	SetType(op->GetType());
	}

bool FieldAssignExpr::PromoteTo(TypePtr t)
	{
	op = check_and_promote_expr(op, t);
	return op != nullptr;
	}

void FieldAssignExpr::EvalIntoAggregate(const zeek::Type* t, Val* aggr, Frame* f)
	const
	{
	if ( IsError() )
		return;

	if ( auto v = op->Eval(f) )
		{
		RecordVal* rec = aggr->AsRecordVal();
		const RecordType* rt = t->AsRecordType();

		int idx = rt->FieldOffset(field_name.c_str());

		if ( idx < 0 )
			reporter->InternalError("Missing record field: %s",
			                              field_name.c_str());

		rec->Assign(idx, std::move(v));
		}
	}

bool FieldAssignExpr::IsRecordElement(TypeDecl* td) const
	{
	if ( td )
		{
		td->type = op->GetType();
		td->id = util::copy_string(field_name.c_str());
		}

	return true;
	}

void FieldAssignExpr::ExprDescribe(ODesc* d) const
	{
	d->Add("$");
	d->Add(FieldName());
	d->Add("=");

	if ( op )
		op->Describe(d);
	else
		d->Add("<error>");
	}

ArithCoerceExpr::ArithCoerceExpr(ExprPtr arg_op, TypeTag t)
: UnaryExpr(EXPR_ARITH_COERCE, std::move(arg_op))
	{
	if ( IsError() )
		return;

	TypeTag bt = op->GetType()->Tag();
	TypeTag vbt = bt;

	if ( IsVector(bt) )
		{
		SetType(make_intrusive<VectorType>(base_type(t)));
		vbt = op->GetType()->AsVectorType()->Yield()->Tag();
		}
	else
		SetType(base_type(t));

	if ( (bt == TYPE_ENUM) != (t == TYPE_ENUM) )
		ExprError("can't convert to/from enumerated type");

	else if ( ! IsArithmetic(t) && ! IsBool(t) &&
		  t != TYPE_TIME && t != TYPE_INTERVAL )
		ExprError("bad coercion");

	else if ( ! IsArithmetic(bt) && ! IsBool(bt) &&
		  ! IsArithmetic(vbt) && ! IsBool(vbt) )
		ExprError("bad coercion value");
	}

ValPtr ArithCoerceExpr::FoldSingleVal(ValPtr v, const TypePtr& t) const
	{
	return check_and_promote(v, t.get(), false, location);
	}

ValPtr ArithCoerceExpr::Fold(Val* v) const
	{
	auto t = GetType();

	if ( ! is_vector(v) )
		{
		// Our result type might be vector, in which case this
		// invocation is being done per-element rather than on
		// the whole vector.  Correct the type if so.
		if ( type->Tag() == TYPE_VECTOR )
			t = t->AsVectorType()->Yield();

		return FoldSingleVal({NewRef{}, v}, t);
		}

	VectorVal* vv = v->AsVectorVal();
	auto result = make_intrusive<VectorVal>(cast_intrusive<VectorType>(t));

	auto yt = t->AsVectorType()->Yield();

	for ( unsigned int i = 0; i < vv->Size(); ++i )
		{
		auto elt = vv->ValAt(i);
		if ( elt )
			result->Assign(i, FoldSingleVal(elt, yt));
		else
			result->Assign(i, nullptr);
		}

	return result;
	}

RecordCoerceExpr::RecordCoerceExpr(ExprPtr arg_op, RecordTypePtr r)
	: UnaryExpr(EXPR_RECORD_COERCE, std::move(arg_op))
	{
	if ( IsError() )
		return;

	SetType(std::move(r));

	if ( GetType()->Tag() != TYPE_RECORD )
		ExprError("coercion to non-record");

	else if ( op->GetType()->Tag() != TYPE_RECORD )
		ExprError("coercion of non-record to record");

	else
		{
		RecordType* t_r = type->AsRecordType();
		RecordType* sub_r = op->GetType()->AsRecordType();

		int map_size = t_r->NumFields();
		map.resize(map_size, -1);	// -1 = field is not mapped

		int i;
		for ( i = 0; i < sub_r->NumFields(); ++i )
			{
			int t_i = t_r->FieldOffset(sub_r->FieldName(i));
			if ( t_i < 0 )
				{
				ExprError(util::fmt("orphaned field \"%s\" in record coercion",
				                          sub_r->FieldName(i)));
				break;
				}

			const auto& sub_t_i = sub_r->GetFieldType(i);
			const auto& sup_t_i = t_r->GetFieldType(t_i);

			if ( ! same_type(sup_t_i, sub_t_i) )
				{
				auto is_arithmetic_promotable = [](zeek::Type* sup, zeek::Type* sub) -> bool
					{
					auto sup_tag = sup->Tag();
					auto sub_tag = sub->Tag();

					if ( ! BothArithmetic(sup_tag, sub_tag) )
						return false;

					if ( sub_tag == TYPE_DOUBLE && IsIntegral(sup_tag) )
						return false;

					if ( sub_tag == TYPE_INT && sup_tag == TYPE_COUNT )
						return false;

					return true;
					};

				auto is_record_promotable = [](zeek::Type* sup, zeek::Type* sub) -> bool
					{
					if ( sup->Tag() != TYPE_RECORD )
						return false;

					if ( sub->Tag() != TYPE_RECORD )
						return false;

					return record_promotion_compatible(sup->AsRecordType(),
					                                   sub->AsRecordType());
					};

				if ( ! is_arithmetic_promotable(sup_t_i.get(), sub_t_i.get()) &&
				     ! is_record_promotable(sup_t_i.get(), sub_t_i.get()) )
					{
					std::string error_msg = util::fmt(
						"type clash for field \"%s\"", sub_r->FieldName(i));
					Error(error_msg.c_str(), sub_t_i.get());
					SetError();
					break;
					}
				}

			map[t_i] = i;
			}

		if ( IsError() )
			return;

		for ( i = 0; i < map_size; ++i )
			{
			if ( map[i] == -1 )
				{
				if ( ! t_r->FieldDecl(i)->GetAttr(ATTR_OPTIONAL) )
					{
					std::string error_msg = util::fmt(
						"non-optional field \"%s\" missing", t_r->FieldName(i));
					Error(error_msg.c_str());
					SetError();
					break;
					}
				}
			else if ( t_r->IsFieldDeprecated(i) )
				reporter->Warning("%s", t_r->GetFieldDeprecationWarning(i, false).c_str());
			}
		}
	}

ValPtr RecordCoerceExpr::InitVal(const zeek::Type* t, ValPtr aggr) const
	{
	if ( IsError() )
		{
		Error("bad record initializer");
		return nullptr;
		}

	if ( ! init_tag_check(this, "record", TYPE_RECORD, t->Tag()) )
		return nullptr;

	if ( auto v = Eval(nullptr) )
		{
		RecordVal* rv = v->AsRecordVal();
		auto bt = const_cast<zeek::Type*>(t);
		RecordTypePtr rt{NewRef{}, bt->AsRecordType()};
		auto aggr_rec = cast_intrusive<RecordVal>(std::move(aggr));

		if ( auto ar = rv->CoerceTo(std::move(rt), std::move(aggr_rec)) )
			return ar;
		}

	Error("bad record initializer");
	return nullptr;
	}

ValPtr RecordCoerceExpr::Fold(Val* v) const
	{
	if ( same_type(GetType(), Op()->GetType()) )
		return IntrusivePtr{NewRef{}, v};

	auto rt = cast_intrusive<RecordType>(GetType());
	return coerce_to_record(rt, v, map);
	}

RecordValPtr coerce_to_record(RecordTypePtr rt, Val* v,
				const std::vector<int>& map)
	{
	int map_size = map.size();
	auto val = make_intrusive<RecordVal>(rt);
	RecordType* val_type = val->GetType()->AsRecordType();

	RecordVal* rv = v->AsRecordVal();

	for ( int i = 0; i < map_size; ++i )
		{
		if ( map[i] >= 0 )
			{
			auto rhs = rv->GetField(map[i]);

			if ( ! rhs )
				{
				auto rv_rt = rv->GetType()->AsRecordType();
				const auto& def = rv_rt->FieldDecl(map[i])->
							GetAttr(ATTR_DEFAULT);

				if ( def )
					rhs = def->GetExpr()->Eval(nullptr);
				}

			assert(rhs || rt->FieldDecl(i)->GetAttr(ATTR_OPTIONAL));

			if ( ! rhs )
				{
				// Optional field is missing.
				val->Remove(i);
				continue;
				}

			const auto& rhs_type = rhs->GetType();
			const auto& field_type = val_type->GetFieldType(i);

			if ( rhs_type->Tag() == TYPE_RECORD &&
			     field_type->Tag() == TYPE_RECORD &&
			     ! same_type(rhs_type, field_type) )
				{
				if ( auto new_val = rhs->AsRecordVal()->CoerceTo(cast_intrusive<RecordType>(field_type)) )
					rhs = std::move(new_val);
				}
			else if ( BothArithmetic(rhs_type->Tag(), field_type->Tag()) &&
			          ! same_type(rhs_type, field_type) )
				{
				auto new_val = check_and_promote(rhs, field_type.get(), false);
				rhs = std::move(new_val);
				}

			val->Assign(i, std::move(rhs));
			}
		else
			{
			if ( const auto& def = rt->FieldDecl(i)->GetAttr(ATTR_DEFAULT) )
				{
				auto def_val = def->GetExpr()->Eval(nullptr);
				const auto& def_type = def_val->GetType();
				const auto& field_type = rt->GetFieldType(i);

				if ( def_type->Tag() == TYPE_RECORD &&
				     field_type->Tag() == TYPE_RECORD &&
				     ! same_type(def_type, field_type) )
					{
					auto tmp = def_val->AsRecordVal()->CoerceTo(
					        cast_intrusive<RecordType>(field_type));

					if ( tmp )
						def_val = std::move(tmp);
					}

				val->Assign(i, std::move(def_val));
				}
			else
				val->Remove(i);
			}
		}

	return val;
	}

TableCoerceExpr::TableCoerceExpr(ExprPtr arg_op, TableTypePtr r)
	: UnaryExpr(EXPR_TABLE_COERCE, std::move(arg_op))
	{
	if ( IsError() )
		return;

	SetType(std::move(r));

	if ( GetType()->Tag() != TYPE_TABLE )
		ExprError("coercion to non-table");

	else if ( op->GetType()->Tag() != TYPE_TABLE )
		ExprError("coercion of non-table/set to table/set");
	}


TableCoerceExpr::~TableCoerceExpr()
	{
	}

ValPtr TableCoerceExpr::Fold(Val* v) const
	{
	TableVal* tv = v->AsTableVal();

	if ( tv->Size() > 0 )
		RuntimeErrorWithCallStack("coercion of non-empty table/set");

	return make_intrusive<TableVal>(GetType<TableType>(), tv->GetAttrs());
	}

VectorCoerceExpr::VectorCoerceExpr(ExprPtr arg_op, VectorTypePtr v)
	: UnaryExpr(EXPR_VECTOR_COERCE, std::move(arg_op))
	{
	if ( IsError() )
		return;

	SetType(std::move(v));

	if ( GetType()->Tag() != TYPE_VECTOR )
		ExprError("coercion to non-vector");

	else if ( op->GetType()->Tag() != TYPE_VECTOR )
		ExprError("coercion of non-vector to vector");
	}


VectorCoerceExpr::~VectorCoerceExpr()
	{
	}

ValPtr VectorCoerceExpr::Fold(Val* v) const
	{
	VectorVal* vv = v->AsVectorVal();

	if ( vv->Size() > 0 )
		RuntimeErrorWithCallStack("coercion of non-empty vector");

	return make_intrusive<VectorVal>(GetType<VectorType>());
	}

ScheduleTimer::ScheduleTimer(const EventHandlerPtr& arg_event, Args arg_args,
                             double t)
	: Timer(t, TIMER_SCHEDULE),
	  event(arg_event), args(std::move(arg_args))
	{
	}

ScheduleTimer::~ScheduleTimer()
	{
	}

void ScheduleTimer::Dispatch(double /* t */, bool /* is_expire */)
	{
	if ( event )
		event_mgr.Enqueue(event, std::move(args));
	}

ScheduleExpr::ScheduleExpr(ExprPtr arg_when, EventExprPtr arg_event)
	: Expr(EXPR_SCHEDULE),
	  when(std::move(arg_when)), event(std::move(arg_event))
	{
	if ( IsError() || when->IsError() || event->IsError() )
		return;

	TypeTag bt = when->GetType()->Tag();

	if ( bt != TYPE_TIME && bt != TYPE_INTERVAL )
		ExprError("schedule expression requires a time or time interval");
	else
		SetType(base_type(TYPE_TIMER));
	}

bool ScheduleExpr::IsPure() const
	{
	return false;
	}

ValPtr ScheduleExpr::Eval(Frame* f) const
	{
	if ( run_state::terminating )
		return nullptr;

	auto when_val = when->Eval(f);

	if ( ! when_val )
		return nullptr;

	double dt = when_val->InternalDouble();

	if ( when->GetType()->Tag() == TYPE_INTERVAL )
		dt += run_state::network_time;

	auto args = eval_list(f, event->Args());

	if ( args )
		timer_mgr->Add(new ScheduleTimer(event->Handler(), std::move(*args), dt));

	return nullptr;
	}

TraversalCode ScheduleExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	tc = when->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = event->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}

void ScheduleExpr::ExprDescribe(ODesc* d) const
	{
	if ( d->IsReadable() )
		d->AddSP("schedule");

	when->Describe(d);
	d->SP();

	if ( d->IsReadable() )
		{
		d->Add("{");
		d->PushIndent();
		event->Describe(d);
		d->PopIndent();
		d->Add("}");
		}
	else
		event->Describe(d);
	}

InExpr::InExpr(ExprPtr arg_op1, ExprPtr arg_op2)
	: BinaryExpr(EXPR_IN, std::move(arg_op1), std::move(arg_op2))
	{
	if ( IsError() )
		return;

	if ( op1->GetType()->Tag() == TYPE_PATTERN )
		{
		if ( op2->GetType()->Tag() != TYPE_STRING )
			{
			op2->GetType()->Error("pattern requires string index", op1.get());
			SetError();
			}
		else
			SetType(base_type(TYPE_BOOL));
		}

	else if ( op1->GetType()->Tag() == TYPE_STRING &&
		  op2->GetType()->Tag() == TYPE_STRING )
		SetType(base_type(TYPE_BOOL));

	else
		{
		// Check for:	<addr> in <subnet>
		//		<addr> in set[subnet]
		//		<addr> in table[subnet] of ...
		if ( op1->GetType()->Tag() == TYPE_ADDR )
			{
			if ( op2->GetType()->Tag() == TYPE_SUBNET )
				{
				SetType(base_type(TYPE_BOOL));
				return;
				}

			if ( op2->GetType()->Tag() == TYPE_TABLE &&
			     op2->GetType()->AsTableType()->IsSubNetIndex() )
				{
				SetType(base_type(TYPE_BOOL));
				return;
				}
			}

		if ( op1->Tag() != EXPR_LIST )
			op1 = make_intrusive<ListExpr>(std::move(op1));

		ListExpr* lop1 = op1->AsListExpr();

		if ( ! op2->GetType()->MatchesIndex(lop1) )
			SetError("not an index type");
		else
			SetType(base_type(TYPE_BOOL));
		}
	}

ValPtr InExpr::Fold(Val* v1, Val* v2) const
	{
	if ( v1->GetType()->Tag() == TYPE_PATTERN )
		{
		auto re = v1->As<PatternVal*>();
		const String* s = v2->AsString();
		return val_mgr->Bool(re->MatchAnywhere(s) != 0);
		}

	if ( v2->GetType()->Tag() == TYPE_STRING )
		{
		const String* s1 = v1->AsString();
		const String* s2 = v2->AsString();

		// Could do better here e.g. Boyer-Moore if done repeatedly.
		auto s = reinterpret_cast<const unsigned char*>(s1->CheckString());
		auto res = util::strstr_n(s2->Len(), s2->Bytes(), s1->Len(), s) != -1;
		return val_mgr->Bool(res);
		}

	if ( v1->GetType()->Tag() == TYPE_ADDR &&
	     v2->GetType()->Tag() == TYPE_SUBNET )
		return val_mgr->Bool(v2->AsSubNetVal()->Contains(v1->AsAddr()));

	bool res;

	if ( is_vector(v2) )
		{
		auto vv2 = v2->AsVectorVal();
		auto ind = v1->AsListVal()->Idx(0)->CoerceToUnsigned();
		res = ind < vv2->Size() && vv2->ValAt(ind);
		}
	else
		res = (bool)v2->AsTableVal()->Find({NewRef{}, v1});

	return val_mgr->Bool(res);
	}

CallExpr::CallExpr(ExprPtr arg_func, ListExprPtr arg_args, bool in_hook)
	: Expr(EXPR_CALL), func(std::move(arg_func)), args(std::move(arg_args))
	{
	if ( func->IsError() || args->IsError() )
		{
		SetError();
		return;
		}

	const auto& func_type = func->GetType();

	if ( ! IsFunc(func_type->Tag()) )
		{
		func->Error("not a function");
		SetError();
		return;
		}

	if ( func_type->AsFuncType()->Flavor() == FUNC_FLAVOR_HOOK && ! in_hook )
		{
		func->Error("hook cannot be called directly, use hook operator");
		SetError();
		return;
		}

	if ( ! func_type->MatchesIndex(args.get()) )
		SetError("argument type mismatch in function call");
	else
		{
		const auto& yield = func_type->Yield();

		if ( ! yield )
			{
			switch ( func_type->AsFuncType()->Flavor() ) {

			case FUNC_FLAVOR_FUNCTION:
				Error("function has no yield type");
				SetError();
				break;

			case FUNC_FLAVOR_EVENT:
				Error("event called in expression, use event statement instead");
				SetError();
				break;

			case FUNC_FLAVOR_HOOK:
				Error("hook has no yield type");
				SetError();
				break;

			default:
				Error("invalid function flavor");
				SetError();
				break;
			}
			}
		else
			SetType(yield);

		// Check for call to built-ins that can be statically analyzed.
		ValPtr func_val;

		if ( func->Tag() == EXPR_NAME &&
		     // This is cheating, but without it processing gets
		     // quite confused regarding "value used but not set"
		     // run-time errors when we apply this analysis during
		     // parsing.  Really we should instead do it after we've
		     // parsed the entire set of scripts.
		     util::streq(((NameExpr*) func.get())->Id()->Name(), "fmt") &&
		     // The following is needed because fmt might not yet
		     // be bound as a name.
		     did_builtin_init &&
		     (func_val = func->Eval(nullptr)) )
			{
			zeek::Func* f = func_val->AsFunc();
			if ( f->GetKind() == Func::BUILTIN_FUNC &&
			     ! check_built_in_call((BuiltinFunc*) f, this) )
				SetError();
			}
		}
	}

bool CallExpr::IsPure() const
	{
	if ( IsError() )
		return true;

	if ( ! func->IsPure() )
		return false;

	auto func_val = func->Eval(nullptr);

	if ( ! func_val )
		return false;

	zeek::Func* f = func_val->AsFunc();

	// Only recurse for built-in functions, as recursing on script
	// functions can lead to infinite recursion if the function being
	// called here happens to be recursive (either directly
	// or indirectly).
	bool pure = false;

	if ( f->GetKind() == Func::BUILTIN_FUNC )
		pure = f->IsPure() && args->IsPure();

	return pure;
	}

ValPtr CallExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return nullptr;

	// If we are inside a trigger condition, we may have already been
	// called, delayed, and then produced a result which is now cached.
	// Check for that.
	if ( f )
		{
		if ( trigger::Trigger* trigger = f->GetTrigger() )
			{
			if ( Val* v = trigger->Lookup(this) )
				{
				DBG_LOG(DBG_NOTIFIERS,
					"%s: provides cached function result",
					trigger->Name());
				return {NewRef{}, v};
				}
			}
		}

	ValPtr ret;
	auto func_val = func->Eval(f);
	auto v = eval_list(f, args.get());

	if ( func_val && v )
		{
		const zeek::Func* funcv = func_val->AsFunc();
		const CallExpr* current_call = f ? f->GetCall() : nullptr;

		if ( f )
			f->SetCall(this);

		auto& args = *v;
		ret = funcv->Invoke(&args, f);

		if ( f )
			f->SetCall(current_call);
		}

	return ret;
	}

TraversalCode CallExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	tc = func->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = args->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}

void CallExpr::ExprDescribe(ODesc* d) const
	{
	func->Describe(d);
	if ( d->IsReadable() || d->IsPortable() )
		{
		d->Add("(");
		args->Describe(d);
		d->Add(")");
		}
	else
		args->Describe(d);
	}

LambdaExpr::LambdaExpr(std::unique_ptr<function_ingredients> arg_ing,
                       IDPList arg_outer_ids) : Expr(EXPR_LAMBDA)
	{
	ingredients = std::move(arg_ing);
	outer_ids = std::move(arg_outer_ids);

	SetType(ingredients->id->GetType());

	CheckCaptures();

	// Install a dummy version of the function globally for use only
	// when broker provides a closure.
	auto dummy_func = make_intrusive<ScriptFunc>(
		ingredients->id,
		ingredients->body,
		ingredients->inits,
		ingredients->frame_size,
		ingredients->priority);

	dummy_func->SetOuterIDs(outer_ids);

	// Get the body's "string" representation.
	ODesc d;
	dummy_func->Describe(&d);

	for ( ; ; )
		{
		hash128_t h;
		KeyedHash::Hash128(d.Bytes(), d.Len(), &h);

		my_name = "lambda_<" + std::to_string(h[0]) + ">";
		auto fullname = make_full_var_name(current_module.data(), my_name.data());
		const auto& id = global_scope()->Find(fullname);

		if ( id )
			// Just try again to make a unique lambda name.
			// If two peer processes need to agree on the same
			// lambda name, this assumes they're loading the same
			// scripts and thus have the same hash collisions.
			d.Add(" ");
		else
			break;
		}

	// Install that in the global_scope
	auto id = install_ID(my_name.c_str(), current_module.c_str(), true, false);

	// Update lamb's name
	dummy_func->SetName(my_name.c_str());

	auto v = make_intrusive<FuncVal>(std::move(dummy_func));
	id->SetVal(std::move(v));
	id->SetType(ingredients->id->GetType());
	id->SetConst();
	}

void LambdaExpr::CheckCaptures()
	{
	auto ft = type->AsFuncType();
	const auto& captures = ft->GetCaptures();

	capture_by_ref = false;

	if ( ! captures )
		{
		if ( outer_ids.size() > 0 )
			{
			// TODO: Remove in v5.1: these deprecated closure semantics
			reporter->Warning("use of outer identifiers in lambdas without [] captures is deprecated: %s%s",
				outer_ids.size() > 1 ? "e.g., " : "",
				outer_ids[0]->Name());
			capture_by_ref = true;
			}

		return;
		}

	std::set<const ID*> outer_is_matched;
	std::set<const ID*> capture_is_matched;

	for ( const auto& c : *captures )
		{
		auto cid = c.id.get();

		if ( ! cid )
			// This happens for undefined/inappropriate
			// identifiers listed in captures.  There's
			// already been an error message.
			continue;

		if ( capture_is_matched.count(cid) > 0 )
			{
			ExprError(util::fmt("%s listed multiple times in capture", cid->Name()));
			continue;
			}

		for ( auto id : outer_ids )
			if ( cid == id )
				{
				outer_is_matched.insert(id);
				capture_is_matched.insert(cid);
				break;
				}
		}

	for ( auto id : outer_ids )
		if ( outer_is_matched.count(id) == 0 )
			ExprError(util::fmt("%s is used inside lambda but not captured", id->Name()));

	for ( const auto& c : *captures )
		{
		auto cid = c.id.get();
		if ( cid && capture_is_matched.count(cid) == 0 )
			ExprError(util::fmt("%s is captured but not used inside lambda", cid->Name()));
		}
	}

ScopePtr LambdaExpr::GetScope() const
	{
	return ingredients->scope;
	}

ValPtr LambdaExpr::Eval(Frame* f) const
	{
	auto lamb = make_intrusive<ScriptFunc>(
		ingredients->id,
		ingredients->body,
		ingredients->inits,
		ingredients->frame_size,
		ingredients->priority);

	if ( capture_by_ref )
		lamb->AddClosure(outer_ids, f);
	else
		lamb->CreateCaptures(f);

	// Set name to corresponding dummy func.
	// Allows for lookups by the receiver.
	lamb->SetName(my_name.c_str());

	return make_intrusive<FuncVal>(std::move(lamb));
	}

void LambdaExpr::ExprDescribe(ODesc* d) const
	{
	d->Add(expr_name(Tag()));
	ingredients->body->Describe(d);
	}

TraversalCode LambdaExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	tc = ingredients->body->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}

EventExpr::EventExpr(const char* arg_name, ListExprPtr arg_args)
	: Expr(EXPR_EVENT), name(arg_name), args(std::move(arg_args))
	{
	EventHandler* h = event_registry->Lookup(name);

	if ( ! h )
		{
		h = new EventHandler(name.c_str());
		event_registry->Register(h);
		}

	h->SetUsed();

	handler = h;

	if ( args->IsError() )
		{
		SetError();
		return;
		}

	const auto& func_type = h->GetType();

	if ( ! func_type )
		{
		Error("not an event");
		SetError();
		return;
		}

	if ( ! func_type->MatchesIndex(args.get()) )
		SetError("argument type mismatch in event invocation");
	else
		{
		if ( func_type->Yield() )
			{
			Error("function invoked as an event");
			SetError();
			}
		}
	}

ValPtr EventExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return nullptr;

	auto v = eval_list(f, args.get());

	if ( handler )
		event_mgr.Enqueue(handler, std::move(*v));

	return nullptr;
	}

TraversalCode EventExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	tc = args->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}

void EventExpr::ExprDescribe(ODesc* d) const
	{
	d->Add(name.c_str());
	if ( d->IsReadable() || d->IsPortable() )
		{
		d->Add("(");
		args->Describe(d);
		d->Add(")");
		}
	else
		args->Describe(d);
	}

ListExpr::ListExpr() : Expr(EXPR_LIST)
	{
	SetType(make_intrusive<TypeList>());
	}

ListExpr::ListExpr(ExprPtr e) : Expr(EXPR_LIST)
	{
	SetType(make_intrusive<TypeList>());
	Append(std::move(e));
	}

ListExpr::~ListExpr()
	{
	for ( const auto& expr: exprs )
		Unref(expr);
	}

void ListExpr::Append(ExprPtr e)
	{
	exprs.push_back(e.release());
	((TypeList*) type.get())->Append(exprs.back()->GetType());
	}

bool ListExpr::IsPure() const
	{
	for ( const auto& expr : exprs )
		if ( ! expr->IsPure() )
			return false;

	return true;
	}

ValPtr ListExpr::Eval(Frame* f) const
	{
	auto v = make_intrusive<ListVal>(TYPE_ANY);

	for ( const auto& expr : exprs )
		{
		auto ev = expr->Eval(f);

		if ( ! ev )
			{
			RuntimeError("uninitialized list value");
			return nullptr;
			}

		v->Append(std::move(ev));
		}

	return v;
	}

TypePtr ListExpr::InitType() const
	{
	if ( exprs.empty() )
		{
		Error("empty list in untyped initialization");
		return nullptr;
		}

	if ( exprs[0]->IsRecordElement(nullptr) )
		{
		type_decl_list* types = new type_decl_list(exprs.length());
		for ( const auto& expr : exprs )
			{
			TypeDecl* td = new TypeDecl(nullptr, nullptr);
			if ( ! expr->IsRecordElement(td) )
				{
				expr->Error("record element expected");
				delete td;
				delete types;
				return nullptr;
				}

			types->push_back(td);
			}


		return make_intrusive<RecordType>(types);
		}

	else
		{
		auto tl = make_intrusive<TypeList>();

		for ( const auto& e : exprs )
			{
			const auto& ti = e->GetType();

			// Collapse any embedded sets or lists.
			if ( ti->IsSet() || ti->Tag() == TYPE_LIST )
				{
				TypeList* til = ti->IsSet() ?
					ti->AsSetType()->GetIndices().get() :
					ti->AsTypeList();

				if ( ! til->IsPure() ||
				     ! til->AllMatch(til->GetPureType(), true) )
					tl->Append({NewRef{}, til});
				else
					tl->Append(til->GetPureType());
				}
			else
				tl->Append(ti);
			}

		return tl;
		}
	}

ValPtr ListExpr::InitVal(const zeek::Type* t, ValPtr aggr) const
	{
	// While fairly similar to the EvalIntoAggregate() code,
	// we keep this separate since it also deals with initialization
	// idioms such as embedded aggregates and cross-product
	// expansion.
	if ( IsError() )
		return nullptr;

	// Check whether each element of this list itself matches t,
	// in which case we should expand as a ListVal.
	if ( ! aggr && type->AsTypeList()->AllMatch(t, true) )
		{
		auto v = make_intrusive<ListVal>(TYPE_ANY);
		const auto& tl = type->AsTypeList()->GetTypes();

		if ( exprs.length() != static_cast<int>(tl.size()) )
			{
			Error("index mismatch", t);
			return nullptr;
			}

		loop_over_list(exprs, i)
			{
			auto vi = exprs[i]->InitVal(tl[i].get(), nullptr);
			if ( ! vi )
				return nullptr;

			v->Append(std::move(vi));
			}

		return v;
		}

	if ( t->Tag() == TYPE_LIST )
		{
		if ( aggr )
			{
			Error("bad use of list in initialization", t);
			return nullptr;
			}

		const auto& tl = t->AsTypeList()->GetTypes();

		if ( exprs.length() != static_cast<int>(tl.size()) )
			{
			Error("index mismatch", t);
			return nullptr;
			}

		auto v = make_intrusive<ListVal>(TYPE_ANY);

		loop_over_list(exprs, i)
			{
			auto vi = exprs[i]->InitVal(tl[i].get(), nullptr);

			if ( ! vi )
				return nullptr;

			v->Append(std::move(vi));
			}

		return v;
		}

	if ( t->Tag() != TYPE_RECORD && t->Tag() != TYPE_TABLE &&
	     t->Tag() != TYPE_VECTOR )
		{
		if ( exprs.length() == 1 )
			// Allow "global x:int = { 5 }"
			return exprs[0]->InitVal(t, aggr);
		else
			{
			Error("aggregate initializer for scalar type", t);
			return nullptr;
			}
		}

	if ( ! aggr )
		Internal("missing aggregate in ListExpr::InitVal");

	if ( t->IsSet() )
		return AddSetInit(t, std::move(aggr));

	if ( t->Tag() == TYPE_VECTOR )
		{
		// v: vector = [10, 20, 30];
		VectorVal* vec = aggr->AsVectorVal();

		loop_over_list(exprs, i)
			{
			ExprPtr e = {NewRef{}, exprs[i]};
			const auto& vyt = vec->GetType()->AsVectorType()->Yield();
			auto promoted_e = check_and_promote_expr(e, vyt);

			if ( promoted_e )
				e = promoted_e;

			if ( ! vec->Assign(i, e->Eval(nullptr)) )
				{
				e->Error(util::fmt("type mismatch at index %d", i));
				return nullptr;
				}
			}

		return aggr;
		}

	// If we got this far, then it's either a table or record
	// initialization.  Both of those involve AssignExpr's, which
	// know how to add themselves to a table or record.  Another
	// possibility is an expression that evaluates itself to a
	// table, which we can then add to the aggregate.
	for ( const auto& e : exprs )
		{
		if ( e->Tag() == EXPR_ASSIGN || e->Tag() == EXPR_FIELD_ASSIGN )
			{
			if ( ! e->InitVal(t, aggr) )
				return nullptr;
			}
		else
			{
			if ( t->Tag() == TYPE_RECORD )
				{
				e->Error("bad record initializer", t);
				return nullptr;
				}

			auto v = e->Eval(nullptr);

			if ( ! same_type(v->GetType(), t) )
				{
				v->GetType()->Error("type clash in table initializer", t);
				return nullptr;
				}

			if ( ! v->AsTableVal()->AddTo(aggr->AsTableVal(), true) )
				return nullptr;
			}
		}

	return aggr;
	}

ValPtr ListExpr::AddSetInit(const zeek::Type* t, ValPtr aggr) const
	{
	if ( aggr->GetType()->Tag() != TYPE_TABLE )
		Internal("bad aggregate in ListExpr::InitVal");

	TableVal* tv = aggr->AsTableVal();
	const TableType* tt = tv->GetType()->AsTableType();
	const TypeList* it = tt->GetIndices().get();

	for ( const auto& expr : exprs )
		{
		ValPtr element;

		if ( expr->GetType()->IsSet() )
			// A set to flatten.
			element = expr->Eval(nullptr);
		else if ( expr->GetType()->Tag() == TYPE_LIST )
			element = expr->InitVal(it, nullptr);
		else
			element = expr->InitVal(it->GetTypes()[0].get(), nullptr);

		if ( ! element )
			return nullptr;

		if ( element->GetType()->IsSet() )
			{
			if ( ! same_type(element->GetType(), t) )
				{
				element->Error("type clash in set initializer", t);
				return nullptr;
				}

			if ( ! element->AsTableVal()->AddTo(tv, true) )
				return nullptr;

			continue;
			}

		if ( expr->GetType()->Tag() == TYPE_LIST )
			element = check_and_promote(std::move(element), it, true);
		else
			element = check_and_promote(std::move(element), it->GetTypes()[0].get(), true);

		if ( ! element )
			return nullptr;

		if ( ! tv->ExpandAndInit(std::move(element), nullptr) )
			return nullptr;
		}

	return aggr;
	}

void ListExpr::ExprDescribe(ODesc* d) const
	{
	d->AddCount(exprs.length());

	loop_over_list(exprs, i)
		{
		if ( (d->IsReadable() || d->IsPortable()) && i > 0 )
			d->Add(", ");

		exprs[i]->Describe(d);
		}
	}

ExprPtr ListExpr::MakeLvalue()
	{
	for ( const auto & expr : exprs )
		if ( expr->Tag() != EXPR_NAME )
			ExprError("can only assign to list of identifiers");

	return make_intrusive<RefExpr>(IntrusivePtr{NewRef{}, this});
	}

void ListExpr::Assign(Frame* f, ValPtr v)
	{
	ListVal* lv = v->AsListVal();

	if ( exprs.length() != lv->Length() )
		RuntimeError("mismatch in list lengths");

	loop_over_list(exprs, i)
		exprs[i]->Assign(f, lv->Idx(i));
	}

TraversalCode ListExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	for ( const auto& expr : exprs )
		{
		tc = expr->Traverse(cb);
		HANDLE_TC_EXPR_PRE(tc);
		}

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}

RecordAssignExpr::RecordAssignExpr(const ExprPtr& record,
                                   const ExprPtr& init_list, bool is_init)
	{
	const ExprPList& inits = init_list->AsListExpr()->Exprs();

	RecordType* lhs = record->GetType()->AsRecordType();

	// The inits have two forms:
	// 1) other records -- use all matching field names+types
	// 2) a string indicating the field name, then (as the next element)
	//    the value to use for that field.

	for ( const auto& init : inits )
		{
		if ( init->GetType()->Tag() == TYPE_RECORD )
			{
			RecordType* t = init->GetType()->AsRecordType();

			for ( int j = 0; j < t->NumFields(); ++j )
				{
				const char* field_name = t->FieldName(j);
				int field = lhs->FieldOffset(field_name);

				if ( field >= 0 &&
				     same_type(lhs->GetFieldType(field), t->GetFieldType(j)) )
					{
					auto fe_lhs = make_intrusive<FieldExpr>(record, field_name);
					auto fe_rhs = make_intrusive<FieldExpr>(IntrusivePtr{NewRef{}, init}, field_name);
					Append(get_assign_expr(std::move(fe_lhs), std::move(fe_rhs), is_init));
					}
				}
			}

		else if ( init->Tag() == EXPR_FIELD_ASSIGN )
			{
			FieldAssignExpr* rf = (FieldAssignExpr*) init;
			rf->Ref();

			const char* field_name = ""; // rf->FieldName();
			if ( lhs->HasField(field_name) )
				{
				auto fe_lhs = make_intrusive<FieldExpr>(record, field_name);
				ExprPtr fe_rhs = {NewRef{}, rf->Op()};
				Append(get_assign_expr(std::move(fe_lhs), std::move(fe_rhs), is_init));
				}
			else
				{
				std::string s = "No such field '";
				s += field_name;
				s += "'";
				init_list->SetError(s.c_str());
				}
			}

		else
			{
			init_list->SetError("bad record initializer");
			return;
			}
		}
	}

CastExpr::CastExpr(ExprPtr arg_op, TypePtr t)
	: UnaryExpr(EXPR_CAST, std::move(arg_op))
	{
	auto stype = Op()->GetType();

	SetType(std::move(t));

	if ( ! can_cast_value_to_type(stype.get(), GetType().get()) )
		ExprError("cast not supported");
	}

ValPtr CastExpr::Fold(Val* v) const
	{
	std::string error;
	auto res = cast_value({NewRef{}, v}, GetType(), error);

	if ( ! res )
		RuntimeError(error.c_str());

	return res;
	}

ValPtr cast_value(ValPtr v, const TypePtr& t, std::string& error)
	{
	auto nv = cast_value_to_type(v.get(), t.get());

	if ( nv )
		return nv;

	ODesc d;

	d.Add("invalid cast of value with type '");
	v->GetType()->Describe(&d);
	d.Add("' to type '");
	t->Describe(&d);
	d.Add("'");

	if ( same_type(v->GetType(), Broker::detail::DataVal::ScriptDataType()) &&
	     ! v->AsRecordVal()->HasField(0) )
		d.Add(" (nil $data field)");

	error = d.Description();
	return nullptr;
	}

void CastExpr::ExprDescribe(ODesc* d) const
	{
	Op()->Describe(d);
	d->Add(" as ");
	GetType()->Describe(d);
	}

IsExpr::IsExpr(ExprPtr arg_op, TypePtr arg_t)
	: UnaryExpr(EXPR_IS, std::move(arg_op)), t(std::move(arg_t))
	{
	SetType(base_type(TYPE_BOOL));
	}

ValPtr IsExpr::Fold(Val* v) const
	{
	if ( IsError() )
		return nullptr;

	return val_mgr->Bool(can_cast_value_to_type(v, t.get()));
	}

void IsExpr::ExprDescribe(ODesc* d) const
	{
	Op()->Describe(d);
	d->Add(" is ");
	t->Describe(d);
	}

ExprPtr get_assign_expr(ExprPtr op1, ExprPtr op2, bool is_init)
	{
	if ( op1->GetType()->Tag() == TYPE_RECORD &&
	     op2->GetType()->Tag() == TYPE_LIST )
		return make_intrusive<RecordAssignExpr>(
			std::move(op1), std::move(op2), is_init);

	else if ( op1->Tag() == EXPR_INDEX && op1->AsIndexExpr()->IsSlice() )
		return make_intrusive<IndexSliceAssignExpr>(
			std::move(op1), std::move(op2), is_init);

	else
		return make_intrusive<AssignExpr>(
			std::move(op1), std::move(op2), is_init);
	}

ExprPtr check_and_promote_expr(ExprPtr e, TypePtr t)
	{
	const auto& et = e->GetType();
	TypeTag e_tag = et->Tag();
	TypeTag t_tag = t->Tag();

	if ( t_tag == TYPE_ANY )
		{
		if ( e_tag != TYPE_ANY )
			return make_intrusive<CoerceToAnyExpr>(e);

		return e;
		}

	if ( e_tag == TYPE_ANY )
		return make_intrusive<CoerceFromAnyExpr>(e, t);

	if ( EitherArithmetic(t_tag, e_tag) )
		{
		if ( e_tag == t_tag )
			return e;

		if ( ! BothArithmetic(t_tag, e_tag) )
			{
			t->Error("arithmetic mixed with non-arithmetic", e.get());
			return nullptr;
			}

		TypeTag mt = max_type(t_tag, e_tag);
		if ( mt != t_tag )
			{
			t->Error("over-promotion of arithmetic value", e.get());
			return nullptr;
			}

		return make_intrusive<ArithCoerceExpr>(e, t_tag);
		}

	if ( t->Tag() == TYPE_RECORD && et->Tag() == TYPE_RECORD )
		{
		RecordType* t_r = t->AsRecordType();
		RecordType* et_r = et->AsRecordType();

		if ( same_type(t, et) )
			return e;

		if ( record_promotion_compatible(t_r, et_r) )
			return make_intrusive<RecordCoerceExpr>(e,
				IntrusivePtr{NewRef{}, t_r});

		t->Error("incompatible record types", e.get());
		return nullptr;
		}


	if ( ! same_type(t, et) )
		{
		if ( t->Tag() == TYPE_TABLE && et->Tag() == TYPE_TABLE &&
			  et->AsTableType()->IsUnspecifiedTable() )
			return make_intrusive<TableCoerceExpr>(e,
				IntrusivePtr{NewRef{}, t->AsTableType()});

		if ( t->Tag() == TYPE_VECTOR && et->Tag() == TYPE_VECTOR &&
		     et->AsVectorType()->IsUnspecifiedVector() )
			return make_intrusive<VectorCoerceExpr>(e,
				IntrusivePtr{NewRef{}, t->AsVectorType()});

		if ( t->Tag() != TYPE_ERROR && et->Tag() != TYPE_ERROR )
			t->Error("type clash", e.get());

		return nullptr;
		}

	return e;
	}

bool check_and_promote_exprs(ListExpr* const elements, TypeList* types)
	{
	ExprPList& el = elements->Exprs();
	const auto& tl = types->GetTypes();

	if ( tl.size() == 1 && tl[0]->Tag() == TYPE_ANY )
		return true;

	if ( el.length() != static_cast<int>(tl.size()) )
		{
		types->Error("indexing mismatch", elements);
		return false;
		}

	loop_over_list(el, i)
		{
		ExprPtr e = {NewRef{}, el[i]};
		auto promoted_e = check_and_promote_expr(e, tl[i]);

		if ( ! promoted_e )
			{
			e->Error("type mismatch", tl[i].get());
			return false;
			}

		if ( promoted_e != e )
			Unref(el.replace(i, promoted_e.release()));
		}

	return true;
	}

bool check_and_promote_args(ListExpr* const args, const RecordType* types)
	{
	ExprPList& el = args->Exprs();
	int ntypes = types->NumFields();

	// give variadic BIFs automatic pass
	if ( ntypes == 1 && types->FieldDecl(0)->type->Tag() == TYPE_ANY )
		return true;

	if ( el.length() < ntypes )
		{
		std::vector<ExprPtr> def_elements;

		// Start from rightmost parameter, work backward to fill in missing
		// arguments using &default expressions.
		for ( int i = ntypes - 1; i >= el.length(); --i )
			{
			auto td = types->FieldDecl(i);
			const auto& def_attr = td->attrs ? td->attrs->Find(ATTR_DEFAULT).get() : nullptr;

			if ( ! def_attr )
				{
				types->Error("parameter mismatch", args);
				return false;
				}

			// Don't use the default expression directly, as
			// doing so will wind up sharing its code across
			// different invocations that use the default
			// argument.  That works okay for the interpreter,
			// but if we transform the code we want that done
			// separately for each instance, rather than
			// one instance inheriting the transformed version
			// from another.
			const auto& e = def_attr->GetExpr();
			def_elements.emplace_back(e->Duplicate());
			}

		auto ne = def_elements.size();
		while ( ne )
			el.push_back(def_elements[--ne].release());
		}

	TypeList* tl = new TypeList();

	for ( int i = 0; i < types->NumFields(); ++i )
		tl->Append(types->GetFieldType(i));

	int rval = check_and_promote_exprs(args, tl);
	Unref(tl);

	return rval;
	}

bool check_and_promote_exprs_to_type(ListExpr* const elements, TypePtr t)
	{
	ExprPList& el = elements->Exprs();

	if ( t->Tag() == TYPE_ANY )
		return true;

	loop_over_list(el, i)
		{
		ExprPtr e = {NewRef{}, el[i]};
		auto promoted_e = check_and_promote_expr(e, t);

		if ( ! promoted_e )
			{
			e->Error("type mismatch", t.get());
			return false;
			}

		if ( promoted_e != e )
			Unref(el.replace(i, promoted_e.release()));
		}

	return true;
	}

std::optional<std::vector<ValPtr>> eval_list(Frame* f, const ListExpr* l)
	{
	const ExprPList& e = l->Exprs();
	auto rval = std::make_optional<std::vector<ValPtr>>();
	rval->reserve(e.length());

	for ( const auto& expr : e )
		{
		auto ev = expr->Eval(f);

		if ( ! ev )
			return {};

		rval->emplace_back(std::move(ev));
		}

	return rval;
	}

bool expr_greater(const Expr* e1, const Expr* e2)
	{
	return e1->Tag() > e2->Tag();
	}

} // namespace zeek::detail
