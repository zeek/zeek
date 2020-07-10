// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "Expr.h"
#include "Event.h"
#include "Desc.h"
#include "Frame.h"
#include "Func.h"
#include "RE.h"
#include "Scope.h"
#include "Stmt.h"
#include "EventRegistry.h"
#include "Net.h"
#include "Traverse.h"
#include "Trigger.h"
#include "IPAddr.h"
#include "digest.h"
#include "module_util.h"
#include "DebugLogger.h"
#include "Hash.h"

#include "broker/Data.h"

namespace zeek::detail {

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
		"sizeof", "cast", "is", "[:]="
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

Expr::Expr(BroExprTag arg_tag) : tag(arg_tag), type(nullptr), paren(false)
	{
	SetLocationInfo(&start_location, &end_location);
	}

const ListExpr* Expr::AsListExpr() const
	{
	CHECK_TAG(tag, EXPR_LIST, "ExprVal::AsListExpr", expr_name)
	return (const ListExpr*) this;
	}

ListExpr* Expr::AsListExpr()
	{
	CHECK_TAG(tag, EXPR_LIST, "ExprVal::AsListExpr", expr_name)
	return (ListExpr*) this;
	}

const NameExpr* Expr::AsNameExpr() const
	{
	CHECK_TAG(tag, EXPR_NAME, "ExprVal::AsNameExpr", expr_name)
	return (const NameExpr*) this;
	}

NameExpr* Expr::AsNameExpr()
	{
	CHECK_TAG(tag, EXPR_NAME, "ExprVal::AsNameExpr", expr_name)
	return (NameExpr*) this;
	}

const AssignExpr* Expr::AsAssignExpr() const
	{
	CHECK_TAG(tag, EXPR_ASSIGN, "ExprVal::AsAssignExpr", expr_name)
	return (const AssignExpr*) this;
	}

AssignExpr* Expr::AsAssignExpr()
	{
	CHECK_TAG(tag, EXPR_ASSIGN, "ExprVal::AsAssignExpr", expr_name)
	return (AssignExpr*) this;
	}

const IndexExpr* Expr::AsIndexExpr() const
	{
	CHECK_TAG(tag, EXPR_INDEX, "ExprVal::AsIndexExpr", expr_name)
	return (const IndexExpr*) this;
	}

IndexExpr* Expr::AsIndexExpr()
	{
	CHECK_TAG(tag, EXPR_INDEX, "ExprVal::AsIndexExpr", expr_name)
	return (IndexExpr*) this;
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
	Internal("Expr::Delete called");
	}

void Expr::Delete(Frame* /* f */)
	{
	Internal("Expr::Delete called");
	}

ExprPtr Expr::MakeLvalue()
	{
	if ( ! IsError() )
		ExprError("can't be assigned to");

	return {zeek::NewRef{}, this};
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

zeek::TypePtr Expr::InitType() const
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
	return type && type->Tag() == zeek::TYPE_ERROR;
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

void Expr::SetType(zeek::TypePtr t)
	{
	if ( ! type || type->Tag() != zeek::TYPE_ERROR )
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
		reporter->RuntimeError(GetLocationInfo(), "%s, expression: %s, call stack: %s",
		                       msg.data(), d.Description(), rcs.data());
		}
	}

NameExpr::NameExpr(zeek::detail::IDPtr arg_id, bool const_init)
	: Expr(EXPR_NAME), id(std::move(arg_id))
	{
	in_const_init = const_init;

	if ( id->IsType() )
		SetType(zeek::make_intrusive<TypeType>(id->GetType()));
	else
		SetType(id->GetType());

	EventHandler* h = event_registry->Lookup(id->Name());
	if ( h )
		h->SetUsed();
	}

ValPtr NameExpr::Eval(Frame* f) const
	{
	ValPtr v;

	if ( id->IsType() )
		return zeek::make_intrusive<zeek::Val>(id->GetType(), true);

	if ( id->IsGlobal() )
		v = id->GetVal();

	else if ( f )
		v = f->GetElementByID(id);

	else
		// No frame - evaluating for Simplify() purposes
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

	return zeek::make_intrusive<RefExpr>(IntrusivePtr{zeek::NewRef{}, this});
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
	if ( val->GetType()->Tag() == zeek::TYPE_LIST && val->AsListVal()->Length() == 1 )
		val = val->AsListVal()->Idx(0);

	SetType(val->GetType());
	}

void ConstExpr::ExprDescribe(ODesc* d) const
	{
	val->Describe(d);
	}

ValPtr ConstExpr::Eval(Frame* /* f */) const
	{
	return {zeek::NewRef{}, Value()};
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

	if ( is_vector(v) && Tag() != EXPR_IS && Tag() != EXPR_CAST )
		{
		VectorVal* v_op = v->AsVectorVal();
		zeek::VectorTypePtr out_t;

		if ( GetType()->Tag() == zeek::TYPE_ANY )
			out_t = v->GetType<zeek::VectorType>();
		else
			out_t = GetType<zeek::VectorType>();

		auto result = zeek::make_intrusive<zeek::VectorVal>(std::move(out_t));

		for ( unsigned int i = 0; i < v_op->Size(); ++i )
			{
			const auto& v_i = v_op->At(i);
			result->Assign(i, v_i ? Fold(v_i.get()) : nullptr);
			}

		return result;
		}
	else
		{
		return Fold(v.get());
		}
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
	return {zeek::NewRef{}, v};
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

		auto v_result = zeek::make_intrusive<zeek::VectorVal>(GetType<zeek::VectorType>());

		for ( unsigned int i = 0; i < v_op1->Size(); ++i )
			{
			if ( v_op1->At(i) && v_op2->At(i) )
				v_result->Assign(i, Fold(v_op1->At(i).get(), v_op2->At(i).get()));
			else
				v_result->Assign(i, nullptr);
			// SetError("undefined element in vector operation");
			}

		return v_result;
		}

	if ( IsVector(GetType()->Tag()) && (is_vec1 || is_vec2) )
		{ // fold vector against scalar
		VectorVal* vv = (is_vec1 ? v1 : v2)->AsVectorVal();
		auto v_result = zeek::make_intrusive<zeek::VectorVal>(GetType<zeek::VectorType>());

		for ( unsigned int i = 0; i < vv->Size(); ++i )
			{
			if ( const auto& vv_i = vv->At(i) )
				v_result->Assign(i, is_vec1 ? Fold(vv_i.get(), v2.get())
				                            : Fold(v1.get(), vv_i.get()));
			else
				v_result->Assign(i, nullptr);

			// SetError("Undefined element in vector operation");
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

	if ( it == zeek::TYPE_INTERNAL_STRING )
		return StringFold(v1, v2);

	if ( v1->GetType()->Tag() == zeek::TYPE_PATTERN )
		return PatternFold(v1, v2);

	if ( v1->GetType()->IsSet() )
		return SetFold(v1, v2);

	if ( it == zeek::TYPE_INTERNAL_ADDR )
		return AddrFold(v1, v2);

	if ( it == zeek::TYPE_INTERNAL_SUBNET )
		return SubNetFold(v1, v2);

	bro_int_t i1 = 0, i2 = 0, i3 = 0;
	bro_uint_t u1 = 0, u2 = 0, u3 = 0;
	double d1 = 0.0, d2 = 0.0, d3 = 0.0;
	bool is_integral = false;
	bool is_unsigned = false;

	if ( it == zeek::TYPE_INTERNAL_INT )
		{
		i1 = v1->InternalInt();
		i2 = v2->InternalInt();
		is_integral = true;
		}
	else if ( it == zeek::TYPE_INTERNAL_UNSIGNED )
		{
		u1 = v1->InternalUnsigned();
		u2 = v2->InternalUnsigned();
		is_unsigned = true;
		}
	else if ( it == zeek::TYPE_INTERNAL_DOUBLE )
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

	if ( ret_type->Tag() == zeek::TYPE_INTERVAL )
		return zeek::make_intrusive<zeek::IntervalVal>(d3);
	else if ( ret_type->Tag() == zeek::TYPE_TIME )
		return zeek::make_intrusive<zeek::TimeVal>(d3);
	else if ( ret_type->Tag() == zeek::TYPE_DOUBLE )
		return zeek::make_intrusive<zeek::DoubleVal>(d3);
	else if ( ret_type->InternalType() == zeek::TYPE_INTERNAL_UNSIGNED )
		return zeek::val_mgr->Count(u3);
	else if ( ret_type->Tag() == zeek::TYPE_BOOL )
		return zeek::val_mgr->Bool(i3);
	else
		return zeek::val_mgr->Int(i3);
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

		return zeek::make_intrusive<zeek::StringVal>(concatenate(strings));
		}

	default:
		BadTag("BinaryExpr::StringFold", expr_name(tag));
	}

	return zeek::val_mgr->Bool(result);
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

	return zeek::make_intrusive<zeek::PatternVal>(res);
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

	return zeek::val_mgr->Bool(res);
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

	return zeek::val_mgr->Bool(result);
	}

ValPtr BinaryExpr::SubNetFold(Val* v1, Val* v2) const
	{
	const IPPrefix& n1 = v1->AsSubNet();
	const IPPrefix& n2 = v2->AsSubNet();

	bool result = n1 == n2;

	if ( tag == EXPR_NE )
		result = ! result;

	return zeek::val_mgr->Bool(result);
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
		op1 = zeek::make_intrusive<ArithCoerceExpr>(op1, t);
	if ( bt2 != t )
		op2 = zeek::make_intrusive<ArithCoerceExpr>(op2, t);
	}

void BinaryExpr::PromoteType(TypeTag t, bool is_vector)
	{
	PromoteOps(t);

	if ( is_vector)
		SetType(zeek::make_intrusive<zeek::VectorType>(base_type(t)));
	else
		SetType(base_type(t));
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
		     v->GetType()->InternalType() == zeek::TYPE_INTERNAL_UNSIGNED )
			RuntimeError("count underflow");
		}

	const auto& ret_type = IsVector(GetType()->Tag()) ? GetType()->Yield() : GetType();

	if ( ret_type->Tag() == zeek::TYPE_INT )
		return zeek::val_mgr->Int(k);
	else
		return zeek::val_mgr->Count(k);
	}


ValPtr IncrExpr::Eval(Frame* f) const
	{
	auto v = op->Eval(f);

	if ( ! v )
		return nullptr;

	if ( is_vector(v) )
		{
		VectorValPtr v_vec{zeek::NewRef{}, v->AsVectorVal()};

		for ( unsigned int i = 0; i < v_vec->Size(); ++i )
			{
			const auto& elt = v_vec->At(i);

			if ( elt )
				v_vec->Assign(i, DoSingleEval(f, elt.get()));
			else
				v_vec->Assign(i, nullptr);
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

	if ( bt != zeek::TYPE_COUNT )
		ExprError("requires \"count\" operand");
	else
		SetType(base_type(zeek::TYPE_COUNT));
	}

ValPtr ComplementExpr::Fold(Val* v) const
	{
	return zeek::val_mgr->Count(~ v->InternalUnsigned());
	}

NotExpr::NotExpr(ExprPtr arg_op)
	: UnaryExpr(EXPR_NOT, std::move(arg_op))
	{
	if ( IsError() )
		return;

	TypeTag bt = op->GetType()->Tag();

	if ( ! IsIntegral(bt) && bt != zeek::TYPE_BOOL )
		ExprError("requires an integral or boolean operand");
	else
		SetType(base_type(zeek::TYPE_BOOL));
	}

ValPtr NotExpr::Fold(Val* v) const
	{
	return zeek::val_mgr->Bool(! v->InternalInt());
	}

PosExpr::PosExpr(ExprPtr arg_op)
	: UnaryExpr(EXPR_POSITIVE, std::move(arg_op))
	{
	if ( IsError() )
		return;

	const auto& t = IsVector(op->GetType()->Tag()) ? op->GetType()->Yield() : op->GetType();

	TypeTag bt = t->Tag();
	zeek::TypePtr base_result_type;

	if ( IsIntegral(bt) )
		// Promote count and counter to int.
		base_result_type = base_type(zeek::TYPE_INT);
	else if ( bt == zeek::TYPE_INTERVAL || bt == zeek::TYPE_DOUBLE )
		base_result_type = t;
	else
		ExprError("requires an integral or double operand");

	if ( is_vector(op) )
		SetType(zeek::make_intrusive<zeek::VectorType>(std::move(base_result_type)));
	else
		SetType(std::move(base_result_type));
	}

ValPtr PosExpr::Fold(Val* v) const
	{
	TypeTag t = v->GetType()->Tag();

	if ( t == zeek::TYPE_DOUBLE || t == zeek::TYPE_INTERVAL || t == zeek::TYPE_INT )
		return {zeek::NewRef{}, v};
	else
		return zeek::val_mgr->Int(v->CoerceToInt());
	}

NegExpr::NegExpr(ExprPtr arg_op)
	: UnaryExpr(EXPR_NEGATE, std::move(arg_op))
	{
	if ( IsError() )
		return;

	const auto& t = IsVector(op->GetType()->Tag()) ? op->GetType()->Yield() : op->GetType();

	TypeTag bt = t->Tag();
	zeek::TypePtr base_result_type;

	if ( IsIntegral(bt) )
		// Promote count and counter to int.
		base_result_type = base_type(zeek::TYPE_INT);
	else if ( bt == zeek::TYPE_INTERVAL || bt == zeek::TYPE_DOUBLE )
		base_result_type = t;
	else
		ExprError("requires an integral or double operand");

	if ( is_vector(op) )
		SetType(zeek::make_intrusive<zeek::VectorType>(std::move(base_result_type)));
	else
		SetType(std::move(base_result_type));
	}

ValPtr NegExpr::Fold(Val* v) const
	{
	if ( v->GetType()->Tag() == zeek::TYPE_DOUBLE )
		return zeek::make_intrusive<zeek::DoubleVal>(- v->InternalDouble());
	else if ( v->GetType()->Tag() == zeek::TYPE_INTERVAL )
		return zeek::make_intrusive<zeek::IntervalVal>(- v->InternalDouble());
	else
		return zeek::val_mgr->Int(- v->CoerceToInt());
	}

SizeExpr::SizeExpr(ExprPtr arg_op)
	: UnaryExpr(EXPR_SIZE, std::move(arg_op))
	{
	if ( IsError() )
		return;

	if ( op->GetType()->InternalType() == zeek::TYPE_INTERNAL_DOUBLE )
		SetType(base_type(zeek::TYPE_DOUBLE));
	else
		SetType(base_type(zeek::TYPE_COUNT));
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

	zeek::TypePtr base_result_type;

	if ( bt2 == zeek::TYPE_INTERVAL && ( bt1 == zeek::TYPE_TIME || bt1 == zeek::TYPE_INTERVAL ) )
		base_result_type = base_type(bt1);
	else if ( bt2 == zeek::TYPE_TIME && bt1 == zeek::TYPE_INTERVAL )
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
			SetType(zeek::make_intrusive<zeek::VectorType>(std::move(base_result_type)));
		else
			SetType(std::move(base_result_type));
		}
	}

void AddExpr::Canonicize()
	{
	if ( expr_greater(op2.get(), op1.get()) ||
	     (op1->GetType()->Tag() == zeek::TYPE_INTERVAL &&
	      op2->GetType()->Tag() == zeek::TYPE_TIME) ||
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
					op2 = zeek::make_intrusive<ArithCoerceExpr>(std::move(op2), bt1);

				SetType(op1->GetType());
				}

			else
				ExprError("appending non-arithmetic to arithmetic vector");
			}

		else if ( bt1 != bt2 && bt1 != zeek::TYPE_ANY )
			ExprError(fmt("incompatible vector append: %s and %s",
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

	zeek::TypePtr base_result_type;

	if ( bt2 == zeek::TYPE_INTERVAL && ( bt1 == zeek::TYPE_TIME || bt1 == zeek::TYPE_INTERVAL ) )
		base_result_type = base_type(bt1);

	else if ( bt1 == zeek::TYPE_TIME && bt2 == zeek::TYPE_TIME )
		SetType(base_type(zeek::TYPE_INTERVAL));

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
			SetType(zeek::make_intrusive<zeek::VectorType>(std::move(base_result_type)));
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

	if ( bt1 == zeek::TYPE_INTERVAL || bt2 == zeek::TYPE_INTERVAL )
		{
		if ( IsArithmetic(bt1) || IsArithmetic(bt2) )
			PromoteType(zeek::TYPE_INTERVAL, is_vector(op1) || is_vector(op2) );
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
	if ( expr_greater(op2.get(), op1.get()) || op2->GetType()->Tag() == zeek::TYPE_INTERVAL ||
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

	if ( bt1 == zeek::TYPE_INTERVAL || bt2 == zeek::TYPE_INTERVAL )
		{
		if ( IsArithmetic(bt1) || IsArithmetic(bt2) )
			PromoteType(zeek::TYPE_INTERVAL, is_vector(op1) || is_vector(op2));
		else if ( bt1 == zeek::TYPE_INTERVAL && bt2 == zeek::TYPE_INTERVAL )
			{
			if ( is_vector(op1) || is_vector(op2) )
				SetType(zeek::make_intrusive<zeek::VectorType>(base_type(zeek::TYPE_DOUBLE)));
			else
				SetType(base_type(zeek::TYPE_DOUBLE));
			}
		else
			ExprError("division of interval requires arithmetic operand");
		}

	else if ( BothArithmetic(bt1, bt2) )
		PromoteType(max_type(bt1, bt2), is_vector(op1) || is_vector(op2));

	else if ( bt1 == zeek::TYPE_ADDR && ! is_vector(op2) &&
		  (bt2 == zeek::TYPE_COUNT || bt2 == zeek::TYPE_INT) )
		SetType(base_type(zeek::TYPE_SUBNET));

	else
		ExprError("requires arithmetic operands");
	}

ValPtr DivideExpr::AddrFold(Val* v1, Val* v2) const
	{
	uint32_t mask;

	if ( v2->GetType()->Tag() == zeek::TYPE_COUNT )
		mask = static_cast<uint32_t>(v2->InternalUnsigned());
	else
		mask = static_cast<uint32_t>(v2->InternalInt());

	auto& a = v1->AsAddr();

	if ( a.GetFamily() == IPv4 )
		{
		if ( mask > 32 )
			RuntimeError(fmt("bad IPv4 subnet prefix length: %" PRIu32, mask));
		}
	else
		{
		if ( mask > 128 )
			RuntimeError(fmt("bad IPv6 subnet prefix length: %" PRIu32, mask));
		}

	return zeek::make_intrusive<zeek::SubNetVal>(a, mask);
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
			SetType(zeek::make_intrusive<zeek::VectorType>(base_type(zeek::TYPE_BOOL)));
			}
		else
			SetType(base_type(zeek::TYPE_BOOL));
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
			vector_v = {zeek::AdoptRef{}, v1.release()->AsVectorVal()};
			}
		else
			{
			scalar_v = std::move(v1);
			vector_v = {zeek::AdoptRef{}, op2->Eval(f).release()->AsVectorVal()};
			}

		if ( ! scalar_v || ! vector_v )
			return nullptr;

		VectorValPtr result;

		// It's either an EXPR_AND_AND or an EXPR_OR_OR.
		bool is_and = (tag == EXPR_AND_AND);

		if ( scalar_v->IsZero() == is_and )
			{
			result = zeek::make_intrusive<zeek::VectorVal>(GetType<zeek::VectorType>());
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

	auto result = zeek::make_intrusive<zeek::VectorVal>(GetType<zeek::VectorType>());
	result->Resize(vec_v1->Size());

	for ( unsigned int i = 0; i < vec_v1->Size(); ++i )
		{
		const auto& op1 = vec_v1->At(i);
		const auto& op2 = vec_v2->At(i);
		if ( op1 && op2 )
			{
			bool local_result = (tag == EXPR_AND_AND) ?
				(! op1->IsZero() && ! op2->IsZero()) :
				(! op1->IsZero() || ! op2->IsZero());

			result->Assign(i, zeek::val_mgr->Bool(local_result));
			}
		else
			result->Assign(i, nullptr);
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

	if ( (bt1 == zeek::TYPE_COUNT || bt1 == zeek::TYPE_COUNTER) &&
	     (bt2 == zeek::TYPE_COUNT || bt2 == zeek::TYPE_COUNTER) )
		{
		if ( bt1 == zeek::TYPE_COUNTER && bt2 == zeek::TYPE_COUNTER )
			ExprError("cannot apply a bitwise operator to two \"counter\" operands");
		else if ( is_vector(op1) || is_vector(op2) )
			SetType(zeek::make_intrusive<zeek::VectorType>(base_type(zeek::TYPE_COUNT)));
		else
			SetType(base_type(zeek::TYPE_COUNT));
		}

	else if ( bt1 == zeek::TYPE_PATTERN )
		{
		if ( bt2 != zeek::TYPE_PATTERN )
			ExprError("cannot mix pattern and non-pattern operands");
		else if ( tag == EXPR_XOR )
			ExprError("'^' operator does not apply to patterns");
		else
			SetType(base_type(zeek::TYPE_PATTERN));
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
		SetType(zeek::make_intrusive<zeek::VectorType>(base_type(zeek::TYPE_BOOL)));
	else
		SetType(base_type(zeek::TYPE_BOOL));

	if ( BothArithmetic(bt1, bt2) )
		PromoteOps(max_type(bt1, bt2));

	else if ( EitherArithmetic(bt1, bt2) &&
		// Allow comparisons with zero.
		  ((bt1 == zeek::TYPE_TIME && op2->IsZero()) ||
		   (bt2 == zeek::TYPE_TIME && op1->IsZero())) )
		PromoteOps(zeek::TYPE_TIME);

	else if ( bt1 == bt2 )
		{
		switch ( bt1 ) {
		case zeek::TYPE_BOOL:
		case zeek::TYPE_TIME:
		case zeek::TYPE_INTERVAL:
		case zeek::TYPE_STRING:
		case zeek::TYPE_PORT:
		case zeek::TYPE_ADDR:
		case zeek::TYPE_SUBNET:
		case zeek::TYPE_ERROR:
		case zeek::TYPE_FUNC:
			break;

		case zeek::TYPE_ENUM:
			if ( ! same_type(t1, t2) )
				ExprError("illegal enum comparison");
			break;

		case zeek::TYPE_TABLE:
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

	else if ( bt1 == zeek::TYPE_PATTERN && bt2 == zeek::TYPE_STRING )
		;

	else
		ExprError("type clash in comparison");
	}

void EqExpr::Canonicize()
	{
	if ( op2->GetType()->Tag() == zeek::TYPE_PATTERN )
		SwapOps();

	else if ( op1->GetType()->Tag() == zeek::TYPE_PATTERN )
		;

	else if ( expr_greater(op2.get(), op1.get()) )
		SwapOps();
	}

ValPtr EqExpr::Fold(Val* v1, Val* v2) const
	{
	if ( op1->GetType()->Tag() == zeek::TYPE_PATTERN )
		{
		RE_Matcher* re = v1->AsPattern();
		const String* s = v2->AsString();
		if ( tag == EXPR_EQ )
			return zeek::val_mgr->Bool(re->MatchExactly(s));
		else
			return zeek::val_mgr->Bool(! re->MatchExactly(s));
		}
	else if ( op1->GetType()->Tag() == zeek::TYPE_FUNC )
		{
		auto res = v1->AsFunc() == v2->AsFunc();
		return val_mgr->Bool(tag == EXPR_EQ ? res : ! res);
		}

	else
		return BinaryExpr::Fold(v1, v2);
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
		SetType(zeek::make_intrusive<zeek::VectorType>(base_type(zeek::TYPE_BOOL)));
	else
		SetType(base_type(zeek::TYPE_BOOL));

	if ( BothArithmetic(bt1, bt2) )
		PromoteOps(max_type(bt1, bt2));

	else if ( t1->IsSet() && t2->IsSet() )
		{
		if ( ! same_type(t1, t2) )
			ExprError("incompatible sets in comparison");
		}

	else if ( bt1 != bt2 )
		ExprError("operands must be of the same type");

	else if ( bt1 != zeek::TYPE_TIME && bt1 != zeek::TYPE_INTERVAL &&
		  bt1 != zeek::TYPE_PORT && bt1 != zeek::TYPE_ADDR &&
		  bt1 != zeek::TYPE_STRING )
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

CondExpr::CondExpr(ExprPtr arg_op1, ExprPtr arg_op2, ExprPtr arg_op3)
	: Expr(EXPR_COND),
	  op1(std::move(arg_op1)), op2(std::move(arg_op2)), op3(std::move(arg_op3))
	{
	TypeTag bt1 = op1->GetType()->Tag();

	if ( IsVector(bt1) )
		bt1 = op1->GetType()->AsVectorType()->Yield()->Tag();

	if ( op1->IsError() || op2->IsError() || op3->IsError() )
		SetError();

	else if ( bt1 != zeek::TYPE_BOOL )
		ExprError("requires boolean conditional");

	else
		{
		TypeTag bt2 = op2->GetType()->Tag();

		if ( is_vector(op2) )
			bt2 = op2->GetType()->AsVectorType()->Yield()->Tag();

		TypeTag bt3 = op3->GetType()->Tag();

		if ( IsVector(bt3) )
			bt3 = op3->GetType()->AsVectorType()->Yield()->Tag();

		if ( is_vector(op1) && ! (is_vector(op2) && is_vector(op3)) )
			{
			ExprError("vector conditional requires vector alternatives");
			return;
			}

		if ( BothArithmetic(bt2, bt3) )
			{
			TypeTag t = max_type(bt2, bt3);
			if ( bt2 != t )
				op2 = zeek::make_intrusive<ArithCoerceExpr>(std::move(op2), t);
			if ( bt3 != t )
				op3 = zeek::make_intrusive<ArithCoerceExpr>(std::move(op3), t);

			if ( is_vector(op2) )
				SetType(zeek::make_intrusive<zeek::VectorType>(base_type(t)));
			else
				SetType(base_type(t));
			}

		else if ( bt2 != bt3 )
			ExprError("operands must be of the same type");

		else
			{
			if ( IsRecord(bt2) && IsRecord(bt3) &&
			     ! same_type(op2->GetType(), op3->GetType()) )
				ExprError("operands must be of the same type");
			else
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

	auto result = zeek::make_intrusive<zeek::VectorVal>(GetType<zeek::VectorType>());
	result->Resize(cond->Size());

	for ( unsigned int i = 0; i < cond->Size(); ++i )
		{
		const auto& local_cond = cond->At(i);

		if ( local_cond )
			{
			const auto& v = local_cond->IsZero() ? b->At(i) : a->At(i);
			result->Assign(i, v);
			}
		else
			result->Assign(i, nullptr);
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

	if ( ! zeek::is_assignable(op->GetType()->Tag()) )
		ExprError("illegal assignment target");
	else
		SetType(op->GetType());
	}

ExprPtr RefExpr::MakeLvalue()
	{
	return {zeek::NewRef{}, this};
	}

void RefExpr::Assign(Frame* f, ValPtr v)
	{
	op->Assign(f, std::move(v));
	}

AssignExpr::AssignExpr(ExprPtr arg_op1,
                       ExprPtr arg_op2,
                       bool arg_is_init, ValPtr arg_val,
                       const AttributesPtr& attrs)
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

	if ( bt1 == zeek::TYPE_LIST && bt2 == zeek::TYPE_ANY )
		// This is ok because we cannot explicitly declare lists on
		// the script level.
		return true;

	// This should be one of them, but not both (i.e. XOR)
	if ( ((bt1 == zeek::TYPE_ENUM) ^ (bt2 == zeek::TYPE_ENUM)) )
		{
		ExprError("can't convert to/from enumerated type");
		return false;
		}

	if ( IsArithmetic(bt1) )
		return TypeCheckArithmetics(bt1, bt2);

	if ( bt1 == zeek::TYPE_TIME && IsArithmetic(bt2) && op2->IsZero() )
		{ // Allow assignments to zero as a special case.
		op2 = zeek::make_intrusive<ArithCoerceExpr>(std::move(op2), bt1);
		return true;
		}

	if ( bt1 == zeek::TYPE_TABLE && bt2 == bt1 &&
	     op2->GetType()->AsTableType()->IsUnspecifiedTable() )
		{
		op2 = zeek::make_intrusive<TableCoerceExpr>(std::move(op2), op1->GetType<TableType>());
		return true;
		}

	if ( bt1 == zeek::TYPE_TABLE && op2->Tag() == EXPR_LIST )
		{
		std::unique_ptr<std::vector<AttrPtr>> attr_copy;

		if ( attrs )
			attr_copy = std::make_unique<std::vector<AttrPtr>>(attrs->GetAttrs());

		bool empty_list_assignment = (op2->AsListExpr()->Exprs().empty());

		if ( op1->GetType()->IsSet() )
			op2 = zeek::make_intrusive<SetConstructorExpr>(
			        zeek::cast_intrusive<ListExpr>(op2), std::move(attr_copy));
		else
			op2 = zeek::make_intrusive<TableConstructorExpr>(
			        zeek::cast_intrusive<ListExpr>(op2), std::move(attr_copy));

		if ( ! empty_list_assignment && ! same_type(op1->GetType(), op2->GetType()) )
			{
			if ( op1->GetType()->IsSet() )
				ExprError("set type mismatch in assignment");
			else
				ExprError("table type mismatch in assignment");

			return false;
			}

		return true;
		}

	if ( bt1 == zeek::TYPE_VECTOR )
		{
		if ( bt2 == bt1 && op2->GetType()->AsVectorType()->IsUnspecifiedVector() )
			{
			op2 = zeek::make_intrusive<VectorCoerceExpr>(std::move(op2), op1->GetType<zeek::VectorType>());
			return true;
			}

		if ( op2->Tag() == EXPR_LIST )
			{
			op2 = zeek::make_intrusive<VectorConstructorExpr>(
				IntrusivePtr{zeek::AdoptRef{}, op2.release()->AsListExpr()},
				op1->GetType());
			return true;
			}
		}

	if ( op1->GetType()->Tag() == zeek::TYPE_RECORD &&
	     op2->GetType()->Tag() == zeek::TYPE_RECORD )
		{
		if ( same_type(op1->GetType(), op2->GetType()) )
			{
			RecordType* rt1 = op1->GetType()->AsRecordType();
			RecordType* rt2 = op2->GetType()->AsRecordType();

			// Make sure the attributes match as well.
			for ( int i = 0; i < rt1->NumFields(); ++i )
				{
				const TypeDecl* td1 = rt1->FieldDecl(i);
				const TypeDecl* td2 = rt2->FieldDecl(i);

				if ( same_attrs(td1->attrs.get(), td2->attrs.get()) )
					// Everything matches.
					return true;
				}
			}

		// Need to coerce.
		op2 = zeek::make_intrusive<RecordCoerceExpr>(std::move(op2), op1->GetType<RecordType>());
		return true;
		}

	if ( ! same_type(op1->GetType(), op2->GetType()) )
		{
		if ( bt1 == zeek::TYPE_TABLE && bt2 == zeek::TYPE_TABLE )
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
				op2 = zeek::make_intrusive<SetConstructorExpr>(
					IntrusivePtr{zeek::NewRef{}, ctor_list},
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
		ExprError(fmt("assignment of non-arithmetic value to arithmetic (%s/%s)",
				type_name(bt1), type_name(bt2)));
		return false;
		}

	if ( bt1 == zeek::TYPE_DOUBLE )
		{
		PromoteOps(zeek::TYPE_DOUBLE);
		return true;
		}

	if ( bt2 == zeek::TYPE_DOUBLE )
		{
		Warn("dangerous assignment of double to integral");
		op2 = zeek::make_intrusive<ArithCoerceExpr>(std::move(op2), bt1);
		bt2 = op2->GetType()->Tag();
		}

	if ( bt1 == zeek::TYPE_INT )
		PromoteOps(zeek::TYPE_INT);
	else
		{
		if ( bt2 == zeek::TYPE_INT )
			{
			Warn("dangerous assignment of integer to count");
			op2 = zeek::make_intrusive<ArithCoerceExpr>(std::move(op2), bt1);
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

zeek::TypePtr AssignExpr::InitType() const
	{
	if ( op1->Tag() != EXPR_LIST )
		{
		Error("bad initializer");
		return nullptr;
		}

	const auto& tl = op1->GetType();
	if ( tl->Tag() != zeek::TYPE_LIST )
		Internal("inconsistent list expr in AssignExpr::InitType");

	return zeek::make_intrusive<TableType>(
		IntrusivePtr{zeek::NewRef{}, tl->AsTypeList()},
		op2->GetType());
	}

void AssignExpr::EvalIntoAggregate(const zeek::Type* t, Val* aggr, Frame* f) const
	{
	if ( IsError() )
		return;

	TypeDecl td;

	if ( IsRecordElement(&td) )
		{
		if ( t->Tag() != zeek::TYPE_RECORD )
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
		if ( t->Tag() != zeek::TYPE_RECORD )
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

		if ( aggr->GetType()->Tag() != zeek::TYPE_RECORD )
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
		if ( t->Tag() != zeek::TYPE_TABLE )
			{
			Error("not a table initialization", t);
			return nullptr;
			}

		if ( aggr->GetType()->Tag() != zeek::TYPE_TABLE )
			Internal("bad aggregate in AssignExpr::InitVal");

		auto tv = zeek::cast_intrusive<zeek::TableVal>(std::move(aggr));
		const TableType* tt = tv->GetType()->AsTableType();
		const auto& yt = tv->GetType()->Yield();

		auto index = op1->InitVal(tt->GetIndices().get(), nullptr);
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
			td->id = copy_string(n->Id()->Name());
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
		    fmt("expression with type '%s' is not a type that can be indexed",
		        type_name(op1->GetType()->Tag()));
		SetError(error_msg.data());
		}

	else if ( ! op1->GetType()->Yield() )
		{
		if ( IsString(op1->GetType()->Tag()) && match_type == MATCHES_INDEX_SCALAR )
			SetType(base_type(zeek::TYPE_STRING));
		else
			// It's a set - so indexing it yields void.  We don't
			// directly generate an error message, though, since this
			// expression might be part of an add/delete statement,
			// rather than yielding a value.
			SetType(base_type(zeek::TYPE_VOID));
		}

	else if ( match_type == MATCHES_INDEX_SCALAR )
		SetType(op1->GetType()->Yield());

	else if ( match_type == MATCHES_INDEX_VECTOR )
		SetType(zeek::make_intrusive<zeek::VectorType>(op1->GetType()->Yield()));

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

	return op1->GetType()->Tag() == zeek::TYPE_TABLE;
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

	v1->AsTableVal()->Assign(std::move(v2), nullptr);
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

	v1->AsTableVal()->Remove(*v2);
	}

ExprPtr IndexExpr::MakeLvalue()
	{
	if ( IsString(op1->GetType()->Tag()) )
		ExprError("cannot assign to string index expression");

	return zeek::make_intrusive<RefExpr>(IntrusivePtr{zeek::NewRef{}, this});
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
		auto v_result = zeek::make_intrusive<zeek::VectorVal>(GetType<zeek::VectorType>());

		// Booleans select each element (or not).
		if ( IsBool(v_v2->GetType()->Yield()->Tag()) )
			{
			if ( v_v1->Size() != v_v2->Size() )
				{
				RuntimeError("size mismatch, boolean index and vector");
				return nullptr;
				}

			for ( unsigned int i = 0; i < v_v2->Size(); ++i )
				{
				if ( v_v2->At(i)->AsBool() )
					v_result->Assign(v_result->Size() + 1, v_v1->At(i));
				}
			}
		else
			{ // The elements are indices.
			// ### Should handle negative indices here like
			// S does, i.e., by excluding those elements.
			// Probably only do this if *all* are negative.
			v_result->Resize(v_v2->Size());
			for ( unsigned int i = 0; i < v_v2->Size(); ++i )
				v_result->Assign(i, v_v1->At(v_v2->At(i)->CoerceToInt()));
			}

		return v_result;
		}
	else
		return Fold(v1.get(), v2.get());
	}

static int get_slice_index(int idx, int len)
	{
	if ( abs(idx) > len )
		idx = idx > 0 ? len : 0; // Clamp maximum positive/negative indices.
	else if ( idx < 0 )
		idx += len;  // Map to a positive index.

	return idx;
	}

ValPtr IndexExpr::Fold(Val* v1, Val* v2) const
	{
	if ( IsError() )
		return nullptr;

	ValPtr v;

	switch ( v1->GetType()->Tag() ) {
	case zeek::TYPE_VECTOR:
		{
		VectorVal* vect = v1->AsVectorVal();
		const ListVal* lv = v2->AsListVal();

		if ( lv->Length() == 1 )
			v = vect->At(lv->Idx(0)->CoerceToUnsigned());
		else
			{
			size_t len = vect->Size();
			auto result = zeek::make_intrusive<zeek::VectorVal>(vect->GetType<zeek::VectorType>());

			bro_int_t first = get_slice_index(lv->Idx(0)->CoerceToInt(), len);
			bro_int_t last = get_slice_index(lv->Idx(1)->CoerceToInt(), len);
			bro_int_t sub_length = last - first;

			if ( sub_length >= 0 )
				{
				result->Resize(sub_length);

				for ( int idx = first; idx < last; idx++ )
					result->Assign(idx - first, vect->At(idx));
				}

			return result;
			}
		}
		break;

	case zeek::TYPE_TABLE:
		v = v1->AsTableVal()->FindOrDefault({zeek::NewRef{}, v2}); // Then, we jump into the TableVal here.
		break;

	case zeek::TYPE_STRING:
		{
		const ListVal* lv = v2->AsListVal();
		const String* s = v1->AsString();
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

		return zeek::make_intrusive<zeek::StringVal>(substring ? substring : new String(""));
		}

	default:
		RuntimeError("type cannot be indexed");
		break;
	}

	if ( v )
		return v;

	RuntimeError("no such index");
	return nullptr;
	}

void IndexExpr::Assign(Frame* f, ValPtr v)
	{
	if ( IsError() )
		return;

	auto v1 = op1->Eval(f);

	if ( ! v1 )
		return;

	auto v2 = op2->Eval(f);

	if ( ! v1 || ! v2 )
		return;

	// Hold an extra reference to 'arg_v' in case the ownership transfer to
	// the table/vector goes wrong and we still want to obtain diagnostic info
	// from the original value after the assignment already unref'd.
	auto v_extra = v;

	switch ( v1->GetType()->Tag() ) {
	case zeek::TYPE_VECTOR:
		{
		const ListVal* lv = v2->AsListVal();
		VectorVal* v1_vect = v1->AsVectorVal();

		if ( lv->Length() > 1 )
			{
			auto len = v1_vect->Size();
			bro_int_t first = get_slice_index(lv->Idx(0)->CoerceToInt(), len);
			bro_int_t last = get_slice_index(lv->Idx(1)->CoerceToInt(), len);

			// Remove the elements from the vector within the slice
			for ( auto idx = first; idx < last; idx++ )
				v1_vect->Remove(first);

			// Insert the new elements starting at the first position
			VectorVal* v_vect = v->AsVectorVal();

			for ( auto idx = 0u; idx < v_vect->Size(); idx++, first++ )
				v1_vect->Insert(first, v_vect->At(idx));
			}
		else if ( ! v1_vect->Assign(lv->Idx(0)->CoerceToUnsigned(), std::move(v)) )
			{
			v = std::move(v_extra);

			if ( v )
				{
				ODesc d;
				v->Describe(&d);
				const auto& vt = v->GetType();
				auto vtt = vt->Tag();
				std::string tn = vtt == zeek::TYPE_RECORD ? vt->GetName() : type_name(vtt);
				RuntimeErrorWithCallStack(fmt(
				  "vector index assignment failed for invalid type '%s', value: %s",
				  tn.data(), d.Description()));
				}
			else
				RuntimeErrorWithCallStack("assignment failed with null value");
			}
		break;
		}

	case zeek::TYPE_TABLE:
		if ( ! v1->AsTableVal()->Assign(std::move(v2), std::move(v)) )
			{
			v = std::move(v_extra);

			if ( v )
				{
				ODesc d;
				v->Describe(&d);
				const auto& vt = v->GetType();
				auto vtt = vt->Tag();
				std::string tn = vtt == zeek::TYPE_RECORD ? vt->GetName() : type_name(vtt);
				RuntimeErrorWithCallStack(fmt(
				  "table index assignment failed for invalid type '%s', value: %s",
				  tn.data(), d.Description()));
				}
			else
				RuntimeErrorWithCallStack("assignment failed with null value");
			}
		break;

	case zeek::TYPE_STRING:
		RuntimeErrorWithCallStack("assignment via string index accessor not allowed");
		break;

	default:
		RuntimeErrorWithCallStack("bad index expression type in assignment");
		break;
	}
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

TraversalCode IndexExpr::Traverse(TraversalCallback* cb) const
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

FieldExpr::FieldExpr(ExprPtr arg_op, const char* arg_field_name)
	: UnaryExpr(EXPR_FIELD, std::move(arg_op)),
	  field_name(copy_string(arg_field_name)), td(nullptr), field(0)
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
	return zeek::make_intrusive<RefExpr>(IntrusivePtr{zeek::NewRef{}, this});
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

		SetType(base_type(zeek::TYPE_BOOL));
		}
	}

HasFieldExpr::~HasFieldExpr()
	{
	delete field_name;
	}

ValPtr HasFieldExpr::Fold(Val* v) const
	{
	auto rv = v->AsRecordVal();
	return zeek::val_mgr->Bool(rv->GetField(field) != nullptr);
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
	: UnaryExpr(EXPR_RECORD_CONSTRUCTOR, std::move(constructor_list))
	{
	if ( IsError() )
		return;

	// Spin through the list, which should be comprised only of
	// record-field-assign expressions, and build up a
	// record type to associate with this constructor.
	const expr_list& exprs = op->AsListExpr()->Exprs();
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
		char* field_name = copy_string(field->FieldName());
		record_types->push_back(new TypeDecl(field_name, field_type));
		}

	SetType(zeek::make_intrusive<RecordType>(record_types));
	}

RecordConstructorExpr::~RecordConstructorExpr()
	{
	}

ValPtr RecordConstructorExpr::InitVal(const zeek::Type* t, ValPtr aggr) const
	{
	auto v = Eval(nullptr);

	if ( v )
		{
		RecordVal* rv = v->AsRecordVal();
		auto bt = const_cast<zeek::Type*>(t);
		RecordTypePtr rt{zeek::NewRef{}, bt->AsRecordType()};
		auto aggr_rec = zeek::cast_intrusive<zeek::RecordVal>(std::move(aggr));
		auto ar = rv->CoerceTo(std::move(rt), std::move(aggr_rec));

		if ( ar )
			return ar;
		}

	Error("bad record initializer");
	return nullptr;
	}

ValPtr RecordConstructorExpr::Fold(Val* v) const
	{
	ListVal* lv = v->AsListVal();
	auto rt = zeek::cast_intrusive<RecordType>(type);

	if ( lv->Length() != rt->NumFields() )
		RuntimeErrorWithCallStack("inconsistency evaluating record constructor");

	auto rv = zeek::make_intrusive<zeek::RecordVal>(std::move(rt));

	for ( int i = 0; i < lv->Length(); ++i )
		rv->Assign(i, lv->Idx(i));

	return rv;
	}

void RecordConstructorExpr::ExprDescribe(ODesc* d) const
	{
	d->Add("[");
	op->Describe(d);
	d->Add("]");
	}

TableConstructorExpr::TableConstructorExpr(ListExprPtr constructor_list,
                                           std::unique_ptr<std::vector<AttrPtr>> arg_attrs,
                                           zeek::TypePtr arg_type)
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
			SetType(zeek::make_intrusive<TableType>(zeek::make_intrusive<TypeList>(base_type(zeek::TYPE_ANY)), nullptr));
		else
			{
			SetType(init_type(op.get()));

			if ( ! type )
				SetError();

			else if ( type->Tag() != zeek::TYPE_TABLE ||
				  type->AsTableType()->IsSet() )
				SetError("values in table(...) constructor do not specify a table");
			}
		}

	if ( arg_attrs )
		attrs = zeek::make_intrusive<Attributes>(std::move(*arg_attrs), type, false, false);

	const auto& indices = type->AsTableType()->GetIndices()->GetTypes();
	const expr_list& cle = op->AsListExpr()->Exprs();

	// check and promote all index expressions in ctor list
	for ( const auto& expr : cle )
		{
		if ( expr->Tag() != EXPR_ASSIGN )
			continue;

		Expr* idx_expr = expr->AsAssignExpr()->Op1();

		if ( idx_expr->Tag() != EXPR_LIST )
			continue;

		expr_list& idx_exprs = idx_expr->AsListExpr()->Exprs();

		if ( idx_exprs.length() != static_cast<int>(indices.size()) )
			continue;

		loop_over_list(idx_exprs, j)
			{
			Expr* idx = idx_exprs[j];

			auto promoted_idx = check_and_promote_expr(idx, indices[j].get());

			if ( promoted_idx )
				{
				if ( promoted_idx.get() != idx )
					{
					Unref(idx);
					idx_exprs.replace(j, promoted_idx.release());
					}

				continue;
				}

			ExprError("inconsistent types in table constructor");
			}
		}
	}

ValPtr TableConstructorExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return nullptr;

	auto aggr = zeek::make_intrusive<zeek::TableVal>(GetType<TableType>(), attrs);
	const expr_list& exprs = op->AsListExpr()->Exprs();

	for ( const auto& expr : exprs )
		expr->EvalIntoAggregate(type.get(), aggr.get(), f);

	aggr->InitDefaultFunc(f);

	return aggr;
	}

ValPtr TableConstructorExpr::InitVal(const zeek::Type* t, ValPtr aggr) const
	{
	if ( IsError() )
		return nullptr;

	auto tt = GetType<TableType>();

	auto tval = aggr ?
	        TableValPtr{zeek::AdoptRef{}, aggr.release()->AsTableVal()} :
	zeek::make_intrusive<zeek::TableVal>(std::move(tt), attrs);
	const expr_list& exprs = op->AsListExpr()->Exprs();

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
                                       zeek::TypePtr arg_type)
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
			SetType(zeek::make_intrusive<zeek::SetType>(zeek::make_intrusive<zeek::TypeList>(zeek::base_type(zeek::TYPE_ANY)), nullptr));
		else
			SetType(init_type(op.get()));
		}

	if ( ! type )
		SetError();

	else if ( type->Tag() != zeek::TYPE_TABLE || ! type->AsTableType()->IsSet() )
		SetError("values in set(...) constructor do not specify a set");

	if ( arg_attrs )
		attrs = zeek::make_intrusive<Attributes>(std::move(*arg_attrs), type, false, false);

	const auto& indices = type->AsTableType()->GetIndices()->GetTypes();
	expr_list& cle = op->AsListExpr()->Exprs();

	if ( indices.size() == 1 )
		{
		if ( ! check_and_promote_exprs_to_type(op->AsListExpr(),
		                                       indices[0].get()) )
			ExprError("inconsistent type in set constructor");
		}

	else if ( indices.size() > 1 )
		{
		// Check/promote each expression in composite index.
		loop_over_list(cle, i)
			{
			Expr* ce = cle[i];
			ListExpr* le = ce->AsListExpr();

			if ( ce->Tag() == EXPR_LIST &&
			     check_and_promote_exprs(le, type->AsTableType()->GetIndices().get()) )
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

	auto aggr = zeek::make_intrusive<zeek::TableVal>(IntrusivePtr{zeek::NewRef{}, type->AsTableType()},
	                                     attrs);
	const expr_list& exprs = op->AsListExpr()->Exprs();

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

	const auto& index_type = t->AsTableType()->GetIndices();
	auto tt = GetType<TableType>();
	auto tval = aggr ?
	        TableValPtr{zeek::AdoptRef{}, aggr.release()->AsTableVal()} :
	zeek::make_intrusive<zeek::TableVal>(std::move(tt), attrs);
	const expr_list& exprs = op->AsListExpr()->Exprs();

	for ( const auto& e : exprs )
		{
		auto element = check_and_promote(e->Eval(nullptr), index_type.get(), true);

		if ( ! element || ! tval->Assign(std::move(element), nullptr) )
			{
			Error(fmt("initialization type mismatch in set"), e);
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
                                             zeek::TypePtr arg_type)
	: UnaryExpr(EXPR_VECTOR_CONSTRUCTOR, std::move(constructor_list))
	{
	if ( IsError() )
		return;

	if ( arg_type )
		{
		if ( arg_type->Tag() != zeek::TYPE_VECTOR )
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
			SetType(zeek::make_intrusive<zeek::VectorType>(zeek::base_type(zeek::TYPE_VOID)));
			return;
			}

		if ( auto t = merge_type_list(op->AsListExpr()) )
			SetType(zeek::make_intrusive<zeek::VectorType>(std::move(t)));
		else
			{
			SetError();
			return;
			}
		}

	if ( ! check_and_promote_exprs_to_type(op->AsListExpr(),
					       type->AsVectorType()->Yield().get()) )
		ExprError("inconsistent types in vector constructor");
	}

ValPtr VectorConstructorExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return nullptr;

	auto vec = zeek::make_intrusive<zeek::VectorVal>(GetType<zeek::VectorType>());
	const expr_list& exprs = op->AsListExpr()->Exprs();

	loop_over_list(exprs, i)
		{
		Expr* e = exprs[i];

		if ( ! vec->Assign(i, e->Eval(f)) )
			{
			RuntimeError(fmt("type mismatch at index %d", i));
			return nullptr;
			}
		}

	return vec;
	}

ValPtr VectorConstructorExpr::InitVal(const zeek::Type* t, ValPtr aggr) const
	{
	if ( IsError() )
		return nullptr;

	auto vt = GetType<zeek::VectorType>();
	auto vec = aggr ?
	        VectorValPtr{zeek::AdoptRef{}, aggr.release()->AsVectorVal()} :
	zeek::make_intrusive<zeek::VectorVal>(std::move(vt));
	const expr_list& exprs = op->AsListExpr()->Exprs();

	loop_over_list(exprs, i)
		{
		Expr* e = exprs[i];
		auto v = check_and_promote(e->Eval(nullptr), t->Yield().get(), true);

		if ( ! v || ! vec->Assign(i, std::move(v)) )
			{
			Error(fmt("initialization type mismatch at index %d", i), e);
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
		td->id = copy_string(field_name.c_str());
		}

	return true;
	}

void FieldAssignExpr::ExprDescribe(ODesc* d) const
	{
	d->Add("$");
	d->Add(FieldName());
	d->Add("=");
	op->Describe(d);
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
		SetType(zeek::make_intrusive<zeek::VectorType>(zeek::base_type(t)));
		vbt = op->GetType()->AsVectorType()->Yield()->Tag();
		}
	else
		SetType(zeek::base_type(t));

	if ( (bt == zeek::TYPE_ENUM) != (t == zeek::TYPE_ENUM) )
		ExprError("can't convert to/from enumerated type");

	else if ( ! IsArithmetic(t) && ! IsBool(t) &&
		  t != zeek::TYPE_TIME && t != zeek::TYPE_INTERVAL )
		ExprError("bad coercion");

	else if ( ! IsArithmetic(bt) && ! IsBool(bt) &&
		  ! IsArithmetic(vbt) && ! IsBool(vbt) )
		ExprError("bad coercion value");
	}

ValPtr ArithCoerceExpr::FoldSingleVal(Val* v, InternalTypeTag t) const
	{
	switch ( t ) {
	case zeek::TYPE_INTERNAL_DOUBLE:
		return zeek::make_intrusive<zeek::DoubleVal>(v->CoerceToDouble());

	case zeek::TYPE_INTERNAL_INT:
		return zeek::val_mgr->Int(v->CoerceToInt());

	case zeek::TYPE_INTERNAL_UNSIGNED:
		return zeek::val_mgr->Count(v->CoerceToUnsigned());

	default:
		RuntimeErrorWithCallStack("bad type in CoerceExpr::Fold");
		return nullptr;
	}
	}

ValPtr ArithCoerceExpr::Fold(Val* v) const
	{
	InternalTypeTag t = type->InternalType();

	if ( ! is_vector(v) )
		{
		// Our result type might be vector, in which case this
		// invocation is being done per-element rather than on
		// the whole vector.  Correct the type tag if necessary.
		if ( type->Tag() == zeek::TYPE_VECTOR )
			t = GetType()->AsVectorType()->Yield()->InternalType();

		return FoldSingleVal(v, t);
		}

	t = GetType()->AsVectorType()->Yield()->InternalType();

	VectorVal* vv = v->AsVectorVal();
	auto result = zeek::make_intrusive<zeek::VectorVal>(GetType<zeek::VectorType>());

	for ( unsigned int i = 0; i < vv->Size(); ++i )
		{
		if ( const auto& elt = vv->At(i) )
			result->Assign(i, FoldSingleVal(elt.get(), t));
		else
			result->Assign(i, nullptr);
		}

	return result;
	}

RecordCoerceExpr::RecordCoerceExpr(ExprPtr arg_op, zeek::RecordTypePtr r)
	: UnaryExpr(EXPR_RECORD_COERCE, std::move(arg_op)),
	  map(nullptr), map_size(0)
	{
	if ( IsError() )
		return;

	SetType(std::move(r));

	if ( GetType()->Tag() != zeek::TYPE_RECORD )
		ExprError("coercion to non-record");

	else if ( op->GetType()->Tag() != zeek::TYPE_RECORD )
		ExprError("coercion of non-record to record");

	else
		{
		RecordType* t_r = type->AsRecordType();
		RecordType* sub_r = op->GetType()->AsRecordType();

		map_size = t_r->NumFields();
		map = new int[map_size];

		int i;
		for ( i = 0; i < map_size; ++i )
			map[i] = -1;	// -1 = field is not mapped

		for ( i = 0; i < sub_r->NumFields(); ++i )
			{
			int t_i = t_r->FieldOffset(sub_r->FieldName(i));
			if ( t_i < 0 )
				{
				ExprError(fmt("orphaned field \"%s\" in record coercion",
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

					if ( sub_tag == zeek::TYPE_DOUBLE && IsIntegral(sup_tag) )
						return false;

					if ( sub_tag == zeek::TYPE_INT && sup_tag == zeek::TYPE_COUNT )
						return false;

					return true;
					};

				auto is_record_promotable = [](zeek::Type* sup, zeek::Type* sub) -> bool
					{
					if ( sup->Tag() != zeek::TYPE_RECORD )
						return false;

					if ( sub->Tag() != zeek::TYPE_RECORD )
						return false;

					return record_promotion_compatible(sup->AsRecordType(),
					                                   sub->AsRecordType());
					};

				if ( ! is_arithmetic_promotable(sup_t_i.get(), sub_t_i.get()) &&
				     ! is_record_promotable(sup_t_i.get(), sub_t_i.get()) )
					{
					std::string error_msg = fmt(
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
					std::string error_msg = fmt(
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

RecordCoerceExpr::~RecordCoerceExpr()
	{
	delete [] map;
	}

ValPtr RecordCoerceExpr::InitVal(const zeek::Type* t, ValPtr aggr) const
	{
	if ( auto v = Eval(nullptr) )
		{
		RecordVal* rv = v->AsRecordVal();
		auto bt = const_cast<zeek::Type*>(t);
		zeek::RecordTypePtr rt{zeek::NewRef{}, bt->AsRecordType()};
		auto aggr_rec = zeek::cast_intrusive<zeek::RecordVal>(std::move(aggr));

		if ( auto ar = rv->CoerceTo(std::move(rt), std::move(aggr_rec)) )
			return ar;
		}

	Error("bad record initializer");
	return nullptr;
	}

ValPtr RecordCoerceExpr::Fold(Val* v) const
	{
	auto val = zeek::make_intrusive<zeek::RecordVal>(GetType<RecordType>());
	RecordType* val_type = val->GetType()->AsRecordType();

	RecordVal* rv = v->AsRecordVal();

	for ( int i = 0; i < map_size; ++i )
		{
		if ( map[i] >= 0 )
			{
			auto rhs = rv->GetField(map[i]);

			if ( ! rhs )
				{
				const auto& def = rv->GetType()->AsRecordType()->FieldDecl(
					map[i])->GetAttr(ATTR_DEFAULT);

				if ( def )
					rhs = def->GetExpr()->Eval(nullptr);
				}

			assert(rhs || GetType()->AsRecordType()->FieldDecl(i)->GetAttr(ATTR_OPTIONAL));

			if ( ! rhs )
				{
				// Optional field is missing.
				val->Assign(i, nullptr);
				continue;
				}

			const auto& rhs_type = rhs->GetType();
			const auto& field_type = val_type->GetFieldType(i);

			if ( rhs_type->Tag() == zeek::TYPE_RECORD &&
			     field_type->Tag() == zeek::TYPE_RECORD &&
			     ! same_type(rhs_type, field_type) )
				{
				if ( auto new_val = rhs->AsRecordVal()->CoerceTo(zeek::cast_intrusive<RecordType>(field_type)) )
					rhs = std::move(new_val);
				}
			else if ( BothArithmetic(rhs_type->Tag(), field_type->Tag()) &&
			          ! same_type(rhs_type, field_type) )
				{
				if ( auto new_val = check_and_promote(rhs, field_type.get(), false, op->GetLocationInfo()) )
					rhs = std::move(new_val);
				else
					RuntimeError("Failed type conversion");
				}

			val->Assign(i, std::move(rhs));
			}
		else
			{
			if ( const auto& def = GetType()->AsRecordType()->FieldDecl(i)->GetAttr(ATTR_DEFAULT) )
				{
				auto def_val = def->GetExpr()->Eval(nullptr);
				const auto& def_type = def_val->GetType();
				const auto& field_type = GetType()->AsRecordType()->GetFieldType(i);

				if ( def_type->Tag() == zeek::TYPE_RECORD &&
				     field_type->Tag() == zeek::TYPE_RECORD &&
				     ! same_type(def_type, field_type) )
					{
					auto tmp = def_val->AsRecordVal()->CoerceTo(
					        zeek::cast_intrusive<RecordType>(field_type));

					if ( tmp )
						def_val = std::move(tmp);
					}

				val->Assign(i, std::move(def_val));
				}
			else
				val->Assign(i, nullptr);
			}
		}

	return val;
	}

TableCoerceExpr::TableCoerceExpr(ExprPtr arg_op, zeek::TableTypePtr r)
	: UnaryExpr(EXPR_TABLE_COERCE, std::move(arg_op))
	{
	if ( IsError() )
		return;

	SetType(std::move(r));

	if ( GetType()->Tag() != zeek::TYPE_TABLE )
		ExprError("coercion to non-table");

	else if ( op->GetType()->Tag() != zeek::TYPE_TABLE )
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

	return zeek::make_intrusive<zeek::TableVal>(GetType<TableType>(), tv->GetAttrs());
	}

VectorCoerceExpr::VectorCoerceExpr(ExprPtr arg_op, zeek::VectorTypePtr v)
	: UnaryExpr(EXPR_VECTOR_COERCE, std::move(arg_op))
	{
	if ( IsError() )
		return;

	SetType(std::move(v));

	if ( GetType()->Tag() != zeek::TYPE_VECTOR )
		ExprError("coercion to non-vector");

	else if ( op->GetType()->Tag() != zeek::TYPE_VECTOR )
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

	return zeek::make_intrusive<zeek::VectorVal>(GetType<zeek::VectorType>());
	}

ScheduleTimer::ScheduleTimer(const EventHandlerPtr& arg_event, zeek::Args arg_args,
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
		mgr.Enqueue(event, std::move(args));
	}

ScheduleExpr::ScheduleExpr(ExprPtr arg_when, EventExprPtr arg_event)
	: Expr(EXPR_SCHEDULE),
	  when(std::move(arg_when)), event(std::move(arg_event))
	{
	if ( IsError() || when->IsError() || event->IsError() )
		return;

	TypeTag bt = when->GetType()->Tag();

	if ( bt != zeek::TYPE_TIME && bt != zeek::TYPE_INTERVAL )
		ExprError("schedule expression requires a time or time interval");
	else
		SetType(zeek::base_type(zeek::TYPE_TIMER));
	}

bool ScheduleExpr::IsPure() const
	{
	return false;
	}

ValPtr ScheduleExpr::Eval(Frame* f) const
	{
	if ( terminating )
		return nullptr;

	auto when_val = when->Eval(f);

	if ( ! when_val )
		return nullptr;

	double dt = when_val->InternalDouble();

	if ( when->GetType()->Tag() == zeek::TYPE_INTERVAL )
		dt += network_time;

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

	if ( op1->GetType()->Tag() == zeek::TYPE_PATTERN )
		{
		if ( op2->GetType()->Tag() != zeek::TYPE_STRING )
			{
			op2->GetType()->Error("pattern requires string index", op1.get());
			SetError();
			}
		else
			SetType(zeek::base_type(zeek::TYPE_BOOL));
		}

	else if ( op1->GetType()->Tag() == zeek::TYPE_RECORD )
		{
		if ( op2->GetType()->Tag() != zeek::TYPE_TABLE )
			{
			op2->GetType()->Error("table/set required");
			SetError();
			}

		else
			{
			const auto& t1 = op1->GetType();
			const auto& it = op2->GetType()->AsTableType()->GetIndices();

			if ( ! same_type(t1, it) )
				{
				t1->Error("indexing mismatch", op2->GetType().get());
				SetError();
				}
			else
				SetType(zeek::base_type(zeek::TYPE_BOOL));
			}
		}

	else if ( op1->GetType()->Tag() == zeek::TYPE_STRING &&
		  op2->GetType()->Tag() == zeek::TYPE_STRING )
		SetType(zeek::base_type(zeek::TYPE_BOOL));

	else
		{
		// Check for:	<addr> in <subnet>
		//		<addr> in set[subnet]
		//		<addr> in table[subnet] of ...
		if ( op1->GetType()->Tag() == zeek::TYPE_ADDR )
			{
			if ( op2->GetType()->Tag() == zeek::TYPE_SUBNET )
				{
				SetType(zeek::base_type(zeek::TYPE_BOOL));
				return;
				}

			if ( op2->GetType()->Tag() == zeek::TYPE_TABLE &&
			     op2->GetType()->AsTableType()->IsSubNetIndex() )
				{
				SetType(zeek::base_type(zeek::TYPE_BOOL));
				return;
				}
			}

		if ( op1->Tag() != EXPR_LIST )
			op1 = zeek::make_intrusive<ListExpr>(std::move(op1));

		ListExpr* lop1 = op1->AsListExpr();

		if ( ! op2->GetType()->MatchesIndex(lop1) )
			SetError("not an index type");
		else
			SetType(zeek::base_type(zeek::TYPE_BOOL));
		}
	}

ValPtr InExpr::Fold(Val* v1, Val* v2) const
	{
	if ( v1->GetType()->Tag() == zeek::TYPE_PATTERN )
		{
		RE_Matcher* re = v1->AsPattern();
		const String* s = v2->AsString();
		return zeek::val_mgr->Bool(re->MatchAnywhere(s) != 0);
		}

	if ( v2->GetType()->Tag() == zeek::TYPE_STRING )
		{
		const String* s1 = v1->AsString();
		const String* s2 = v2->AsString();

		// Could do better here e.g. Boyer-Moore if done repeatedly.
		auto s = reinterpret_cast<const unsigned char*>(s1->CheckString());
		auto res = strstr_n(s2->Len(), s2->Bytes(), s1->Len(), s) != -1;
		return zeek::val_mgr->Bool(res);
		}

	if ( v1->GetType()->Tag() == zeek::TYPE_ADDR &&
	     v2->GetType()->Tag() == zeek::TYPE_SUBNET )
		return zeek::val_mgr->Bool(v2->AsSubNetVal()->Contains(v1->AsAddr()));

	bool res;

	if ( is_vector(v2) )
		res = (bool)v2->AsVectorVal()->At(v1->AsListVal()->Idx(0)->CoerceToUnsigned());
	else
		res = (bool)v2->AsTableVal()->Find({zeek::NewRef{}, v1});

	return zeek::val_mgr->Bool(res);
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
		     streq(((NameExpr*) func.get())->Id()->Name(), "fmt") &&
		     // The following is needed because fmt might not yet
		     // be bound as a name.
		     did_builtin_init &&
		     (func_val = func->Eval(nullptr)) )
			{
			zeek::Func* f = func_val->AsFunc();
			if ( f->GetKind() == zeek::Func::BUILTIN_FUNC &&
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

	if ( f->GetKind() == zeek::Func::BUILTIN_FUNC )
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
				return {zeek::NewRef{}, v};
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
                       id_list arg_outer_ids) : Expr(EXPR_LAMBDA)
	{
	ingredients = std::move(arg_ing);
	outer_ids = std::move(arg_outer_ids);

	SetType(ingredients->id->GetType());

	// Install a dummy version of the function globally for use only
	// when broker provides a closure.
	auto dummy_func = zeek::make_intrusive<ScriptFunc>(
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
			// Just try again to make a unique lambda name.  If two peer
			// processes need to agree on the same lambda name, this assumes
			// they're loading the same scripts and thus have the same hash
			// collisions.
			d.Add(" ");
		else
			break;
		}

	// Install that in the global_scope
	auto id = install_ID(my_name.c_str(), current_module.c_str(), true, false);

	// Update lamb's name
	dummy_func->SetName(my_name.c_str());

	auto v = zeek::make_intrusive<zeek::Val>(std::move(dummy_func));
	id->SetVal(std::move(v));
	id->SetType(ingredients->id->GetType());
	id->SetConst();
	}

Scope* LambdaExpr::GetScope() const
	{
	return ingredients->scope.get();
	}

ValPtr LambdaExpr::Eval(Frame* f) const
	{
	auto lamb = zeek::make_intrusive<ScriptFunc>(
		ingredients->id,
		ingredients->body,
		ingredients->inits,
		ingredients->frame_size,
		ingredients->priority);

	lamb->AddClosure(outer_ids, f);

	// Set name to corresponding dummy func.
	// Allows for lookups by the receiver.
	lamb->SetName(my_name.c_str());

	return zeek::make_intrusive<zeek::Val>(std::move(lamb));
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
		mgr.Enqueue(handler, std::move(*v));

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
	SetType(zeek::make_intrusive<TypeList>());
	}

ListExpr::ListExpr(ExprPtr e) : Expr(EXPR_LIST)
	{
	SetType(zeek::make_intrusive<TypeList>());
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
	auto v = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_ANY);

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

zeek::TypePtr ListExpr::InitType() const
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


		return zeek::make_intrusive<RecordType>(types);
		}

	else
		{
		auto tl = zeek::make_intrusive<TypeList>();

		for ( const auto& e : exprs )
			{
			const auto& ti = e->GetType();

			// Collapse any embedded sets or lists.
			if ( ti->IsSet() || ti->Tag() == zeek::TYPE_LIST )
				{
				TypeList* til = ti->IsSet() ?
					ti->AsSetType()->GetIndices().get() :
					ti->AsTypeList();

				if ( ! til->IsPure() ||
				     ! til->AllMatch(til->GetPureType(), true) )
					tl->Append({zeek::NewRef{}, til});
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
		auto v = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_ANY);
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

	if ( t->Tag() == zeek::TYPE_LIST )
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

		auto v = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_ANY);

		loop_over_list(exprs, i)
			{
			auto vi = exprs[i]->InitVal(tl[i].get(), nullptr);

			if ( ! vi )
				return nullptr;

			v->Append(std::move(vi));
			}

		return v;
		}

	if ( t->Tag() != zeek::TYPE_RECORD && t->Tag() != zeek::TYPE_TABLE &&
	     t->Tag() != zeek::TYPE_VECTOR )
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

	if ( t->Tag() == zeek::TYPE_VECTOR )
		{
		// v: vector = [10, 20, 30];
		VectorVal* vec = aggr->AsVectorVal();

		loop_over_list(exprs, i)
			{
			Expr* e = exprs[i];
			const auto& vyt = vec->GetType()->AsVectorType()->Yield();
			auto promoted_e = check_and_promote_expr(e, vyt.get());

			if ( promoted_e )
				e = promoted_e.get();

			if ( ! vec->Assign(i, e->Eval(nullptr)) )
				{
				e->Error(fmt("type mismatch at index %d", i));
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
			if ( t->Tag() == zeek::TYPE_RECORD )
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
	if ( aggr->GetType()->Tag() != zeek::TYPE_TABLE )
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
		else if ( expr->GetType()->Tag() == zeek::TYPE_LIST )
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

		if ( expr->GetType()->Tag() == zeek::TYPE_LIST )
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

	return zeek::make_intrusive<RefExpr>(IntrusivePtr{zeek::NewRef{}, this});
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
	const expr_list& inits = init_list->AsListExpr()->Exprs();

	RecordType* lhs = record->GetType()->AsRecordType();

	// The inits have two forms:
	// 1) other records -- use all matching field names+types
	// 2) a string indicating the field name, then (as the next element)
	//    the value to use for that field.

	for ( const auto& init : inits )
		{
		if ( init->GetType()->Tag() == zeek::TYPE_RECORD )
			{
			RecordType* t = init->GetType()->AsRecordType();

			for ( int j = 0; j < t->NumFields(); ++j )
				{
				const char* field_name = t->FieldName(j);
				int field = lhs->FieldOffset(field_name);

				if ( field >= 0 &&
				     same_type(lhs->GetFieldType(field), t->GetFieldType(j)) )
					{
					auto fe_lhs = zeek::make_intrusive<FieldExpr>(record, field_name);
					auto fe_rhs = zeek::make_intrusive<FieldExpr>(IntrusivePtr{zeek::NewRef{}, init}, field_name);
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
				auto fe_lhs = zeek::make_intrusive<FieldExpr>(record, field_name);
				ExprPtr fe_rhs = {zeek::NewRef{}, rf->Op()};
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

CastExpr::CastExpr(ExprPtr arg_op, zeek::TypePtr t)
	: UnaryExpr(EXPR_CAST, std::move(arg_op))
	{
	auto stype = Op()->GetType();

	SetType(std::move(t));

	if ( ! can_cast_value_to_type(stype.get(), GetType().get()) )
		ExprError("cast not supported");
	}

ValPtr CastExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return nullptr;

	auto v = op->Eval(f);

	if ( ! v )
		return nullptr;

	auto nv = cast_value_to_type(v.get(), GetType().get());

	if ( nv )
		return nv;

	ODesc d;
	d.Add("invalid cast of value with type '");
	v->GetType()->Describe(&d);
	d.Add("' to type '");
	GetType()->Describe(&d);
	d.Add("'");

	if ( same_type(v->GetType(), bro_broker::DataVal::ScriptDataType()) &&
		 ! v->AsRecordVal()->GetField(0) )
		d.Add(" (nil $data field)");

	RuntimeError(d.Description());
	return nullptr;  // not reached.
	}

void CastExpr::ExprDescribe(ODesc* d) const
	{
	Op()->Describe(d);
	d->Add(" as ");
	GetType()->Describe(d);
	}

IsExpr::IsExpr(ExprPtr arg_op, zeek::TypePtr arg_t)
	: UnaryExpr(EXPR_IS, std::move(arg_op)), t(std::move(arg_t))
	{
	SetType(zeek::base_type(zeek::TYPE_BOOL));
	}

ValPtr IsExpr::Fold(Val* v) const
	{
	if ( IsError() )
		return nullptr;

	return zeek::val_mgr->Bool(can_cast_value_to_type(v, t.get()));
	}

void IsExpr::ExprDescribe(ODesc* d) const
	{
	Op()->Describe(d);
	d->Add(" is ");
	t->Describe(d);
	}

ExprPtr get_assign_expr(ExprPtr op1, ExprPtr op2, bool is_init)
	{
	if ( op1->GetType()->Tag() == zeek::TYPE_RECORD &&
	     op2->GetType()->Tag() == zeek::TYPE_LIST )
		return zeek::make_intrusive<RecordAssignExpr>(
			std::move(op1), std::move(op2), is_init);

	else if ( op1->Tag() == EXPR_INDEX && op1->AsIndexExpr()->IsSlice() )
		return zeek::make_intrusive<IndexSliceAssignExpr>(
			std::move(op1), std::move(op2), is_init);

	else
		return zeek::make_intrusive<AssignExpr>(
			std::move(op1), std::move(op2), is_init);
	}

ExprPtr check_and_promote_expr(Expr* const e, zeek::Type* t)
	{
	const auto& et = e->GetType();
	TypeTag e_tag = et->Tag();
	TypeTag t_tag = t->Tag();

	if ( t->Tag() == zeek::TYPE_ANY )
		return {zeek::NewRef{}, e};

	if ( EitherArithmetic(t_tag, e_tag) )
		{
		if ( e_tag == t_tag )
			return {zeek::NewRef{}, e};

		if ( ! BothArithmetic(t_tag, e_tag) )
			{
			t->Error("arithmetic mixed with non-arithmetic", e);
			return nullptr;
			}

		TypeTag mt = max_type(t_tag, e_tag);
		if ( mt != t_tag )
			{
			t->Error("over-promotion of arithmetic value", e);
			return nullptr;
			}

		return zeek::make_intrusive<ArithCoerceExpr>(IntrusivePtr{zeek::NewRef{}, e}, t_tag);
		}

	if ( t->Tag() == zeek::TYPE_RECORD && et->Tag() == zeek::TYPE_RECORD )
		{
		RecordType* t_r = t->AsRecordType();
		RecordType* et_r = et->AsRecordType();

		if ( same_type(t, et) )
			{
			// Make sure the attributes match as well.
			for ( int i = 0; i < t_r->NumFields(); ++i )
				{
				const TypeDecl* td1 = t_r->FieldDecl(i);
				const TypeDecl* td2 = et_r->FieldDecl(i);

				if ( same_attrs(td1->attrs.get(), td2->attrs.get()) )
					// Everything matches perfectly.
					return {zeek::NewRef{}, e};
				}
			}

		if ( record_promotion_compatible(t_r, et_r) )
			return zeek::make_intrusive<RecordCoerceExpr>(
				IntrusivePtr{zeek::NewRef{}, e},
				IntrusivePtr{zeek::NewRef{}, t_r});

		t->Error("incompatible record types", e);
		return nullptr;
		}


	if ( ! same_type(t, et) )
		{
		if ( t->Tag() == zeek::TYPE_TABLE && et->Tag() == zeek::TYPE_TABLE &&
			  et->AsTableType()->IsUnspecifiedTable() )
			return zeek::make_intrusive<TableCoerceExpr>(
				IntrusivePtr{zeek::NewRef{}, e},
				IntrusivePtr{zeek::NewRef{}, t->AsTableType()});

		if ( t->Tag() == zeek::TYPE_VECTOR && et->Tag() == zeek::TYPE_VECTOR &&
		     et->AsVectorType()->IsUnspecifiedVector() )
			return zeek::make_intrusive<VectorCoerceExpr>(
				IntrusivePtr{zeek::NewRef{}, e},
				IntrusivePtr{zeek::NewRef{}, t->AsVectorType()});

		t->Error("type clash", e);
		return nullptr;
		}

	return {zeek::NewRef{}, e};
	}

bool check_and_promote_exprs(ListExpr* const elements, TypeList* types)
	{
	expr_list& el = elements->Exprs();
	const auto& tl = types->GetTypes();

	if ( tl.size() == 1 && tl[0]->Tag() == zeek::TYPE_ANY )
		return true;

	if ( el.length() != static_cast<int>(tl.size()) )
		{
		types->Error("indexing mismatch", elements);
		return false;
		}

	loop_over_list(el, i)
		{
		Expr* e = el[i];
		auto promoted_e = check_and_promote_expr(e, tl[i].get());

		if ( ! promoted_e )
			{
			e->Error("type mismatch", tl[i].get());
			return false;
			}

		if ( promoted_e.get() != e )
			{
			Unref(e);
			el.replace(i, promoted_e.release());
			}
		}

	return true;
	}

bool check_and_promote_args(ListExpr* const args, RecordType* types)
	{
	expr_list& el = args->Exprs();
	int ntypes = types->NumFields();

	// give variadic BIFs automatic pass
	if ( ntypes == 1 && types->FieldDecl(0)->type->Tag() == zeek::TYPE_ANY )
		return true;

	if ( el.length() < ntypes )
		{
		expr_list def_elements;

		// Start from rightmost parameter, work backward to fill in missing
		// arguments using &default expressions.
		for ( int i = ntypes - 1; i >= el.length(); --i )
			{
			TypeDecl* td = types->FieldDecl(i);
			const auto& def_attr = td->attrs ? td->attrs->Find(ATTR_DEFAULT).get() : nullptr;

			if ( ! def_attr )
				{
				types->Error("parameter mismatch", args);
				return false;
				}

			def_elements.push_front(def_attr->GetExpr().get());
			}

		for ( const auto& elem : def_elements )
			el.push_back(elem->Ref());
		}

	TypeList* tl = new TypeList();

	for ( int i = 0; i < types->NumFields(); ++i )
		tl->Append(types->GetFieldType(i));

	int rval = check_and_promote_exprs(args, tl);
	Unref(tl);

	return rval;
	}

bool check_and_promote_exprs_to_type(ListExpr* const elements, zeek::Type* type)
	{
	expr_list& el = elements->Exprs();

	if ( type->Tag() == zeek::TYPE_ANY )
		return true;

	loop_over_list(el, i)
		{
		Expr* e = el[i];
		auto promoted_e = check_and_promote_expr(e, type);

		if ( ! promoted_e )
			{
			e->Error("type mismatch", type);
			return false;
			}

		if ( promoted_e.get() != e )
			{
			Unref(e);
			el.replace(i, promoted_e.release());
			}
		}

	return true;
	}

std::optional<std::vector<ValPtr>> eval_list(Frame* f, const ListExpr* l)
	{
	const expr_list& e = l->Exprs();
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

}
