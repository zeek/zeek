// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "Expr.h"
#include "Event.h"
#include "Frame.h"
#include "Func.h"
#include "RE.h"
#include "Scope.h"
#include "Stmt.h"
#include "EventRegistry.h"
#include "RemoteSerializer.h"
#include "Net.h"
#include "Traverse.h"
#include "Trigger.h"
#include "IPAddr.h"

const char* expr_name(BroExprTag t)
	{
	static char errbuf[512];

	static const char* expr_names[int(NUM_EXPRS)] = {
		"name", "const",
		"(*)",
		"++", "--", "!", "+", "-",
		"+", "-", "+=", "-=", "*", "/", "%", "&&", "||",
		"<", "<=", "==", "!=", ">=", ">", "?:", "ref",
		"=", "~", "[]", "$", "?$", "[=]",
		"table()", "set()", "vector()",
		"$=", "in", "<<>>",
		"()", "event", "schedule",
		"coerce", "record_coerce", "table_coerce",
		"sizeof", "flatten"
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

Expr::Expr(BroExprTag arg_tag)
	{
	tag = arg_tag;
	type = 0;
	paren = 0;

	SetLocationInfo(&start_location, &end_location);
	}

Expr::~Expr()
	{
	Unref(type);
	}

int Expr::CanAdd() const
	{
	return 0;
	}

int Expr::CanDel() const
	{
	return 0;
	}

void Expr::Add(Frame* /* f */)
	{
	Internal("Expr::Delete called");
	}

void Expr::Delete(Frame* /* f */)
	{
	Internal("Expr::Delete called");
	}

Expr* Expr::MakeLvalue()
	{
	if ( ! IsError() )
		ExprError("can't be assigned to");
	return this;
	}

void Expr::EvalIntoAggregate(const BroType* /* t */, Val* /* aggr */,
				Frame* /* f */) const
	{
	Internal("Expr::EvalIntoAggregate called");
	}

void Expr::Assign(Frame* /* f */, Val* /* v */, Opcode /* op */)
	{
	Internal("Expr::Assign called");
	}

BroType* Expr::InitType() const
	{
	return type->Ref();
	}

int Expr::IsRecordElement(TypeDecl* /* td */) const
	{
	return 0;
	}

int Expr::IsPure() const
	{
	return 1;
	}

Val* Expr::InitVal(const BroType* t, Val* aggr) const
	{
	if ( aggr )
		{
		Error("bad initializer");
		return 0;
		}

	if ( IsError() )
		return 0;

	return check_and_promote(Eval(0), t, 1);
	}

void Expr::SetError(const char* msg)
	{
	Error(msg);
	SetError();
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

void Expr::SetType(BroType* t)
	{
	if ( ! type || type->Tag() != TYPE_ERROR )
		{
		Unref(type);
		type = t;
		}
	else
		Unref(t);
	}

void Expr::ExprError(const char msg[])
	{
	Error(msg);
	SetError();
	}

bool Expr::Serialize(SerialInfo* info) const
	{
	return SerialObj::Serialize(info);
	}

Expr* Expr::Unserialize(UnserialInfo* info, BroExprTag want)
	{
	Expr* e = (Expr*) SerialObj::Unserialize(info, SER_EXPR);

	if ( ! e )
		return 0;

	if ( want != EXPR_ANY && e->tag != want )
		{
		info->s->Error("wrong expression type");
		Unref(e);
		return 0;
		}

	return e;
	}

bool Expr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_EXPR, BroObj);

	if ( ! (SERIALIZE(char(tag)) && SERIALIZE(paren)) )
		return false;

	SERIALIZE_OPTIONAL(type);
	return true;
	}

bool Expr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroObj);

	char c;
	if ( ! (UNSERIALIZE(&c) && UNSERIALIZE(&paren)) )
		return 0;

	tag = BroExprTag(c);

	BroType* t = 0;
	UNSERIALIZE_OPTIONAL(t, BroType::Unserialize(info));
	SetType(t);
	return true;
	}


NameExpr::NameExpr(ID* arg_id, bool const_init) : Expr(EXPR_NAME)
	{
	id = arg_id;
	in_const_init = const_init;

	if ( id->AsType() )
		SetType(new TypeType(id->AsType()));
	else
		SetType(id->Type()->Ref());

	EventHandler* h = event_registry->Lookup(id->Name());
	if ( h )
		h->SetUsed();
	}

NameExpr::~NameExpr()
	{
	Unref(id);
	}

Expr* NameExpr::Simplify(SimplifyType simp_type)
	{
	if ( simp_type != SIMPLIFY_LHS && id->IsConst() )
		{
		Val* v = Eval(0);
		if ( v )
			return new ConstExpr(v);
		}

	return this;
	}

Val* NameExpr::Eval(Frame* f) const
	{
	Val* v;

	if ( id->AsType() )
		return new Val(id->AsType(), true);

	if ( id->IsGlobal() )
		v = id->ID_Val();

	else if ( f )
		v = f->NthElement(id->Offset());

	else
		// No frame - evaluating for Simplify() purposes
		return 0;

	if ( v )
		return v->Ref();
	else
		{
		Error("value used but not set");
		return 0;
		}
	}

Expr* NameExpr::MakeLvalue()
	{
	if ( id->AsType() )
		ExprError("Type name is not an lvalue");

	if ( id->IsConst() && ! in_const_init )
		ExprError("const is not a modifiable lvalue");

	return new RefExpr(this);
	}

void NameExpr::Assign(Frame* f, Val* v, Opcode op)
	{
	if ( id->IsGlobal() )
		id->SetVal(v, op);
	else
		f->SetElement(id->Offset(), v);
	}

int NameExpr::IsPure() const
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

IMPLEMENT_SERIAL(NameExpr, SER_NAME_EXPR);

bool NameExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_NAME_EXPR, Expr);

	// Write out just the name of the function if requested.
	if ( info->globals_as_names && id->IsGlobal() )
		return SERIALIZE('n') && SERIALIZE(id->Name()) &&
		       SERIALIZE(in_const_init);
	else
		return SERIALIZE('f') && id->Serialize(info) &&
		       SERIALIZE(in_const_init);
	}

bool NameExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Expr);

	char type;
	if ( ! UNSERIALIZE(&type) )
		return false;

	if ( type == 'n' )
		{
		const char* name;
		if ( ! UNSERIALIZE_STR(&name, 0) )
			return false;

		id = global_scope()->Lookup(name);
		if ( id )
			::Ref(id);
		else
			reporter->Warning("configuration changed: unserialized unknown global name from persistent state");

		delete [] name;
		}
	else
		id = ID::Unserialize(info);

	if ( ! id )
		return false;

	if ( ! UNSERIALIZE(&in_const_init) )
		return false;

	return true;
	}

ConstExpr::ConstExpr(Val* arg_val) : Expr(EXPR_CONST)
	{
	val = arg_val;

	if ( val->Type()->Tag() == TYPE_LIST && val->AsListVal()->Length() == 1 )
		{
		val = val->AsListVal()->Index(0);
		val->Ref();
		Unref(arg_val);
		}

	SetType(val->Type()->Ref());
	}

ConstExpr::~ConstExpr()
	{
	Unref(val);
	}

void ConstExpr::ExprDescribe(ODesc* d) const
	{
	val->Describe(d);
	}

Expr* ConstExpr::Simplify(SimplifyType /* simp_type */)
	{
	return this;
	}

Val* ConstExpr::Eval(Frame* /* f */) const
	{
	return Value()->Ref();
	}

TraversalCode ConstExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}

IMPLEMENT_SERIAL(ConstExpr, SER_CONST_EXPR);

bool ConstExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_CONST_EXPR, Expr);
	return val->Serialize(info);
	}

bool ConstExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Expr);
	val = Val::Unserialize(info);
	return val != 0;
	}


UnaryExpr::UnaryExpr(BroExprTag arg_tag, Expr* arg_op) : Expr(arg_tag)
	{
	op = arg_op;
	if ( op->IsError() )
		SetError();
	}

UnaryExpr::~UnaryExpr()
	{
	Unref(op);
	}

Expr* UnaryExpr::Simplify(SimplifyType simp_type)
	{
	if ( IsError() )
		return this;

	op = simplify_expr(op, simp_type);
	Canonicize();
	return DoSimplify();
	}

Val* UnaryExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return 0;

	Val* v = op->Eval(f);

	if ( ! v )
		return 0;

	if ( is_vector(v) )
		{
		VectorVal* v_op = v->AsVectorVal();
		VectorVal* result = new VectorVal(Type()->AsVectorType());

		for ( unsigned int i = 0; i < v_op->Size(); ++i )
			{
			Val* v_i = v_op->Lookup(i);
			result->Assign(i, v_i ? Fold(v_i) : 0);
			}

		Unref(v);
		return result;
		}
	else
		{
		Val* result = Fold(v);
		Unref(v);
		return result;
		}
	}

int UnaryExpr::IsPure() const
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

Expr* UnaryExpr::DoSimplify()
	{
	return this;
	}

Val* UnaryExpr::Fold(Val* v) const
	{
	return v->Ref();
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
		else if ( Tag() == EXPR_FLATTEN )
			d->Add("flatten ");
		else if ( Tag() != EXPR_REF )
			d->Add(expr_name(Tag()));
		}

	op->Describe(d);

	if ( d->IsReadable() && is_coerce )
		{
		d->Add(" to ");
		Type()->Describe(d);
		d->Add(")");
		}
	}

IMPLEMENT_SERIAL(UnaryExpr, SER_UNARY_EXPR);

bool UnaryExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_UNARY_EXPR, Expr);
	return op->Serialize(info);
	}

bool UnaryExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Expr);
	op = Expr::Unserialize(info);
	return op != 0;
	}

BinaryExpr::~BinaryExpr()
	{
	Unref(op1);
	Unref(op2);
	}

Expr* BinaryExpr::Simplify(SimplifyType /* simp_type */)
	{
	if ( IsError() )
		return this;

	SimplifyOps();

	if ( BothConst() )
		return new ConstExpr(Fold(op1->ExprVal(), op2->ExprVal()));
	else
		return DoSimplify();
	}

Val* BinaryExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return 0;

	Val* v1 = op1->Eval(f);
	if ( ! v1 )
		return 0;

	Val* v2 = op2->Eval(f);
	if ( ! v2 )
		{
		Unref(v1);
		return 0;
		}

	Val* result = 0;

	int is_vec1 = is_vector(v1);
	int is_vec2 = is_vector(v2);

	if ( is_vec1 && is_vec2 )
		{ // fold pairs of elements
		VectorVal* v_op1 = v1->AsVectorVal();
		VectorVal* v_op2 = v2->AsVectorVal();

		if ( v_op1->Size() != v_op2->Size() )
			{
			Error("vector operands are of different sizes");
			return 0;
			}

		VectorVal* v_result = new VectorVal(Type()->AsVectorType());

		for ( unsigned int i = 0; i < v_op1->Size(); ++i )
			{
			if ( v_op1->Lookup(i) && v_op2->Lookup(i) )
				v_result->Assign(i,
						 Fold(v_op1->Lookup(i),
						      v_op2->Lookup(i)));
			else
				v_result->Assign(i, 0);
			// SetError("undefined element in vector operation");
			}

		Unref(v1);
		Unref(v2);
		return v_result;
		}

	if ( is_vec1 || is_vec2 )
		{ // fold vector against scalar
		VectorVal* vv = (is_vec1 ? v1 : v2)->AsVectorVal();
		VectorVal* v_result = new VectorVal(Type()->AsVectorType());

		for ( unsigned int i = 0; i < vv->Size(); ++i )
			{
			Val* vv_i = vv->Lookup(i);
			if ( vv_i )
				v_result->Assign(i,
					 is_vec1 ?
						 Fold(vv_i, v2) : Fold(v1, vv_i));
			else
				v_result->Assign(i, 0);

			// SetError("Undefined element in vector operation");
			}

		Unref(v1);
		Unref(v2);
		return v_result;
		}

	// scalar op scalar
	result = Fold(v1, v2);

	Unref(v1);
	Unref(v2);
	return result;
	}

int BinaryExpr::IsPure() const
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

Expr* BinaryExpr::DoSimplify()
	{
	return this;
	}

void BinaryExpr::ExprDescribe(ODesc* d) const
	{
	op1->Describe(d);

	d->SP();
	if ( d->IsReadable() )
		d->AddSP(expr_name(Tag()));

	op2->Describe(d);
	}

void BinaryExpr::SimplifyOps()
	{
	op1 = simplify_expr(op1, SIMPLIFY_GENERAL);
	op2 = simplify_expr(op2, SIMPLIFY_GENERAL);
	Canonicize();
	}

Val* BinaryExpr::Fold(Val* v1, Val* v2) const
	{
	InternalTypeTag it = v1->Type()->InternalType();

	if ( it == TYPE_INTERNAL_STRING )
		return StringFold(v1, v2);

	if ( it == TYPE_INTERNAL_ADDR )
		return AddrFold(v1, v2);

	if ( it == TYPE_INTERNAL_SUBNET )
		return SubNetFold(v1, v2);

	bro_int_t i1 = 0, i2 = 0, i3 = 0;
	bro_uint_t u1 = 0, u2 = 0, u3 = 0;
	double d1 = 0.0, d2 = 0.0, d3 = 0.0;
	int is_integral = 0;
	int is_unsigned = 0;

	if ( it == TYPE_INTERNAL_INT )
		{
		i1 = v1->InternalInt();
		i2 = v2->InternalInt();
		++is_integral;
		}
	else if ( it == TYPE_INTERNAL_UNSIGNED )
		{
		u1 = v1->InternalUnsigned();
		u2 = v2->InternalUnsigned();
		++is_unsigned;
		}
	else if ( it == TYPE_INTERNAL_DOUBLE )
		{
		d1 = v1->InternalDouble();
		d2 = v2->InternalDouble();
		}
	else
		Internal("bad type in BinaryExpr::Fold");

	switch ( tag ) {
#define DO_INT_FOLD(op) \
	if ( is_integral ) \
		i3 = i1 op i2; \
	else if ( is_unsigned ) \
		u3 = u1 op u2; \
	else \
		Internal("bad type in BinaryExpr::Fold");

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

	case EXPR_ADD:		DO_FOLD(+); break;
	case EXPR_ADD_TO:	DO_FOLD(+); break;
	case EXPR_SUB:		DO_FOLD(-); break;
	case EXPR_REMOVE_FROM:	DO_FOLD(-); break;
	case EXPR_TIMES:	DO_FOLD(*); break;
	case EXPR_DIVIDE:
		{
		if ( is_integral )
			{
			if ( i2 == 0 )
				reporter->ExprRuntimeError(this, "division by zero");

			i3 = i1 / i2;
			}

		else if ( is_unsigned )
			{
			if ( u2 == 0 )
				reporter->ExprRuntimeError(this, "division by zero");

			u3 = u1 / u2;
			}
		else
			{
			if ( d2 == 0 )
				reporter->ExprRuntimeError(this, "division by zero");

			d3 = d1 / d2;
			}

		}
		break;

	case EXPR_MOD:
		{
		if ( is_integral )
			{
			if ( i2 == 0 )
				reporter->ExprRuntimeError(this, "modulo by zero");

			i3 = i1 % i2;
			}

		else if ( is_unsigned )
			{
			if ( u2 == 0 )
				reporter->ExprRuntimeError(this, "modulo by zero");

			u3 = u1 % u2;
			}

		else
			Internal("bad type in BinaryExpr::Fold");
		}

		break;

	case EXPR_AND:		DO_INT_FOLD(&&); break;
	case EXPR_OR:		DO_INT_FOLD(||); break;

	case EXPR_LT:		DO_INT_VAL_FOLD(<); break;
	case EXPR_LE:		DO_INT_VAL_FOLD(<=); break;
	case EXPR_EQ:		DO_INT_VAL_FOLD(==); break;
	case EXPR_NE:		DO_INT_VAL_FOLD(!=); break;
	case EXPR_GE:		DO_INT_VAL_FOLD(>=); break;
	case EXPR_GT:		DO_INT_VAL_FOLD(>); break;

	default:
		BadTag("BinaryExpr::Fold", expr_name(tag));
	}

	BroType* ret_type = type;
	if ( IsVector(ret_type->Tag()) )
	     ret_type = ret_type->YieldType();

	if ( ret_type->Tag() == TYPE_INTERVAL )
		return new IntervalVal(d3, 1.0);
	else if ( ret_type->InternalType() == TYPE_INTERNAL_DOUBLE )
		return new Val(d3, ret_type->Tag());
	else if ( ret_type->InternalType() == TYPE_INTERNAL_UNSIGNED )
		return new Val(u3, ret_type->Tag());
	else
		return new Val(i3, ret_type->Tag());
	}

Val* BinaryExpr::StringFold(Val* v1, Val* v2) const
	{
	const BroString* s1 = v1->AsString();
	const BroString* s2 = v2->AsString();
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
		vector<const BroString*> strings;
		strings.push_back(s1);
		strings.push_back(s2);

		return new StringVal(concatenate(strings));
		}

	default:
		BadTag("BinaryExpr::StringFold", expr_name(tag));
	}

	return new Val(result, TYPE_BOOL);
	}

Val* BinaryExpr::AddrFold(Val* v1, Val* v2) const
	{
	IPAddr a1 = v1->AsAddr();
	IPAddr a2 = v2->AsAddr();
	int result = 0;

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

	return new Val(result, TYPE_BOOL);
	}

Val* BinaryExpr::SubNetFold(Val* v1, Val* v2) const
	{
	const IPPrefix& n1 = v1->AsSubNet();
	const IPPrefix& n2 = v2->AsSubNet();

	bool result = ( n1 == n2 ) ? true : false;

	if ( tag == EXPR_NE )
		result = ! result;

	return new Val(result, TYPE_BOOL);
	}

void BinaryExpr::SwapOps()
	{
	// We could check here whether the operator is commutative.
	Expr* t = op1;
	op1 = op2;
	op2 = t;
	}

void BinaryExpr::PromoteOps(TypeTag t)
	{
	TypeTag bt1 = op1->Type()->Tag();
	TypeTag bt2 = op2->Type()->Tag();

	if ( IsVector(bt1) )
		bt1 = op1->Type()->AsVectorType()->YieldType()->Tag();
	if ( IsVector(bt2) )
		bt2 = op2->Type()->AsVectorType()->YieldType()->Tag();

	if ( bt1 != t )
		op1 = new ArithCoerceExpr(op1, t);
	if ( bt2 != t )
		op2 = new ArithCoerceExpr(op2, t);
	}

void BinaryExpr::PromoteType(TypeTag t, bool is_vector)
	{
	PromoteOps(t);
	SetType(is_vector ? new VectorType(base_type(t)) : base_type(t));
	}

IMPLEMENT_SERIAL(BinaryExpr, SER_BINARY_EXPR);

bool BinaryExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BINARY_EXPR, Expr);
	return op1->Serialize(info) && op2->Serialize(info);
	}

bool BinaryExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Expr);

	op1 = Expr::Unserialize(info);
	if ( ! op1 )
		return false;

	op2 = Expr::Unserialize(info);
	return op2 != 0;
	}

CloneExpr::CloneExpr(Expr* arg_op) : UnaryExpr(EXPR_CLONE, arg_op)
	{
	if ( IsError() )
		return;

	BroType* t = op->Type();
	SetType(t->Ref());
	}

Val* CloneExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return 0;

	Val* v = op->Eval(f);

	if ( ! v )
		return 0;

	Val* result = Fold(v);
	Unref(v);

	return result;
	}

Val* CloneExpr::Fold(Val* v) const
	{
	return v->Clone();
	}

IMPLEMENT_SERIAL(CloneExpr, SER_CLONE_EXPR);

bool CloneExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_CLONE_EXPR, UnaryExpr);
	return true;
	}

bool CloneExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	return true;
	}

IncrExpr::IncrExpr(BroExprTag arg_tag, Expr* arg_op)
: UnaryExpr(arg_tag, arg_op->MakeLvalue())
	{
	if ( IsError() )
		return;

	BroType* t = op->Type();

	if ( IsVector(t->Tag()) )
		{
		if ( ! IsIntegral(t->AsVectorType()->YieldType()->Tag()) )
			ExprError("vector elements must be integral for increment operator");
		else
			SetType(t->Ref());
		}
	else
		{
		if ( ! IsIntegral(t->Tag()) )
			ExprError("requires an integral operand");
		else
			SetType(t->Ref());
		}
	}

Val* IncrExpr::DoSingleEval(Frame* f, Val* v) const
	 {
	bro_int_t k = v->CoerceToInt();

	if ( Tag() == EXPR_INCR )
		++k;
	else
		{
		--k;

		if ( k < 0 &&
		     v->Type()->InternalType() == TYPE_INTERNAL_UNSIGNED )
			Error("count underflow");
		}

	 BroType* ret_type = Type();
	 if ( IsVector(ret_type->Tag()) )
		 ret_type = Type()->YieldType();

	 return new Val(k, ret_type->Tag());
	 }


Val* IncrExpr::Eval(Frame* f) const
	{
	Val* v = op->Eval(f);
	if ( ! v )
		return 0;

	if ( is_vector(v) )
		{
		VectorVal* v_vec = v->AsVectorVal();
		for ( unsigned int i = 0; i < v_vec->Size(); ++i )
			{
			Val* elt = v_vec->Lookup(i);
			if ( elt )
				{
				Val* new_elt = DoSingleEval(f, elt);
				v_vec->Assign(i, new_elt, OP_INCR);
				}
			else
				v_vec->Assign(i, 0, OP_INCR);
			}
		op->Assign(f, v_vec, OP_INCR);
		}

	else
		{
		Val* old_v = v;
		op->Assign(f, v = DoSingleEval(f, old_v), OP_INCR);
		Unref(old_v);
		}

	return v->Ref();
	}

int IncrExpr::IsPure() const
	{
	return 0;
	}

IMPLEMENT_SERIAL(IncrExpr, SER_INCR_EXPR);

bool IncrExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_INCR_EXPR, UnaryExpr);
	return true;
	}

bool IncrExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	return true;
	}

NotExpr::NotExpr(Expr* arg_op) : UnaryExpr(EXPR_NOT, arg_op)
	{
	if ( IsError() )
		return;

	BroType* t = op->Type();
	TypeTag bt = t->Tag();

	if ( ! IsIntegral(bt) && bt != TYPE_BOOL )
		ExprError("requires an integral or boolean operand");
	else
		SetType(base_type(TYPE_BOOL));
	}

Expr* NotExpr::DoSimplify()
	{
	op = simplify_expr(op, SIMPLIFY_GENERAL);
	Canonicize();

	if ( op->Tag() == EXPR_NOT )
		// !!x == x
		return ((NotExpr*) op)->Op()->Ref();

	if ( op->IsConst() )
		return new ConstExpr(Fold(op->ExprVal()));

	return this;
	}

Val* NotExpr::Fold(Val* v) const
	{
	return new Val(! v->InternalInt(), type->Tag());
	}

IMPLEMENT_SERIAL(NotExpr, SER_NOT_EXPR);

bool NotExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_NOT_EXPR, UnaryExpr);
	return true;
	}

bool NotExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	return true;
	}

PosExpr::PosExpr(Expr* arg_op) : UnaryExpr(EXPR_POSITIVE, arg_op)
	{
	if ( IsError() )
		return;

	BroType* t = op->Type();
	if ( IsVector(t->Tag()) )
		t = t->AsVectorType()->YieldType();
	TypeTag bt = t->Tag();

	BroType* base_result_type = 0;

	if ( IsIntegral(bt) )
		// Promote count and counter to int.
		base_result_type = base_type(TYPE_INT);
	else if ( bt == TYPE_INTERVAL || bt == TYPE_DOUBLE )
		base_result_type = t->Ref();
	else
		ExprError("requires an integral or double operand");

	if ( is_vector(op) )
		SetType(new VectorType(base_result_type));
	else
		SetType(base_result_type);
	}

Expr* PosExpr::DoSimplify()
	{
	op = simplify_expr(op, SIMPLIFY_GENERAL);
	Canonicize();

	TypeTag t = op->Type()->Tag();

	if ( t == TYPE_DOUBLE || t == TYPE_INTERVAL || t == TYPE_INT )
		return op->Ref();

	if ( op->IsConst() && ! is_vector(op->ExprVal()) )
		return new ConstExpr(Fold(op->ExprVal()));

	return this;
	}

Val* PosExpr::Fold(Val* v) const
	{
	TypeTag t = v->Type()->Tag();

	if ( t == TYPE_DOUBLE || t == TYPE_INTERVAL || t == TYPE_INT )
		return v->Ref();
	else
		return new Val(v->CoerceToInt(), type->Tag());
	}

IMPLEMENT_SERIAL(PosExpr, SER_POS_EXPR);

bool PosExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_POS_EXPR, UnaryExpr);
	return true;
	}

bool PosExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	return true;
	}

NegExpr::NegExpr(Expr* arg_op) : UnaryExpr(EXPR_NEGATE, arg_op)
	{
	if ( IsError() )
		return;

	BroType* t = op->Type();
	if ( IsVector(t->Tag()) )
		t = t->AsVectorType()->YieldType();
	TypeTag bt = t->Tag();

	BroType* base_result_type = 0;

	if ( IsIntegral(bt) )
		// Promote count and counter to int.
		base_result_type = base_type(TYPE_INT);
	else if ( bt == TYPE_INTERVAL || bt == TYPE_DOUBLE )
		base_result_type = t->Ref();
	else
		ExprError("requires an integral or double operand");

	if ( is_vector(op) )
		SetType(new VectorType(base_result_type));
	else
		SetType(base_result_type);
	}

Expr* NegExpr::DoSimplify()
	{
	op = simplify_expr(op, SIMPLIFY_GENERAL);
	Canonicize();

	if ( op->Tag() == EXPR_NEGATE )
		// -(-x) == x
		return ((NegExpr*) op)->Op()->Ref();

	if ( op->IsConst() && ! is_vector(op->ExprVal()) )
		return new ConstExpr(Fold(op->ExprVal()));

	if ( op->Tag() == EXPR_SUB )
		{ // -(a-b) == b-a
		SubExpr* s = (SubExpr*) op;
		return new SubExpr(s->Op2()->Ref(), s->Op1()->Ref());
		}

	return this;
	}

Val* NegExpr::Fold(Val* v) const
	{
	if ( v->Type()->Tag() == TYPE_DOUBLE )
		return new Val(- v->InternalDouble(), v->Type()->Tag());
	else if ( v->Type()->Tag() == TYPE_INTERVAL )
		return new IntervalVal(- v->InternalDouble(), 1.0);
	else
		return new Val(- v->CoerceToInt(), TYPE_INT);
	}


IMPLEMENT_SERIAL(NegExpr, SER_NEG_EXPR);

bool NegExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_NEG_EXPR, UnaryExpr);
	return true;
	}

bool NegExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	return true;
	}

SizeExpr::SizeExpr(Expr* arg_op) : UnaryExpr(EXPR_SIZE, arg_op)
	{
	if ( IsError() )
		return;

	SetType(base_type(TYPE_COUNT));
	}

Val* SizeExpr::Eval(Frame* f) const
	{
	Val* v = op->Eval(f);
	if ( ! v )
		return 0;

	Val* result = Fold(v);
	Unref(v);
	return result;
	}

Val* SizeExpr::Fold(Val* v) const
	{
	return v->SizeVal();
	}

IMPLEMENT_SERIAL(SizeExpr, SER_SIZE_EXPR);

bool SizeExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_SIZE_EXPR, UnaryExpr);
	return true;
	}

bool SizeExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	return true;
	}


AddExpr::AddExpr(Expr* arg_op1, Expr* arg_op2)
: BinaryExpr(EXPR_ADD, arg_op1, arg_op2)
	{
	if ( IsError() )
		return;

	TypeTag bt1 = op1->Type()->Tag();
	if ( IsVector(bt1) )
		bt1 = op1->Type()->AsVectorType()->YieldType()->Tag();

	TypeTag bt2 = op2->Type()->Tag();
	if ( IsVector(bt2) )
		bt2 = op2->Type()->AsVectorType()->YieldType()->Tag();

	BroType* base_result_type = 0;

	if ( bt1 == TYPE_TIME && bt2 == TYPE_INTERVAL )
		base_result_type = base_type(bt1);
	else if ( bt2 == TYPE_TIME && bt1 == TYPE_INTERVAL )
		base_result_type = base_type(bt2);
	else if ( bt1 == TYPE_INTERVAL && bt2 == TYPE_INTERVAL )
		base_result_type = base_type(bt1);
	else if ( BothArithmetic(bt1, bt2) )
		PromoteType(max_type(bt1, bt2), is_vector(op1) || is_vector(op2));
	else if ( BothString(bt1, bt2) )
		base_result_type = base_type(bt1);
	else
		ExprError("requires arithmetic operands");

	if ( base_result_type )
		{
		if ( is_vector(op1) || is_vector(op2) )
			SetType(new VectorType(base_result_type));
		else
			SetType(base_result_type);
		}
	}

Expr* AddExpr::DoSimplify()
	{
	// If there's a constant, then it's in op1, since Canonicize()
	// makes sure of that.
	if ( op1->IsZero() )
		return op2->Ref();

	else if ( op1->Tag() == EXPR_NEGATE )
		// (-a)+b = b-a
		return new AddExpr(op2->Ref(), ((NegExpr*) op1)->Op()->Ref());

	else if ( op2->Tag() == EXPR_NEGATE )
		// a+(-b) == a-b
		return new SubExpr(op1->Ref(), ((NegExpr*) op2)->Op()->Ref());

	return this;
	}

void AddExpr::Canonicize()
	{
	if ( expr_greater(op2, op1) ||
	     (op1->Type()->Tag() == TYPE_INTERVAL &&
	      op2->Type()->Tag() == TYPE_TIME) ||
	     (op2->IsConst() && ! is_vector(op2->ExprVal()) && ! op1->IsConst()))
		SwapOps();
	}

IMPLEMENT_SERIAL(AddExpr, SER_ADD_EXPR);

bool AddExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_ADD_EXPR, BinaryExpr);
	return true;
	}

bool AddExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BinaryExpr);
	return true;
	}

AddToExpr::AddToExpr(Expr* arg_op1, Expr* arg_op2)
: BinaryExpr(EXPR_ADD_TO, arg_op1, arg_op2)
	{
	if ( IsError() )
		return;

	TypeTag bt1 = op1->Type()->Tag();
	TypeTag bt2 = op2->Type()->Tag();

	if ( BothArithmetic(bt1, bt2) )
		PromoteType(max_type(bt1, bt2), is_vector(op1) || is_vector(op2));
	else if ( BothString(bt1, bt2) )
		SetType(base_type(bt1));
	else if ( BothInterval(bt1, bt2) )
		SetType(base_type(bt1));
	else
		ExprError("requires two arithmetic or two string operands");
	}

Val* AddToExpr::Eval(Frame* f) const
	{
	Val* v1 = op1->Eval(f);
	if ( ! v1 )
		return 0;

	Val* v2 = op2->Eval(f);
	if ( ! v2 )
		{
		Unref(v1);
		return 0;
		}

	Val* result = Fold(v1, v2);
	Unref(v1);
	Unref(v2);

	if ( result )
		{
		op1->Assign(f, result);
		return result->Ref();
		}
	else
		return 0;
	}

IMPLEMENT_SERIAL(AddToExpr, SER_ADD_TO_EXPR);

bool AddToExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_ADD_TO_EXPR, BinaryExpr);
	return true;
	}

bool AddToExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BinaryExpr);
	return true;
	}

SubExpr::SubExpr(Expr* arg_op1, Expr* arg_op2)
: BinaryExpr(EXPR_SUB, arg_op1, arg_op2)
	{
	if ( IsError() )
		return;

	TypeTag bt1 = op1->Type()->Tag();
	if ( IsVector(bt1) )
		bt1 = op1->Type()->AsVectorType()->YieldType()->Tag();

	TypeTag bt2 = op2->Type()->Tag();
	if ( IsVector(bt2) )
		bt2 = op2->Type()->AsVectorType()->YieldType()->Tag();

	BroType* base_result_type = 0;

	if ( bt1 == TYPE_TIME && bt2 == TYPE_INTERVAL )
		base_result_type = base_type(bt1);
	else if ( bt1 == TYPE_TIME && bt2 == TYPE_TIME )
		SetType(base_type(TYPE_INTERVAL));
	else if ( bt1 == TYPE_INTERVAL && bt2 == TYPE_INTERVAL )
		base_result_type = base_type(bt1);
	else if ( BothArithmetic(bt1, bt2) )
		PromoteType(max_type(bt1, bt2), is_vector(op1) || is_vector(op2));
	else
		ExprError("requires arithmetic operands");

	if ( base_result_type )
		{
		if ( is_vector(op1) || is_vector(op2) )
			SetType(new VectorType(base_result_type));
		else
			SetType(base_result_type);
		}
	}

Expr* SubExpr::DoSimplify()
	{
	if ( op1->IsZero() )
		return new NegExpr(op2->Ref());

	else if ( op2->IsZero() )
		return op1->Ref();

	else if ( op2->Tag() == EXPR_NEGATE )
		// a-(-b) = a+b
		return new AddExpr(op1->Ref(), ((NegExpr*) op2)->Op()->Ref());

	return this;
	}

IMPLEMENT_SERIAL(SubExpr, SER_SUB_EXPR);

bool SubExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_SUB_EXPR, BinaryExpr);
	return true;
	}

bool SubExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BinaryExpr);
	return true;
	}

RemoveFromExpr::RemoveFromExpr(Expr* arg_op1, Expr* arg_op2)
: BinaryExpr(EXPR_REMOVE_FROM, arg_op1, arg_op2)
	{
	if ( IsError() )
		return;

	TypeTag bt1 = op1->Type()->Tag();
	TypeTag bt2 = op2->Type()->Tag();

	if ( BothArithmetic(bt1, bt2) )
		PromoteType(max_type(bt1, bt2), is_vector(op1) || is_vector(op2));
	else if ( BothInterval(bt1, bt2) )
		SetType(base_type(bt1));
	else
		ExprError("requires two arithmetic operands");
	}

Val* RemoveFromExpr::Eval(Frame* f) const
	{
	Val* v1 = op1->Eval(f);
	if ( ! v1 )
		return 0;

	Val* v2 = op2->Eval(f);
	if ( ! v2 )
		{
		Unref(v1);
		return 0;
		}

	Val* result = Fold(v1, v2);

	Unref(v1);
	Unref(v2);

	if ( result )
		{
		op1->Assign(f, result);
		return result->Ref();
		}
	else
		return 0;
	}

IMPLEMENT_SERIAL(RemoveFromExpr, SER_REMOVE_FROM_EXPR);

bool RemoveFromExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_REMOVE_FROM_EXPR, BinaryExpr);
	return true;
	}

bool RemoveFromExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BinaryExpr);
	return true;
	}

TimesExpr::TimesExpr(Expr* arg_op1, Expr* arg_op2)
: BinaryExpr(EXPR_TIMES, arg_op1, arg_op2)
	{
	if ( IsError() )
		return;

	Canonicize();

	TypeTag bt1 = op1->Type()->Tag();
	if ( IsVector(bt1) )
		bt1 = op1->Type()->AsVectorType()->YieldType()->Tag();

	TypeTag bt2 = op2->Type()->Tag();
	if ( IsVector(bt2) )
		bt2 = op2->Type()->AsVectorType()->YieldType()->Tag();

	if ( bt1 == TYPE_INTERVAL || bt2 == TYPE_INTERVAL )
		{
		if ( IsArithmetic(bt1) || IsArithmetic(bt2) )
			PromoteType(TYPE_INTERVAL, is_vector(op1) || is_vector(op2) );
		else
			ExprError("multiplication with interval requires arithmetic operand");
		}
	else if ( BothArithmetic(bt1, bt2) )
		PromoteType(max_type(bt1, bt2), is_vector(op1) || is_vector(op2));
	else
		ExprError("requires arithmetic operands");
	}

Expr* TimesExpr::DoSimplify()
	{
	// If there's a constant, then it's in op1, since Canonicize()
	// makes sure of that.
	if ( op1->IsConst() )
		{
		if ( op1->IsZero() )
			{
			if ( IsVector(op2->Type()->Tag()) )
				return this;
			else
				return make_zero(type);
			}

		else if ( op1->IsOne() )
			return op2->Ref();
		}

	return this;
	}

void TimesExpr::Canonicize()
	{
	if ( expr_greater(op2, op1) || op2->Type()->Tag() == TYPE_INTERVAL ||
	     (op2->IsConst() && ! is_vector(op2->ExprVal()) && ! op1->IsConst()) )
		SwapOps();
	}

IMPLEMENT_SERIAL(TimesExpr, SER_TIMES_EXPR);

bool TimesExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_TIMES_EXPR, BinaryExpr);
	return true;
	}

bool TimesExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BinaryExpr);
	return true;
	}

DivideExpr::DivideExpr(Expr* arg_op1, Expr* arg_op2)
: BinaryExpr(EXPR_DIVIDE, arg_op1, arg_op2)
	{
	if ( IsError() )
		return;

	TypeTag bt1 = op1->Type()->Tag();
	if ( IsVector(bt1) )
		bt1 = op1->Type()->AsVectorType()->YieldType()->Tag();

	TypeTag bt2 = op2->Type()->Tag();
	if ( IsVector(bt2) )
		bt2 = op2->Type()->AsVectorType()->YieldType()->Tag();

	if ( bt1 == TYPE_INTERVAL || bt2 == TYPE_INTERVAL )
		{
		if ( IsArithmetic(bt1) || IsArithmetic(bt2) )
			PromoteType(TYPE_INTERVAL, is_vector(op1) || is_vector(op2));
		else if ( bt1 == TYPE_INTERVAL && bt2 == TYPE_INTERVAL )
			{
			if ( is_vector(op1) || is_vector(op2) )
				SetType(new VectorType(base_type(TYPE_DOUBLE)));
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

Val* DivideExpr::AddrFold(Val* v1, Val* v2) const
	{
	uint32 mask;
	if ( v2->Type()->Tag() == TYPE_COUNT )
		mask = static_cast<uint32>(v2->InternalUnsigned());
	else
		mask = static_cast<uint32>(v2->InternalInt());

	return new SubNetVal(v1->AsAddr(), mask);
	}

Expr* DivideExpr::DoSimplify()
	{
	if ( IsError() )
		return this;

	if ( op1->Type()->Tag() == TYPE_ADDR )
		return this;

	if ( is_vector(op1) || is_vector(op2) )
		return this;

	if ( op2->IsConst() )
		{
		if ( op2->IsOne() )
			return op1->Ref();
		else if ( op2->IsZero() )
			Error("zero divisor");
		}

	else if ( same_expr(op1, op2) )
		return make_one(type);

	return this;
	}

IMPLEMENT_SERIAL(DivideExpr, SER_DIVIDE_EXPR);

bool DivideExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_DIVIDE_EXPR, BinaryExpr);
	return true;
	}

bool DivideExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BinaryExpr);
	return true;
	}

ModExpr::ModExpr(Expr* arg_op1, Expr* arg_op2)
: BinaryExpr(EXPR_MOD, arg_op1, arg_op2)
	{
	if ( IsError() )
		return;

	TypeTag bt1 = op1->Type()->Tag();
	if ( IsVector(bt1) )
		bt1 = op1->Type()->AsVectorType()->YieldType()->Tag();

	TypeTag bt2 = op2->Type()->Tag();
	if ( IsVector(bt2) )
		bt2 = op2->Type()->AsVectorType()->YieldType()->Tag();

	if ( BothIntegral(bt1, bt2) )
		PromoteType(max_type(bt1, bt2), is_vector(op1) || is_vector(op2));
	else
		ExprError("requires integral operands");
	}

Expr* ModExpr::DoSimplify()
	{
	if ( IsError() )
		return this;

	TypeTag bt1 = op1->Type()->Tag();
	TypeTag bt2 = op2->Type()->Tag();

	if ( IsVector(bt1) || IsVector(bt2) )
		return this;

	if ( op2->IsConst() )
		{
		if ( op2->IsOne() )
			return make_zero(type);
		else if ( op2->IsZero() )
			Error("zero modulus");
		}

	else if ( same_expr(op1, op2) )
		return make_zero(type);

	return this;
	}

IMPLEMENT_SERIAL(ModExpr, SER_MOD_EXPR);

bool ModExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_MOD_EXPR, BinaryExpr);
	return true;
	}

bool ModExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BinaryExpr);
	return true;
	}

BoolExpr::BoolExpr(BroExprTag arg_tag, Expr* arg_op1, Expr* arg_op2)
: BinaryExpr(arg_tag, arg_op1, arg_op2)
	{
	if ( IsError() )
		return;

	TypeTag bt1 = op1->Type()->Tag();
	if ( IsVector(bt1) )
		bt1 = op1->Type()->AsVectorType()->YieldType()->Tag();

	TypeTag bt2 = op2->Type()->Tag();
	if ( IsVector(bt2) )
		bt2 = op2->Type()->AsVectorType()->YieldType()->Tag();

	if ( BothBool(bt1, bt2) )
		{
		if ( is_vector(op1) || is_vector(op2) )
			SetType(new VectorType(base_type(TYPE_BOOL)));
		else
			SetType(base_type(TYPE_BOOL));
		}

	else if ( bt1 == TYPE_PATTERN && bt2 == bt1 )
		SetType(base_type(TYPE_PATTERN));

	else
		ExprError("requires boolean operands");
	}

Val* BoolExpr::DoSingleEval(Frame* f, Val* v1, Expr* op2) const
	{
	if ( ! v1 )
		return 0;

	if ( Type()->Tag() == TYPE_PATTERN )
		{
		Val* v2 = op2->Eval(f);
		if ( ! v2 )
			return 0;

		RE_Matcher* re1 = v1->AsPattern();
		RE_Matcher* re2 = v2->AsPattern();

		RE_Matcher* res = tag == EXPR_AND ?
			RE_Matcher_conjunction(re1, re2) :
			RE_Matcher_disjunction(re1, re2);

		return new PatternVal(res);
		}

	if ( tag == EXPR_AND )
		{
		if ( v1->IsZero() )
			return v1;
		else
			{
			Unref(v1);
			return op2->Eval(f);
			}
		}

	else
		{
		if ( v1->IsZero() )
			{
			Unref(v1);
			return op2->Eval(f);
			}
		else
			return v1;
		}
	}


Val* BoolExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return 0;

	Val* v1 = op1->Eval(f);
	if ( ! v1 )
		return 0;

	int is_vec1 = is_vector(op1);
	int is_vec2 = is_vector(op2);

	// Handle scalar op scalar
	if ( ! is_vec1 && ! is_vec2 )
		return DoSingleEval(f, v1, op2);

	// Handle scalar op vector  or  vector op scalar
	// We can't short-circuit everything since we need to eval
	// a vector in order to find out its length.
	if ( ! (is_vec1 && is_vec2) )
		{ // Only one is a vector.
		Val* scalar_v = 0;
		VectorVal* vector_v = 0;

		if ( is_vec1 )
			{
			scalar_v = op2->Eval(f);
			vector_v = v1->AsVectorVal();
			}
		else
			{
			scalar_v = v1;
			vector_v = op2->Eval(f)->AsVectorVal();
			}

		if ( ! scalar_v || ! vector_v )
			return 0;

		VectorVal* result = 0;

		// It's either and EXPR_AND or an EXPR_OR.
		bool is_and = (tag == EXPR_AND);

		if ( scalar_v->IsZero() == is_and )
			{
			result = new VectorVal(Type()->AsVectorType());
			result->Resize(vector_v->Size());
			result->AssignRepeat(0, result->Size(),
						scalar_v);
			}
		else
			result = vector_v->Ref()->AsVectorVal();

		Unref(scalar_v);
		Unref(vector_v);

		return result;
		}

	// Only case remaining: both are vectors.
	Val* v2 = op2->Eval(f);
	if ( ! v2 )
		return 0;

	VectorVal* vec_v1 = v1->AsVectorVal();
	VectorVal* vec_v2 = v2->AsVectorVal();

	if ( vec_v1->Size() != vec_v2->Size() )
		{
		Error("vector operands have different sizes");
		return 0;
		}

	VectorVal* result = new VectorVal(Type()->AsVectorType());
	result->Resize(vec_v1->Size());

	for ( unsigned int i = 0; i < vec_v1->Size(); ++i )
		{
		Val* op1 = vec_v1->Lookup(i);
		Val* op2 = vec_v2->Lookup(i);
		if ( op1 && op2 )
			{
			bool local_result = (tag == EXPR_AND) ?
				(! op1->IsZero() && ! op2->IsZero()) :
				(! op1->IsZero() || ! op2->IsZero());

			result->Assign(i, new Val(local_result, TYPE_BOOL));
			}
		else
			result->Assign(i, 0);
		}

	Unref(v1);
	Unref(v2);

	return result;
	}

Expr* BoolExpr::DoSimplify()
	{
	if ( op1->IsConst() && ! is_vector(op1) )
		{
		if ( op1->IsZero() )
			// F && x  or  F || x
			return (tag == EXPR_AND) ? make_zero(type) : op2->Ref();
		else
			// T && x  or  T || x
			return (tag == EXPR_AND) ? op2->Ref() : make_one(type);
		}

	else if ( op2->IsConst() && ! is_vector(op2) )
		{
		if ( op1->IsZero() )
			// x && F  or  x || F
			return (tag == EXPR_AND) ? make_zero(type) : op1->Ref();
		else
			// x && T  or  x || T
			return (tag == EXPR_AND) ? op1->Ref() : make_one(type);
		}

	else if ( same_expr(op1, op2) )
		{
		Warn("redundant boolean operation");
		return op1->Ref();
		}

	return this;
	}

IMPLEMENT_SERIAL(BoolExpr, SER_BOOL_EXPR);

bool BoolExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BOOL_EXPR, BinaryExpr);
	return true;
	}

bool BoolExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BinaryExpr);
	return true;
	}

EqExpr::EqExpr(BroExprTag arg_tag, Expr* arg_op1, Expr* arg_op2)
: BinaryExpr(arg_tag, arg_op1, arg_op2)
	{
	if ( IsError() )
		return;

	Canonicize();

	TypeTag bt1 = op1->Type()->Tag();
	if ( IsVector(bt1) )
		bt1 = op1->Type()->AsVectorType()->YieldType()->Tag();

	TypeTag bt2 = op2->Type()->Tag();
	if ( IsVector(bt2) )
		bt2 = op2->Type()->AsVectorType()->YieldType()->Tag();

	if ( is_vector(op1) || is_vector(op2) )
		SetType(new VectorType(base_type(TYPE_BOOL)));
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
			break;

		case TYPE_ENUM:
			if ( ! same_type(op1->Type(), op2->Type()) )
				ExprError("illegal enum comparison");
			break;

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
	if ( op2->Type()->Tag() == TYPE_PATTERN )
		SwapOps();

	else if ( op1->Type()->Tag() == TYPE_PATTERN )
		;

	else if ( expr_greater(op2, op1) )
		SwapOps();
	}

Expr* EqExpr::DoSimplify()
	{
	if ( same_expr(op1, op2) && ! is_vector(op1) )
		{
		if ( ! optimize )
			Warn("redundant comparison");

		if ( tag == EXPR_EQ )
			return make_one(type);
		else
			return make_zero(type);
		}

	return this;
	}

Val* EqExpr::Fold(Val* v1, Val* v2) const
	{
	if ( op1->Type()->Tag() == TYPE_PATTERN )
		{
		RE_Matcher* re = v1->AsPattern();
		const BroString* s = v2->AsString();
		if ( tag == EXPR_EQ )
			return new Val(re->MatchExactly(s), TYPE_BOOL);
		else
			return new Val(! re->MatchExactly(s), TYPE_BOOL);
		}

	else
		return BinaryExpr::Fold(v1, v2);
	}

IMPLEMENT_SERIAL(EqExpr, SER_EQ_EXPR);

bool EqExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_EQ_EXPR, BinaryExpr);
	return true;
	}

bool EqExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BinaryExpr);
	return true;
	}

RelExpr::RelExpr(BroExprTag arg_tag, Expr* arg_op1, Expr* arg_op2)
: BinaryExpr(arg_tag, arg_op1, arg_op2)
	{
	if ( IsError() )
		return;

	Canonicize();

	TypeTag bt1 = op1->Type()->Tag();
	if ( IsVector(bt1) )
		bt1 = op1->Type()->AsVectorType()->YieldType()->Tag();

	TypeTag bt2 = op2->Type()->Tag();
	if ( IsVector(bt2) )
		bt2 = op2->Type()->AsVectorType()->YieldType()->Tag();

	if ( is_vector(op1) || is_vector(op2) )
		SetType(new VectorType(base_type(TYPE_BOOL)));
	else
		SetType(base_type(TYPE_BOOL));

	if ( BothArithmetic(bt1, bt2) )
		PromoteOps(max_type(bt1, bt2));

	else if ( bt1 != bt2 )
		ExprError("operands must be of the same type");

	else if ( bt1 != TYPE_TIME && bt1 != TYPE_INTERVAL &&
		  bt1 != TYPE_PORT && bt1 != TYPE_ADDR &&
		  bt1 != TYPE_STRING )
		ExprError("illegal comparison");
	}

Expr* RelExpr::DoSimplify()
	{
	if ( same_expr(op1, op2) )
		{
		Warn("redundant comparison");
		// Here we use the fact that the canonical form of
		// a RelExpr only uses EXPR_LE or EXPR_LT.
		if ( tag == EXPR_LE )
			return make_one(type);
		else
			return make_zero(type);
		}

	return this;
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

IMPLEMENT_SERIAL(RelExpr, SER_REL_EXPR);

bool RelExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_REL_EXPR, BinaryExpr);
	return true;
	}

bool RelExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BinaryExpr);
	return true;
	}

CondExpr::CondExpr(Expr* arg_op1, Expr* arg_op2, Expr* arg_op3)
: Expr(EXPR_COND)
	{
	op1 = arg_op1;
	op2 = arg_op2;
	op3 = arg_op3;

	TypeTag bt1 = op1->Type()->Tag();
	if ( IsVector(bt1) )
		bt1 = op1->Type()->AsVectorType()->YieldType()->Tag();

	if ( op1->IsError() || op2->IsError() || op3->IsError() )
		SetError();

	else if ( bt1 != TYPE_BOOL )
		ExprError("requires boolean conditional");

	else
		{
		TypeTag bt2 = op2->Type()->Tag();
		if ( is_vector(op2) )
			bt2 = op2->Type()->AsVectorType()->YieldType()->Tag();

		TypeTag bt3 = op3->Type()->Tag();
		if ( IsVector(bt3) )
			bt3 = op3->Type()->AsVectorType()->YieldType()->Tag();

		if ( is_vector(op1) && ! (is_vector(op2) && is_vector(op3)) )
			{
			ExprError("vector conditional requires vector alternatives");
			return;
			}

		if ( BothArithmetic(bt2, bt3) )
			{
			TypeTag t = max_type(bt2, bt3);
			if ( bt2 != t )
				op2 = new ArithCoerceExpr(op2, t);
			if ( bt3 != t )
				op3 = new ArithCoerceExpr(op3, t);

			if ( is_vector(op2) )
				SetType(new VectorType(base_type(t)));
			else
				SetType(base_type(t));
			}

		else if ( bt2 != bt3 )
			ExprError("operands must be of the same type");

		else
			SetType(op2->Type()->Ref());
		}
	}

CondExpr::~CondExpr()
	{
	Unref(op1);
	Unref(op2);
	Unref(op3);
	}

Expr* CondExpr::Simplify(SimplifyType /* simp_type */)
	{
	op1 = simplify_expr(op1, SIMPLIFY_GENERAL);
	op2 = simplify_expr(op2, SIMPLIFY_GENERAL);
	op3 = simplify_expr(op3, SIMPLIFY_GENERAL);

	if ( op1->IsConst() && ! is_vector(op1) )
		{
		Val* v = op1->ExprVal();
		return (v->IsZero() ? op3 : op2)->Ref();
		}

	if ( op1->Tag() == EXPR_NOT )
		return new CondExpr(((NotExpr*) op1)->Op()->Ref(),
					op3->Ref(), op2->Ref());

	return this;
	}

Val* CondExpr::Eval(Frame* f) const
	{
	if ( ! is_vector(op1) )
		{ // scalar is easy
		Val* v = op1->Eval(f);
		int false_eval = v->IsZero();
		Unref(v);

		return (false_eval ? op3 : op2)->Eval(f);
		}

	// Vector case: no mixed scalar/vector cases allowed
	Val* v1 = op1->Eval(f);
	if ( ! v1 )
		return 0;

	Val* v2 = op2->Eval(f);
	if ( ! v2 )
		return 0;

	Val* v3 = op3->Eval(f);
	if ( ! v3 )
		return 0;

	VectorVal* cond = v1->AsVectorVal();
	VectorVal* a = v2->AsVectorVal();
	VectorVal* b = v3->AsVectorVal();

	if ( cond->Size() != a->Size() || a->Size() != b->Size() )
		{
		Error("vectors in conditional expression have different sizes");
		return 0;
		}

	VectorVal* result = new VectorVal(Type()->AsVectorType());
	result->Resize(cond->Size());

	for ( unsigned int i = 0; i < cond->Size(); ++i )
		{
		Val* local_cond = cond->Lookup(i);
		if ( local_cond )
			result->Assign(i,
				       local_cond->IsZero() ?
					       b->Lookup(i) : a->Lookup(i));
		else
			result->Assign(i, 0);
		}

	return result;
	}

int CondExpr::IsPure() const
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

IMPLEMENT_SERIAL(CondExpr, SER_COND_EXPR);

bool CondExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_COND_EXPR, Expr);
	return op1->Serialize(info) && op2->Serialize(info)
			&& op3->Serialize(info);
	}

bool CondExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Expr);

	op1 = Expr::Unserialize(info);
	if ( ! op1 )
		return false;

	op2 = Expr::Unserialize(info);
	if ( ! op2 )
		return false;

	op3 = Expr::Unserialize(info);

	return op3 != 0;
	}

RefExpr::RefExpr(Expr* arg_op) : UnaryExpr(EXPR_REF, arg_op)
	{
	if ( IsError() )
		return;

	if ( ! ::is_assignable(op->Type()) )
		ExprError("illegal assignment target");
	else
		SetType(op->Type()->Ref());
	}

Expr* RefExpr::MakeLvalue()
	{
	return this;
	}

void RefExpr::Assign(Frame* f, Val* v, Opcode opcode)
	{
	op->Assign(f, v, opcode);
	}

IMPLEMENT_SERIAL(RefExpr, SER_REF_EXPR);

bool RefExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_REF_EXPR, UnaryExpr);
	return true;
	}

bool RefExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	return true;
	}

AssignExpr::AssignExpr(Expr* arg_op1, Expr* arg_op2, int arg_is_init,
		       Val* arg_val, attr_list* arg_attrs)
: BinaryExpr(EXPR_ASSIGN,
		arg_is_init ? arg_op1 : arg_op1->MakeLvalue(), arg_op2)
	{
	val = 0;
	is_init = arg_is_init;

	if ( IsError() )
		return;

	SetType(arg_val ? arg_val->Type()->Ref() : op1->Type()->Ref());

	if ( is_init )
		{
		SetLocationInfo(arg_op1->GetLocationInfo(),
				arg_op2->GetLocationInfo());
		return;
		}

	// We discard the status from TypeCheck since it has already
	// generated error messages.
	(void) TypeCheck(arg_attrs);

	val = arg_val ? arg_val->Ref() : 0;

	SetLocationInfo(arg_op1->GetLocationInfo(), arg_op2->GetLocationInfo());
	}

bool AssignExpr::TypeCheck(attr_list* attrs)
	{
	TypeTag bt1 = op1->Type()->Tag();
	TypeTag bt2 = op2->Type()->Tag();

	if ( bt1 == TYPE_LIST && bt2 == TYPE_ANY )
		// This is ok because we cannot explicitly declare lists on
		// the script level.
		return true;

	if ( ((bt1 == TYPE_ENUM) ^ (bt2 == TYPE_ENUM)) )
		{
		ExprError("can't convert to/from enumerated type");
		return false;
		}

	if ( IsArithmetic(bt1) )
		return TypeCheckArithmetics(bt1, bt2);

	if ( bt1 == TYPE_TIME && IsArithmetic(bt2) && op2->IsZero() )
		{ // Allow assignments to zero as a special case.
		op2 = new ArithCoerceExpr(op2, bt1);
		return true;
		}

	if ( bt1 == TYPE_TABLE && bt2 == bt1 &&
	     op2->Type()->AsTableType()->IsUnspecifiedTable() )
		{
		op2 = new TableCoerceExpr(op2, op1->Type()->AsTableType());
		return true;
		}

	if ( bt1 == TYPE_TABLE && op2->Tag() == EXPR_LIST )
		{
		attr_list* attr_copy = 0;

		if ( attrs )
			{
			attr_copy = new attr_list;
			loop_over_list(*attrs, i)
				attr_copy->append((*attrs)[i]);
			}

		if ( op1->Type()->IsSet() )
			op2 = new SetConstructorExpr(op2->AsListExpr(), attr_copy);
		else
			op2 = new TableConstructorExpr(op2->AsListExpr(), attr_copy);

		return true;
		}

	if ( bt1 == TYPE_VECTOR )
		{
		if ( bt2 == bt1 && op2->Type()->AsVectorType()->IsUnspecifiedVector() )
			{
			op2 = new VectorCoerceExpr(op2, op1->Type()->AsVectorType());
			return true;
			}

		if ( op2->Tag() == EXPR_LIST )
			{
			op2 = new VectorConstructorExpr(op2->AsListExpr());
			return true;
			}
		}

	if ( op1->Type()->Tag() == TYPE_RECORD &&
	     op2->Type()->Tag() == TYPE_RECORD )
		{
		if ( same_type(op1->Type(), op2->Type()) )
			{
			RecordType* rt1 = op1->Type()->AsRecordType();
			RecordType* rt2 = op2->Type()->AsRecordType();

			// Make sure the attributes match as well.
			for ( int i = 0; i < rt1->NumFields(); ++i )
				{
				const TypeDecl* td1 = rt1->FieldDecl(i);
				const TypeDecl* td2 = rt2->FieldDecl(i);

				if ( same_attrs(td1->attrs, td2->attrs) )
					// Everything matches.
					return true;
				}
			}

		// Need to coerce.
		op2 = new RecordCoerceExpr(op2, op1->Type()->AsRecordType());
		return true;
		}

	if ( ! same_type(op1->Type(), op2->Type()) )
		{
		ExprError("type clash in assignment");
		return false;
		}

	return true;
	}

bool AssignExpr::TypeCheckArithmetics(TypeTag bt1, TypeTag bt2)
	{
	if ( ! IsArithmetic(bt2) )
		{
		char err[512];
		snprintf(err, sizeof(err),
			"assignment of non-arithmetic value to arithmetic (%s/%s)",
			 type_name(bt1), type_name(bt2));
		ExprError(err);
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
		op2 = new ArithCoerceExpr(op2, bt1);
		bt2 = op2->Type()->Tag();
		}

	if ( bt1 == TYPE_INT )
		PromoteOps(TYPE_INT);
	else
		{
		if ( bt2 == TYPE_INT )
			{
			Warn("dangerous assignment of integer to count");
			op2 = new ArithCoerceExpr(op2, bt1);
			bt2 = op2->Type()->Tag();
			}

		// Assignment of count to counter or vice
		// versa is allowed, and requires no
		// coercion.
		}

	return true;
	}


Expr* AssignExpr::Simplify(SimplifyType /* simp_type */)
	{
	op1 = simplify_expr(op1, SIMPLIFY_LHS);
	op2 = simplify_expr(op2, SIMPLIFY_GENERAL);
	return this;
	}

Val* AssignExpr::Eval(Frame* f) const
	{
	if ( is_init )
		{
		Error("illegal assignment in initialization");
		return 0;
		}

	Val* v = op2->Eval(f);

	if ( v )
		{
		op1->Assign(f, v);
		return val ? val->Ref() : v->Ref();
		}
	else
		return 0;
	}

BroType* AssignExpr::InitType() const
	{
	if ( op1->Tag() != EXPR_LIST )
		{
		Error("bad initializer");
		return 0;
		}

	BroType* tl = op1->Type();
	if ( tl->Tag() != TYPE_LIST )
		Internal("inconsistent list expr in AssignExpr::InitType");

	return new TableType(tl->Ref()->AsTypeList(), op2->Type()->Ref());
	}

void AssignExpr::EvalIntoAggregate(const BroType* t, Val* aggr, Frame* f) const
	{
	if ( IsError() )
		return;

	TypeDecl td(0, 0);
	if ( IsRecordElement(&td) )
		{
		if ( t->Tag() != TYPE_RECORD )
			{
			Error("not a record initializer", t);
			return;
			}

		const RecordType* rt = t->AsRecordType();
		int field = rt->FieldOffset(td.id);

		if ( field < 0 )
			{
			Error("no such field");
			return;
			}

		RecordVal* aggr_r = aggr->AsRecordVal();

		Val* v = op2->Eval(f);
		if ( v )
			aggr_r->Assign(field, v);

		return;
		}

	if ( op1->Tag() != EXPR_LIST )
		Error("bad table insertion");

	TableVal* tv = aggr->AsTableVal();

	Val* index = op1->Eval(f);
	Val* v = check_and_promote(op2->Eval(f), t->YieldType(), 1);
	if ( ! index || ! v )
		return;

	if ( ! tv->Assign(index, v) )
		Error("type clash in table assignment");

	Unref(index);
	}

Val* AssignExpr::InitVal(const BroType* t, Val* aggr) const
	{
	if ( ! aggr )
		{
		Error("assignment in initialization");
		return 0;
		}

	if ( IsError() )
		return 0;

	TypeDecl td(0, 0);
	if ( IsRecordElement(&td) )
		{
		if ( t->Tag() != TYPE_RECORD )
			{
			Error("not a record initializer", t);
			return 0;
			}
		const RecordType* rt = t->AsRecordType();
		int field = rt->FieldOffset(td.id);

		if ( field < 0 )
			{
			Error("no such field");
			return 0;
			}

		if ( aggr->Type()->Tag() != TYPE_RECORD )
			Internal("bad aggregate in AssignExpr::InitVal");
		RecordVal* aggr_r = aggr->AsRecordVal();

		Val* v = op2->InitVal(rt->FieldType(td.id), 0);
		if ( ! v )
			return 0;

		aggr_r->Assign(field, v);
		return v;
		}

	else if ( op1->Tag() == EXPR_LIST )
		{
		if ( t->Tag() != TYPE_TABLE )
			{
			Error("not a table initialization", t);
			return 0;
			}

		if ( aggr->Type()->Tag() != TYPE_TABLE )
			Internal("bad aggregate in AssignExpr::InitVal");

		TableVal* tv = aggr->AsTableVal();
		const TableType* tt = tv->Type()->AsTableType();
		const BroType* yt = tv->Type()->YieldType();
		Val* index = op1->InitVal(tt->Indices(), 0);
		Val* v = op2->InitVal(yt, 0);
		if ( ! index || ! v )
			return 0;

		if ( ! tv->ExpandAndInit(index, v) )
			{
			Unref(index);
			Unref(tv);
			return 0;
			}

		Unref(index);
		return tv;
		}

	else
		{
		Error("illegal initializer");
		return 0;
		}
	}

int AssignExpr::IsRecordElement(TypeDecl* td) const
	{
	if ( op1->Tag() == EXPR_NAME )
		{
		if ( td )
			{
			const NameExpr* n = (const NameExpr*) op1;
			td->type = op2->Type()->Ref();
			td->id = copy_string(n->Id()->Name());
			}

		return 1;
		}
	else
		return 0;
	}

int AssignExpr::IsPure() const
	{
	return 0;
	}

IMPLEMENT_SERIAL(AssignExpr, SER_ASSIGN_EXPR);

bool AssignExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_ASSIGN_EXPR, BinaryExpr);
	SERIALIZE_OPTIONAL(val);
	return SERIALIZE(is_init);
	}

bool AssignExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BinaryExpr);
	UNSERIALIZE_OPTIONAL(val, Val::Unserialize(info));
	return UNSERIALIZE(&is_init);
	}

IndexExpr::IndexExpr(Expr* arg_op1, ListExpr* arg_op2, bool is_slice)
: BinaryExpr(EXPR_INDEX, arg_op1, arg_op2)
	{
	if ( IsError() )
		return;

	if ( is_slice )
		{
		if ( ! IsString(op1->Type()->Tag()) )
			ExprError("slice notation indexing only supported for strings currently");
		}

	else if ( IsString(op1->Type()->Tag()) )
		{
		if ( arg_op2->Exprs().length() != 1 )
			ExprError("invalid string index expression");
		}

	if ( IsError() )
		return;

	int match_type = op1->Type()->MatchesIndex(arg_op2);
	if ( match_type == DOES_NOT_MATCH_INDEX )
		SetError("not an index type");

	else if ( ! op1->Type()->YieldType() )
		{
		if ( IsString(op1->Type()->Tag()) &&
		     match_type == MATCHES_INDEX_SCALAR )
			SetType(base_type(TYPE_STRING));
		else
		// It's a set - so indexing it yields void.  We don't
		// directly generate an error message, though, since this
		// expression might be part of an add/delete statement,
		// rather than yielding a value.
			SetType(base_type(TYPE_VOID));
		}

	else if ( match_type == MATCHES_INDEX_SCALAR )
		SetType(op1->Type()->YieldType()->Ref());

	else if ( match_type == MATCHES_INDEX_VECTOR )
		SetType(new VectorType(op1->Type()->YieldType()->Ref()));

	else
		ExprError("Unknown MatchesIndex() return value");

	}

int IndexExpr::CanAdd() const
	{
	if ( IsError() )
		return 1;	// avoid cascading the error report

	// "add" only allowed if our type is "set".
	return op1->Type()->IsSet();
	}

int IndexExpr::CanDel() const
	{
	if ( IsError() )
		return 1;	// avoid cascading the error report

	return op1->Type()->Tag() == TYPE_TABLE;
	}

void IndexExpr::Add(Frame* f)
	{
	if ( IsError() )
		return;

	Val* v1 = op1->Eval(f);
	if ( ! v1 )
		return;

	Val* v2 = op2->Eval(f);
	if ( ! v2 )
		{
		Unref(v1);
		return;
		}

	v1->AsTableVal()->Assign(v2, 0);

	Unref(v1);
	Unref(v2);
	}

void IndexExpr::Delete(Frame* f)
	{
	if ( IsError() )
		return;

	Val* v1 = op1->Eval(f);
	if ( ! v1 )
		return;

	Val* v2 = op2->Eval(f);
	if ( ! v2 )
		{
		Unref(v1);
		return;
		}

	Unref(v1->AsTableVal()->Delete(v2));

	Unref(v1);
	Unref(v2);
	}

Expr* IndexExpr::MakeLvalue()
	{
	if ( IsString(op1->Type()->Tag()) )
		ExprError("cannot assign to string index expression");

	return new RefExpr(this);
	}

Expr* IndexExpr::Simplify(SimplifyType simp_type)
	{
	op1 = simplify_expr(op1, simp_type);
	op2 = simplify_expr(op2, SIMPLIFY_GENERAL);
	return this;
	}

Val* IndexExpr::Eval(Frame* f) const
	{
	Val* v1 = op1->Eval(f);
	if ( ! v1 )
		return 0;

	Val* v2 = op2->Eval(f);
	if ( ! v2 )
		{
		Unref(v1);
		return 0;
		}

	Val* result;

	Val* indv = v2->AsListVal()->Index(0);
	if ( is_vector(indv) )
		{
		VectorVal* v_v1 = v1->AsVectorVal();
		VectorVal* v_v2 = indv->AsVectorVal();
		VectorVal* v_result = new VectorVal(Type()->AsVectorType());
		result = v_result;

		// Booleans select each element (or not).
		if ( IsBool(v_v2->Type()->YieldType()->Tag()) )
			{
			if ( v_v1->Size() != v_v2->Size() )
				{
				Error("size mismatch, boolean index and vector");
				Unref(v_result);
				return 0;
				}

			for ( unsigned int i = 0; i < v_v2->Size(); ++i )
				{
				if ( v_v2->Lookup(i)->AsBool() )
					v_result->Assign(v_result->Size() + 1, v_v1->Lookup(i));
				}
			}
		else
			{ // The elements are indices.
			// ### Should handle negative indices here like
			// S does, i.e., by excluding those elements.
			// Probably only do this if *all* are negative.
			v_result->Resize(v_v2->Size());
			for ( unsigned int i = 0; i < v_v2->Size(); ++i )
				v_result->Assign(i, v_v1->Lookup(v_v2->Lookup(i)->CoerceToInt()));
			}
		}
	else
		result = Fold(v1, v2);

	Unref(v1);
	Unref(v2);
	return result;
	}

static int get_slice_index(int idx, int len)
	{
	if ( abs(idx) > len )
		idx = idx > 0 ? len : 0; // Clamp maximum positive/negative indices.
	else if ( idx < 0 )
		idx += len;  // Map to a positive index.

	return idx;
	}

Val* IndexExpr::Fold(Val* v1, Val* v2) const
	{
	if ( IsError() )
		return 0;

	Val* v = 0;

	switch ( v1->Type()->Tag() ) {
	case TYPE_VECTOR:
		v = v1->AsVectorVal()->Lookup(v2);
		break;

	case TYPE_TABLE:
		v = v1->AsTableVal()->Lookup(v2);
		break;

	case TYPE_STRING:
		{
		const ListVal* lv = v2->AsListVal();
		const BroString* s = v1->AsString();
		int len = s->Len();
		BroString* substring = 0;

		if ( lv->Length() == 1 )
			{
			bro_int_t idx = lv->Index(0)->AsInt();

			if ( idx < 0 )
				idx += len;

			// Out-of-range index will return null pointer.
			substring = s->GetSubstring(idx, 1);
			}
		else
			{
			bro_int_t first = get_slice_index(lv->Index(0)->AsInt(), len);
			bro_int_t last = get_slice_index(lv->Index(1)->AsInt(), len);
			int substring_len = last - first;

			if ( substring_len < 0 )
				substring = 0;
			else
				substring = s->GetSubstring(first, substring_len);
			}

		return new StringVal(substring ? substring : new BroString(""));
		}

	default:
		Error("type cannot be indexed");
		break;
	}

	if ( v )
		return v->Ref();

	Error("no such index");
	return 0;
	}

void IndexExpr::Assign(Frame* f, Val* v, Opcode op)
	{
	if ( IsError() )
		return;

	Val* v1 = op1->Eval(f);
	if ( ! v1 )
		return;

	Val* v2 = op2->Eval(f);

	if ( ! v1 || ! v2 )
		{
		Unref(v1);
		Unref(v2);
		return;
		}

	switch ( v1->Type()->Tag() ) {
	case TYPE_VECTOR:
		if ( ! v1->AsVectorVal()->Assign(v2, v, op) )
			Internal("assignment failed");
		break;

	case TYPE_TABLE:
		if ( ! v1->AsTableVal()->Assign(v2, v, op) )
			Internal("assignment failed");
		break;

	case TYPE_STRING:
		Internal("assignment via string index accessor not allowed");
		break;

	default:
		Internal("bad index expression type in assignment");
		break;
	}

	Unref(v1);
	Unref(v2);
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


IMPLEMENT_SERIAL(IndexExpr, SER_INDEX_EXPR);

bool IndexExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_INDEX_EXPR, BinaryExpr);
	return true;
	}

bool IndexExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BinaryExpr);
	return true;
	}

FieldExpr::FieldExpr(Expr* arg_op, const char* arg_field_name)
: UnaryExpr(EXPR_FIELD, arg_op)
	{
	field_name = copy_string(arg_field_name);
	td = 0;
	field = 0;

	if ( IsError() )
		return;

	if ( ! IsRecord(op->Type()->Tag()) )
		ExprError("not a record");
	else
		{
		RecordType* rt = op->Type()->AsRecordType();
		field = rt->FieldOffset(field_name);

		if ( field < 0 )
			ExprError("no such field in record");
		else
			{
			SetType(rt->FieldType(field)->Ref());
			td = rt->FieldDecl(field);
			}
		}
	}

FieldExpr::~FieldExpr()
	{
	delete [] field_name;
	}

Expr* FieldExpr::MakeLvalue()
	{
	return new RefExpr(this);
	}

Expr* FieldExpr::Simplify(SimplifyType simp_type)
	{
	op = simplify_expr(op, simp_type);
	return this;
	}

int FieldExpr::CanDel() const
	{
	return td->FindAttr(ATTR_DEFAULT) || td->FindAttr(ATTR_OPTIONAL);
	}

void FieldExpr::Assign(Frame* f, Val* v, Opcode opcode)
	{
	if ( IsError() )
		return;

	if ( field < 0 )
		ExprError("no such field in record");

	Val* op_v = op->Eval(f);
	if ( op_v )
		{
		RecordVal* r = op_v->AsRecordVal();
		r->Assign(field, v, opcode);
		Unref(r);
		}
	}

void FieldExpr::Delete(Frame* f)
	{
	Assign(f, 0, OP_ASSIGN_IDX);
	}

Val* FieldExpr::Fold(Val* v) const
	{
	Val* result = v->AsRecordVal()->Lookup(field);
	if ( result )
		return result->Ref();

	// Check for &default.
	const Attr* def_attr = td ? td->FindAttr(ATTR_DEFAULT) : 0;
	if ( def_attr )
		return def_attr->AttrExpr()->Eval(0);
	else
		{
		reporter->ExprRuntimeError(this, "field value missing");
		assert(false);
		return 0; // Will never get here, but compiler can't tell.
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

IMPLEMENT_SERIAL(FieldExpr, SER_FIELD_EXPR);

bool FieldExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_FIELD_EXPR, UnaryExpr);

	if ( ! (SERIALIZE(field_name) && SERIALIZE(field) ) )
		return false;

	return td->Serialize(info);
	}

bool FieldExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);

	if ( ! (UNSERIALIZE_STR(&field_name, 0) && UNSERIALIZE(&field) ) )
		return false;

	td = TypeDecl::Unserialize(info);
	return td != 0;
	}

HasFieldExpr::HasFieldExpr(Expr* arg_op, const char* arg_field_name)
: UnaryExpr(EXPR_HAS_FIELD, arg_op)
	{
	field_name = arg_field_name;
	field = 0;

	if ( IsError() )
		return;

	if ( ! IsRecord(op->Type()->Tag()) )
		ExprError("not a record");
	else
		{
		RecordType* rt = op->Type()->AsRecordType();
		field = rt->FieldOffset(field_name);

		if ( field < 0 )
			ExprError("no such field in record");

		SetType(base_type(TYPE_BOOL));
		}
	}

HasFieldExpr::~HasFieldExpr()
	{
	delete field_name;
	}

Val* HasFieldExpr::Fold(Val* v) const
	{
	RecordVal* rec_to_look_at;

	rec_to_look_at = v->AsRecordVal();

	if ( ! rec_to_look_at )
		return new Val(0, TYPE_BOOL);

	RecordVal* r = rec_to_look_at->Ref()->AsRecordVal();
	Val* ret = new Val(r->Lookup(field) != 0, TYPE_BOOL);
	Unref(r);

	return ret;
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

IMPLEMENT_SERIAL(HasFieldExpr, SER_HAS_FIELD_EXPR);

bool HasFieldExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_HAS_FIELD_EXPR, UnaryExpr);

	// Serialize former "bool is_attr" member first for backwards compatibility.
	return SERIALIZE(false) && SERIALIZE(field_name) && SERIALIZE(field);
	}

bool HasFieldExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	// Unserialize former "bool is_attr" member for backwards compatibility.
	bool not_used;
	return UNSERIALIZE(&not_used) && UNSERIALIZE_STR(&field_name, 0) && UNSERIALIZE(&field);
	}

RecordConstructorExpr::RecordConstructorExpr(ListExpr* constructor_list)
: UnaryExpr(EXPR_RECORD_CONSTRUCTOR, constructor_list)
	{
	if ( IsError() )
		return;

	// Spin through the list, which should be comprised of
	// either record's or record-field-assign, and build up a
	// record type to associate with this constructor.
	type_decl_list* record_types = new type_decl_list;

	const expr_list& exprs = constructor_list->Exprs();
	loop_over_list(exprs, i)
		{
		Expr* e = exprs[i];
		BroType* t = e->Type();

		if ( e->Tag() == EXPR_FIELD_ASSIGN )
			{
			FieldAssignExpr* field = (FieldAssignExpr*) e;

			BroType* field_type = field->Type()->Ref();
			char* field_name = copy_string(field->FieldName());

			record_types->append(new TypeDecl(field_type, field_name));
			continue;
			}

		if ( t->Tag() != TYPE_RECORD )
			{
			Error("bad type in record constructor", e);
			SetError();
			continue;
			}

		// It's a record - add in its fields.
		const RecordType* rt = t->AsRecordType();
		int n = rt->NumFields();
		for ( int j = 0; j < n; ++j )
			{
			const TypeDecl* td = rt->FieldDecl(j);
			record_types->append(new TypeDecl(td->type->Ref(), td->id));
			}
		}

	SetType(new RecordType(record_types));
	}

RecordConstructorExpr::~RecordConstructorExpr()
	{
	}

Val* RecordConstructorExpr::InitVal(const BroType* t, Val* aggr) const
	{
	Val* v = Eval(0);

	if ( v )
		{
		RecordVal* rv = v->AsRecordVal();
		RecordVal* ar = rv->CoerceTo(t->AsRecordType(), aggr);

		if ( ar )
			{
			Unref(rv);
			return ar;
			}
		}

	Error("bad record initializer");
	return 0;
	}

Val* RecordConstructorExpr::Fold(Val* v) const
	{
	ListVal* lv = v->AsListVal();
	RecordType* rt = type->AsRecordType();

	if ( lv->Length() != rt->NumFields() )
		Internal("inconsistency evaluating record constructor");

	RecordVal* rv = new RecordVal(rt);

	for ( int i = 0; i < lv->Length(); ++i )
		rv->Assign(i, lv->Index(i)->Ref());

	return rv;
	}

void RecordConstructorExpr::ExprDescribe(ODesc* d) const
	{
	d->Add("[");
	op->Describe(d);
	d->Add("]");
	}

IMPLEMENT_SERIAL(RecordConstructorExpr, SER_RECORD_CONSTRUCTOR_EXPR);

bool RecordConstructorExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_RECORD_CONSTRUCTOR_EXPR, UnaryExpr);
	return true;
	}

bool RecordConstructorExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	return true;
	}

TableConstructorExpr::TableConstructorExpr(ListExpr* constructor_list,
					   attr_list* arg_attrs, BroType* arg_type)
: UnaryExpr(EXPR_TABLE_CONSTRUCTOR, constructor_list)
	{
	attrs = 0;

	if ( IsError() )
		return;

	if ( arg_type )
		{
		if ( ! arg_type->IsTable() )
			{
			Error("bad table constructor type", arg_type);
			SetError();
			return;
			}

		SetType(arg_type->Ref());
		}
	else
		{
		if ( constructor_list->Exprs().length() == 0 )
			SetType(new TableType(new TypeList(base_type(TYPE_ANY)), 0));
		else
			{
			SetType(init_type(constructor_list));

			if ( ! type )
				SetError();

			else if ( type->Tag() != TYPE_TABLE ||
				  type->AsTableType()->IsSet() )
				SetError("values in table(...) constructor do not specify a table");
			}
		}

	attrs = arg_attrs ? new Attributes(arg_attrs, type, false) : 0;

	type_list* indices = type->AsTableType()->Indices()->Types();
	const expr_list& cle = constructor_list->Exprs();

	// check and promote all index expressions in ctor list
	loop_over_list(cle, i)
		{
		if ( cle[i]->Tag() != EXPR_ASSIGN )
			continue;

		Expr* idx_expr = cle[i]->AsAssignExpr()->Op1();

		if ( idx_expr->Tag() != EXPR_LIST )
			continue;

		expr_list& idx_exprs = idx_expr->AsListExpr()->Exprs();

		if ( idx_exprs.length() != indices->length() )
			continue;

		loop_over_list(idx_exprs, j)
			{
			Expr* idx = idx_exprs[j];

			if ( check_and_promote_expr(idx, (*indices)[j]) )
				{
				if ( idx != idx_exprs[j] )
					idx_exprs.replace(j, idx);
				continue;
				}

			ExprError("inconsistent types in table constructor");
			}
		}
	}

Val* TableConstructorExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return 0;

	Val* aggr = new TableVal(Type()->AsTableType(), attrs);
	const expr_list& exprs = op->AsListExpr()->Exprs();

	loop_over_list(exprs, i)
		exprs[i]->EvalIntoAggregate(type, aggr, f);

	return aggr;
	}

Val* TableConstructorExpr::InitVal(const BroType* t, Val* aggr) const
	{
	if ( IsError() )
		return 0;

	TableType* tt = Type()->AsTableType();
	TableVal* tval = aggr ? aggr->AsTableVal() : new TableVal(tt, attrs);
	const expr_list& exprs = op->AsListExpr()->Exprs();

	loop_over_list(exprs, i)
		exprs[i]->EvalIntoAggregate(t, tval, 0);

	return tval;
	}

void TableConstructorExpr::ExprDescribe(ODesc* d) const
	{
	d->Add("table(");
	op->Describe(d);
	d->Add(")");
	}

IMPLEMENT_SERIAL(TableConstructorExpr, SER_TABLE_CONSTRUCTOR_EXPR);

bool TableConstructorExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_TABLE_CONSTRUCTOR_EXPR, UnaryExpr);
	SERIALIZE_OPTIONAL(attrs);
	return true;
	}

bool TableConstructorExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	UNSERIALIZE_OPTIONAL(attrs, Attributes::Unserialize(info));
	return true;
	}

SetConstructorExpr::SetConstructorExpr(ListExpr* constructor_list,
				       attr_list* arg_attrs, BroType* arg_type)
: UnaryExpr(EXPR_SET_CONSTRUCTOR, constructor_list)
	{
	attrs = 0;

	if ( IsError() )
		return;

	if ( arg_type )
		{
		if ( ! arg_type->IsSet() )
			{
			Error("bad set constructor type", arg_type);
			SetError();
			return;
			}

		SetType(arg_type->Ref());
		}
	else
		{
		if ( constructor_list->Exprs().length() == 0 )
			SetType(new ::SetType(new TypeList(base_type(TYPE_ANY)), 0));
		else
			SetType(init_type(constructor_list));
		}

	if ( ! type )
		SetError();

	else if ( type->Tag() != TYPE_TABLE || ! type->AsTableType()->IsSet() )
		SetError("values in set(...) constructor do not specify a set");

	attrs = arg_attrs ? new Attributes(arg_attrs, type, false) : 0;

	type_list* indices = type->AsTableType()->Indices()->Types();
	expr_list& cle = constructor_list->Exprs();

	if ( indices->length() == 1 )
		{
		if ( ! check_and_promote_exprs_to_type(constructor_list,
		                                       (*indices)[0]) )
			ExprError("inconsistent type in set constructor");
		}

	else if ( indices->length() > 1 )
		{
		// Check/promote each expression in composite index.
		loop_over_list(cle, i)
			{
			Expr* ce = cle[i];
			ListExpr* le = ce->AsListExpr();

			if ( ce->Tag() == EXPR_LIST &&
			     check_and_promote_exprs(le, type->AsTableType()->Indices()) )
				{
				if ( le != cle[i] )
					cle.replace(i, le);

				continue;
				}

			ExprError("inconsistent types in set constructor");
			}
		}
	}

Val* SetConstructorExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return 0;

	TableVal* aggr = new TableVal(type->AsTableType(), attrs);
	const expr_list& exprs = op->AsListExpr()->Exprs();

	loop_over_list(exprs, i)
		{
		Val* element = exprs[i]->Eval(f);
		aggr->Assign(element, 0);
		Unref(element);
		}

	return aggr;
	}

Val* SetConstructorExpr::InitVal(const BroType* t, Val* aggr) const
	{
	if ( IsError() )
		return 0;

	const BroType* index_type = t->AsTableType()->Indices();
	TableType* tt = Type()->AsTableType();
	TableVal* tval = aggr ? aggr->AsTableVal() : new TableVal(tt, attrs);
	const expr_list& exprs = op->AsListExpr()->Exprs();

	loop_over_list(exprs, i)
		{
		Expr* e = exprs[i];
		Val* element = check_and_promote(e->Eval(0), index_type, 1);

		if ( ! element || ! tval->Assign(element, 0) )
			{
			Error(fmt("initialization type mismatch in set"), e);
			return 0;
			}

		Unref(element);
		}

	return tval;
	}

void SetConstructorExpr::ExprDescribe(ODesc* d) const
	{
	d->Add("set(");
	op->Describe(d);
	d->Add(")");
	}

IMPLEMENT_SERIAL(SetConstructorExpr, SER_SET_CONSTRUCTOR_EXPR);

bool SetConstructorExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_SET_CONSTRUCTOR_EXPR, UnaryExpr);
	SERIALIZE_OPTIONAL(attrs);
	return true;
	}

bool SetConstructorExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	UNSERIALIZE_OPTIONAL(attrs, Attributes::Unserialize(info));
	return true;
	}

VectorConstructorExpr::VectorConstructorExpr(ListExpr* constructor_list,
					     BroType* arg_type)
: UnaryExpr(EXPR_VECTOR_CONSTRUCTOR, constructor_list)
	{
	if ( IsError() )
		return;

	if ( arg_type )
		{
		if ( arg_type->Tag() != TYPE_VECTOR )
			{
			Error("bad vector constructor type", arg_type);
			SetError();
			return;
			}

		SetType(arg_type->Ref());
		}
	else
		{
		if ( constructor_list->Exprs().length() == 0 )
			{
			// vector().
			// By default, assign VOID type here. A vector with
			// void type set is seen as an unspecified vector.
			SetType(new ::VectorType(base_type(TYPE_VOID)));
			return;
			}

		BroType* t = merge_type_list(constructor_list);

		if ( t )
			{
			SetType(new VectorType(t->Ref()));
			Unref(t);
			}
		else
			{
			SetError();
			return;
			}
		}

	if ( ! check_and_promote_exprs_to_type(constructor_list,
					       type->AsVectorType()->YieldType()) )
		ExprError("inconsistent types in vector constructor");
	}

Val* VectorConstructorExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return 0;

	VectorVal* vec = new VectorVal(Type()->AsVectorType());
	const expr_list& exprs = op->AsListExpr()->Exprs();

	loop_over_list(exprs, i)
		{
		Expr* e = exprs[i];
		Val* v = e->Eval(f);
		if ( ! vec->Assign(i, v) )
			{
			Error(fmt("type mismatch at index %d", i), e);
			return 0;
			}
		}

	return vec;
	}

Val* VectorConstructorExpr::InitVal(const BroType* t, Val* aggr) const
	{
	if ( IsError() )
		return 0;

	VectorType* vt = Type()->AsVectorType();
	VectorVal* vec = aggr ? aggr->AsVectorVal() : new VectorVal(vt);
	const expr_list& exprs = op->AsListExpr()->Exprs();

	loop_over_list(exprs, i)
		{
		Expr* e = exprs[i];
		Val* v = check_and_promote(e->Eval(0), t->YieldType(), 1);

		if ( ! v || ! vec->Assign(i, v) )
			{
			Error(fmt("initialization type mismatch at index %d", i), e);
			if ( ! aggr )
				Unref(vec);
			return 0;
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

IMPLEMENT_SERIAL(VectorConstructorExpr, SER_VECTOR_CONSTRUCTOR_EXPR);

bool VectorConstructorExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_VECTOR_CONSTRUCTOR_EXPR, UnaryExpr);
	return true;
	}

bool VectorConstructorExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	return true;
	}

FieldAssignExpr::FieldAssignExpr(const char* arg_field_name, Expr* value)
: UnaryExpr(EXPR_FIELD_ASSIGN, value), field_name(arg_field_name)
	{
	op->Ref();
	SetType(value->Type()->Ref());
	}

void FieldAssignExpr::EvalIntoAggregate(const BroType* t, Val* aggr, Frame* f)
	const
	{
	if ( IsError() )
		return;

	RecordVal* rec = aggr->AsRecordVal();
	const RecordType* rt = t->AsRecordType();
	Val* v = op->Eval(f);

	if ( v )
		{
		int idx = rt->FieldOffset(field_name.c_str());

		if ( idx < 0 )
			reporter->InternalError("Missing record field: %s",
			                        field_name.c_str());

		rec->Assign(idx, v);
		}
	}

int FieldAssignExpr::IsRecordElement(TypeDecl* td) const
	{
	if ( td )
		{
		td->type = op->Type()->Ref();
		td->id = copy_string(field_name.c_str());
		}

	return 1;
	}

void FieldAssignExpr::ExprDescribe(ODesc* d) const
	{
	d->Add("$");
	d->Add(FieldName());
	d->Add("=");
	op->Describe(d);
	}

IMPLEMENT_SERIAL(FieldAssignExpr, SER_FIELD_ASSIGN_EXPR);

bool FieldAssignExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_FIELD_ASSIGN_EXPR, UnaryExpr);
	return true;
	}

bool FieldAssignExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	return true;
	}

ArithCoerceExpr::ArithCoerceExpr(Expr* arg_op, TypeTag t)
: UnaryExpr(EXPR_ARITH_COERCE, arg_op)
	{
	if ( IsError() )
		return;

	TypeTag bt = op->Type()->Tag();
	TypeTag vbt = bt;

	if ( IsVector(bt) )
		{
		SetType(new VectorType(base_type(t)));
		vbt = op->Type()->AsVectorType()->YieldType()->Tag();
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

Expr* ArithCoerceExpr::DoSimplify()
	{
	if ( is_vector(op) )
		return this;

	InternalTypeTag my_int = type->InternalType();
	InternalTypeTag op_int = op->Type()->InternalType();

	if ( my_int == TYPE_INTERNAL_UNSIGNED )
		my_int = TYPE_INTERNAL_INT;
	if ( op_int == TYPE_INTERNAL_UNSIGNED )
		op_int = TYPE_INTERNAL_INT;

	if ( my_int == op_int )
		return op->Ref();

	if ( op->IsConst() )
		{
		if ( my_int == TYPE_INTERNAL_INT )
			{
			if ( op_int != TYPE_INTERNAL_DOUBLE )
				Internal("bad coercion in CoerceExpr::DoSimplify");
			double d = op->ExprVal()->InternalDouble();
			bro_int_t i = bro_int_t(d);

			if ( i < 0 &&
			     type->InternalType() == TYPE_INTERNAL_UNSIGNED )
				Warn("coercion produces negative count value");

			if ( d != double(i) )
				Warn("coercion loses precision");

			return new ConstExpr(new Val(i, type->Tag()));
			}

		if ( my_int == TYPE_INTERNAL_DOUBLE )
			{
			if ( op_int == TYPE_INTERNAL_INT )
				{
				bro_int_t i = op->ExprVal()->InternalInt();
				double d = double(i);

				if ( i != bro_int_t(d) )
					Warn("coercion loses precision");

				return new ConstExpr(new Val(d, type->Tag()));
				}

			if ( op_int == TYPE_INTERNAL_UNSIGNED )
				{
				bro_uint_t u = op->ExprVal()->InternalUnsigned();
				double d = double(u);

				if ( u != (bro_uint_t) (d) )
					Warn("coercion loses precision");

				return new ConstExpr(new Val(d, type->Tag()));
				}

			}

		Internal("bad coercion in CoerceExpr::DoSimplify");
		}

	return this;
	}

Val* ArithCoerceExpr::FoldSingleVal(Val* v, InternalTypeTag t) const
	{
	switch ( t ) {
	case TYPE_INTERNAL_DOUBLE:
		return new Val(v->CoerceToDouble(), TYPE_DOUBLE);

	case TYPE_INTERNAL_INT:
		return new Val(v->CoerceToInt(), TYPE_INT);

	case TYPE_INTERNAL_UNSIGNED:
		return new Val(v->CoerceToUnsigned(), TYPE_COUNT);

	default:
		Internal("bad type in CoerceExpr::Fold");
		return 0;
	}
	}

Val* ArithCoerceExpr::Fold(Val* v) const
	{
	InternalTypeTag t = type->InternalType();

	if ( ! is_vector(v) )
		{
		// Our result type might be vector, in which case this
		// invocation is being done per-element rather than on
		// the whole vector.  Correct the type tag if necessary.
		if ( type->Tag() == TYPE_VECTOR )
			t = Type()->AsVectorType()->YieldType()->InternalType();
		return FoldSingleVal(v, t);
		}

	t = Type()->AsVectorType()->YieldType()->InternalType();

	VectorVal* vv = v->AsVectorVal();
	VectorVal* result = new VectorVal(Type()->AsVectorType());
	for ( unsigned int i = 0; i < vv->Size(); ++i )
		{
		Val* elt = vv->Lookup(i);
		if ( elt )
			result->Assign(i, FoldSingleVal(elt, t));
		else
			result->Assign(i, 0);
		}

	return result;
	}

IMPLEMENT_SERIAL(ArithCoerceExpr, SER_ARITH_COERCE_EXPR);

bool ArithCoerceExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_ARITH_COERCE_EXPR, UnaryExpr);
	return true;
	}

bool ArithCoerceExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	return true;
	}


RecordCoerceExpr::RecordCoerceExpr(Expr* op, RecordType* r)
: UnaryExpr(EXPR_RECORD_COERCE, op)
	{
	map_size = 0;
	map = 0;

	if ( IsError() )
		return;

	SetType(r->Ref());

	if ( Type()->Tag() != TYPE_RECORD )
		ExprError("coercion to non-record");

	else if ( op->Type()->Tag() != TYPE_RECORD )
		ExprError("coercion of non-record to record");

	else
		{
		RecordType* t_r = type->AsRecordType();
		RecordType* sub_r = op->Type()->AsRecordType();

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

			BroType* sub_t_i = sub_r->FieldType(i);
			BroType* sup_t_i = t_r->FieldType(t_i);

			if ( ! same_type(sup_t_i, sub_t_i) )
				{
				if ( sup_t_i->Tag() != TYPE_RECORD ||
				     sub_t_i->Tag() != TYPE_RECORD ||
				     ! record_promotion_compatible(sup_t_i->AsRecordType(),
				                                   sub_t_i->AsRecordType()) )
					{
					char buf[512];
					safe_snprintf(buf, sizeof(buf),
						"type clash for field \"%s\"", sub_r->FieldName(i));
					Error(buf, sub_t_i);
					SetError();
					break;
					}
				}

			map[t_i] = i;
			}

		for ( i = 0; i < map_size; ++i )
			if ( map[i] == -1 &&
			     ! t_r->FieldDecl(i)->FindAttr(ATTR_OPTIONAL) )
				{
				char buf[512];
				safe_snprintf(buf, sizeof(buf),
					      "non-optional field \"%s\" missing", t_r->FieldName(i));
				Error(buf);
				SetError();
				break;
				}
		}
	}

RecordCoerceExpr::~RecordCoerceExpr()
	{
	delete [] map;
	}

Val* RecordCoerceExpr::InitVal(const BroType* t, Val* aggr) const
	{
	Val* v = Eval(0);

	if ( v )
		{
		RecordVal* rv = v->AsRecordVal();
		RecordVal* ar = rv->CoerceTo(t->AsRecordType(), aggr);

		if ( ar )
			{
			Unref(rv);
			return ar;
			}
		}

	Error("bad record initializer");
	return 0;
	}

Val* RecordCoerceExpr::Fold(Val* v) const
	{
	RecordVal* val = new RecordVal(Type()->AsRecordType());
	RecordVal* rv = v->AsRecordVal();

	for ( int i = 0; i < map_size; ++i )
		{
		if ( map[i] >= 0 )
			{
			Val* rhs = rv->Lookup(map[i]);
			if ( ! rhs )
				{
				const Attr* def = rv->Type()->AsRecordType()->FieldDecl(
					map[i])->FindAttr(ATTR_DEFAULT);

				if ( def )
					rhs = def->AttrExpr()->Eval(0);
				}

			if ( rhs )
				rhs = rhs->Ref();

			assert(rhs || Type()->AsRecordType()->FieldDecl(i)->FindAttr(ATTR_OPTIONAL));

			if ( ! rhs )
				{
				// Optional field is missing.
				val->Assign(i, 0);
				continue;
				}

			BroType* rhs_type = rhs->Type();
			RecordType* val_type = val->Type()->AsRecordType();
			BroType* field_type = val_type->FieldType(i);

			if ( rhs_type->Tag() == TYPE_RECORD &&
			     field_type->Tag() == TYPE_RECORD &&
			     ! same_type(rhs_type, field_type) )
				{
				Val* new_val = rhs->AsRecordVal()->CoerceTo(
				    field_type->AsRecordType());
				if ( new_val )
					{
					Unref(rhs);
					rhs = new_val;
					}
				}

			val->Assign(i, rhs);
			}
		else
			{
			const Attr* def =
			     Type()->AsRecordType()->FieldDecl(i)->FindAttr(ATTR_DEFAULT);

			if ( def )
				{
				Val* def_val = def->AttrExpr()->Eval(0);
				BroType* def_type = def_val->Type();
				BroType* field_type = Type()->AsRecordType()->FieldType(i);

				if ( def_type->Tag() == TYPE_RECORD &&
				     field_type->Tag() == TYPE_RECORD &&
				     ! same_type(def_type, field_type) )
					{
					Val* tmp = def_val->AsRecordVal()->CoerceTo(
					        field_type->AsRecordType());

					if ( tmp )
						{
						Unref(def_val);
						def_val = tmp;
						}
					}

				val->Assign(i, def_val);
				}
			else
				val->Assign(i, 0);
			}
		}

	return val;
	}

IMPLEMENT_SERIAL(RecordCoerceExpr, SER_RECORD_COERCE_EXPR);

bool RecordCoerceExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_RECORD_COERCE_EXPR, UnaryExpr);

	if ( ! SERIALIZE(map_size) )
		return false;

	for ( int i = 0; i < map_size; ++i )
		if ( ! SERIALIZE(map[i]) )
			return false;

	return true;
	}

bool RecordCoerceExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);

	if ( ! UNSERIALIZE(&map_size) )
		return false;

	map = new int[map_size];

	for ( int i = 0; i < map_size; ++i )
		if ( ! UNSERIALIZE(&map[i]) )
			return false;

	return true;
	}


TableCoerceExpr::TableCoerceExpr(Expr* op, TableType* r)
: UnaryExpr(EXPR_TABLE_COERCE, op)
	{
	if ( IsError() )
		return;

	SetType(r->Ref());

	if ( Type()->Tag() != TYPE_TABLE )
		ExprError("coercion to non-table");

	else if ( op->Type()->Tag() != TYPE_TABLE )
		ExprError("coercion of non-table/set to table/set");
	}


TableCoerceExpr::~TableCoerceExpr()
	{
	}

Val* TableCoerceExpr::Fold(Val* v) const
	{
	TableVal* tv = v->AsTableVal();

	if ( tv->Size() > 0 )
		Internal("coercion of non-empty table/set");

	return new TableVal(Type()->Ref()->AsTableType(), tv->Attrs());
	}

IMPLEMENT_SERIAL(TableCoerceExpr, SER_TABLE_COERCE_EXPR);

bool TableCoerceExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_TABLE_COERCE_EXPR, UnaryExpr);
	return true;
	}

bool TableCoerceExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	return true;
	}

VectorCoerceExpr::VectorCoerceExpr(Expr* op, VectorType* v)
: UnaryExpr(EXPR_VECTOR_COERCE, op)
	{
	if ( IsError() )
		return;

	SetType(v->Ref());

	if ( Type()->Tag() != TYPE_VECTOR )
		ExprError("coercion to non-vector");

	else if ( op->Type()->Tag() != TYPE_VECTOR )
		ExprError("coercion of non-vector to vector");
	}


VectorCoerceExpr::~VectorCoerceExpr()
	{
	}

Val* VectorCoerceExpr::Fold(Val* v) const
	{
	VectorVal* vv = v->AsVectorVal();

	if ( vv->Size() > 0 )
		Internal("coercion of non-empty vector");

	return new VectorVal(Type()->Ref()->AsVectorType());
	}

IMPLEMENT_SERIAL(VectorCoerceExpr, SER_VECTOR_COERCE_EXPR);

bool VectorCoerceExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_VECTOR_COERCE_EXPR, UnaryExpr);
	return true;
	}

bool VectorCoerceExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	return true;
	}

FlattenExpr::FlattenExpr(Expr* arg_op)
: UnaryExpr(EXPR_FLATTEN, arg_op)
	{
	if ( IsError() )
		return;

	BroType* t = op->Type();
	if ( t->Tag() != TYPE_RECORD )
		Internal("bad type in FlattenExpr::FlattenExpr");

	RecordType* rt = t->AsRecordType();
	num_fields = rt->NumFields();

	TypeList* tl = new TypeList();
	for ( int i = 0; i < num_fields; ++i )
		tl->Append(rt->FieldType(i)->Ref());

	Unref(rt);
	SetType(tl);
	}

Val* FlattenExpr::Fold(Val* v) const
	{
	RecordVal* rv = v->AsRecordVal();
	ListVal* l = new ListVal(TYPE_ANY);

	for ( int i = 0; i < num_fields; ++i )
		{
		Val* fv = rv->Lookup(i);

		if ( fv )
			{
			l->Append(fv->Ref());
			continue;
			}

		const RecordType* rv_t = rv->Type()->AsRecordType();
		const Attr* fa = rv_t->FieldDecl(i)->FindAttr(ATTR_DEFAULT);
		if ( fa )
			l->Append(fa->AttrExpr()->Eval(0));

		else
			reporter->ExprRuntimeError(this, "missing field value");
		}

	return l;
	}

IMPLEMENT_SERIAL(FlattenExpr, SER_FLATTEN_EXPR);

bool FlattenExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_FLATTEN_EXPR, UnaryExpr);
	return SERIALIZE(num_fields);
	}

bool FlattenExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(UnaryExpr);
	return UNSERIALIZE(&num_fields);
	}

ScheduleTimer::ScheduleTimer(EventHandlerPtr arg_event, val_list* arg_args,
				double t, TimerMgr* arg_tmgr)
: Timer(t, TIMER_SCHEDULE)
	{
	event = arg_event;
	args = arg_args;
	tmgr = arg_tmgr;
	}

ScheduleTimer::~ScheduleTimer()
	{
	}

void ScheduleTimer::Dispatch(double /* t */, int /* is_expire */)
	{
	mgr.QueueEvent(event, args, SOURCE_LOCAL, 0, tmgr);
	}

ScheduleExpr::ScheduleExpr(Expr* arg_when, EventExpr* arg_event)
: Expr(EXPR_SCHEDULE)
	{
	when = arg_when;
	event = arg_event;

	if ( IsError() || when->IsError() || event->IsError() )
		return;

	TypeTag bt = when->Type()->Tag();
	if ( bt != TYPE_TIME && bt != TYPE_INTERVAL )
		ExprError("schedule expression requires a time or time interval");
	else
		SetType(base_type(TYPE_TIMER));
	}

ScheduleExpr::~ScheduleExpr()
	{
	Unref(when);
	Unref(event);
	}

int ScheduleExpr::IsPure() const
	{
	return 0;
	}

Expr* ScheduleExpr::Simplify(SimplifyType simp_type)
	{
	when = when->Simplify(simp_type);
	Expr* generic_event = event->Simplify(simp_type);

	if ( ! generic_event )
		return 0;

	if ( generic_event->Tag() != EXPR_CALL )
		Internal("bad event type in ScheduleExpr::Simplify");

	event = (EventExpr*) generic_event;

	return this;
	}

Val* ScheduleExpr::Eval(Frame* f) const
	{
	if ( terminating )
		return 0;

	Val* when_val = when->Eval(f);
	if ( ! when_val )
		return 0;

	double dt = when_val->InternalDouble();
	if ( when->Type()->Tag() == TYPE_INTERVAL )
		dt += network_time;

	val_list* args = eval_list(f, event->Args());

	if ( args )
		{
		TimerMgr* tmgr = mgr.CurrentTimerMgr();

		if ( ! tmgr )
			tmgr = timer_mgr;

		tmgr->Add(new ScheduleTimer(event->Handler(), args, dt, tmgr));
		}

	Unref(when_val);

	return 0;
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

IMPLEMENT_SERIAL(ScheduleExpr, SER_SCHEDULE_EXPR);

bool ScheduleExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_SCHEDULE_EXPR, Expr);
	return when->Serialize(info) && event->Serialize(info);
	}

bool ScheduleExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Expr);

	when = Expr::Unserialize(info);
	if ( ! when )
		return false;

	event = (EventExpr*) Expr::Unserialize(info, EXPR_EVENT);
	return event != 0;
	}

InExpr::InExpr(Expr* arg_op1, Expr* arg_op2)
: BinaryExpr(EXPR_IN, arg_op1, arg_op2)
	{
	if ( IsError() )
		return;

	if ( op1->Type()->Tag() == TYPE_PATTERN )
		{
		if ( op2->Type()->Tag() != TYPE_STRING )
			{
			op2->Type()->Error("pattern requires string index", op1);
			SetError();
			}
		else
			SetType(base_type(TYPE_BOOL));
		}

	else if ( op1->Type()->Tag() == TYPE_RECORD )
		{
		if ( op2->Type()->Tag() != TYPE_TABLE )
			{
			op2->Type()->Error("table/set required");
			SetError();
			}

		else
			{
			const BroType* t1 = op1->Type();
			const TypeList* it =
				op2->Type()->AsTableType()->Indices();

			if ( ! same_type(t1, it) )
				{
				t1->Error("indexing mismatch", op2->Type());
				SetError();
				}
			else
				SetType(base_type(TYPE_BOOL));
			}
		}

	else if ( op1->Type()->Tag() == TYPE_STRING &&
		  op2->Type()->Tag() == TYPE_STRING )
		SetType(base_type(TYPE_BOOL));

	else
		{
		// Check for:	<addr> in <subnet>
		//		<addr> in set[subnet]
		//		<addr> in table[subnet] of ...
		if ( op1->Type()->Tag() == TYPE_ADDR )
			{
			if ( op2->Type()->Tag() == TYPE_SUBNET )
				{
				SetType(base_type(TYPE_BOOL));
				return;
				}

			if ( op2->Type()->Tag() == TYPE_TABLE &&
			     op2->Type()->AsTableType()->IsSubNetIndex() )
				{
				SetType(base_type(TYPE_BOOL));
				return;
				}
			}

		if ( op1->Tag() != EXPR_LIST )
			op1 = new ListExpr(op1);

		ListExpr* lop1 = op1->AsListExpr();

		if ( ! op2->Type()->MatchesIndex(lop1) )
			SetError("not an index type");
		else
			{
			op1 = lop1;
			SetType(base_type(TYPE_BOOL));
			}
		}
	}

Val* InExpr::Fold(Val* v1, Val* v2) const
	{
	if ( v1->Type()->Tag() == TYPE_PATTERN )
		{
		RE_Matcher* re = v1->AsPattern();
		const BroString* s = v2->AsString();
		return new Val(re->MatchAnywhere(s) != 0, TYPE_BOOL);
		}

	if ( v2->Type()->Tag() == TYPE_STRING )
		{
		const BroString* s1 = v1->AsString();
		const BroString* s2 = v2->AsString();

		// Could do better here - either roll our own, to deal with
		// NULs, and/or Boyer-Moore if done repeatedly.
		return new Val(strstr(s2->CheckString(), s1->CheckString()) != 0, TYPE_BOOL);
		}

	if ( v1->Type()->Tag() == TYPE_ADDR &&
	     v2->Type()->Tag() == TYPE_SUBNET )
		return new Val(v2->AsSubNetVal()->Contains(v1->AsAddr()), TYPE_BOOL);

	TableVal* vt = v2->AsTableVal();
	if ( vt->Lookup(v1, false) )
		return new Val(1, TYPE_BOOL);
	else
		return new Val(0, TYPE_BOOL);
	}

IMPLEMENT_SERIAL(InExpr, SER_IN_EXPR);

bool InExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_IN_EXPR, BinaryExpr);
	return true;
	}

bool InExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BinaryExpr);
	return true;
	}

CallExpr::CallExpr(Expr* arg_func, ListExpr* arg_args, bool in_hook)
: Expr(EXPR_CALL)
	{
	func = arg_func;
	args = arg_args;

	if ( func->IsError() || args->IsError() )
		{
		SetError();
		return;
		}

	BroType* func_type = func->Type();
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

	if ( ! func_type->MatchesIndex(args) )
		SetError("argument type mismatch in function call");
	else
		{
		BroType* yield = func_type->YieldType();

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
			SetType(yield->Ref());

		// Check for call to built-ins that can be statically
		// analyzed.
		Val* func_val;
		if ( func->Tag() == EXPR_NAME &&
		     // This is cheating, but without it processing gets
		     // quite confused regarding "value used but not set"
		     // run-time errors when we apply this analysis during
		     // parsing.  Really we should instead do it after we've
		     // parsed the entire set of scripts.
		     streq(((NameExpr*) func)->Id()->Name(), "fmt") &&
		     // The following is needed because fmt might not yet
		     // be bound as a name.
		     did_builtin_init &&
		     (func_val = func->Eval(0)) )
			{
			::Func* f = func_val->AsFunc();
			if ( f->GetKind() == Func::BUILTIN_FUNC &&
			     ! check_built_in_call((BuiltinFunc*) f, this) )
				SetError();
			}
		}
	}

CallExpr::~CallExpr()
	{
	Unref(func);
	Unref(args);
	}

int CallExpr::IsPure() const
	{
	if ( IsError() )
		return 1;

	if ( ! func->IsPure() )
		return 0;

	Val* func_val = func->Eval(0);
	if ( ! func_val )
		return 0;

	::Func* f = func_val->AsFunc();

	// Only recurse for built-in functions, as recursing on script
	// functions can lead to infinite recursion if the function being
	// called here happens to be recursive (either directly
	// or indirectly).
	int pure = 0;
	if ( f->GetKind() == Func::BUILTIN_FUNC )
		pure = f->IsPure() && args->IsPure();
	Unref(func_val);

	return pure;
	}

Expr* CallExpr::Simplify(SimplifyType /* simp_type */)
	{
	if ( IsError() )
		return this;

	func = simplify_expr(func, SIMPLIFY_GENERAL);
	args = simplify_expr_list(args, SIMPLIFY_GENERAL);

	if ( IsPure() )
		return new ConstExpr(Eval(0));
	else
		return this;
	}

Val* CallExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return 0;

	// If we are inside a trigger condition, we may have already been
	// called, delayed, and then produced a result which is now cached.
	// Check for that.
	if ( f )
		{
		Trigger* trigger = f->GetTrigger();

		if ( trigger )
			{
			Val* v = trigger->Lookup(this);
			if ( v )
				{
				DBG_LOG(DBG_NOTIFIERS,
					"%s: provides cached function result",
					trigger->Name());
				return v->Ref();
				}
			}
		}

	Val* ret = 0;
	Val* func_val = func->Eval(f);
	val_list* v = eval_list(f, args);

	if ( func_val && v )
		{
		const ::Func* func = func_val->AsFunc();
		calling_expr = this;
		const CallExpr* current_call = f ? f->GetCall() : 0;

		if ( f )
			f->SetCall(this);

		ret = func->Call(v, f); // No try/catch here; we pass exceptions upstream.

		if ( f )
			f->SetCall(current_call);

		// Don't Unref() the arguments, as Func::Call already did that.
		delete v;

		calling_expr = 0;
		}
	else
		delete_vals(v);

	Unref(func_val);

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

IMPLEMENT_SERIAL(CallExpr, SER_CALL_EXPR);

bool CallExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_CALL_EXPR, Expr);
	return func->Serialize(info) && args->Serialize(info);
	}

bool CallExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Expr);

	func = Expr::Unserialize(info);
	if ( ! func )
		return false;

	args = (ListExpr*) Expr::Unserialize(info, EXPR_LIST);
	return args != 0;
	}

EventExpr::EventExpr(const char* arg_name, ListExpr* arg_args)
: Expr(EXPR_EVENT)
	{
	name = arg_name;
	args = arg_args;

	EventHandler* h = event_registry->Lookup(name.c_str());
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

	FuncType* func_type = h->FType();
	if ( ! func_type )
		{
		Error("not an event");
		SetError();
		return;
		}

	if ( ! func_type->MatchesIndex(args) )
		SetError("argument type mismatch in event invocation");
	else
		{
		if ( func_type->YieldType() )
			{
			Error("function invoked as an event");
			SetError();
			}
		}
	}

EventExpr::~EventExpr()
	{
	Unref(args);
	}

Expr* EventExpr::Simplify(SimplifyType /* simp_type */)
	{
	if ( ! IsError() )
		args = simplify_expr_list(args, SIMPLIFY_GENERAL);

	return this;
	}

Val* EventExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return 0;

	val_list* v = eval_list(f, args);
	mgr.QueueEvent(handler, v);

	return 0;
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

IMPLEMENT_SERIAL(EventExpr, SER_EVENT_EXPR);

bool EventExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_EVENT_EXPR, Expr);

	if ( ! handler->Serialize(info) )
		return false;

	return SERIALIZE(name) && args->Serialize(info);
	}

bool EventExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Expr);

	EventHandler* h = EventHandler::Unserialize(info);
	if ( ! h )
		return false;

	handler = h;

	if ( ! UNSERIALIZE(&name) )
		return false;

	args = (ListExpr*) Expr::Unserialize(info, EXPR_LIST);
	return args;
	}

ListExpr::ListExpr() : Expr(EXPR_LIST)
	{
	SetType(new TypeList());
	}

ListExpr::ListExpr(Expr* e) : Expr(EXPR_LIST)
	{
	SetType(new TypeList());
	Append(e);
	}

ListExpr::~ListExpr()
	{
	loop_over_list(exprs, i)
		Unref(exprs[i]);
	}

void ListExpr::Append(Expr* e)
	{
	exprs.append(e);
	((TypeList*) type)->Append(e->Type()->Ref());
	}

int ListExpr::IsPure() const
	{
	loop_over_list(exprs, i)
		if ( ! exprs[i]->IsPure() )
			return 0;

	return 1;
	}

int ListExpr::AllConst() const
	{
	loop_over_list(exprs, i)
		if ( ! exprs[i]->IsConst() )
			return 0;

	return 1;
	}

Expr* ListExpr::Simplify(SimplifyType /* simp_type */)
	{
	loop_over_list(exprs, i)
		exprs.replace(i, simplify_expr(exprs[i], SIMPLIFY_GENERAL));

	// Note that we do *not* simplify a list with one element
	// to just that element.  The assumption that simplify_expr(ListExpr*)
	// returns a ListExpr* is widespread.
	return this;
	}

Val* ListExpr::Eval(Frame* f) const
	{
	ListVal* v = new ListVal(TYPE_ANY);

	loop_over_list(exprs, i)
		{
		Val* ev = exprs[i]->Eval(f);
		if ( ! ev )
			{
			Error("uninitialized list value");
			Unref(v);
			return 0;
			}

		v->Append(ev);
		}

	return v;
	}

BroType* ListExpr::InitType() const
	{
	if ( exprs.length() == 0 )
		{
		Error("empty list in untyped initialization");
		return 0;
		}

	if ( exprs[0]->IsRecordElement(0) )
		{
		type_decl_list* types = new type_decl_list;
		loop_over_list(exprs, i)
			{
			TypeDecl* td = new TypeDecl(0, 0);
			if ( ! exprs[i]->IsRecordElement(td) )
				{
				exprs[i]->Error("record element expected");
				delete td;
				delete types;
				return 0;
				}

			types->append(td);
			}


		return new RecordType(types);
		}

	else
		{
		TypeList* tl = new TypeList();
		loop_over_list(exprs, i)
			{
			Expr* e = exprs[i];
			BroType* ti = e->Type();

			// Collapse any embedded sets or lists.
			if ( ti->IsSet() || ti->Tag() == TYPE_LIST )
				{
				TypeList* til = ti->IsSet() ?
					ti->AsSetType()->Indices() :
					ti->AsTypeList();

				if ( ! til->IsPure() ||
				     ! til->AllMatch(til->PureType(), 1) )
					tl->Append(til->Ref());
				else
					tl->Append(til->PureType()->Ref());
				}
			else
				tl->Append(ti->Ref());
			}

		return tl;
		}
	}

Val* ListExpr::InitVal(const BroType* t, Val* aggr) const
	{
	// While fairly similar to the EvalIntoAggregate() code,
	// we keep this separate since it also deals with initialization
	// idioms such as embedded aggregates and cross-product
	// expansion.
	if ( IsError() )
		return 0;

	// Check whether each element of this list itself matches t,
	// in which case we should expand as a ListVal.
	if ( ! aggr && type->AsTypeList()->AllMatch(t, 1) )
		{
		ListVal* v = new ListVal(TYPE_ANY);

		const type_list* tl = type->AsTypeList()->Types();
		if ( exprs.length() != tl->length() )
			{
			Error("index mismatch", t);
			Unref(v);
			return 0;
			}

		loop_over_list(exprs, i)
			{
			Val* vi = exprs[i]->InitVal((*tl)[i], 0);
			if ( ! vi )
				{
				Unref(v);
				return 0;
				}
				
			v->Append(vi);
			}
		return v;
		}

	if ( t->Tag() == TYPE_LIST )
		{
		if ( aggr )
			{
			Error("bad use of list in initialization", t);
			return 0;
			}

		const type_list* tl = t->AsTypeList()->Types();
		if ( exprs.length() != tl->length() )
			{
			Error("index mismatch", t);
			return 0;
			}

		ListVal* v = new ListVal(TYPE_ANY);
		loop_over_list(exprs, i)
			{
			Val* vi = exprs[i]->InitVal((*tl)[i], 0);
			if ( ! vi )
				{
				Unref(v);
				return 0;
				}
			v->Append(vi);
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
			return 0;
			}
		}

	if ( ! aggr )
		Internal("missing aggregate in ListExpr::InitVal");

	if ( t->IsSet() )
		return AddSetInit(t, aggr);

	if ( t->Tag() == TYPE_VECTOR )
		{
		// v: vector = [10, 20, 30];
		VectorVal* vec = aggr->AsVectorVal();

		loop_over_list(exprs, i)
			{
			Expr* e = exprs[i];
			check_and_promote_expr(e, vec->Type()->AsVectorType()->YieldType());
			Val* v = e->Eval(0);
			if ( ! vec->Assign(i, v) )
				{
				e->Error(fmt("type mismatch at index %d", i));
				return 0;
				}
			}

		return aggr;
		}

	// If we got this far, then it's either a table or record
	// initialization.  Both of those involve AssignExpr's, which
	// know how to add themselves to a table or record.  Another
	// possibility is an expression that evaluates itself to a
	// table, which we can then add to the aggregate.
	loop_over_list(exprs, i)
		{
		Expr* e = exprs[i];

		if ( e->Tag() == EXPR_ASSIGN || e->Tag() == EXPR_FIELD_ASSIGN )
			{
			if ( ! e->InitVal(t, aggr) )
				return 0;
			}
		else
			{
			if ( t->Tag() == TYPE_RECORD )
				{
				e->Error("bad record initializer", t);
				return 0;
				}

			Val* v = e->Eval(0);
			if ( ! same_type(v->Type(), t) )
				{
				v->Type()->Error("type clash in table initializer", t);
				return 0;
				}

			if ( ! v->AsTableVal()->AddTo(aggr->AsTableVal(), 1) )
				return 0;
			}
		}

	return aggr;
	}

Val* ListExpr::AddSetInit(const BroType* t, Val* aggr) const
	{
	if ( aggr->Type()->Tag() != TYPE_TABLE )
		Internal("bad aggregate in ListExpr::InitVal");

	TableVal* tv = aggr->AsTableVal();
	const TableType* tt = tv->Type()->AsTableType();
	const TypeList* it = tt->Indices();

	loop_over_list(exprs, i)
		{
		Val* element;

		if ( exprs[i]->Type()->IsSet() )
			// A set to flatten.
			element = exprs[i]->Eval(0);
		else if ( exprs[i]->Type()->Tag() == TYPE_LIST )
			element = exprs[i]->InitVal(it, 0);
		else
			element = exprs[i]->InitVal((*it->Types())[0], 0);

		if ( ! element )
			return 0;

		if ( element->Type()->IsSet() )
			{
			if ( ! same_type(element->Type(), t) )
				{
				element->Error("type clash in set initializer", t);
				return 0;
				}

			if ( ! element->AsTableVal()->AddTo(tv, 1) )
				return 0;

			continue;
			}

		if ( exprs[i]->Type()->Tag() == TYPE_LIST )
			element = check_and_promote(element, it, 1);
		else
			element = check_and_promote(element, (*it->Types())[0], 1);

		if ( ! element )
			return 0;

		if ( ! tv->ExpandAndInit(element, 0) )
			{
			Unref(element);
			Unref(tv);
			return 0;
			}

		Unref(element);
		}

	return tv;
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

Expr* ListExpr::MakeLvalue()
	{
	loop_over_list(exprs, i)
		if ( exprs[i]->Tag() != EXPR_NAME )
			ExprError("can only assign to list of identifiers");

	return new RefExpr(this);
	}

void ListExpr::Assign(Frame* f, Val* v, Opcode op)
	{
	ListVal* lv = v->AsListVal();

	if ( exprs.length() != lv->Vals()->length() )
		ExprError("mismatch in list lengths");

	loop_over_list(exprs, i)
		exprs[i]->Assign(f, (*lv->Vals())[i]->Ref(), op);

	Unref(lv);
	}

TraversalCode ListExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	loop_over_list(exprs, i)
		{
		tc = exprs[i]->Traverse(cb);
		HANDLE_TC_EXPR_PRE(tc);
		}

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}

IMPLEMENT_SERIAL(ListExpr, SER_LIST_EXPR);

bool ListExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_LIST_EXPR, Expr);

	if ( ! SERIALIZE(exprs.length()) )
		return false;

	loop_over_list(exprs, i)
		if ( ! exprs[i]->Serialize(info) )
			return false;

	return true;
	}

bool ListExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Expr);

	int len;
	if ( ! UNSERIALIZE(&len) )
		return false;

	while ( len-- )
		{
		Expr* e = Expr::Unserialize(info);
		if ( ! e )
			return false;

		exprs.append(e);
		}

	return true;
	}

RecordAssignExpr::RecordAssignExpr(Expr* record, Expr* init_list, int is_init)
	{
	const expr_list& inits = init_list->AsListExpr()->Exprs();

	RecordType* lhs = record->Type()->AsRecordType();

	// The inits have two forms:
	// 1) other records -- use all matching field names+types
	// 2) a string indicating the field name, then (as the next element)
	//    the value to use for that field.

	for ( int i = 0; i < inits.length(); ++i )
		{
		if ( inits[i]->Type()->Tag() == TYPE_RECORD )
			{
			RecordType* t = inits[i]->Type()->AsRecordType();

			for ( int j = 0; j < t->NumFields(); ++j )
				{
				const char* field_name = t->FieldName(j);
				int field = lhs->FieldOffset(field_name);

				if ( field >= 0 &&
				     same_type(lhs->FieldType(field), t->FieldType(j)) )
					{
					FieldExpr* fe_lhs = new FieldExpr(record, field_name);
					FieldExpr* fe_rhs = new FieldExpr(inits[i], field_name);
					Append(get_assign_expr(fe_lhs->Ref(), fe_rhs->Ref(), is_init));
					}
				}
			}

		else if ( inits[i]->Tag() == EXPR_FIELD_ASSIGN )
			{
			FieldAssignExpr* rf = (FieldAssignExpr*) inits[i];
			rf->Ref();

			const char* field_name = ""; // rf->FieldName();
			if ( lhs->HasField(field_name) )
				{
				FieldExpr* fe_lhs = new FieldExpr(record, field_name);
				Expr* fe_rhs = rf->Op();
				Append(get_assign_expr(fe_lhs->Ref(), fe_rhs, is_init));
				}
			else
				{
				string s = "No such field '";
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

IMPLEMENT_SERIAL(RecordAssignExpr, SER_RECORD_ASSIGN_EXPR);

bool RecordAssignExpr::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_RECORD_ASSIGN_EXPR, ListExpr);
	return true;
	}

bool RecordAssignExpr::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(ListExpr);
	return true;
	}

Expr* get_assign_expr(Expr* op1, Expr* op2, int is_init)
	{
	if ( op1->Type()->Tag() == TYPE_RECORD &&
	     op2->Type()->Tag() == TYPE_LIST )
		return new RecordAssignExpr(op1, op2, is_init);
	else
		return new AssignExpr(op1, op2, is_init);
	}


int check_and_promote_expr(Expr*& e, BroType* t)
	{
	BroType* et = e->Type();
	TypeTag e_tag = et->Tag();
	TypeTag t_tag = t->Tag();

	if ( t->Tag() == TYPE_ANY )
		return 1;

	if ( EitherArithmetic(t_tag, e_tag) )
		{
		if ( e_tag == t_tag )
			return 1;

		if ( ! BothArithmetic(t_tag, e_tag) )
			{
			t->Error("arithmetic mixed with non-arithmetic", e);
			return 0;
			}

		TypeTag mt = max_type(t_tag, e_tag);
		if ( mt != t_tag )
			{
			t->Error("over-promotion of arithmetic value", e);
			return 0;
			}

		e = new ArithCoerceExpr(e, t_tag);
		return 1;
		}

	if ( t->Tag() == TYPE_RECORD && et->Tag() == TYPE_RECORD )
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

				if ( same_attrs(td1->attrs, td2->attrs) )
					// Everything matches perfectly.
					return 1;
				}
			}

		if ( record_promotion_compatible(t_r, et_r) )
			{
			e = new RecordCoerceExpr(e, t_r);
			return 1;
			}

		t->Error("incompatible record types", e);
		return 0;
		}


	if ( ! same_type(t, et) )
		{
		if ( t->Tag() == TYPE_TABLE && et->Tag() == TYPE_TABLE &&
			  et->AsTableType()->IsUnspecifiedTable() )
			{
			e = new TableCoerceExpr(e, t->AsTableType());
			return 1;
			}

		if ( t->Tag() == TYPE_VECTOR && et->Tag() == TYPE_VECTOR &&
		     et->AsVectorType()->IsUnspecifiedVector() )
			{
			e = new VectorCoerceExpr(e, t->AsVectorType());
			return 1;
			}

		t->Error("type clash", e);
		return 0;
		}

	return 1;
	}

int check_and_promote_exprs(ListExpr*& elements, TypeList* types)
	{
	expr_list& el = elements->Exprs();
	const type_list* tl = types->Types();

	if ( tl->length() == 1 && (*tl)[0]->Tag() == TYPE_ANY )
		return 1;

	if ( el.length() != tl->length() )
		{
		types->Error("indexing mismatch", elements);
		return 0;
		}

	loop_over_list(el, i)
		{
		Expr* e = el[i];
		if ( ! check_and_promote_expr(e, (*tl)[i]) )
			{
			e->Error("type mismatch", (*tl)[i]);
			return 0;
			}

		if ( e != el[i] )
			el.replace(i, e);
		}

	return 1;
	}

int check_and_promote_args(ListExpr*& args, RecordType* types)
	{
	expr_list& el = args->Exprs();
	int ntypes = types->NumFields();

	// give variadic BIFs automatic pass
	if ( ntypes == 1 && types->FieldDecl(0)->type->Tag() == TYPE_ANY )
		return 1;

	if ( el.length() < ntypes )
		{
		expr_list def_elements;

		// Start from rightmost parameter, work backward to fill in missing
		// arguments using &default expressions.
		for ( int i = ntypes - 1; i >= el.length(); --i )
			{
			TypeDecl* td = types->FieldDecl(i);
			Attr* def_attr = td->attrs ? td->attrs->FindAttr(ATTR_DEFAULT) : 0;

			if ( ! def_attr )
				{
				types->Error("parameter mismatch", args);
				return 0;
				}

			def_elements.insert(def_attr->AttrExpr());
			}

		loop_over_list(def_elements, i)
			el.append(def_elements[i]->Ref());
		}

	TypeList* tl = new TypeList();

	for ( int i = 0; i < types->NumFields(); ++i )
		tl->Append(types->FieldType(i)->Ref());

	int rval = check_and_promote_exprs(args, tl);
	Unref(tl);

	return rval;
	}

int check_and_promote_exprs_to_type(ListExpr*& elements, BroType* type)
	{
	expr_list& el = elements->Exprs();

	if ( type->Tag() == TYPE_ANY )
		return 1;

	loop_over_list(el, i)
		{
		Expr* e = el[i];
		if ( ! check_and_promote_expr(e, type) )
			{
			e->Error("type mismatch", type);
			return 0;
			}

		if ( e != el[i] )
			el.replace(i, e);
		}

	return 1;
	}

Expr* simplify_expr(Expr* e, SimplifyType simp_type)
	{
	if ( ! e )
		return 0;

	for ( Expr* s = e->Simplify(simp_type); s != e; s = e->Simplify(simp_type) )
		{
		Unref(e);
		e = s;
		}

	return e;
	}

ListExpr* simplify_expr_list(ListExpr* l, SimplifyType simp_type)
	{
	return (ListExpr*) simplify_expr(l, simp_type);
	}

val_list* eval_list(Frame* f, const ListExpr* l)
	{
	const expr_list& e = l->Exprs();
	val_list* v = new val_list(e.length());

	loop_over_list(e, i)
		{
		Val* ev = e[i]->Eval(f);
		if ( ! ev )
			break;
		v->append(ev);
		}

	if ( i < e.length() )
		{ // Failure.
		loop_over_list(*v, j)
			Unref((*v)[j]);
		delete v;
		return 0;
		}

	else
		return v;
	}

int same_expr(const Expr* e1, const Expr* e2)
	{
	if ( e1 == e2 )
		return 1;

	if ( e1->Tag() != e2->Tag() || ! same_type(e1->Type(), e2->Type()) )
		return 0;

	if ( e1->IsError() || e2->IsError() )
		return 0;

	switch ( e1->Tag() ) {
	case EXPR_NAME:
		{
		const NameExpr* n1 = (NameExpr*) e1;
		const NameExpr* n2 = (NameExpr*) e2;
		return n1->Id() == n2->Id();
		}

	case EXPR_CONST:
		{
		const ConstExpr* c1 = (ConstExpr*) e1;
		const ConstExpr* c2 = (ConstExpr*) e2;
		return same_val(c1->Value(), c2->Value());
		}

	case EXPR_INCR:
	case EXPR_DECR:
	case EXPR_NOT:
	case EXPR_NEGATE:
	case EXPR_POSITIVE:
	case EXPR_REF:
	case EXPR_RECORD_CONSTRUCTOR:
	case EXPR_TABLE_CONSTRUCTOR:
	case EXPR_SET_CONSTRUCTOR:
	case EXPR_VECTOR_CONSTRUCTOR:
	case EXPR_FIELD_ASSIGN:
	case EXPR_ARITH_COERCE:
	case EXPR_RECORD_COERCE:
	case EXPR_TABLE_COERCE:
	case EXPR_FLATTEN:
		{
		const UnaryExpr* u1 = (UnaryExpr*) e1;
		const UnaryExpr* u2 = (UnaryExpr*) e2;
		return same_expr(u1->Op(), u2->Op());
		}

	case EXPR_FIELD:
		{
		const FieldExpr* f1 = (FieldExpr*) e1;
		const FieldExpr* f2 = (FieldExpr*) e2;
		return same_expr(f1->Op(), f2->Op()) &&
			f1->Field() == f2->Field();
		}

	case EXPR_SCHEDULE:
		{
		const ScheduleExpr* s1 = (ScheduleExpr*) e1;
		const ScheduleExpr* s2 = (ScheduleExpr*) e2;
		return same_expr(s1->When(), s2->When()) &&
			same_expr(s1->Event(), s2->Event());
		}

	case EXPR_ADD:
	case EXPR_ADD_TO:
	case EXPR_SUB:
	case EXPR_REMOVE_FROM:
	case EXPR_TIMES:
	case EXPR_DIVIDE:
	case EXPR_MOD:
	case EXPR_AND:
	case EXPR_OR:
	case EXPR_LT:
	case EXPR_LE:
	case EXPR_EQ:
	case EXPR_NE:
	case EXPR_GE:
	case EXPR_GT:
	case EXPR_ASSIGN:
	case EXPR_MATCH:
	case EXPR_INDEX:
	case EXPR_IN:
		{
		const BinaryExpr* b1 = (BinaryExpr*) e1;
		const BinaryExpr* b2 = (BinaryExpr*) e2;
		return same_expr(b1->Op1(), b2->Op1()) &&
			same_expr(b1->Op2(), b2->Op2());
		}

	case EXPR_LIST:
		{
		const ListExpr* l1 = (ListExpr*) e1;
		const ListExpr* l2 = (ListExpr*) e2;

		const expr_list& le1 = l1->Exprs();
		const expr_list& le2 = l2->Exprs();

		if ( le1.length() != le2.length() )
			return 0;

		loop_over_list(le1, i)
			if ( ! same_expr(le1[i], le2[i]) )
				return 0;

		return 1;
		}

	case EXPR_CALL:
		{
		const CallExpr* c1 = (CallExpr*) e1;
		const CallExpr* c2 = (CallExpr*) e2;

		return same_expr(c1->Func(), c2->Func()) &&
			c1->IsPure() && same_expr(c1->Args(), c2->Args());
		}

	default:
		reporter->InternalError("bad tag in same_expr()");
	}

	return 0;
	}

int expr_greater(const Expr* e1, const Expr* e2)
	{
	return int(e1->Tag()) > int(e2->Tag());
	}

static Expr* make_constant(BroType* t, double d)
	{
	Val* v = 0;
	switch ( t->InternalType() ) {
	case TYPE_INTERNAL_INT:		v = new Val(bro_int_t(d), t->Tag()); break;
	case TYPE_INTERNAL_UNSIGNED:	v = new Val(bro_uint_t(d), t->Tag()); break;
	case TYPE_INTERNAL_DOUBLE:	v = new Val(double(d), t->Tag()); break;

	default:
		reporter->InternalError("bad type in make_constant()");
	}

	return new ConstExpr(v);
	}

Expr* make_zero(BroType* t)
	{
	return make_constant(t, 0.0);
	}

Expr* make_one(BroType* t)
	{
	return make_constant(t, 1.0);
	}
