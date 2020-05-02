// See the file "COPYING" in the main distribution directory for copyright.

#include "Compile.h"
#include "Expr.h"
#include "RE.h"
#include "OpaqueVal.h"
#include "Desc.h"
#include "Reporter.h"
#include "Traverse.h"


typedef enum {
	OP_NOP,

#include "CompilerOpsDefs.h"

} AbstractOp;

const char* abstract_op_name(AbstractOp op)
	{
	switch ( op ) {
	case OP_NOP:	return "nop";

#include "CompilerOpsNamesDefs.h"
	}
	}


// A bit of this mirrors BroValUnion, but it captures low-level
// representation whereas we aim to keep Val structure for
// more complex Val's.
union AS_ValUnion {
	// Constructor for hand-populating the values.
	AS_ValUnion() {}

	// Construct from a given Bro value with a given type.
	AS_ValUnion(Val* v, BroType* t);

	// Convert to a Bro value.
	IntrusivePtr<Val> ToVal(BroType* t) const;

	// Used for bool, int.
	bro_int_t int_val;

	// Used for count, counter.
	bro_uint_t uint_val;

	// Used for double, time, interval.  While IntervalVal's are
	// distinct, we can readily recover them given type information.
	double double_val;

	// For this we assume we have ownership of the value, so
	// it gets delete'd prior to reassignment.
	BroString* string_val;

	IPAddr* addr_val;
	IPPrefix* subnet_val;

	// A note re memory management.  We do *not* ref these upon
	// assigning to them.  If we use them in a context where ownership
	// will be taken by some other entity, we ref them at that point.
	// We also do not unref on reassignment/destruction.
	BroValUnion any_val;
	EnumVal* enum_val;
	BroFile* file_val;
	Func* func_val;
	ListVal* list_val;
	OpaqueVal* opaque_val;
	PortVal* port_val;
	RE_Matcher* re_val;
	RecordVal* record_val;
	TableVal* table_val;
	BroType* type_val;
	VectorVal* vector_val;
	vector<BroValUnion>* raw_vector_val;

	// Used for the compiler to hold opaque items.
	val_vec* vvec;
};

AS_ValUnion::AS_ValUnion(Val* v, BroType* t)
	{
	union BroValUnion vu = v->val;

	if ( v->Type()->Tag() != t->Tag() )
		reporter->InternalError("type inconsistency in AS_ValUnion constructor");

	switch ( t->Tag() ) {
	case TYPE_BOOL:
	case TYPE_INT:
		int_val = vu.int_val;
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		uint_val = vu.uint_val;
		break;

	case TYPE_DOUBLE:
	case TYPE_INTERVAL:
	case TYPE_TIME:
		double_val = vu.double_val;
		break;

	case TYPE_FUNC:		func_val = vu.func_val; break;
	case TYPE_FILE:		file_val = vu.file_val; break;

	case TYPE_ENUM:		enum_val = v->AsEnumVal(); break;
	case TYPE_LIST:		list_val = v->AsListVal(); break;
	case TYPE_OPAQUE:	opaque_val = v->AsOpaqueVal(); break;
	case TYPE_PATTERN:	re_val = v->AsPattern(); break;
	case TYPE_PORT:		port_val = v->AsPortVal(); break;
	case TYPE_RECORD:	record_val = v->AsRecordVal(); break;
	case TYPE_TABLE:	table_val = v->AsTableVal(); break;
	case TYPE_VECTOR:	vector_val = v->AsVectorVal(); break;

	// ### Need to think about memory management strategy and
	// whether we require the new BroString here.
	case TYPE_STRING:	string_val = new BroString(*v->AsString());
	case TYPE_ADDR:
		addr_val = new IPAddr(*vu.addr_val);
	case TYPE_SUBNET:
		subnet_val = new IPPrefix(*vu.subnet_val);
		break;

	case TYPE_ANY:		any_val = vu; break;
	case TYPE_TYPE:		type_val = t; break;

	case TYPE_ERROR:
	case TYPE_TIMER:
	case TYPE_UNION:
	case TYPE_VOID:
		reporter->InternalError("bad type in AS_ValUnion constructor");
	}
	}

IntrusivePtr<Val> AS_ValUnion::ToVal(BroType* t) const
	{
	Val* v;

	switch ( t->Tag() ) {
	case TYPE_INT:		v = new Val(int_val, TYPE_INT); break;
	case TYPE_BOOL:		v = Val::MakeBool(int_val); break;
	case TYPE_COUNT:	v = new Val(uint_val, TYPE_COUNT); break;
	case TYPE_COUNTER:	v = new Val(uint_val, TYPE_COUNTER); break;
	case TYPE_DOUBLE:	v = new Val(double_val, TYPE_DOUBLE); break;
	case TYPE_INTERVAL:	v = new IntervalVal(double_val, 1.0); break;
	case TYPE_TIME:		v = new Val(double_val, TYPE_TIME); break;
	case TYPE_FUNC:		v = new Val(func_val); break;
	case TYPE_FILE:		v = new Val(file_val); break;
	case TYPE_STRING:	v = new StringVal(new BroString(*string_val));
	case TYPE_ADDR:		v = new AddrVal(*addr_val); break;
	case TYPE_SUBNET:	v = new SubNetVal(*subnet_val); break;
	case TYPE_PATTERN:	v = new PatternVal(re_val); break;

	case TYPE_ANY:		v = new Val(any_val, t->Ref()); break;
	case TYPE_TYPE:		v = new Val(type_val, true); break;

	case TYPE_ENUM:		v = enum_val; v->Ref(); break;
	case TYPE_LIST:		v = list_val; v->Ref(); break;
	case TYPE_OPAQUE:	v = opaque_val; v->Ref(); break;
	case TYPE_PORT:		v = port_val; v->Ref(); break;
	case TYPE_RECORD:	v = record_val; v->Ref(); break;
	case TYPE_TABLE:	v = table_val; v->Ref(); break;
	case TYPE_VECTOR:	v = vector_val; v->Ref(); break;

	case TYPE_ERROR:
	case TYPE_TIMER:
	case TYPE_UNION:
	case TYPE_VOID:
		reporter->InternalError("bad ret type return tag");
	}

	return {AdoptRef{}, v};
	}

// Possible types of statement operands in terms of which
// fields they use.  Used for dumping statements.
typedef enum {
	OP_X, OP_V, OP_VV, OP_VVV, OP_VVVV, OP_C, OP_VC, OP_VVC, OP_VE,
} AS_OpType;

class AbstractStmt {
public:
	AbstractStmt(AbstractOp _op)
		{
		op = _op;
		op_type = OP_X;
		}

	AbstractStmt(AbstractOp _op, int _v1)
		{
		op = _op;
		v1 = _v1;
		op_type = OP_V;
		}

	AbstractStmt(AbstractOp _op, int _v1, int _v2)
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		op_type = OP_VV;
		}

	AbstractStmt(AbstractOp _op, int _v1, int _v2, int _v3)
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		v3 = _v3;
		op_type = OP_VVV;
		}

	AbstractStmt(AbstractOp _op, int _v1, int _v2, int _v3, int _v4)
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		v3 = _v3;
		v4 = _v4;
		op_type = OP_VVVV;
		}

	AbstractStmt(AbstractOp _op, const ConstExpr* ce)
		{
		op = _op;
		op_type = OP_C;
		InitConst(ce);
		}

	AbstractStmt(AbstractOp _op, int _v1, const ConstExpr* ce)
		{
		op = _op;
		v1 = _v1;
		op_type = OP_VC;
		InitConst(ce);
		}

	AbstractStmt(AbstractOp _op, int _v1, int _v2, const ConstExpr* ce)
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		op_type = OP_VVC;
		InitConst(ce);
		}

	AbstractStmt(AbstractOp _op, int _v1, const Expr* _e)
		{
		op = _op;
		v1 = _v1;
		e = _e;
		t = e->Type().get();
		op_type = OP_VE;
		}

	// Constructor used when we're going to just copy in another AS.
	AbstractStmt() { }

	void Dump() const;
	const char* ConstDump() const;

	AbstractOp op;

	// Indices into frame.
	int v1, v2, v3, v4;
	BroType* t = nullptr;
	const Expr* e = nullptr;
	int* int_ptr = nullptr;

	AS_ValUnion c;	// constant

	AS_OpType op_type;

protected:
	void InitConst(const ConstExpr* ce)
		{
		auto v = ce->Value();
		auto ct = ce->Type().get();
		c = AS_ValUnion(v, ct);
		t = ct;
		}
};

void AbstractStmt::Dump() const
	{
	printf("%s ", abstract_op_name(op));

	switch ( op_type ) {
	case OP_X:
		break;

	case OP_V:
		printf("%d", v1);
		break;

	case OP_VV:
		printf("%d, %d", v1, v2);
		break;

	case OP_VVV:
		printf("%d, %d, %d", v1, v2, v3);
		break;

	case OP_VVVV:
		printf("%d, %d, %d, %d", v1, v2, v3, v4);
		break;

	case OP_C:
		printf("%s", ConstDump());
		break;

	case OP_VC:
		printf("%d, %s", v1, ConstDump());
		break;

	case OP_VVC:
		printf("%d, %d, %s", v1, v2, ConstDump());
		break;

	case OP_VE:
		printf("%d, %s", v1, obj_desc(e));
		break;
	}

	printf("\n");
	}

const char* AbstractStmt::ConstDump() const
	{
	auto v = c.ToVal(t);

	static ODesc d;

	d.Clear();
	v->Describe(&d);

	return d.Description();
	}

class OpaqueVals {
public:
	OpaqueVals(int _n)	{ n = _n; }

	int n;
};

// Helper functions, to translate NameExpr*'s to slots.  Some aren't
// needed, but we provide a complete set mirroring those for AbstractStmt
// for consistency.
AbstractStmt GenStmt(AbstractMachine* m, AbstractOp op)
	{
	return AbstractStmt(op);
	}

AbstractStmt GenStmt(AbstractMachine* m, AbstractOp op, const NameExpr* v1)
	{
	return AbstractStmt(op, m->FrameSlot(v1));
	}
AbstractStmt GenStmt(AbstractMachine* m, AbstractOp op, const NameExpr* v1,
			const NameExpr* v2)
	{
	return AbstractStmt(op, m->FrameSlot(v1), m->FrameSlot(v2));
	}
AbstractStmt GenStmt(AbstractMachine* m, AbstractOp op, const NameExpr* v1,
			const NameExpr* v2, const NameExpr* v3)
	{
	return AbstractStmt(op, m->FrameSlot(v1), m->FrameSlot(v2),
				m->FrameSlot(v3));
	}
AbstractStmt GenStmt(AbstractMachine* m, AbstractOp op, const NameExpr* v1,
			const NameExpr* v2, const NameExpr* v3,
			const NameExpr* v4)
	{
	return AbstractStmt(op, m->FrameSlot(v1), m->FrameSlot(v2),
				m->FrameSlot(v3), m->FrameSlot(v4));
	}
AbstractStmt GenStmt(AbstractMachine* m, AbstractOp op, const ConstExpr* ce)
	{
	return AbstractStmt(op, ce);
	}
AbstractStmt GenStmt(AbstractMachine* m, AbstractOp op, const NameExpr* v1,
			const ConstExpr* ce)
	{
	return AbstractStmt(op, m->FrameSlot(v1), ce);
	}
AbstractStmt GenStmt(AbstractMachine* m, AbstractOp op, const NameExpr* v1,
			const ConstExpr* ce, const NameExpr* v2)
	{
	return AbstractStmt(op, m->FrameSlot(v1), m->FrameSlot(v2), ce);
	}
AbstractStmt GenStmt(AbstractMachine* m, AbstractOp op, const NameExpr* v1,
			const NameExpr* v2, const ConstExpr* ce)
	{
	return AbstractStmt(op, m->FrameSlot(v1), m->FrameSlot(v2), ce);
	}
AbstractStmt GenStmt(AbstractMachine* m, AbstractOp op, const NameExpr* v1,
			const NameExpr* v2, int i)
	{
	return AbstractStmt(op, m->FrameSlot(v1), m->FrameSlot(v2), i);
	}


AbstractMachine::AbstractMachine(int _frame_size)
	{
	frame_size = _frame_size;
	frame = new AS_ValUnion[frame_size];
	}

AbstractMachine::~AbstractMachine()
	{
	delete frame;
	}

void AbstractMachine::StmtDescribe(ODesc* d) const
	{
	}

static void vec_exec(AbstractOp op, vector<BroValUnion>* v1,
			const vector<BroValUnion>* v2);

static void vec_exec(AbstractOp op, vector<BroValUnion>* v1,
			const vector<BroValUnion>* v2,
			const vector<BroValUnion>* v3);

// Vector coercion.
#define VEC_COERCE(tag, lhs_accessor, cast, rhs_accessor) \
	static vector<BroValUnion>*  vec_coerce_##tag(vector<BroValUnion>* v) \
		{ \
		vector<BroValUnion>* res = new vector<BroValUnion>; \
		for ( unsigned int i = 0; i < v->size(); ++i ) \
			(*res)[i].lhs_accessor = cast((*v)[i].rhs_accessor); \
		return res; \
		}

VEC_COERCE(IU, int_val, bro_int_t, uint_val)
VEC_COERCE(ID, int_val, bro_int_t, double_val)
VEC_COERCE(UI, uint_val, bro_int_t, int_val)
VEC_COERCE(UD, uint_val, bro_uint_t, double_val)
VEC_COERCE(DI, double_val, double, int_val)
VEC_COERCE(DU, double_val, double, uint_val)

static void run_time_error(const char* msg);

IntrusivePtr<Val> AbstractMachine::Exec(Frame* f, stmt_flow_type& flow) const
	{
	const AS_ValUnion* ret_u;
	Val* ret_v;
	BroType* ret_type;
	int pc = 0;

	auto loop = true;
	while ( loop ) {
		auto& s = stmts[pc];

		switch ( stmts[pc].op ) {
		case OP_NOP:
			break;

#include "CompilerOpsEvalDefs.h"
		}

		++pc;
		}

	if ( ret_u )
		return ret_u->ToVal(ret_type);
	else
		return nullptr;
	}

#include "CompilerOpsMethodsDefs.h"

const CompiledStmt AbstractMachine::InterpretExpr(const NameExpr* n,
							const Expr* e)
	{
	// ### need to flush any variables used in e!
	AbstractStmt s(OP_INTERPRET_EXPR_V, FrameSlot(n), e);
	}

const CompiledStmt AbstractMachine::ArithCoerce(const NameExpr* n,
						const Expr* e)
	{
	auto nt = n->Type();
	auto nt_is_vec = nt->Tag() == TYPE_VECTOR;

	auto op = e->GetOp1();
	auto op_t = op->Type().get();
	auto op_is_vec = op_t->Tag() == TYPE_VECTOR;

	auto e_t = e->Type().get();
	auto et_is_vec = e_t->Tag() == TYPE_VECTOR;

	if ( nt_is_vec || op_is_vec || et_is_vec )
		{
		if ( ! (nt_is_vec && op_is_vec && et_is_vec) )
			reporter->InternalError("vector confusion compiling coercion");

		op_t = op_t->AsVectorType()->YieldType();
		e_t = e_t->AsVectorType()->YieldType();
		}

	auto targ_it = e_t->InternalType();
	auto op_it = op_t->InternalType();

	if ( op_it == targ_it )
		reporter->InternalError("coercion wasn't folded");

	if ( op->Tag() != EXPR_NAME )
		reporter->InternalError("coercion wasn't folded");

	AbstractOp a;

	switch ( targ_it ) {
	case TYPE_INTERNAL_DOUBLE:
		{
		a = op_it == TYPE_INTERNAL_INT ?
			(nt_is_vec ? OP_COERCE_DI_VEC_VV : OP_COERCE_DI_VV) :
			(nt_is_vec ? OP_COERCE_DU_VEC_VV : OP_COERCE_DU_VV);
		break;
		}

	case TYPE_INTERNAL_INT:
		{
		a = op_it == TYPE_INTERNAL_UNSIGNED ?
			(nt_is_vec ? OP_COERCE_IU_VEC_VV : OP_COERCE_IU_VV) :
			(nt_is_vec ? OP_COERCE_ID_VEC_VV : OP_COERCE_ID_VV);
		break;
		}

	case TYPE_INTERNAL_UNSIGNED:
		{
		a = op_it == TYPE_INTERNAL_INT ?
			(nt_is_vec ? OP_COERCE_UI_VEC_VV : OP_COERCE_UI_VV) :
			(nt_is_vec ? OP_COERCE_UD_VEC_VV : OP_COERCE_UD_VV);
		break;
		}

	default:
		reporter->InternalError("bad target internal type in coercion");
	}

	auto n1 = FrameSlot(n);
	auto n2 = FrameSlot(op->AsNameExpr());
	return AddStmt(AbstractStmt(a, n1, n2));
	}

const CompiledStmt AbstractMachine::RecordCoerce(const NameExpr* n,
						const Expr* e)
	{
	auto r = e->AsRecordCoerceExpr();
	auto op = r->GetOp1()->AsNameExpr();
	auto map = r->Map();
	auto map_size = r->MapSize();

	AbstractStmt s(OP_RECORD_COERCE_VVV, FrameSlot(n), FrameSlot(op),
			map_size);

	s.t = e->Type().get();
	s.int_ptr = map;

	return AddStmt(s);
	}

const CompiledStmt AbstractMachine::TableCoerce(const NameExpr* n,
						const Expr* e)
	{
	auto op = e->GetOp1()->AsNameExpr();

	AbstractStmt s(OP_TABLE_COERCE_VV, FrameSlot(n), FrameSlot(op));
	s.t = e->Type().get();

	return AddStmt(s);
	}

const CompiledStmt AbstractMachine::VectorCoerce(const NameExpr* n,
						const Expr* e)
	{
	auto op = e->GetOp1()->AsNameExpr();

	AbstractStmt s(OP_VECTOR_COERCE_VV, FrameSlot(n), FrameSlot(op));
	s.t = e->Type().get();

	return AddStmt(s);
	}


const CompiledStmt AbstractMachine::StartingBlock()
	{
	return CompiledStmt(stmts.size());
	}

const CompiledStmt AbstractMachine::FinishBlock(const CompiledStmt /* start */)
	{
	return CompiledStmt(stmts.size());
	}

const CompiledStmt AbstractMachine::ErrorStmt()
	{
	error_seen = true;
	return CompiledStmt(0);
	}

OpaqueVals* AbstractMachine::BuildVals(const IntrusivePtr<ListExpr>& l)
	{
	return new OpaqueVals(InternalBuildVals(l.get()));
	}

int AbstractMachine::InternalBuildVals(const ListExpr* l)
	{
	auto exprs = l->Exprs();
	int n = exprs.length();
	auto tmp = RegisterSlot();

	(void) AddStmt(AbstractStmt(OP_CREATE_VAL_VEC_VV, tmp, n));

	for ( int i = 0; i < n; ++i )
		{
		const auto& e = exprs[i];

		AbstractStmt as;

		if ( e->Tag() == EXPR_NAME )
			{
			int v = FrameSlot(e);
			as = AbstractStmt(OP_SET_VAL_VEC_VV, tmp, v);
			}
		else
			{
			auto c = e->AsConstExpr();
			as = AbstractStmt(OP_SET_VAL_VEC_VC, tmp, c);
			}

		as.t = e->Type().get();
		(void) AddStmt(as);
		}

	return tmp;
	}

const CompiledStmt AbstractMachine::AddStmt(const AbstractStmt& stmt)
	{
	stmts.push_back(stmt);
	return CompiledStmt(stmts.size());
	}

void AbstractMachine::Dump()
	{
	for ( int i = 0; i < stmts.size(); ++i )
		{
		printf("%d: ", i);
		stmts[i].Dump();
		}
	}

const CompiledStmt AbstractMachine::CompileInExpr(const NameExpr* n1,
				const NameExpr* n2, const ConstExpr* c2,
				const NameExpr* n3, const ConstExpr* c3)
	{
	auto op2 = n2 ? (Expr*) n2 : (Expr*) c2;
	auto op3 = n3 ? (Expr*) n3 : (Expr*) c3;

	AbstractOp a;

	if ( op2->Type()->Tag() == TYPE_PATTERN )
		a = n2 ? (n3 ? OP_P_IN_S_VVV : OP_P_IN_S_VVC) : OP_P_IN_S_VCV;

	else if ( op2->Type()->Tag() == TYPE_STRING )
		a = n2 ? (n3 ? OP_S_IN_S_VVV : OP_S_IN_S_VVC) : OP_S_IN_S_VCV;

	else if ( op2->Type()->Tag() == TYPE_ADDR &&
		  op3->Type()->Tag() == TYPE_SUBNET )
		a = n2 ? (n3 ? OP_A_IN_S_VVV : OP_A_IN_S_VVC) : OP_A_IN_S_VCV;

	else if ( op3->Type()->Tag() == TYPE_VECTOR )
		a = n2 ? (n3 ? OP_U_IN_V_VVV : OP_U_IN_V_VVC) : OP_U_IN_V_VCV;

	else
		reporter->InternalError("bad types when compiling \"in\"");

	auto s1 = FrameSlot(n1);
	auto s2 = n2 ? FrameSlot(n2) : 0;
	auto s3 = n3 ? FrameSlot(n3) : 0;

	if ( n2 )
		{
		if ( n3 )
			return AddStmt(AbstractStmt(a, s1, s2, s3));
		else
			return AddStmt(AbstractStmt(a, s1, s2, c3));
		}
	else
		return AddStmt(AbstractStmt(a, s1, s3, c2));
	}

const CompiledStmt AbstractMachine::CompileInExpr(const NameExpr* n1,
				const ListExpr* l, const NameExpr* n2)
	{
	int n = l->Exprs().length();
	auto build_indices = InternalBuildVals(l);

	auto s = AbstractStmt(OP_TRANSFORM_VAL_VEC_TO_LIST_VAL_VVV,
				build_indices, build_indices, n);
	AddStmt(s);

	s = AbstractStmt(OP_IS_IN_TABLE_VVV, FrameSlot(n1), FrameSlot(n2),
				build_indices);

	return AddStmt(s);
	}

const CompiledStmt AbstractMachine::CompileIndex(const NameExpr* n1,
							const NameExpr* n2,
							const ListExpr* l)
	{
	AbstractStmt s;

	int n = l->Exprs().length();
	auto n2t = n2->Type()->Tag();

	if ( n == 1 && n2t == TYPE_STRING )
		{
		auto ind = l->Exprs()[0];
		if ( ind->Tag() == EXPR_NAME )
			{
			auto n3 = ind->AsNameExpr();
			s = AbstractStmt(OP_INDEX_STRING_VVV, FrameSlot(n1),
					FrameSlot(n2), FrameSlot(n3));
			}

		else
			{
			auto c = ind->AsConstExpr()->Value()->AsInt();
			s = AbstractStmt(OP_INDEX_STRINGC_VVV, FrameSlot(n1),
					FrameSlot(n2), c);
			}

		s.t = n1->Type().get();
		return AddStmt(s);
		}

	auto build_indices = InternalBuildVals(l);
	s = AbstractStmt(OP_TRANSFORM_VAL_VEC_TO_LIST_VAL_VVV,
				build_indices, build_indices, n);
	AddStmt(s);

	auto indexes = l->Exprs();

	switch ( n2->Type()->Tag() ) {
	case TYPE_VECTOR:
		{
		AbstractOp op =
			n == 1 ? OP_INDEX_VEC_VVL : OP_INDEX_VEC_SLICE_VVL;

		s = AbstractStmt(op, FrameSlot(n1), FrameSlot(n2),
					build_indices);
		break;
		}

	case TYPE_TABLE:
		s = AbstractStmt(OP_TABLE_INDEX_VVV, FrameSlot(n1),
					FrameSlot(n2), build_indices);
		s.t = n1->Type().get();
		break;

	case TYPE_STRING:
		s = AbstractStmt(OP_INDEX_STRING_SLICE_VVL, FrameSlot(n1),
					FrameSlot(n2), build_indices);
		break;

	default:
		reporter->InternalError("bad aggregate type when compiling index");
	}

	s.t = n1->Type().get();
	return AddStmt(s);
	}

void AbstractMachine::SyncGlobals()
	{
	// ###
	}

ListVal* AbstractMachine::ValVecToListVal(val_vec* v, int n) const
	{
	auto res = new ListVal(TYPE_ANY);

	for ( int i = 0; i < n; ++i )
		res->Append((*v)[i].release());

	delete v;

	return res;
	}

int AbstractMachine::FrameSlot(const ID* id)
	{
	// ###
	return 0;
	}

int AbstractMachine::FrameSlot(const Expr* e)
	{
	return FrameSlot(e->AsNameExpr()->Id());
	}

int AbstractMachine::RegisterSlot()
	{
	return 0;
	}


TraversalCode Compiler::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}


// Unary vector operation of v1 <vec-op> v2.
static void vec_exec(AbstractOp op, vector<BroValUnion>* v1,
			const vector<BroValUnion>* v2)
	{
	// We could speed this up further still by gen'ing up an
	// instance of the loop inside each switch case (in which
	// case we might as well move the whole kit-and-caboodle
	// into the Exec method).  But that seems like a lot of
	// code bloat for only a very modest gain.

	// ### need to deal with constructing v1 if doesn't already exist.

	for ( unsigned int i = 0; i < v2->size(); ++i )
		switch ( op ) {

#include "CompilerVec1EvalDefs.h"

		default:
			reporter->InternalError("bad invocation of VecExec");
		}
	}

// Binary vector operation of v1 = v2 <vec-op> v3.
static void vec_exec(AbstractOp op, vector<BroValUnion>* v1,
			const vector<BroValUnion>* v2,
			const vector<BroValUnion>* v3)
	{
	// See comment above re further speed-up.

	// ### need to deal with constructing v1 if doesn't already exist.

	for ( unsigned int i = 0; i < v2->size(); ++i )
		switch ( op ) {

#include "CompilerVec2EvalDefs.h"

		default:
			reporter->InternalError("bad invocation of VecExec");
		}
	}

static void run_time_error(const char* msg)
	{
	// ### Needs refinement!  In particular, probably should
	// lead to unwinding the entire current execution (up to
	// the original event handler).
	fprintf(stderr, "%s\n", msg);
	}
