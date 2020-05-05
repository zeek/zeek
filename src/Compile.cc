// See the file "COPYING" in the main distribution directory for copyright.

#include "Compile.h"
#include "CompHash.h"
#include "Expr.h"
#include "RE.h"
#include "OpaqueVal.h"
#include "EventHandler.h"
#include "Trigger.h"
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


struct IterInfo {
	TableVal* tv;
	const PDict<TableEntryVal>* loop_vals;
	IterCookie* c;
	BroType* value_var_type;
	vector<int> loop_vars;
	vector<BroType*> loop_var_types;

	VectorVal* vv;
	BroString* s;

	bro_uint_t iter;
	bro_uint_t n;	// we loop from 0 ... n-1
};

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
	Val* any_val;
	EnumVal* enum_val;
	BroFile* file_val;
	Func* func_val;
	ListVal* list_val;
	OpaqueVal* opaque_val;
	PortVal* port_val;
	PatternVal* re_val;
	RecordVal* record_val;
	TableVal* table_val;
	BroType* type_val;
	VectorVal* vector_val;
	vector<BroValUnion>* raw_vector_val;

	// Used for the compiler to hold opaque items.
	val_vec* vvec;

	// Used for managing "for" loops.
	IterInfo* iter_info;
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
	case TYPE_PATTERN:	re_val = v->AsPatternVal(); break;
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

	// ### Memory management.
	case TYPE_ANY:		any_val = v; break;
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

	// ### memory management
	case TYPE_ANY:		return {NewRef{}, any_val};

	case TYPE_TYPE:		v = new Val(type_val, true); break;

	case TYPE_ENUM:		v = enum_val; v->Ref(); break;
	case TYPE_LIST:		v = list_val; v->Ref(); break;
	case TYPE_OPAQUE:	v = opaque_val; v->Ref(); break;
	case TYPE_PORT:		v = port_val; v->Ref(); break;
	case TYPE_RECORD:	v = record_val; v->Ref(); break;
	case TYPE_TABLE:	v = table_val; v->Ref(); break;
	case TYPE_VECTOR:	v = vector_val; v->Ref(); break;
	case TYPE_PATTERN:	v = re_val; v->Ref(); break;

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
	OP_X, OP_V, OP_VV, OP_VVV, OP_VVVV, OP_VVVC, OP_C, OP_VC, OP_VVC,
	OP_E, OP_VE,
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

	AbstractStmt(AbstractOp _op, int _v1, int _v2, int _v3,
			const ConstExpr* ce)
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		v3 = _v3;
		op_type = OP_VVVC;
		InitConst(ce);
		}

	AbstractStmt(AbstractOp _op, const Expr* _e)
		{
		op = _op;
		e = _e;
		t = e->Type().get();
		op_type = OP_E;
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
	Expr* non_const_e = nullptr;
	int* int_ptr = nullptr;
	EventHandler* event_handler = nullptr;
	Attributes* attrs = nullptr;
	const Location* loc = nullptr;

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

	case OP_VVVC:
		printf("%d, %d, %d, %s", v1, v2, v3, ConstDump());
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

	case OP_E:
		printf("%s", obj_desc(e));
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
			const NameExpr* v2, const NameExpr* v3,
			const ConstExpr* ce)
	{
	return AbstractStmt(op, m->FrameSlot(v1), m->FrameSlot(v2),
				m->FrameSlot(v3), ce);
	}
AbstractStmt GenStmt(AbstractMachine* m, AbstractOp op, const NameExpr* v1,
			const NameExpr* v2, const ConstExpr* ce,
			const NameExpr* v3)
	{
	// Note that here we reverse the order of the arguments; saves
	// us from needing to implement a redundant constructor.
	return AbstractStmt(op, m->FrameSlot(v1), m->FrameSlot(v2),
				m->FrameSlot(v3), ce);
	}
AbstractStmt GenStmt(AbstractMachine* m, AbstractOp op, const NameExpr* v1,
			const ConstExpr* c, int i)
	{
	return AbstractStmt(op, m->FrameSlot(v1), i, c);
	}
AbstractStmt GenStmt(AbstractMachine* m, AbstractOp op, const NameExpr* v1,
			const NameExpr* v2, int i)
	{
	return AbstractStmt(op, m->FrameSlot(v1), m->FrameSlot(v2), i);
	}


AbstractMachine::AbstractMachine(const UseDefs* _ud, const Reducer* _rd,
					const ProfileFunc* _pf)
	{
	ud = _ud;
	reducer = _rd;
	pf = _pf;
	frame_size = 0;
	}

AbstractMachine::~AbstractMachine()
	{
	}

void AbstractMachine::FinishCompile()
	{
	}

void AbstractMachine::StmtDescribe(ODesc* d) const
	{
	d->Add("compiled code");
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
	return DoExec(f, 0, flow);
	}

IntrusivePtr<Val> AbstractMachine::DoExec(Frame* f, int start_pc,
						stmt_flow_type& flow) const
	{
	auto frame = new AS_ValUnion[frame_size];
	const AS_ValUnion* ret_u;
	Val* ret_v;
	BroType* ret_type;
	int pc = start_pc;
	int end_pc = stmts.size();

	while ( pc < end_pc ) {
		auto& s = stmts[pc];

		switch ( stmts[pc].op ) {
		case OP_NOP:
			break;

#include "CompilerOpsEvalDefs.h"
		}

		++pc;
		}

	delete [] frame;

	if ( ret_u )
		return ret_u->ToVal(ret_type);
	else
		return nullptr;
	}

#include "CompilerOpsMethodsDefs.h"

const CompiledStmt AbstractMachine::InterpretExpr(const Expr* e)
	{
	// ### need to flush any variables used in e!
	return AddStmt(AbstractStmt(OP_INTERPRET_EXPR_X, e));
	}

const CompiledStmt AbstractMachine::InterpretExpr(const NameExpr* n,
							const Expr* e)
	{
	// ### need to flush any variables used in e!
	return AddStmt(AbstractStmt(OP_INTERPRET_EXPR_V, FrameSlot(n), e));
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

const CompiledStmt AbstractMachine::IfElse(const NameExpr* n, const Stmt* s1,
						const Stmt* s2)
	{
	AbstractOp op = (s1 && s2) ?
		OP_IF_ELSE_VV : (s1 ? OP_IF_VV : OP_IF_NOT_VV);

	AbstractStmt cond(op, FrameSlot(n), 0);
	auto cond_stmt = AddStmt(cond);

	if ( s1 )
		{
		auto s1_end = s1->Compile(this);
		if ( s2 )
			{
			auto branch_after_s1 = GoTo();
			auto s2_end = s2->Compile(this);
			SetV2(cond_stmt, GoToTargetBeyond(branch_after_s1));
			SetGoTo(branch_after_s1, GoToTargetBeyond(s2_end));

			return s2_end;
			}

		else
			{
			SetV2(cond_stmt, GoToTargetBeyond(s1_end));
			return s1_end;
			}
		}

	else
		{
		auto s2_end = s2->Compile(this);
		SetV2(cond_stmt, GoToTargetBeyond(s2_end));
		return s2_end;
		}
	}

const CompiledStmt AbstractMachine::While(const Stmt* cond_stmt,
					const NameExpr* cond, const Stmt* body)
	{
	auto head = StartingBlock();

	if ( cond_stmt )
		(void) cond_stmt->Compile(this);

	auto cond_IF = AddStmt(AbstractStmt(OP_IF_VV, FrameSlot(cond), 0));
	(void) body->Compile(this);
	auto tail = GoTo(head);

	auto beyond_tail = GoToTargetBeyond(tail);
	SetV2(cond_IF, beyond_tail);

	ResolveNexts(head);
	ResolveBreaks(beyond_tail);

	return tail;
	}

const CompiledStmt AbstractMachine::Loop(const Stmt* body)
	{
	auto head = StartingBlock();
	(void) body->Compile(this);
	auto tail = GoTo(head);

	ResolveNexts(head);
	ResolveBreaks(GoToTargetBeyond(tail));

	return tail;
	}

const CompiledStmt AbstractMachine::When(Expr* cond, const Stmt* body,
				const Expr* timeout, const Stmt* timeout_body,
				bool is_return, const Location* location)
	{
	// ### Flush locals on eval, and also on exit
	AbstractStmt s;

	if ( timeout )
		{
		// Note, we fill in is_return by hand since it's already
		// an int_val, doesn't need translation.
		if ( timeout->Tag() == EXPR_CONST )
			s = GenStmt(this, OP_WHEN_VVVC, timeout->AsConstExpr());
		else
			s = GenStmt(this, OP_WHEN_VVVV, timeout->AsNameExpr());
		}

	else
		s = GenStmt(this, OP_WHEN_VV);

	s.v4 = is_return;
	s.non_const_e = cond;
	s.loc = location;

	AddStmt(s);

	auto branch_past_blocks = GoTo();

	auto when_body = body->Compile(this);
	auto when_done = ReturnX();

	if ( timeout )
		{
		auto t_body = timeout_body->Compile(this);
		auto t_done = ReturnX();

		s.v2 = branch_past_blocks.stmt_num + 1;
		s.v3 = when_done.stmt_num + 1;
		SetGoTo(branch_past_blocks, GoToTargetBeyond(t_done));

		return t_done;
		}

	else
		{
		s.v2 = branch_past_blocks.stmt_num + 1;
		SetGoTo(branch_past_blocks, GoToTargetBeyond(when_done));

		return when_done;
		}
	}

const CompiledStmt AbstractMachine::Switch(const SwitchStmt* sw)
	{
	auto e = sw->StmtExpr();

	if ( e->Tag() == EXPR_CONST )
		return ConstantSwitch(sw, e->AsConstExpr());

	auto var = e->AsNameExpr();
	auto val_map = sw->ValueMap();

	if ( val_map->Length() > 0 )
		return ValueSwitch(sw, var);
	else
		return TypeSwitch(sw, var);
	}

const CompiledStmt AbstractMachine::ConstantSwitch(const SwitchStmt* sw,
							const ConstExpr* ce)
	{
	auto cases = sw->Cases();
	auto val_map = sw->ValueMap();
	auto type_map = sw->TypeMap();

	auto v = ce->Value();

	if ( val_map->Length() > 0 )
		{
		auto h = sw->CompHash();
		HashKey* hk = h->ComputeHash(v, false);
		auto idx_ptr = val_map->Lookup(hk);
		delete hk;

		if ( idx_ptr )
			return (*cases)[*idx_ptr]->Body()->Compile(this);

		return EmptyStmt();
		}

	for ( auto i : *type_map )
		{
		auto id = i.first;
		auto type = id->Type();

		if ( ! can_cast_value_to_type(v, type) )
			continue;

		auto tmp = RegisterSlot();
		int idx = i.second;

		AddStmt(AbstractStmt(OP_ASSIGN_VC, tmp, ce));
		AddStmt(AbstractStmt(OP_CAST_VV, FrameSlot(id), tmp));

		return (*cases)[idx]->Body()->Compile(this);
		}

	return EmptyStmt();
	}

const CompiledStmt AbstractMachine::ValueSwitch(const SwitchStmt* sw,
						const NameExpr* var)
	{
	auto cases = sw->Cases();
	auto val_map = sw->ValueMap();

	// For compiled statements, it doesn't seem worth it (at least
	// for now) to use the hashed lookup to do a branch table,
	// as likely the number of cases doesn't get large enough to
	// merit the overhead.  So we just generate if-else cascades.

	auto body_end = EmptyStmt();

	auto ch = sw->CompHash();

	HashKey* k;
	int* index;
	IterCookie* c = val_map->InitForIteration();
	while ( (index = val_map->NextEntry(k, c)) )
		{
		auto case_val_list = ch->RecoverVals(k);
		delete k;

		auto case_vals = case_val_list->Vals();

		if ( case_vals->length() != 1 )
			reporter->InternalError("bad recovered value when compiling switch");

		IntrusivePtr<Val> case_val = {NewRef{}, (*case_vals)[0]};

		AbstractOp op;

		switch ( case_val->Type()->InternalType() ) {
		case TYPE_INTERNAL_INT:
			op = OP_BRANCH_IF_NOT_INT_VVC;
			break;

		case TYPE_INTERNAL_UNSIGNED:
			op = OP_BRANCH_IF_NOT_UINT_VVC;
			break;

		case TYPE_INTERNAL_ADDR:
			op = OP_BRANCH_IF_NOT_ADDR_VVC;
			break;

		case TYPE_INTERNAL_SUBNET:
			op = OP_BRANCH_IF_NOT_SUBNET_VVC;
			break;

		case TYPE_INTERNAL_DOUBLE:
			op = OP_BRANCH_IF_NOT_DOUBLE_VVC;
			break;

		case TYPE_INTERNAL_STRING:
			op = OP_BRANCH_IF_NOT_STRING_VVC;
			break;

		default:
			reporter->InternalError("bad recovered type when compiling switch");
		}

		ConstExpr ce(case_val);

		AbstractStmt s(op, FrameSlot(var), 0, &ce);
		s.t = case_val->Type();

		body_end = BuildCase(s, (*cases)[*index]->Body());
		}

	return BuildDefault(sw, body_end);
	}

const CompiledStmt AbstractMachine::TypeSwitch(const SwitchStmt* sw,
						const NameExpr* var)
	{
	auto cases = sw->Cases();
	auto type_map = sw->TypeMap();

	auto body_end = EmptyStmt();

	for ( auto i : *type_map )
		{
		auto id = i.first;
		auto type = id->Type();

		AbstractStmt s(OP_BRANCH_IF_NOT_TYPE_VV, FrameSlot(var), 0);
		s.t = type;

		body_end = BuildCase(s, (*cases)[i.second]->Body());
		}

	return BuildDefault(sw, body_end);
	}

const CompiledStmt AbstractMachine::BuildCase(AbstractStmt s, const Stmt* body)
	{
	auto case_test = AddStmt(s);
	ResolveFallThroughs(GoToTargetBeyond(case_test));
	auto body_end = body->Compile(this);
	SetV2(case_test, GoToTargetBeyond(body_end));

	return body_end;
	}

const CompiledStmt AbstractMachine::BuildDefault(const SwitchStmt* sw,
							CompiledStmt body_end)
	{
	int def_ind = sw->DefaultCaseIndex();

	if ( def_ind >= 0 )
		{
		ResolveFallThroughs(GoToTargetBeyond(body_end));
		body_end = (*sw->Cases())[def_ind]->Body()->Compile(this);
		}

	ResolveBreaks(GoToTargetBeyond(body_end));

	return body_end;
	}

const CompiledStmt AbstractMachine::For(const ForStmt* f)
	{
	auto e = f->LoopExpr();
	auto val = e->AsNameExpr();
	auto et = e->Type()->Tag();

	if ( et == TYPE_TABLE )
		return LoopOverTable(f, val);

	else if ( et == TYPE_VECTOR )
		return LoopOverVector(f, val);

	else if ( et == TYPE_STRING )
		return LoopOverString(f, val);

	else
		reporter->InternalError("bad \"for\" loop-over value when compiling");
	}

const CompiledStmt AbstractMachine::LoopOverTable(const ForStmt* f,
							const NameExpr* val)
	{
	auto value_var = f->ValueVar();
	auto value_var_slot = value_var ? FrameSlot(value_var) : -1;
	auto loop_vars = f->LoopVars();

	auto info = NewSlot();
	auto s = AbstractStmt(OP_INIT_TABLE_LOOP_VV, info, FrameSlot(val));
	s.t = value_var ? value_var->Type() : nullptr;
	auto init_end = AddStmt(s);

	for ( int i = 0; i < loop_vars->length(); ++i )
		{
		auto id = (*loop_vars)[i];
		s = AbstractStmt(OP_ADD_VAR_TO_INIT_VV, info, FrameSlot(id));
		s.t = id->Type();
		init_end = AddStmt(s);
		}

	s = AbstractStmt(OP_NEXT_TABLE_ITER_VVV, info, 0, value_var_slot);

	return FinishLoop(s, f->LoopBody(), info);
	}

const CompiledStmt AbstractMachine::LoopOverVector(const ForStmt* f,
							const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto loop_var = (*loop_vars)[0];

	auto info = NewSlot();
	auto s = AbstractStmt(OP_INIT_VECTOR_LOOP_VV, info, FrameSlot(val));
	auto init_end = AddStmt(s);

	s = AbstractStmt(OP_NEXT_VECTOR_ITER_VVV, info, 0, FrameSlot(loop_var));

	return FinishLoop(s, f->LoopBody(), info);
	}

const CompiledStmt AbstractMachine::LoopOverString(const ForStmt* f,
							const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto loop_var = (*loop_vars)[0];

	auto info = NewSlot();
	auto s = AbstractStmt(OP_INIT_STRING_LOOP_VV, info, FrameSlot(val));
	auto init_end = AddStmt(s);

	s = AbstractStmt(OP_NEXT_STRING_ITER_VVV, info, 0, FrameSlot(loop_var));

	return FinishLoop(s, f->LoopBody(), info);
	}

const CompiledStmt AbstractMachine::FinishLoop(AbstractStmt iter_stmt,
						const Stmt* body,
						int info_slot)
	{
	auto loop_iter = AddStmt(iter_stmt);

	auto body_end = body->Compile(this);

	auto s = AbstractStmt(OP_END_LOOP_V, info_slot);
	auto loop_end = AddStmt(s);

	SetV2(loop_iter, loop_end);

	ResolveNexts(loop_iter);
	ResolveBreaks(loop_end);

	return body_end;
	}

const CompiledStmt AbstractMachine::InitRecord(ID* id, RecordType* rt)
	{
	auto s = AbstractStmt(OP_INIT_RECORD_V, FrameSlot(id));
	s.t = rt;
	return AddStmt(s);
	}

const CompiledStmt AbstractMachine::InitVector(ID* id, VectorType* vt)
	{
	auto s = AbstractStmt(OP_INIT_VECTOR_V, FrameSlot(id));
	s.t = vt;
	return AddStmt(s);
	}

const CompiledStmt AbstractMachine::InitTable(ID* id, TableType* tt,
						Attributes* attrs)
	{
	auto s = AbstractStmt(OP_INIT_TABLE_V, FrameSlot(id));
	s.t = tt;
	s.attrs = attrs;
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

bool AbstractMachine::NullStmtOK() const
	{
	// They're okay iff they're the entire statement body.
	return stmts.size() == 0;
	}

const CompiledStmt AbstractMachine::EmptyStmt()
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

	(void) AddStmt(AbstractStmt(OP_CREATE_VAL_VEC_V, tmp, n));

	for ( int i = 0; i < n; ++i )
		{
		const auto& e = exprs[i];

		AbstractStmt as;

		if ( e->Tag() == EXPR_NAME )
			{
			int v = FrameSlot(e->AsNameExpr());
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

	BroType* stmt_type =
		c2 ? c2->Type().get() : (c3 ? c3->Type().get() : nullptr);

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

	else if ( op3->Type()->Tag() == TYPE_TABLE )
		a = n2 ? OP_VAL_IS_IN_TABLE_VVV : OP_CONST_IS_IN_TABLE_VCV;

	else
		reporter->InternalError("bad types when compiling \"in\"");

	auto s1 = FrameSlot(n1);
	auto s2 = n2 ? FrameSlot(n2) : 0;
	auto s3 = n3 ? FrameSlot(n3) : 0;

	AbstractStmt s;

	if ( n2 )
		{
		if ( n3 )
			s = AbstractStmt(a, s1, s2, s3);
		else
			s = AbstractStmt(a, s1, s2, c3);
		}
	else
		s = AbstractStmt(a, s1, s3, c2);

	s.t = stmt_type;

	return AddStmt(s);
	}

const CompiledStmt AbstractMachine::CompileInExpr(const NameExpr* n1,
				const ListExpr* l, const NameExpr* n2)
	{
	int n = l->Exprs().length();
	auto build_indices = InternalBuildVals(l);

	auto s = AbstractStmt(OP_TRANSFORM_VAL_VEC_TO_LIST_VAL_VVV,
				build_indices, build_indices, n);
	AddStmt(s);

	s = AbstractStmt(OP_LIST_IS_IN_TABLE_VVV, FrameSlot(n1), FrameSlot(n2),
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

const CompiledStmt AbstractMachine::CompileSchedule(const NameExpr* n,
					const ConstExpr* c, int is_interval,
					EventHandler* h, const ListExpr* l)
	{
	int len = l->Exprs().length();
	auto build_indices = InternalBuildVals(l);

	AddStmt(AbstractStmt(OP_TRANSFORM_VAL_VEC_TO_LIST_VAL_VVV,
				build_indices, build_indices, len));

	AbstractStmt s;

	if ( n )
		s = AbstractStmt(OP_SCHEDULE_ViHL, FrameSlot(n), build_indices);
	else
		s = AbstractStmt(OP_SCHEDULE_CiHL, build_indices, c);

	s.event_handler = h;

	return AddStmt(s);
	}

const CompiledStmt AbstractMachine::CompileEvent(EventHandler* h,
							const ListExpr* l)
	{
	int len = l->Exprs().length();
	auto build_indices = InternalBuildVals(l);

	AddStmt(AbstractStmt(OP_TRANSFORM_VAL_VEC_TO_LIST_VAL_VVV,
				build_indices, build_indices, len));

	AbstractStmt s(OP_EVENT_HL, build_indices);
	s.event_handler = h;

	return AddStmt(s);
	}

void AbstractMachine::SyncGlobals()
	{
	// ###
	}

void AbstractMachine::ResolveGoTos(vector<int>& gotos, const CompiledStmt s)
	{
	for ( int i = 0; i < gotos.size(); ++i )
		SetGoTo(gotos[i], PrevStmt(s));

	gotos.clear();
	}

CompiledStmt AbstractMachine::GenGoTo(vector<int>& v)
	{
	auto g = GoTo();
	v.push_back(g.stmt_num);

	return g;
	}

CompiledStmt AbstractMachine::GoTo()
	{
	AbstractStmt s(OP_GOTO_V, 0);
	return AddStmt(s);
	}

CompiledStmt AbstractMachine::GoTo(const CompiledStmt s)
	{
	AbstractStmt stmt(OP_GOTO_V, s.stmt_num - 1);
	return AddStmt(stmt);
	}

CompiledStmt AbstractMachine::GoToTargetBeyond(const CompiledStmt s)
	{
	// We use a target one below the actual target due to the
	// pc increment after the statement executes.
	return s;
	}

CompiledStmt AbstractMachine::PrevStmt(const CompiledStmt s)
	{
	return CompiledStmt(s.stmt_num - 1);
	}

void AbstractMachine::SetV1(CompiledStmt s, const CompiledStmt s1)
	{
	stmts[s.stmt_num].v1 = s1.stmt_num;
	}

void AbstractMachine::SetV2(CompiledStmt s, const CompiledStmt s2)
	{
	stmts[s.stmt_num].v2 = s2.stmt_num;
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

int AbstractMachine::FrameSlot(const NameExpr* e)
	{
	return FrameSlot(e->AsNameExpr()->Id());
	}

int AbstractMachine::NewSlot()
	{
	// ###
	return 0;
	}

int AbstractMachine::RegisterSlot()
	{
	// ###
	return 0;
	}


TraversalCode Compiler::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IntrusivePtr<Val> ResumptionAM::Exec(Frame* f, stmt_flow_type& flow) const
	{
	return am->DoExec(f, xfer_pc, flow);
	}

void ResumptionAM::StmtDescribe(ODesc* d) const
	{
	d->Add("resumption of compiled code");
	}

TraversalCode ResumptionAM::Traverse(TraversalCallback* cb) const
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
