// See the file "COPYING" in the main distribution directory for copyright.

#include "Compile.h"
#include "Expr.h"
#include "OpaqueVal.h"
#include "Desc.h"
#include "Reporter.h"
#include "Traverse.h"


#define TYPE_ENUM(prefix) \
	prefix ## _INT,	\
	prefix ## _UINT,	\
	prefix ## _ADDR,	\
	prefix ## _SUBNET,	\
	prefix ## _DOUBLE,	\
	prefix ## _STRING,	\
	prefix ## _FUNC,	\
	prefix ## _FILE,	\
	prefix ## _RE,	\
	prefix ## _TABLE,	\
	prefix ## _VECTOR,	\
	prefix ## _UNION_VAL_LIST,	\
	prefix ## _VAL,	\
	prefix ## _VAL_LIST,

#define VAL_TYPES TYPE_ENUM(VAL_TYPE)

typedef enum {
	VAL_TYPES
} ValType;

#define OP_FAMILY(op) TYPE_ENUM(OP_ ## op)

typedef enum {
	OP_NOP,

	OP_RET_C,
	OP_RET_V,
	OP_RET_X,

	OP_PRINT_V,

	// Internal operands.

	// Initializes a vector of values.
	OP_CREATE_VAL_VEC_VV,

	// Appends an element to such a list.
	OP_SET_VAL_VEC_VC,
	OP_SET_VAL_VEC_VV,

} AbstractOp;

const char* abstract_op_name(AbstractOp op)
	{
	switch ( op ) {
	case OP_NOP:	return "nop";

	case OP_RET_C:	return "retc";
	case OP_RET_V:	return "retv";
	case OP_RET_X:	return "retx";

	case OP_PRINT_V:	return "printv";

	case OP_CREATE_VAL_VEC_VV:	return "create-val-vec-vv";

	case OP_SET_VAL_VEC_VC:	return "set-val-vec-vc";
	case OP_SET_VAL_VEC_VV:	return "set-val-vec-vv";
	}
	}


typedef std::vector<IntrusivePtr<Val>> val_vec;

// A bit of this mirrors BroValUnion, but it captures low-level
// representation whereas we aim to keep Val structure for
// more complex Val's.
union AS_ValUnion {
	IntrusivePtr<Val> ToVal(BroType* t) const;

	// Used for bool, int.
	bro_int_t int_val;

	// Used for count, counter.
	bro_uint_t uint_val;

	// Used for double, time, interval.  While IntervalVal's are
	// distinct, we can readily recover them given type information.
	double double_val;

	AddrVal* addr_val;
	BroValUnion any_val;
	EnumVal* enum_val;
	BroFile* file_val;
	Func* func_val;
	ListVal* list_val;
	OpaqueVal* opaque_val;
	PortVal* port_val;
	PatternVal* re_val;
	RecordVal* record_val;
	StringVal* string_val;
	SubNetVal* subnet_val;
	TableVal* table_val;
	BroType* type_val;
	VectorVal* vector_val;

	// Used for the compiler to hold opaque items.
	val_vec* vvec;
};

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

	case TYPE_ANY:		v = new Val(any_val, t->Ref()); break;
	case TYPE_TYPE:		v = new Val(type_val, true); break;

	case TYPE_ADDR:		v = addr_val; v->Ref(); break;
	case TYPE_ENUM:		v = enum_val; v->Ref(); break;
	case TYPE_LIST:		v = list_val; v->Ref(); break;
	case TYPE_OPAQUE:	v = opaque_val; v->Ref(); break;
	case TYPE_PATTERN:	v = re_val; v->Ref(); break;
	case TYPE_PORT:		v = port_val; v->Ref(); break;
	case TYPE_RECORD:	v = record_val; v->Ref(); break;
	case TYPE_STRING:	v = string_val; v->Ref(); break;
	case TYPE_SUBNET:	v = subnet_val; v->Ref(); break;
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
	OP_X, OP_V, OP_VV, OP_VVV, OP_VVVV, OP_C, OP_VC, OP_VVC,
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

	AbstractStmt(AbstractOp _op, AS_ValUnion _c)
		{
		op = _op;
		c = _c;
		op_type = OP_C;
		}

	AbstractStmt(AbstractOp _op, int _v1, AS_ValUnion _c)
		{
		op = _op;
		v1 = _v1;
		c = _c;
		op_type = OP_VC;
		}

	AbstractStmt(AbstractOp _op, int _v1, int _v2, AS_ValUnion _c)
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		c = _c;
		op_type = OP_VVC;
		}

	// Constructor used when we're going to just copy in another AS.
	AbstractStmt() { }

	void Dump() const;
	const char* ConstDump() const;

	AbstractOp op;

	// Indices into frame.
	int v1, v2, v3, v4;
	BroType* t = nullptr;

	AS_ValUnion c;	// constant

	AS_OpType op_type;
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

		case OP_RET_V:
			ret_u = &frame[s.v1];
			ret_type = s.t;
			loop = false;
			break;

		case OP_RET_C:
			ret_u = &s.c;
			ret_type = s.t;
			loop = false;
			break;

		case OP_RET_X:
			ret_u = nullptr;
			loop = false;
			break;

		case OP_PRINT_V:
			{
			auto vvec = frame[s.v1].vvec;
			do_print(*vvec);
			delete vvec;
			break;
			}

		case OP_CREATE_VAL_VEC_VV:
			// Initializes a new value vector.  We now
			// do this dynamically, but at same point
			// we could switch it to a static vector
			// since we'll only have one of these at
			// at time.
			//
			// v1 is where to store the vector, v2 is
			// its size (which we don't presently use).
			frame[s.v1].vvec = new val_vec;
			break;

		case OP_SET_VAL_VEC_VV:
			{
			// Appends v2 to the vector pointed to by v1.
			auto v = ASValToVal(frame[s.v2], s.t);
			frame[s.v1].vvec->push_back(v);
			break;
			}

		case OP_SET_VAL_VEC_VC:
			{
			// Appends c to the vector pointed to by v1.
			auto c = ASValToVal(s.c, s.t);
			frame[s.v1].vvec->push_back(c);
			break;
			}
		}

		++pc;
		}

	if ( ret_u )
		return ASValToVal(*ret_u, ret_type);
	else
		return nullptr;
	}

const CompiledStmt AbstractMachine::Print(OpaqueVals* v)
	{
	int reg = v->n;
	delete v;

	return AddStmt(AbstractStmt(OP_PRINT_V, reg));
	}

const CompiledStmt AbstractMachine::ReturnV(const NameExpr* n)
	{
	SyncGlobals();

	AbstractStmt s(OP_RET_V, FrameSlot(n->Id()));
	s.t = n->Type().get();
	return AddStmt(s);
	}

const CompiledStmt AbstractMachine::ReturnC(const ConstExpr* c)
	{
	SyncGlobals();

	auto v = c->Value();
	AbstractStmt s(OP_RET_C, ValToASVal(v, c->Type().get()));
	s.t = c->Type().get();
	return AddStmt(s);
	}

const CompiledStmt AbstractMachine::ReturnX()
	{
	SyncGlobals();

	AbstractStmt s(OP_RET_X);
	return AddStmt(AbstractStmt(OP_RET_X));
	}

const CompiledStmt AbstractMachine::StartingBlock()
	{
	return CompiledStmt(stmts.size());
	}

const CompiledStmt AbstractMachine::FinishBlock(const CompiledStmt /* start */)
	{
	return CompiledStmt(stmts.size());
	}

OpaqueVals* AbstractMachine::BuildVals(const IntrusivePtr<ListExpr>& l)
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
			auto id = FrameSlot(e->AsNameExpr()->Id());
			as = AbstractStmt(OP_SET_VAL_VEC_VV, tmp, id);
			}
		else
			{
			auto c = e->AsConstExpr()->Value();
			auto as_val = ValToASVal(c, e->Type().get());
			as = AbstractStmt(OP_SET_VAL_VEC_VC, tmp, as_val);
			}

		as.t = e->Type().get();
		(void) AddStmt(as);
		}

	return new OpaqueVals(tmp);
	}

const CompiledStmt AbstractMachine::AddStmt(const AbstractStmt& stmt)
	{
	stmts.push_back(stmt);
	return CompiledStmt(stmts.size());
	}

IntrusivePtr<Val> AbstractMachine::ASValToVal(const AS_ValUnion& u,
						BroType* t) const
	{
	Val* v;

	switch ( t->Tag() ) {
	case TYPE_INT:		v = new Val(u.int_val, TYPE_INT); break;
	case TYPE_BOOL:		v = Val::MakeBool(u.int_val); break;
	case TYPE_COUNT:	v = new Val(u.uint_val, TYPE_COUNT); break;
	case TYPE_COUNTER:	v = new Val(u.uint_val, TYPE_COUNTER); break;
	case TYPE_DOUBLE:	v = new Val(u.double_val, TYPE_DOUBLE); break;
	case TYPE_INTERVAL:	v = new IntervalVal(u.double_val, 1.0); break;
	case TYPE_TIME:		v = new Val(u.double_val, TYPE_TIME); break;
	case TYPE_FUNC:		v = new Val(u.func_val); break;
	case TYPE_FILE:		v = new Val(u.file_val); break;

	case TYPE_ANY:		v = new Val(u.any_val, t->Ref()); break;
	case TYPE_TYPE:		v = new Val(u.type_val, true); break;

	case TYPE_ADDR:		v = u.addr_val; v->Ref(); break;
	case TYPE_ENUM:		v = u.enum_val; v->Ref(); break;
	case TYPE_LIST:		v = u.list_val; v->Ref(); break;
	case TYPE_OPAQUE:	v = u.opaque_val; v->Ref(); break;
	case TYPE_PATTERN:	v = u.re_val; v->Ref(); break;
	case TYPE_PORT:		v = u.port_val; v->Ref(); break;
	case TYPE_RECORD:	v = u.record_val; v->Ref(); break;
	case TYPE_STRING:	v = u.string_val; v->Ref(); break;
	case TYPE_SUBNET:	v = u.subnet_val; v->Ref(); break;
	case TYPE_TABLE:	v = u.table_val; v->Ref(); break;
	case TYPE_VECTOR:	v = u.vector_val; v->Ref(); break;

	case TYPE_ERROR:
	case TYPE_TIMER:
	case TYPE_UNION:
	case TYPE_VOID:
		reporter->InternalError("bad ret type return tag");
	}

	return {NewRef{}, v};
	}

union AS_ValUnion AbstractMachine::ValToASVal(Val* v, BroType* t) const
	{
	union BroValUnion vu = v->val;
	union AS_ValUnion avu;

	if ( v->Type()->Tag() != t->Tag() )
		reporter->InternalError("type inconsistency in ValToASVal");

	switch ( t->Tag() ) {
	case TYPE_BOOL:
	case TYPE_INT:
		avu.int_val = vu.int_val;
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		avu.uint_val = vu.uint_val;
		break;

	case TYPE_DOUBLE:
	case TYPE_INTERVAL:
	case TYPE_TIME:
		avu.double_val = vu.double_val;
		break;

	case TYPE_FUNC:		avu.func_val = vu.func_val; break;
	case TYPE_FILE:		avu.file_val = vu.file_val; break;

	case TYPE_ADDR:		avu.addr_val = v->AsAddrVal(); break;
	case TYPE_ENUM:		avu.enum_val = v->AsEnumVal(); break;
	case TYPE_LIST:		avu.list_val = v->AsListVal(); break;
	case TYPE_OPAQUE:	avu.opaque_val = v->AsOpaqueVal(); break;
	case TYPE_PATTERN:	avu.re_val = v->AsPatternVal(); break;
	case TYPE_PORT:		avu.port_val = v->AsPortVal(); break;
	case TYPE_RECORD:	avu.record_val = v->AsRecordVal(); break;
	case TYPE_STRING:	avu.string_val = v->AsStringVal(); break;
	case TYPE_SUBNET:	avu.subnet_val = v->AsSubNetVal(); break;
	case TYPE_TABLE:	avu.table_val = v->AsTableVal(); break;
	case TYPE_VECTOR:	avu.vector_val = v->AsVectorVal(); break;

	case TYPE_ANY:		avu.any_val = vu; break;
	case TYPE_TYPE:		avu.type_val = t; break;

	case TYPE_ERROR:
	case TYPE_TIMER:
	case TYPE_UNION:
	case TYPE_VOID:
		reporter->InternalError("bad ret type return tag");
	}

	return avu;
	}

void AbstractMachine::Dump()
	{
	for ( int i = 0; i < stmts.size(); ++i )
		{
		printf("%d: ", i);
		stmts[i].Dump();
		}
	}

void AbstractMachine::SyncGlobals()
	{
	// ###
	}

int AbstractMachine::FrameSlot(const ID* id)
	{
	// ###
	return 0;
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
