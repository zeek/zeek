// See the file "COPYING" in the main distribution directory for copyright.

#include "Compile.h"
#include "Expr.h"
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

	OP_RET_V,
	OP_RET_C,
	OP_RET_X,

	OP_PRINT_V,

	// Internal operands.

	// Initializes a vector of values.
	OP_CREATE_VAL_VEC_VV,

	// Appends an element to such a list.
	OP_SET_VAL_VEC_VV,
	OP_SET_VAL_VEC_VC,

} AbstractOp;


typedef std::vector<IntrusivePtr<Val>> val_vec;

// A bit of this mirrors BroValUnion, but it captures low-level
// representation whereas we aim to keep Val structure for
// more complex Val's.
union AS_ValUnion {
	AS_ValUnion()	{ void_val = nullptr; }

	// Used for bool, int.
	bro_int_t int_val;

	// Used for count, counter.
	bro_uint_t uint_val;

	// Used for double, time, interval.  While IntervalVal's are
	// distinct, we can readily recover them given type information.
	double double_val;

	EnumVal* enum_val;
	PortVal* port_val;
	AddrVal* addr_val;
	SubNetVal* subnet_val;
	Func* func_val;
	BroFile* file_val;
	StringVal* string_val;
	PatternVal* re_val;
	TableVal* table_val;
	RecordVal* record_val;
	ListVal* list_val;
	VectorVal* vector_val;

	// Used for the compiler to hold opaque items.
	val_vec* vvec;
	void* void_val;
};

class AbstractStmt {
public:
	AbstractStmt(AbstractOp _op, int _v1 = 0, int _v2 = 0, int _v3 = 0,
			int _v4 = 0)
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		v3 = _v3;
		v4 = _v4;
		}

	AbstractStmt(AbstractOp _op, AS_ValUnion _c)
		{
		op = _op;
		c = _c;
		v1 = v2 = v3 = v4 = 0;
		}

	AbstractStmt(AbstractOp _op, int _v1, AS_ValUnion _c)
		{
		op = _op;
		v1 = _v1;
		c = _c;
		v2 = v3 = v4 = 0;
		}

	AbstractStmt(AbstractOp _op, int _v1, int _v2, AS_ValUnion _c)
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		c = _c;
		v3 = v4 = 0;
		}

	// Constructor used when we're going to just copy in another AS.
	AbstractStmt() { }

	AbstractOp op;

	// Indices into frame.
	int v1, v2, v3, v4;
	const BroType* t = nullptr;

	AS_ValUnion c;	// constant
};


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
	const BroType* ret_type;
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
						const BroType* t) const
	{
	Val* v;

	switch ( t->Tag() ) {
	case TYPE_INT:		v = new Val(u.int_val, TYPE_INT); break;
	case TYPE_COUNT:	v = new Val(u.uint_val, TYPE_COUNT); break;
	case TYPE_COUNTER:	v = new Val(u.uint_val, TYPE_COUNTER); break;
	case TYPE_DOUBLE:	v = new Val(u.double_val, TYPE_DOUBLE); break;
	case TYPE_TIME:		v = new Val(u.double_val, TYPE_TIME); break;
	case TYPE_FUNC:		v = new Val(u.func_val); break;
	case TYPE_FILE:		v = new Val(u.file_val); break;
	case TYPE_INTERVAL:	v = new IntervalVal(u.double_val, 1.0); break;
	case TYPE_BOOL:		v = Val::MakeBool(u.int_val); break;

	case TYPE_PORT:		v = u.port_val; v->Ref(); break;
	case TYPE_ENUM:		v = u.enum_val; v->Ref(); break;
	case TYPE_STRING:	v = u.string_val; v->Ref(); break;
	case TYPE_PATTERN:	v = u.re_val; v->Ref(); break;
	case TYPE_RECORD:	v = u.record_val; v->Ref(); break;
	case TYPE_TABLE:	v = u.table_val; v->Ref(); break;
	case TYPE_VECTOR:	v = u.vector_val; v->Ref(); break;

#if 0
	default:
		reporter->InternalError("bad ret type return tag");
#endif
	}

	return {NewRef{}, v};
	}

union AS_ValUnion AbstractMachine::ValToASVal(Val* v, const BroType* t) const
	{
	union BroValUnion vu = v->val;
	union AS_ValUnion avu;

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
	case TYPE_TIME:
	case TYPE_INTERVAL:
		avu.double_val = vu.double_val;
		break;

	case TYPE_FUNC:		avu.func_val = vu.func_val; break;
	case TYPE_FILE:		avu.file_val = vu.file_val; break;

	case TYPE_PORT:		avu.port_val = v->AsPortVal(); break;
	case TYPE_ENUM:		avu.enum_val = v->AsEnumVal(); break;
	case TYPE_STRING:	avu.string_val = v->AsStringVal(); break;
	case TYPE_PATTERN:	avu.re_val = v->AsPatternVal(); break;
	case TYPE_RECORD:	avu.record_val = v->AsRecordVal(); break;
	case TYPE_TABLE:	avu.table_val = v->AsTableVal(); break;
	case TYPE_VECTOR:	avu.vector_val = v->AsVectorVal(); break;
	}

	return avu;
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


TraversalCode StmtCompiler::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}
