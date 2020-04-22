// See the file "COPYING" in the main distribution directory for copyright.

#include "Compiled.h"
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

} AbstractOp;

class AbstractStmt {
public:
	AbstractStmt(AbstractOp _op, int _v1 = 0, int _v2 = 0, int _v3 = 0, 
			int _v4 = 0)
	: c(bro_int_t(0))
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		v3 = _v3;
		v4 = _v4;
		}

	AbstractStmt(AbstractOp _op, union BroValUnion _c)
		{
		op = _op;
		c = _c;
		v1 = v2 = v3 = v4 = 0;
		}

	AbstractStmt(AbstractOp _op, int _v1, union BroValUnion _c)
		{
		op = _op;
		v1 = _v1;
		c = _c;
		v2 = v3 = v4 = 0;
		}

	AbstractStmt(AbstractOp _op, int _v1, int _v2, union BroValUnion _c)
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		c = _c;
		v3 = v4 = 0;
		}

	AbstractOp op;

	// Indices into frame.
	int v1, v2, v3, v4;
	TypeTag t = TYPE_VOID;

	union BroValUnion c;	// constant
};


AbstractMachine::AbstractMachine(int _frame_size)
	{
	frame_size = _frame_size;
	frame = new BroValUnion[frame_size];
	}

AbstractMachine::~AbstractMachine()
	{
	delete frame;
	}

void AbstractMachine::StmtDescribe(ODesc* d) const
	{
	}

#define VAL_FROM_UNION(u, accessor, target, func, type) \
	case type: \
		target = func(u.accessor, type); \
		break; \

#define VAL_FROM_UNIONS(u, target) \
	VAL_FROM_UNION(u, int_val, target, new Val, TYPE_INT) \
	VAL_FROM_UNION(u, uint_val, target, new Val, TYPE_COUNT) \
	VAL_FROM_UNION(u, addr_val, target, new Val, TYPE_ADDR) \
	VAL_FROM_UNION(u, subnet_val, target, new Val, TYPE_SUBNET) \
	VAL_FROM_UNION(u, double_val, target, new Val, TYPE_DOUBLE) \
	VAL_FROM_UNION(u, string_val, target, new Val, TYPE_STRING) \
	VAL_FROM_UNION(u, func_val, target, new Val, TYPE_FUNC) \
	VAL_FROM_UNION(u, file_val, target, new Val, TYPE_FILE) \
	VAL_FROM_UNION(u, re_val, target, new Val, TYPE_PATTERN) \
	VAL_FROM_UNION(u, table_val, target, new Val, TYPE_TABLE) \
	VAL_FROM_UNION(u, val_list_val, target, new Val, TYPE_LIST) \
	VAL_FROM_UNION(u, vector_val, target, new Val, TYPE_VECTOR) \


IntrusivePtr<Val> AbstractMachine::Exec(Frame* f, stmt_flow_type& flow) const
	{
	const BroValUnion* ret_u;
	Val* ret_v;
	TypeTag ret_type;
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
		}

		++pc;
		}

	if ( ret_u )
		{
		Val* v;
		switch ( ret_type ) {
		VAL_FROM_UNIONS((*ret_u), v)

		default:
			reporter->InternalError("bad ret type return tag");
		}

		return {AdoptRef{}, v};
		}

	else
		return nullptr;
	}

int AbstractMachine::ReturnV(NameExpr* n)
	{
	SyncGlobals();

	AbstractStmt s(OP_RET_V, FrameSlot(n->Id()));
	s.t = n->Type()->Tag();
	return AddStmt(s);
	}

int AbstractMachine::ReturnC(ConstExpr* c)
	{
	SyncGlobals();

	auto v = c->Value();
	AbstractStmt s(OP_RET_C, v->val);
	s.t = c->Type()->Tag();
	return AddStmt(s);
	}

int AbstractMachine::ReturnX()
	{
	SyncGlobals();

	AbstractStmt s(OP_RET_X);
	return AddStmt(s);
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

int AbstractMachine::AddStmt(const AbstractStmt& stmt)
	{
	stmts.push_back(stmt);
	return stmts.size();
	}


TraversalCode CompiledStmts::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}
