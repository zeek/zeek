// See the file "COPYING" in the main distribution directory for copyright.

#include "Compile.h"
#include "CompHash.h"
#include "Func.h"
#include "Expr.h"
#include "RE.h"
#include "OpaqueVal.h"
#include "Frame.h"
#include "EventHandler.h"
#include "Reduce.h"
#include "UseDefs.h"
#include "Scope.h"
#include "ProfileFunc.h"
#include "Trigger.h"
#include "Desc.h"
#include "Reporter.h"
#include "Traverse.h"


const Stmt* curr_stmt;


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

static void run_time_error(bool& error_flag, const BroObj* o, const char* msg)
	{
	fprintf(stderr, "%s: %s\n", msg, obj_desc(o));
	error_flag = true;
	}

// A bit of this mirrors BroValUnion, but BroValUnion captures low-level
// representation whereas we aim to keep Val structure for more complex
// Val's.
//
// Ideally we'd use IntrusivePtr's for memory management, but we can't
// given we have a union and thus on destruction C++ doesn't know which
// member flavor to destruct.  See the comment below re shadowing in
// the AbstractMachine frame.
union AS_ValUnion {
	// Constructor for hand-populating the values.
	AS_ValUnion() {}

	// Construct from a given Bro value with a given type.
	AS_ValUnion(Val* v, BroType* t, const BroObj* o, bool& error_flag);

	// Convert to a Bro value.
	IntrusivePtr<Val> ToVal(BroType* t) const;

	// Used for bool, int.
	bro_int_t int_val;

	// Used for count, counter.
	bro_uint_t uint_val;

	// Used for double, time, interval.  While IntervalVal's are
	// distinct, we can readily recover them given type information.
	double double_val;

	// For these types, we assume we have ownership of the value, so
	// they need to be explicitly deleted prior to reassignment.
	BroString* string_val;
	IPAddr* addr_val;
	IPPrefix* subnet_val;
	vector<BroValUnion>* raw_vector_val;

	// The types are all variants of Val (or BroType).  For memory
	// management, in the AM frame we shadow these with IntrusivePtr's.
	// Thus we do not unref these on reassignment.
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

	// Used for the compiler to hold opaque items.  Memory management
	// is explicit in the operations accessing it.
	val_vec* vvec;

	// Used for managing "for" loops.  Explicit memory management.
	IterInfo* iter_info;

	// Used for loading/spilling globals.
	ID* id_val;

	// Only used when we want to clear any pointer via OP_CLEAR_V.
	void* void_val;
};

AS_ValUnion::AS_ValUnion(Val* v, BroType* t, const BroObj* o, bool& error)
	{
	if ( ! v )
		{
		run_time_error(error, o, "uninitialized value in compiled code");
		int_val = 0;
		return;
		}

	auto vu = v->val;

	if ( v->Type()->Tag() != t->Tag() && t->Tag() != TYPE_ANY )
		{
		if ( t->InternalType() == TYPE_INTERNAL_OTHER ||
		     t->InternalType() != v->Type()->InternalType() )
			reporter->InternalError("type inconsistency in AS_ValUnion constructor");
		}

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

	case TYPE_STRING:
		string_val = new BroString(*v->AsString());
		break;

	case TYPE_ADDR:
		addr_val = new IPAddr(*vu.addr_val);
		break;

	case TYPE_SUBNET:
		subnet_val = new IPPrefix(*vu.subnet_val);
		break;

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
	case TYPE_ADDR:		v = new AddrVal(*addr_val); break;
	case TYPE_SUBNET:	v = new SubNetVal(*subnet_val); break;
	case TYPE_STRING:
		v = new StringVal(new BroString(*string_val));
		break;

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
	OP_E, OP_VE, OP_VV_FRAME, OP_VC_ID,
	OP_V_I1, OP_VV_I2, OP_VVC_I2, OP_VVV_I3,
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

	const char* VName(int max_n, int n, const frame_map& frame_ids) const;
	int NumFrameSlots() const;
	void Dump(const frame_map& frame_ids) const;
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
	const Stmt* stmt = curr_stmt;

	AS_ValUnion c;	// constant

	AS_OpType op_type;

protected:
	void InitConst(const ConstExpr* ce)
		{
		auto v = ce->Value();
		auto ct = ce->Type().get();
		t = ct;

		bool error = false;
		c = AS_ValUnion(v, t, ce, error);

		if ( error )
			reporter->InternalError("bad value compiling code");
		}
};

int AbstractStmt::NumFrameSlots() const
	{
	switch ( op_type ) {
	case OP_X:	return 0;
	case OP_V:	return 1;
	case OP_VV:	return 2;
	case OP_VVV:	return 3;
	case OP_VVVV:	return 4;
	case OP_VVVC:	return 3;
	case OP_C:	return 0;
	case OP_VC:	return 1;
	case OP_VVC:	return 2;
	case OP_E:	return 0;
	case OP_VE:	return 1;

	case OP_V_I1:	return 0;
	case OP_VV_FRAME:	return 1;
	case OP_VC_ID:	return 1;
	case OP_VV_I2:	return 1;
	case OP_VVC_I2:	return 1;
	case OP_VVV_I3:	return 2;
	}
	}

const char* AbstractStmt::VName(int max_n, int n, const frame_map& frame_ids) const
	{
	if ( n > max_n )
		return nullptr;

	int slot = n == 1 ? v1 : (n == 2 ? v2 : (n == 3 ? v3 : v4));

	if ( slot == 0 )
		return copy_string("<reg0>");

	if ( slot >= frame_ids.size() )
		return copy_string(fmt("extra-slot %d", slot));

	return copy_string(fmt("%d (%s)", slot, frame_ids[slot]->Name()));
	}

void AbstractStmt::Dump(const frame_map& frame_ids) const
	{
	printf("%s ", abstract_op_name(op));
	if ( t && 0 )
		printf("(%s) ", type_name(t->Tag()));

	int n = NumFrameSlots();

	auto id1 = VName(n, 1, frame_ids);
	auto id2 = VName(n, 2, frame_ids);
	auto id3 = VName(n, 3, frame_ids);
	auto id4 = VName(n, 4, frame_ids);

	switch ( op_type ) {
	case OP_X:
		break;

	case OP_V:
		printf("%s", id1);
		break;

	case OP_VV:
		printf("%s, %s", id1, id2);
		break;

	case OP_VVV:
		printf("%s, %s, %s", id1, id2, id3);
		break;

	case OP_VVVV:
		printf("%s, %s, %s, %s", id1, id2, id3, id4);
		break;

	case OP_VVVC:
		printf("%s, %s, %s, %s", id1, id2, id3, ConstDump());
		break;

	case OP_C:
		printf("%s", ConstDump());
		break;

	case OP_VC:
		printf("%s, %s", id1, ConstDump());
		break;

	case OP_VVC:
		printf("%s, %s, %s", id1, id2, ConstDump());
		break;

	case OP_E:
		printf("%s", obj_desc(e));
		break;

	case OP_VE:
		printf("%s, %s", id1, obj_desc(e));
		break;

	case OP_V_I1:
		printf("%d", v1);
		break;

	case OP_VV_FRAME:
		printf("%s, interpreter frame[%d]", id1, v2);
		break;

	case OP_VC_ID:
		printf("%s, ID %s", id1, obj_desc(c.any_val));
		break;

	case OP_VV_I2:
		printf("%s, %d", id1, v2);
		break;

	case OP_VVC_I2:
		printf("%s, %d, %s", id1, v2, ConstDump());
		break;

	case OP_VVV_I3:
		printf("%s, %s, %d", id1, id2, v3);
		break;
	}

	printf("\n");

	delete id1;
	delete id2;
	delete id3;
	delete id4;
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
	auto s = AbstractStmt(op, m->FrameSlot(v1), i, c);
	s.op_type = OP_VVC_I2;
	return s;
	}
AbstractStmt GenStmt(AbstractMachine* m, AbstractOp op, const NameExpr* v1,
			const NameExpr* v2, int i)
	{
	auto s = AbstractStmt(op, m->FrameSlot(v1), m->FrameSlot(v2), i);
	s.op_type = OP_VVV_I3;
	return s;
	}


AbstractMachine::AbstractMachine(const BroFunc* f, Stmt* _body, UseDefs* _ud,
					Reducer* _rd, ProfileFunc* _pf)
	{
	tag = STMT_COMPILED;
	func = f;
	body = _body;
	body->Ref();
	ud = _ud;
	reducer = _rd;
	pf = _pf;
	frame_size = 0;

	Init();
	}

AbstractMachine::~AbstractMachine()
	{
	Unref(body);
	delete ud;
	delete reducer;
	delete pf;
	}

Stmt* AbstractMachine::CompileBody()
	{
	curr_stmt = nullptr;
	(void) body->Compile(this);

	if ( LastStmt()->Tag() != STMT_RETURN )
		SyncGlobals(nullptr);

	if ( breaks.size() > 0 )
		{
		if ( func->Flavor() == FUNC_FLAVOR_HOOK )
			{
			// Rewrite the breaks.
			for ( auto b : breaks )
				stmts[b] = AbstractStmt(OP_HOOK_BREAK_X);
			}

		else
			reporter->Error("\"break\" used without an enclosing \"for\" or \"switch\"");
		}

	if ( nexts.size() > 0 )
		reporter->Error("\"next\" used without an enclosing \"for\"");

	if ( fallthroughs.size() > 0 )
		reporter->Error("\"fallthrough\" used without an enclosing \"switch\"");

	return this;
	}

void AbstractMachine::Init()
	{
	auto uds = ud->HasUsage(body) ? ud->GetUsage(body) : nullptr;
	auto scope = func->GetScope();
	auto args = scope->OrderedVars();
	auto nparam = func->FType()->Args()->NumFields();

	// Use slot 0 for the temporary register.
	register_slot = frame_size++;
	frame_denizens.push_back(nullptr);

	::Ref(scope);
	push_existing_scope(scope);

	for ( auto a : args )
		{
		if ( --nparam < 0 )
			break;

		auto arg_id = a.get();
		if ( uds && uds->HasID(arg_id) )
			LoadParam(arg_id);
		else
			{
			// printf("param %s unused\n", obj_desc(arg_id.get()));
			}
		}

	pop_scope();

	for ( auto g : pf->globals )
		{
		// Only load a global if it has a use-def.  If it doesn't,
		// that can be because it's uninitialized on entry and
		// it's this function body that initializes it.
		if ( uds && uds->HasID(g) )
			LoadGlobal(g);
		else
			// But still make sure it's in the frame layout.
			(void) AddToFrame(g);
		}

	// Assign slots for locals (which includes temporaries).
	for ( auto l : pf->locals )
		{
		// ### should check for unused variables.
		// Don't add locals that were already added because they're
		// parameters.
		if ( ! HasFrameSlot(l) )
			{
			auto slot = AddToFrame(l);

			// Look for locals with values of types for which
			// we do explicit memory management on (re)assignment.
			auto t = l->Type()->Tag();
			if ( t == TYPE_ADDR || t == TYPE_SUBNET || 
			     t == TYPE_STRING )
				{
				managed_slots.push_back(slot);
				managed_slot_types.push_back(t);
				}
			}
		}
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

IntrusivePtr<Val> AbstractMachine::Exec(Frame* f, stmt_flow_type& flow) const
	{
	return DoExec(f, 0, flow);
	}

IntrusivePtr<Val> AbstractMachine::DoExec(Frame* f, int start_pc,
						stmt_flow_type& flow) const
	{
	auto frame = new AS_ValUnion[frame_size];
	int pc = start_pc;
	bool error_flag = false;
	int end_pc = stmts.size();

	// Memory management: all of the BroObj's that we have used
	// in interior values.  By managing them here rather than
	// per-frame-slot, we don't need to add frame state about
	// whether an object should be delete'd or not on reassignment.
	std::vector<IntrusivePtr<BroObj>> vals;

#define BuildVal(v, t, s) (vals.push_back(v), AS_ValUnion(v.get(), t, s, error_flag))
#define CopyVal(v) ((s.t->Tag() == TYPE_ADDR || s.t->Tag() == TYPE_SUBNET || s.t->Tag() == TYPE_STRING) ? BuildVal(v.ToVal(s.t), s.t, s.stmt) : v)

	// Return value, or nil if none.
	const AS_ValUnion* ret_u;

	// Type of the return value.  If nil, then we don't have a value.
	BroType* ret_type = nullptr;

	// Clear slots for which we do explicit memory management.
	for ( auto s : managed_slots )
		frame[s].void_val = nullptr;

	flow = FLOW_RETURN;	// can be over-written by a Hook-Break

	while ( pc < end_pc && ! error_flag ) {
		auto& s = stmts[pc];

		if ( 0 )
			{
			printf("executing %d: ", pc);
			s.Dump(frame_denizens);
			}

		switch ( s.op ) {
		case OP_NOP:
			break;

#include "CompilerOpsEvalDefs.h"
		}

		++pc;
		}

	auto result = ret_type ? ret_u->ToVal(ret_type) : nullptr;

	// Free those slots for which we do explicit memory management.
	for ( auto i = 0; i < managed_slots.size(); ++i )
		{
		int s = managed_slots[i];

		switch ( managed_slot_types[i] ) {
		case TYPE_ADDR:		delete frame[s].addr_val; break;
		case TYPE_SUBNET:	delete frame[s].subnet_val; break;
		case TYPE_STRING:	delete frame[s].string_val; break;

		default:
			reporter->InternalError("bad type tag for managed slots");
		}
		}

	delete [] frame;

	// ### should propagate error.

	flow = FLOW_RETURN;

	return result;
	}

#include "CompilerOpsMethodsDefs.h"

const CompiledStmt AbstractMachine::InterpretExpr(const Expr* e)
	{
	FlushVars(e);
	return AddStmt(AbstractStmt(OP_INTERPRET_EXPR_X, e));
	}

const CompiledStmt AbstractMachine::InterpretExpr(const NameExpr* n,
							const Expr* e)
	{
	FlushVars(e);
	return AddStmt(AbstractStmt(OP_INTERPRET_EXPR_V, FrameSlot(n), e));
	}

const CompiledStmt AbstractMachine::DoCall(const CallExpr* c,
						const NameExpr* n, UDs uds)
	{
	SyncGlobals(c);

	// In principle, we could split these up into calls to other script
	// functions vs. BiF's.  However, before biting that off we need to
	// rework the Trigger framework so that it doesn't require CallExpr's
	// to associate delayed values with.  This can be done by introducing
	// an abstract TriggerCaller class that manages both CallExpr's and
	// internal statements (e.g., associated with the PC value at the call
	// site).  But for now, we just punt the whole problem to the
	// interpreter.

	// Look for any locals that are used in the argument list.
	// We do this separately from FlushVars because we have to
	// sync *all* the globals, whereas it only sync's those
	// that are explicitly present in the expression.
	ProfileFunc call_pf;
	c->Traverse(&call_pf);

	for ( auto l : call_pf.locals )
		StoreLocal(l);

	auto a_s = n ? AbstractStmt(OP_INTERPRET_EXPR_V, FrameSlot(n), c) :
			AbstractStmt(OP_INTERPRET_EXPR_X, c);

	auto s = AddStmt(a_s);

	// Restore globals that are relevant after the call.
	//
	// Ideally, we'd also analyze the function to see whether it
	// directly-or-indirectly can affect particular globals.
	if ( uds )
		for ( auto g : pf->globals )
			{
			if ( g->IsConst() )
				continue;

			if ( uds->HasID(g) )
				s = LoadOrStoreGlobal(g, true, false);
			}

	return s;
	}

void AbstractMachine::FlushVars(const Expr* e)
	{
	ProfileFunc expr_pf;
	e->Traverse(&expr_pf);

	auto mgr = reducer->GetDefSetsMgr();
	auto entry_rds = mgr->GetPreMaxRDs(body);

	for ( auto g : expr_pf.globals )
		SyncGlobal(g, e, entry_rds);

	for ( auto l : expr_pf.locals )
		StoreLocal(l);
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
	s.op_type = OP_VVV_I3;
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
	TopStmt().op_type = OP_VV_I2;

	if ( body && body->Tag() != STMT_NULL )
		(void) body->Compile(this);

	auto tail = GoTo(head);

	auto beyond_tail = GoToTargetBeyond(tail);
	SetV2(cond_IF, beyond_tail);

	ResolveNexts(GoToTarget(head));
	ResolveBreaks(beyond_tail);

	return tail;
	}

const CompiledStmt AbstractMachine::Loop(const Stmt* body)
	{
	auto head = StartingBlock();
	(void) body->Compile(this);
	auto tail = GoTo(head);

	ResolveNexts(GoToTarget(head));
	ResolveBreaks(GoToTargetBeyond(tail));

	return tail;
	}

const CompiledStmt AbstractMachine::When(Expr* cond, const Stmt* body,
				const Expr* timeout, const Stmt* timeout_body,
				bool is_return)
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

		AddStmt(AbstractStmt(OP_COPY_TO_VC, tmp, ce));
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
		s.op_type = OP_VV_I2;

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

const CompiledStmt AbstractMachine::Call(const ExprStmt* e)
	{
	auto uds = ud->GetUsageAfter(e);
	auto call = e->StmtExpr()->AsCallExpr();
	return DoCall(call, nullptr, uds);
	}

const CompiledStmt AbstractMachine::AssignToCall(const ExprStmt* e)
	{
	// This is a bit subtle.  Normally, we'd get the UDs *after* the
	// statement, since UDs reflect use-defs prior to statement execution.
	// However, this could be an assignment of the form "global = func()",
	// in which case whether there are UDs for "global" *after* the 
	// assignment aren't what's relevant - we still need to load
	// the global in order to do the assignment.  OTOH, the UDs *before*
	// this assignment statement will correctly capture the UDs after
	// it with the sole exception of what's being assigned.  Given
	// if what's being assigned is a globa, it doesn't need to be loaded,
	// we therefore use the UDs before this statement.
	auto uds = ud->GetUsage(e);
	auto assign = e->StmtExpr()->AsAssignExpr();
	auto n = assign->GetOp1()->AsRefExpr()->GetOp1()->AsNameExpr();
	auto call = assign->GetOp2()->AsCallExpr();

	return DoCall(call, n, uds);
	}

const CompiledStmt AbstractMachine::LoopOverTable(const ForStmt* f,
							const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto value_var = f->ValueVar();

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

	if ( value_var )
		{
		s = AbstractStmt(OP_NEXT_TABLE_ITER_VAL_VAR_VVV, info,
					FrameSlot(value_var), 0);
		s.op_type = OP_VVV_I3;
		}
	else
		{
		s = AbstractStmt(OP_NEXT_TABLE_ITER_VV, info, 0);
		s.op_type = OP_VV_I2;
		}

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

	s = AbstractStmt(OP_NEXT_VECTOR_ITER_VVV, info, FrameSlot(loop_var), 0);
	s.op_type = OP_VVV_I3;

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

	s = AbstractStmt(OP_NEXT_STRING_ITER_VVV, info, FrameSlot(loop_var), 0);
	s.op_type = OP_VVV_I3;

	return FinishLoop(s, f->LoopBody(), info);
	}

const CompiledStmt AbstractMachine::FinishLoop(AbstractStmt iter_stmt,
						const Stmt* body,
						int info_slot)
	{
	auto loop_iter = AddStmt(iter_stmt);

	auto body_end = body->Compile(this);

	auto loop_end = GoTo(loop_iter);
	auto final_stmt = AddStmt(AbstractStmt(OP_END_LOOP_V, info_slot));

	if ( iter_stmt.op_type == OP_VVV_I3 )
		SetV3(loop_iter, final_stmt);
	else
		SetV2(loop_iter, final_stmt);

	ResolveNexts(GoToTarget(loop_iter));
	ResolveBreaks(GoToTarget(final_stmt));

	return loop_end;
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
	return CompiledStmt(stmts.size() - 1);
	}

bool AbstractMachine::NullStmtOK() const
	{
	// They're okay iff they're the entire statement body.
	return stmts.size() == 0;
	}

const CompiledStmt AbstractMachine::EmptyStmt()
	{
	return CompiledStmt(stmts.size() - 1);
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

	auto s = AbstractStmt(OP_CREATE_VAL_VEC_V, tmp, n);
	s.op_type = OP_VV_I2;
	(void) AddStmt(s);

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
	return CompiledStmt(stmts.size() - 1);
	}

AbstractStmt& AbstractMachine::TopStmt()
	{
	return stmts.back();
	}

const Stmt* AbstractMachine::LastStmt() const
	{
	if ( body->Tag() == STMT_LIST )
		{
		auto sl = body->AsStmtList()->Stmts();
		return sl[sl.length() - 1];
		}

	else
		return body;
	}

const CompiledStmt AbstractMachine::LoadOrStoreLocal(ID* id, bool is_load,
							bool add)
	{
	if ( id->AsType() )
		reporter->InternalError("don't know how to compile local variable that's a type not a value");

	bool is_any = id->Type()->Tag() == TYPE_ANY;

	AbstractOp op;

	if ( is_any )
		op = is_load ? OP_LOAD_ANY_VAL_VV : OP_STORE_ANY_VAL_VV;
	else
		op = is_load ? OP_LOAD_VAL_VV : OP_STORE_VAL_VV;

	int slot = (is_load && add) ? AddToFrame(id) : FrameSlot(id);

	AbstractStmt s(op, slot, id->Offset());
	s.t = id->Type();
	s.op_type = OP_VV_FRAME;

	return AddStmt(s);
	}

const CompiledStmt AbstractMachine::LoadOrStoreGlobal(ID* id, bool is_load,
							bool add)
	{
	if ( id->AsType() )
		// We never operate on these directly, so don't bother
		// storing or loading them.
		return EmptyStmt();

	bool is_any = id->Type()->Tag() == TYPE_ANY;

	AbstractOp op;

	if ( is_any )
		op = is_load ? OP_LOAD_ANY_GLOBAL_VC : OP_STORE_ANY_GLOBAL_VC;
	else
		op = is_load ? OP_LOAD_GLOBAL_VC : OP_STORE_GLOBAL_VC;

	int slot = (is_load && add) ? AddToFrame(id) : FrameSlot(id);

	AbstractStmt s(op, slot);
	s.c.id_val = id;
	s.t = id->Type();
	s.op_type = OP_VC_ID;

	return AddStmt(s);
	}

int AbstractMachine::AddToFrame(const ID* id)
	{
	frame_layout[id] = frame_size;
	frame_denizens.push_back(id);
	return frame_size++;
	}

void AbstractMachine::Dump()
	{
	for ( auto frame_elem : frame_layout )
		printf("frame[%d] = %s\n", frame_elem.second, frame_elem.first->Name());

	for ( int i = 0; i < stmts.size(); ++i )
		{
		printf("%d: ", i);
		stmts[i].Dump(frame_denizens);
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

	BroType* stmt_type =
		c2 ? c2->Type().get() : (c3 ? c3->Type().get() : nullptr);

	if ( c2 )
		s.t = c2->Type().get();
	else if ( c3 )
		s.t = c3->Type().get();
	else if ( n3 )
		s.t = n3->Type().get();
	else
		{
		ASSERT(op3->Type()->Tag() != TYPE_TABLE);
		}

	return AddStmt(s);
	}

const CompiledStmt AbstractMachine::CompileInExpr(const NameExpr* n1,
				const ListExpr* l, const NameExpr* n2)
	{
	int n = l->Exprs().length();
	auto build_indices = InternalBuildVals(l);

	auto s = AbstractStmt(OP_TRANSFORM_VAL_VEC_TO_LIST_VAL_VVV,
				build_indices, build_indices, n);
	s.op_type = OP_VVV_I3;
	AddStmt(s);

	AbstractOp op =
		n2->Type()->Tag() == TYPE_VECTOR ?
			OP_INDEX_IS_IN_VECTOR_VVV : OP_LIST_IS_IN_TABLE_VVV;

	s = AbstractStmt(op, FrameSlot(n1), FrameSlot(n2), build_indices);

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
			s.op_type = OP_VVV_I3;
			}

		s.t = n1->Type().get();
		return AddStmt(s);
		}

	auto build_indices = InternalBuildVals(l);
	s = AbstractStmt(OP_TRANSFORM_VAL_VEC_TO_LIST_VAL_VVV,
				build_indices, build_indices, n);
	s.op_type = OP_VVV_I3;
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

	AbstractStmt s;

	if ( n )
		s = AbstractStmt(OP_SCHEDULE_ViHL, FrameSlot(n),
					is_interval, build_indices);
	else
		s = AbstractStmt(OP_SCHEDULE_CiHL, is_interval,
					build_indices, c);

	s.event_handler = h;

	return AddStmt(s);
	}

const CompiledStmt AbstractMachine::CompileEvent(EventHandler* h,
							const ListExpr* l)
	{
	int len = l->Exprs().length();
	auto build_indices = InternalBuildVals(l);

	AbstractStmt s(OP_EVENT_HL, build_indices);
	s.event_handler = h;

	return AddStmt(s);
	}

void AbstractMachine::SyncGlobals(const BroObj* o)
	{
	// (Could cache the upon-entry DPs for globals for a modest
	// speed gain.)
	auto mgr = reducer->GetDefSetsMgr();
	auto entry_rds = mgr->GetPreMaxRDs(body);

	for ( auto g : pf->globals )
		SyncGlobal(g, o, entry_rds);
	}

void AbstractMachine::SyncGlobal(ID* g, const BroObj* o,
					const RD_ptr& entry_rds)
	{
	auto mgr = reducer->GetDefSetsMgr();

	RD_ptr rds;

	if ( o )
		rds = mgr->GetPreMaxRDs(o);
	else
		// Use the *post* RDs from the last statement in the
		// function body.
		rds = mgr->GetPostMaxRDs(LastStmt());

	auto di = mgr->GetConstID_DI(g);
	auto entry_dps = entry_rds->GetDefPoints(di);
	auto stmt_dps = rds->GetDefPoints(di);

	if ( ! same_DPs(entry_dps, stmt_dps) )
		StoreGlobal(g);
	}

void AbstractMachine::ResolveGoTos(vector<int>& gotos, const CompiledStmt s)
	{
	for ( int i = 0; i < gotos.size(); ++i )
		SetGoTo(gotos[i], s);

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
	s.op_type = OP_V_I1;
	return AddStmt(s);
	}

CompiledStmt AbstractMachine::GoTo(const CompiledStmt s)
	{
	AbstractStmt stmt(OP_GOTO_V, s.stmt_num - 1);
	stmt.op_type = OP_V_I1;
	return AddStmt(stmt);
	}

CompiledStmt AbstractMachine::GoToTarget(const CompiledStmt s)
	{
	// We use one before the actual target due to pc increment
	// after the statement executes.
	return PrevStmt(s);
	}

CompiledStmt AbstractMachine::GoToTargetBeyond(const CompiledStmt s)
	{
	// See above.
	return s;
	}

CompiledStmt AbstractMachine::PrevStmt(const CompiledStmt s)
	{
	return CompiledStmt(s.stmt_num - 1);
	}

void AbstractMachine::SetV1(CompiledStmt s, const CompiledStmt s1)
	{
	auto& stmt = stmts[s.stmt_num];
	stmt.v1 = s1.stmt_num;
	ASSERT(stmt.op_type == OP_V || stmt.op_type == OP_V_I1);
	stmt.op_type = OP_V_I1;
	}

void AbstractMachine::SetV2(CompiledStmt s, const CompiledStmt s2)
	{
	auto& stmt = stmts[s.stmt_num];
	stmt.v2 = s2.stmt_num;

	if ( stmt.op_type == OP_VV )
		stmt.op_type = OP_VV_I2;

	else if ( stmt.op_type == OP_VVC )
		stmt.op_type = OP_VVC_I2;

	else
		ASSERT(stmt.op_type == OP_VV_I2 || stmt.op_type == OP_VVC_I2);
	}

void AbstractMachine::SetV3(CompiledStmt s, const CompiledStmt s2)
	{
	auto& stmt = stmts[s.stmt_num];
	stmt.v3 = s2.stmt_num;
	ASSERT(stmt.op_type == OP_VVV || stmt.op_type == OP_VVV_I3);
	stmt.op_type = OP_VVV_I3;
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
	auto id_slot = frame_layout.find(id);

	if ( id_slot == frame_layout.end() )
		reporter->InternalError("ID %s missing from frame layout", id->Name());

	return id_slot->second;
	}

bool AbstractMachine::HasFrameSlot(const ID* id) const
	{
	return frame_layout.find(id) != frame_layout.end();
	}

int AbstractMachine::FrameSlot(const NameExpr* e)
	{
	return FrameSlot(e->AsNameExpr()->Id());
	}

int AbstractMachine::NewSlot()
	{
	return frame_size++;
	}

int AbstractMachine::RegisterSlot()
	{
	return register_slot;
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
