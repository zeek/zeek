// See the file "COPYING" in the main distribution directory for copyright.

#include "ZAM.h"
#include "CompHash.h"
#include "RE.h"
#include "Frame.h"
#include "Reduce.h"
#include "Scope.h"
#include "ProfileFunc.h"
#include "Trigger.h"
#include "Desc.h"
#include "Reporter.h"
#include "Traverse.h"


void ZAM_run_time_error(bool& error_flag, const BroObj* o, const char* msg)
	{
	fprintf(stderr, "%s: %s\n", msg, obj_desc(o));
	error_flag = true;
	}


class OpaqueVals {
public:
	OpaqueVals(int _n)	{ n = _n; }

	int n;
};


// Helper functions, to translate NameExpr*'s to slots.  Some aren't
// needed, but we provide a complete set mirroring those for ZInst
// for consistency.
ZInst GenInst(ZAM* m, ZOp op)
	{
	return ZInst(op);
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1)
	{
	auto z = ZInst(op, m->FrameSlot(v1));
	z.CheckIfManaged(v1);
	return z;
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, int i)
	{
	auto z = ZInst(op, m->FrameSlot(v1), i);
	z.CheckIfManaged(v1);
	return z;
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const Expr* e)
	{
	auto z = ZInst(op, m->FrameSlot(v1), e);
	z.CheckIfManaged(v1);
	return z;
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2)
	{
	auto z = ZInst(op, m->FrameSlot(v1), m->FrameSlot(v2));
	z.CheckIfManaged(v1);
	return z;
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const NameExpr* v3)
	{
	auto z = ZInst(op, m->FrameSlot(v1), m->FrameSlot(v2),
				m->FrameSlot(v3));
	z.CheckIfManaged(v1);
	return z;
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const NameExpr* v3, const NameExpr* v4)
	{
	auto z = ZInst(op, m->FrameSlot(v1), m->FrameSlot(v2),
				m->FrameSlot(v3), m->FrameSlot(v4));
	z.CheckIfManaged(v1);
	return z;
	}

ZInst GenInst(ZAM* m, ZOp op, const ConstExpr* ce)
	{
	return ZInst(op, ce);
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* ce)
	{
	auto z = ZInst(op, m->FrameSlot(v1), ce);
	z.CheckIfManaged(v1);
	return z;
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* ce,
		const NameExpr* v2)
	{
	auto z = ZInst(op, m->FrameSlot(v1), m->FrameSlot(v2), ce);
	z.CheckIfManaged(v1);
	return z;
	}
ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const ConstExpr* ce)
	{
	auto z = ZInst(op, m->FrameSlot(v1), m->FrameSlot(v2), ce);
	z.CheckIfManaged(v1);
	return z;
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const NameExpr* v3, const ConstExpr* ce)
	{
	auto z = ZInst(op, m->FrameSlot(v1), m->FrameSlot(v2),
				m->FrameSlot(v3), ce);
	z.CheckIfManaged(v1);
	return z;
	}
ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const ConstExpr* ce, const NameExpr* v3)
	{
	// Note that here we reverse the order of the arguments; saves
	// us from needing to implement a redundant constructor.
	auto z = ZInst(op, m->FrameSlot(v1), m->FrameSlot(v2),
				m->FrameSlot(v3), ce);
	z.CheckIfManaged(v1);
	return z;
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* c, int i)
	{
	auto z = ZInst(op, m->FrameSlot(v1), i, c);
	z.CheckIfManaged(v1);
	z.op_type = OP_VVC_I2;
	return z;
	}
ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2, int i)
	{
	auto z = ZInst(op, m->FrameSlot(v1), m->FrameSlot(v2), i);
	z.CheckIfManaged(v1);
	z.op_type = OP_VVV_I3;
	return z;
	}


ZAM::ZAM(const BroFunc* f, Stmt* _body, UseDefs* _ud, Reducer* _rd,
		ProfileFunc* _pf)
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

ZAM::~ZAM()
	{
	Unref(body);
	delete ud;
	delete reducer;
	delete pf;
	}

Stmt* ZAM::CompileBody()
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
				insts[b] = ZInst(OP_HOOK_BREAK_X);
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

void ZAM::Init()
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
			(void) AddToFrame(l);
		}

	// Complain about unused aggregates.
	for ( auto a : pf->inits )
		{
		if ( pf->locals.find(a) == pf->locals.end() )
			reporter->Warning("%s unused", a->Name());
		}

	for ( auto& slot : frame_layout )
		{
		// Look for locals with values of types for which
		// we do explicit memory management on (re)assignment.
		auto t = slot.first->Type();
		if ( IsManagedType(t) )
			{
			managed_slots.push_back(slot.second);
			managed_slot_types.push_back(t);
			}
		}
	}

void ZAM::StmtDescribe(ODesc* d) const
	{
	d->Add("compiled code");
	}

static void vec_exec(ZOp op, ZAMVectorMgr*& v1, const ZAMVectorMgr* v2);

static void vec_exec(ZOp op, ZAMVectorMgr*& v1, const ZAMVectorMgr* v2,
			const ZAMVectorMgr* v3);

// Vector coercion.
#define VEC_COERCE(tag, lhs_accessor, cast, rhs_accessor) \
	static ZAMVectorMgr* vec_coerce_##tag(ZAMVectorMgr* vec) \
		{ \
		auto v = vec->ConstVec(); \
		auto res = make_shared<ZAM_vector>(); \
		for ( unsigned int i = 0; i < v->size(); ++i ) \
			(*res)[i].lhs_accessor = cast((*v)[i].rhs_accessor); \
		return new ZAMVectorMgr(res, nullptr); \
		}

VEC_COERCE(IU, int_val, bro_int_t, uint_val)
VEC_COERCE(ID, int_val, bro_int_t, double_val)
VEC_COERCE(UI, uint_val, bro_int_t, int_val)
VEC_COERCE(UD, uint_val, bro_uint_t, double_val)
VEC_COERCE(DI, double_val, double, int_val)
VEC_COERCE(DU, double_val, double, uint_val)

IntrusivePtr<Val> ZAM::Exec(Frame* f, stmt_flow_type& flow) const
	{
	return DoExec(f, 0, flow);
	}

IntrusivePtr<Val> ZAM::DoExec(Frame* f, int start_pc,
						stmt_flow_type& flow) const
	{
	auto frame = new ZAMValUnion[frame_size];
	int pc = start_pc;
	bool error_flag = false;
	int end_pc = insts.size();

	// Memory management: all of the BroObj's that we have used
	// in interior values.  By managing them here rather than
	// per-frame-slot, we don't need to add frame state about
	// whether an object should be delete'd or not on reassignment.
	std::vector<IntrusivePtr<BroObj>> vals;

#define BuildVal(v, t, s) (vals.push_back(v), ZAMValUnion(v.get(), t, s, error_flag))
#define CopyVal(v) (IsManagedType(z.t) ? BuildVal(v.ToVal(z.t), z.t, z.stmt) : v)

// Managed assignments to frame[s.v1].
#define AssignV1(v) AssignV1T(v, z.t)
#define AssignV1T(v, t) { if ( z.is_managed ) DeleteManagedType(frame[z.v1], t); frame[z.v1] = v; }

	ZAM_tracker_type ZAM_VM_Tracker;
	curr_ZAM_VM_Tracker = &ZAM_VM_Tracker;

	// Return value, or nil if none.
	const ZAMValUnion* ret_u;

	// Type of the return value.  If nil, then we don't have a value.
	BroType* ret_type = nullptr;

	// Clear slots for which we do explicit memory management.
	for ( auto s : managed_slots )
		frame[s].void_val = nullptr;

	flow = FLOW_RETURN;	// can be over-written by a Hook-Break

	while ( pc < end_pc && ! error_flag ) {
		auto& z = insts[pc];

		if ( 0 )
			{
			printf("executing %d: ", pc);
			z.Dump(frame_denizens);
			}

		switch ( z.op ) {
		case OP_NOP:
			break;

#include "ZAM-OpsEvalDefs.h"
		}

		++pc;
		}

	auto result = ret_type ? ret_u->ToVal(ret_type) : nullptr;

	// Free those slots for which we do explicit memory management.
	for ( auto i = 0; i < managed_slots.size(); ++i )
		{
		auto& v = frame[managed_slots[i]];
		DeleteManagedType(v, managed_slot_types[i]);
		}

	delete [] frame;

	return result;
	}

#include "ZAM-OpsMethodsDefs.h"

const CompiledStmt ZAM::InterpretExpr(const Expr* e)
	{
	FlushVars(e);
	return AddInst(ZInst(OP_INTERPRET_EXPR_X, e));
	}

const CompiledStmt ZAM::InterpretExpr(const NameExpr* n, const Expr* e)
	{
	FlushVars(e);
	return AddInst(GenInst(this, OP_INTERPRET_EXPR_V, n, e));
	}

const CompiledStmt ZAM::DoCall(const CallExpr* c, const NameExpr* n, UDs uds)
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

	auto a_s = n ? GenInst(this, OP_INTERPRET_EXPR_V, n, c) :
			ZInst(OP_INTERPRET_EXPR_X, c);

	auto z = AddInst(a_s);

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
				z = LoadOrStoreGlobal(g, true, false);
			}

	return z;
	}

void ZAM::FlushVars(const Expr* e)
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

const CompiledStmt ZAM::ArithCoerce(const NameExpr* n, const Expr* e)
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

	ZOp a;

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

	return AddInst(GenInst(this, a, n, op->AsNameExpr()));
	}

const CompiledStmt ZAM::RecordCoerce(const NameExpr* n, const Expr* e)
	{
	auto r = e->AsRecordCoerceExpr();
	auto op = r->GetOp1()->AsNameExpr();
	auto map = r->Map();
	auto map_size = r->MapSize();

	ZInst z(OP_RECORD_COERCE_VVV, FrameSlot(n), FrameSlot(op), map_size);

	z.t = e->Type().get();
	z.op_type = OP_VVV_I3;
	z.int_ptr = map;

	return AddInst(z);
	}

const CompiledStmt ZAM::TableCoerce(const NameExpr* n, const Expr* e)
	{
	auto op = e->GetOp1()->AsNameExpr();

	ZInst z(OP_TABLE_COERCE_VV, FrameSlot(n), FrameSlot(op));
	z.t = e->Type().get();

	return AddInst(z);
	}

const CompiledStmt ZAM::VectorCoerce(const NameExpr* n, const Expr* e)
	{
	auto op = e->GetOp1()->AsNameExpr();

	ZInst z(IsAny(n) ? OP_ANY_VECTOR_COERCE_VV : OP_VECTOR_COERCE_VV,
		FrameSlot(n), FrameSlot(op));
	z.t = e->Type().get();

	return AddInst(z);
	}

const CompiledStmt ZAM::Is(const NameExpr* n, const Expr* e)
	{
	auto is = e->AsIsExpr();
	auto op = e->GetOp1()->AsNameExpr();

	ZInst z(OP_IS_VV, FrameSlot(n), FrameSlot(op));
	z.e = op;
	z.t = is->TestType().get();

	return AddInst(z);
	}

const CompiledStmt ZAM::IfElse(const NameExpr* n, const Stmt* s1, const Stmt* s2)
	{
	ZOp op = (s1 && s2) ?
		OP_IF_ELSE_VV : (s1 ? OP_IF_VV : OP_IF_NOT_VV);

	ZInst cond(op, FrameSlot(n), 0);
	auto cond_stmt = AddInst(cond);

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

const CompiledStmt ZAM::While(const Stmt* cond_stmt, const NameExpr* cond,
				const Stmt* body)
	{
	auto head = StartingBlock();

	if ( cond_stmt )
		(void) cond_stmt->Compile(this);

	auto cond_IF = AddInst(ZInst(OP_IF_VV, FrameSlot(cond), 0));
	TopInst().op_type = OP_VV_I2;

	if ( body && body->Tag() != STMT_NULL )
		(void) body->Compile(this);

	auto tail = GoTo(head);

	auto beyond_tail = GoToTargetBeyond(tail);
	SetV2(cond_IF, beyond_tail);

	ResolveNexts(GoToTarget(head));
	ResolveBreaks(beyond_tail);

	return tail;
	}

const CompiledStmt ZAM::Loop(const Stmt* body)
	{
	auto head = StartingBlock();
	(void) body->Compile(this);
	auto tail = GoTo(head);

	ResolveNexts(GoToTarget(head));
	ResolveBreaks(GoToTargetBeyond(tail));

	return tail;
	}

const CompiledStmt ZAM::When(Expr* cond, const Stmt* body,
				const Expr* timeout, const Stmt* timeout_body,
				bool is_return)
	{
	// ### Flush locals on eval, and also on exit
	ZInst z;

	if ( timeout )
		{
		// Note, we fill in is_return by hand since it's already
		// an int_val, doesn't need translation.
		if ( timeout->Tag() == EXPR_CONST )
			z = GenInst(this, OP_WHEN_VVVC, timeout->AsConstExpr());
		else
			z = GenInst(this, OP_WHEN_VVVV, timeout->AsNameExpr());
		}

	else
		z = GenInst(this, OP_WHEN_VV);

	z.v4 = is_return;
	z.non_const_e = cond;

	AddInst(z);

	auto branch_past_blocks = GoTo();

	auto when_body = body->Compile(this);
	auto when_done = ReturnX();

	if ( timeout )
		{
		auto t_body = timeout_body->Compile(this);
		auto t_done = ReturnX();

		z.v2 = branch_past_blocks.stmt_num + 1;
		z.v3 = when_done.stmt_num + 1;
		SetGoTo(branch_past_blocks, GoToTargetBeyond(t_done));

		return t_done;
		}

	else
		{
		z.v2 = branch_past_blocks.stmt_num + 1;
		SetGoTo(branch_past_blocks, GoToTargetBeyond(when_done));

		return when_done;
		}
	}

const CompiledStmt ZAM::Switch(const SwitchStmt* sw)
	{
	auto e = sw->StmtExpr();

	const NameExpr* n = e->Tag() == EXPR_NAME ? e->AsNameExpr() : nullptr;
	const ConstExpr* c = e->Tag() == EXPR_CONST ? e->AsConstExpr() : nullptr;

	auto t = e->Type()->Tag();

	if ( t != TYPE_ANY && t != TYPE_TYPE )
		return ValueSwitch(sw, n, c);
	else
		return TypeSwitch(sw, n, c);
	}

const CompiledStmt ZAM::ValueSwitch(const SwitchStmt* sw, const NameExpr* v,
					const ConstExpr* c)
	{
	auto body_end = EmptyStmt();

	int slot = v ? FrameSlot(v) : 0;

	if ( c )
		{
		// Weird to have a constant switch expression, enough
		// so that it doesn't seem worth optimizing.
		slot = RegisterSlot();
		auto z = ZInst(OP_ASSIGN_CONST_VC, slot, c);
		z.CheckIfManaged(c);
		body_end = AddInst(z);
		}

	// Figure out which jump table we're using.
	auto t = v ? v->Type() : c->Type();
	int tbl = 0;
	ZOp op;

	switch ( t->InternalType() ) {
	case TYPE_INTERNAL_INT:
		op = OP_SWITCHI_VVV;
		tbl = int_cases.size();
		break;

	case TYPE_INTERNAL_UNSIGNED:
		op = OP_SWITCHU_VVV;
		tbl = uint_cases.size();
		break;

	case TYPE_INTERNAL_DOUBLE:
		op = OP_SWITCHD_VVV;
		tbl = double_cases.size();
		break;

	case TYPE_INTERNAL_STRING:
		op = OP_SWITCHS_VVV;
		tbl = str_cases.size();
		break;

	case TYPE_INTERNAL_ADDR:
		op = OP_SWITCHA_VVV;
		tbl = str_cases.size();
		break;

	case TYPE_INTERNAL_SUBNET:
		op = OP_SWITCHN_VVV;
		tbl = str_cases.size();
		break;

	default:
		reporter->InternalError("bad switch type");
	}

	// Add the "head", i.e., the execution of the jump table.
	auto sw_head_op = ZInst(op, slot, tbl, 0);
	sw_head_op.op_type = OP_VVV_I2_I3;

	auto sw_head = AddInst(sw_head_op);
	body_end = sw_head;

	// Generate each of the cases.
	auto cases = sw->Cases();
	std::vector<CompiledStmt> case_start;

	for ( auto c : *cases )
		{
		auto start = GoToTargetBeyond(body_end);
		ResolveFallThroughs(start);
		case_start.push_back(start);
		body_end = c->Body()->Compile(this);
		}

	auto sw_end = GoToTargetBeyond(body_end);
	ResolveFallThroughs(sw_end);
	ResolveBreaks(sw_end);

	int def_ind = sw->DefaultCaseIndex();
	if ( def_ind >= 0 )
		SetV3(sw_head, case_start[def_ind]);
	else
		SetV3(sw_head, sw_end);

	// Now fill out the corresponding jump table.
	//
	// We will only use one of these.
	CaseMap<bro_int_t> new_int_cases;
	CaseMap<bro_uint_t> new_uint_cases;
	CaseMap<double> new_double_cases;
	CaseMap<std::string> new_str_cases;

	auto val_map = sw->ValueMap();

	// Ugh: the switch statement data structures don't store
	// the values directly, so we have to back-scrape them from
	// the interpreted jump table.
	auto ch = sw->CompHash();

	HashKey* k;
	int* index;
	IterCookie* cookie = val_map->InitForIteration();
	while ( (index = val_map->NextEntry(k, cookie)) )
		{
		auto case_val_list = ch->RecoverVals(k);
		delete k;

		auto case_vals = case_val_list->Vals();

		if ( case_vals->length() != 1 )
			reporter->InternalError("bad recovered value when compiling switch");

		auto cv = (*case_vals)[0];
		auto case_body_start = case_start[*index].stmt_num;

		switch ( cv->Type()->InternalType() ) {
		case TYPE_INTERNAL_INT:
			new_int_cases[cv->InternalInt()] = case_body_start;
			break;

		case TYPE_INTERNAL_UNSIGNED:
			new_uint_cases[cv->InternalUnsigned()] = case_body_start;
			break;

		case TYPE_INTERNAL_DOUBLE:
			new_double_cases[cv->InternalDouble()] = case_body_start;
			break;

		case TYPE_INTERNAL_STRING:
			{
			// This leaks, but only statically so not worth
			// tracking the value for ultimate deletion.
			auto sv = cv->AsString()->Render();
			std::string s(sv);
			new_str_cases[s] = case_body_start;
			break;
			}

		case TYPE_INTERNAL_ADDR:
			{
			auto a = cv->AsAddr().AsString();
			new_str_cases[a] = case_body_start;
			break;
			}

		case TYPE_INTERNAL_SUBNET:
			{
			auto n = cv->AsSubNet().AsString();
			new_str_cases[n] = case_body_start;
			break;
			}

		default:
			reporter->InternalError("bad recovered type when compiling switch");
		}
		}

	// Now add the jump table to the set we're keeping for the
	// corresponding type.

	switch ( t->InternalType() ) {
	case TYPE_INTERNAL_INT:
		int_cases.push_back(new_int_cases);
		break;

	case TYPE_INTERNAL_UNSIGNED:
		uint_cases.push_back(new_uint_cases);
		break;

	case TYPE_INTERNAL_DOUBLE:
		double_cases.push_back(new_double_cases);
		break;

	case TYPE_INTERNAL_STRING:
	case TYPE_INTERNAL_ADDR:
	case TYPE_INTERNAL_SUBNET:
		str_cases.push_back(new_str_cases);
		break;

	default:
		reporter->InternalError("bad switch type");
	}

	return body_end;
	}

const CompiledStmt ZAM::TypeSwitch(const SwitchStmt* sw, const NameExpr* v,
					const ConstExpr* c)
	{
	auto cases = sw->Cases();
	auto type_map = sw->TypeMap();

	auto body_end = EmptyStmt();

	auto tmp = RegisterSlot();

	int slot = v ? FrameSlot(v) : 0;

	if ( v && v->Type()->Tag() != TYPE_ANY )
		{
		auto z = ZInst(OP_ASSIGN_ANY_VV, tmp, slot);
		body_end = AddInst(z);
		slot = tmp;
		}

	if ( c )
		{
		auto z = ZInst(OP_ASSIGN_ANY_VC, tmp, c);
		body_end = AddInst(z);
		slot = tmp;
		}

	int def_ind = sw->DefaultCaseIndex();
	CompiledStmt def_succ(0);	// successor to default, if any
	bool saw_def_succ = false;	// whether def_succ is meaningful

	for ( auto& i : *type_map )
		{
		auto id = i.first;
		auto type = id->Type();

		ZInst z;

		z = ZInst(OP_BRANCH_IF_NOT_TYPE_VV, slot, 0);
		z.t = type;
		z.op_type = OP_VV_I2;
		auto case_test = AddInst(z);

		// Type cases that don't use "as" create a placeholder
		// ID with a null name.
		if ( id->Name() )
			{
			int id_slot = FrameSlot(id);
			z = ZInst(OP_CAST_ANY_VV, id_slot, slot);
			z.t = type;
			body_end = AddInst(z);
			}
		else
			body_end = case_test;

		ResolveFallThroughs(GoToTargetBeyond(body_end));
		body_end = (*cases)[i.second]->Body()->Compile(this);
		SetV2(case_test, GoToTargetBeyond(body_end));

		if ( def_ind >= 0 && i.second == def_ind + 1 )
			{
			def_succ = case_test;
			saw_def_succ = true;
			}
		}

	ResolveFallThroughs(GoToTargetBeyond(body_end));

	if ( def_ind >= 0 )
		{
		body_end = (*sw->Cases())[def_ind]->Body()->Compile(this);

		// Now resolve any fallthrough's in the default.
		if ( saw_def_succ )
			ResolveFallThroughs(GoToTargetBeyond(def_succ));
		else
			ResolveFallThroughs(GoToTargetBeyond(body_end));
		}

	ResolveBreaks(GoToTargetBeyond(body_end));

	return body_end;
	}

const CompiledStmt ZAM::For(const ForStmt* f)
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

const CompiledStmt ZAM::Call(const ExprStmt* e)
	{
	auto uds = ud->GetUsageAfter(e);
	auto call = e->StmtExpr()->AsCallExpr();
	return DoCall(call, nullptr, uds);
	}

const CompiledStmt ZAM::AssignToCall(const ExprStmt* e)
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

const CompiledStmt ZAM::AssignVecElems(const Expr* e)
	{
	auto index_assign = e->AsIndexAssignExpr();

	auto op1 = index_assign->GetOp1();
	auto op2 = index_assign->GetOp2()->AsListExpr()->Exprs()[0];
	auto op3 = index_assign->GetOp3();

	auto lhs = op1->AsNameExpr();
	auto is_any = IsAny(lhs);

	if ( op2->Tag() == EXPR_NAME )
		{
		CompiledStmt inst(0);

		if ( op3->Tag() == EXPR_NAME )
			inst = is_any ?
					Any_Vector_Elem_AssignVVV(lhs,
							op2->AsNameExpr(),
							op3->AsNameExpr()) :
					Vector_Elem_AssignVVV(lhs,
							op2->AsNameExpr(),
							op3->AsNameExpr());
		else
			inst = is_any ?
					Any_Vector_Elem_AssignVVC(lhs,
							op2->AsNameExpr(),
							op3->AsConstExpr()) :
					Vector_Elem_AssignVVC(lhs,
							op2->AsNameExpr(),
							op3->AsConstExpr());

		TopInst().t = op3->Type().get();
		return inst;
		}

	else
		{
		auto c = op2->AsConstExpr();
		if ( op3->Tag() == EXPR_NAME )
			{
			auto index = c->Value()->AsCount();

			auto inst = is_any ?
					Any_Vector_Elem_AssignVVi(lhs,
						op3->AsNameExpr(), index) :
					Vector_Elem_AssignVVi(lhs,
						op3->AsNameExpr(), index);

			TopInst().t = op3->Type().get();
			return inst;
			}

		// A pain - two constants.
		auto c3 = op3->AsConstExpr();
		auto tmp = RegisterSlot();
		auto z = ZInst(OP_ASSIGN_VC, tmp, c3);
		z.CheckIfManaged(c3);
		z.t = c3->Type().get();

		AddInst(z);

		return is_any ? Any_Vector_Elem_AssignVCi(lhs,
						op2->AsConstExpr(), tmp) :
			Vector_Elem_AssignVCi(lhs, op2->AsConstExpr(), tmp);
		}
	}

const CompiledStmt ZAM::LoopOverTable(const ForStmt* f, const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto value_var = f->ValueVar();

	auto info = NewSlot();
	auto z = ZInst(OP_INIT_TABLE_LOOP_VV, info, FrameSlot(val));
	z.t = value_var ? value_var->Type() : nullptr;
	auto init_end = AddInst(z);

	for ( int i = 0; i < loop_vars->length(); ++i )
		{
		auto id = (*loop_vars)[i];
		z = ZInst(OP_ADD_VAR_TO_INIT_VV, info, FrameSlot(id));
		z.CheckIfManaged(id->Type());
		z.t = id->Type();
		init_end = AddInst(z);
		}

	if ( value_var )
		{
		z = ZInst(OP_NEXT_TABLE_ITER_VAL_VAR_VVV, info,
					FrameSlot(value_var), 0);
		z.CheckIfManaged(value_var->Type());
		z.op_type = OP_VVV_I3;
		}
	else
		{
		z = ZInst(OP_NEXT_TABLE_ITER_VV, info, 0);
		z.op_type = OP_VV_I2;
		}

	return FinishLoop(z, f->LoopBody(), info);
	}

const CompiledStmt ZAM::LoopOverVector(const ForStmt* f, const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto loop_var = (*loop_vars)[0];

	bool is_any = IsAny(val);

	auto info = NewSlot();
	auto z = ZInst(is_any ? OP_INIT_ANY_VECTOR_LOOP_VV :
				OP_INIT_VECTOR_LOOP_VV, info, FrameSlot(val));
	z.t = val->Type().get();
	auto init_end = AddInst(z);

	z = ZInst(is_any ? OP_NEXT_ANY_VECTOR_ITER_VVV :
			OP_NEXT_VECTOR_ITER_VVV, info, FrameSlot(loop_var), 0);
	z.op_type = OP_VVV_I3;

	return FinishLoop(z, f->LoopBody(), info);
	}

const CompiledStmt ZAM::LoopOverString(const ForStmt* f, const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto loop_var = (*loop_vars)[0];

	auto info = NewSlot();
	auto z = ZInst(OP_INIT_STRING_LOOP_VV, info, FrameSlot(val));
	z.CheckIfManaged(val);
	auto init_end = AddInst(z);

	z = ZInst(OP_NEXT_STRING_ITER_VVV, info, FrameSlot(loop_var), 0);
	z.CheckIfManaged(loop_var->Type());
	z.op_type = OP_VVV_I3;

	return FinishLoop(z, f->LoopBody(), info);
	}

const CompiledStmt ZAM::FinishLoop(ZInst iter_stmt, const Stmt* body,
					int info_slot)
	{
	auto loop_iter = AddInst(iter_stmt);

	auto body_end = body->Compile(this);

	auto loop_end = GoTo(loop_iter);
	auto final_stmt = AddInst(ZInst(OP_END_LOOP_V, info_slot));

	if ( iter_stmt.op_type == OP_VVV_I3 )
		SetV3(loop_iter, final_stmt);
	else
		SetV2(loop_iter, final_stmt);

	ResolveNexts(GoToTarget(loop_iter));
	ResolveBreaks(GoToTarget(final_stmt));

	return loop_end;
	}

const CompiledStmt ZAM::InitRecord(ID* id, RecordType* rt)
	{
	auto z = ZInst(OP_INIT_RECORD_V, FrameSlot(id));
	z.t = rt;
	return AddInst(z);
	}

const CompiledStmt ZAM::InitVector(ID* id, VectorType* vt)
	{
	auto op = vt->YieldType()->Tag() == TYPE_ANY ?
			OP_INIT_ANY_VECTOR_VV :
			OP_INIT_VECTOR_VV;

	auto z = ZInst(op, FrameSlot(id), id->Offset());
	z.t = vt;
	z.op_type = OP_VV_FRAME;
	return AddInst(z);
	}

const CompiledStmt ZAM::InitTable(ID* id, TableType* tt, Attributes* attrs)
	{
	auto z = ZInst(OP_INIT_TABLE_V, FrameSlot(id));
	z.t = tt;
	z.attrs = attrs;
	return AddInst(z);
	}

const CompiledStmt ZAM::StartingBlock()
	{
	return CompiledStmt(insts.size());
	}

const CompiledStmt ZAM::FinishBlock(const CompiledStmt /* start */)
	{
	return CompiledStmt(insts.size() - 1);
	}

bool ZAM::NullStmtOK() const
	{
	// They're okay iff they're the entire statement body.
	return insts.size() == 0;
	}

const CompiledStmt ZAM::EmptyStmt()
	{
	return CompiledStmt(insts.size() - 1);
	}

const CompiledStmt ZAM::ErrorStmt()
	{
	error_seen = true;
	return CompiledStmt(0);
	}

bool ZAM::IsUnused(const ID* id, const Stmt* where) const
	{
	if ( ! ud->HasUsage(where) )
		return true;

	return ! ud->GetUsage(where)->HasID(id);
	}

OpaqueVals* ZAM::BuildVals(const IntrusivePtr<ListExpr>& l)
	{
	return new OpaqueVals(InternalBuildVals(l.get()));
	}

int ZAM::InternalBuildVals(const ListExpr* l)
	{
	auto exprs = l->Exprs();
	int n = exprs.length();
	auto tmp = RegisterSlot();

	auto z = ZInst(OP_CREATE_VAL_VEC_V, tmp, n);
	z.op_type = OP_VV_I2;
	(void) AddInst(z);

	for ( int i = 0; i < n; ++i )
		{
		const auto& e = exprs[i];

		ZInst as;

		if ( e->Tag() == EXPR_NAME )
			{
			int v = FrameSlot(e->AsNameExpr());
			as = ZInst(OP_SET_VAL_VEC_VV, tmp, v);
			}
		else
			{
			auto c = e->AsConstExpr();
			as = ZInst(OP_SET_VAL_VEC_VC, tmp, c);
			}

		as.t = e->Type().get();
		(void) AddInst(as);
		}

	return tmp;
	}

const CompiledStmt ZAM::AddInst(const ZInst& inst)
	{
	insts.push_back(inst);
	return CompiledStmt(insts.size() - 1);
	}

ZInst& ZAM::TopInst()
	{
	return insts.back();
	}

const Stmt* ZAM::LastStmt() const
	{
	if ( body->Tag() == STMT_LIST )
		{
		auto sl = body->AsStmtList()->Stmts();
		return sl[sl.length() - 1];
		}

	else
		return body;
	}

const CompiledStmt ZAM::LoadOrStoreLocal(ID* id, bool is_load, bool add)
	{
	if ( id->AsType() )
		reporter->InternalError("don't know how to compile local variable that's a type not a value");

	bool is_any = IsAny(id->Type());

	ZOp op;

	if ( is_any )
		op = is_load ? OP_LOAD_ANY_VAL_VV : OP_STORE_ANY_VAL_VV;
	else
		op = is_load ? OP_LOAD_VAL_VV : OP_STORE_VAL_VV;

	int slot = (is_load && add) ? AddToFrame(id) : FrameSlot(id);

	ZInst z(op, slot, id->Offset());
	z.t = id->Type();
	z.op_type = OP_VV_FRAME;

	return AddInst(z);
	}

const CompiledStmt ZAM::LoadOrStoreGlobal(ID* id, bool is_load, bool add)
	{
	if ( id->AsType() )
		// We never operate on these directly, so don't bother
		// storing or loading them.
		return EmptyStmt();

	ZOp op;
	bool is_any = IsAny(id->Type());

	if ( is_any )
		op = is_load ? OP_LOAD_ANY_GLOBAL_VC : OP_STORE_ANY_GLOBAL_VC;
	else
		op = is_load ? OP_LOAD_GLOBAL_VC : OP_STORE_GLOBAL_VC;

	int slot = (is_load && add) ? AddToFrame(id) : FrameSlot(id);

	ZInst z(op, slot);
	z.c.id_val = id;
	z.t = id->Type();
	z.op_type = OP_VC_ID;

	return AddInst(z);
	}

int ZAM::AddToFrame(const ID* id)
	{
	frame_layout[id] = frame_size;
	frame_denizens.push_back(id);
	return frame_size++;
	}

void ZAM::Dump()
	{
	for ( auto frame_elem : frame_layout )
		printf("frame[%d] = %s\n", frame_elem.second, frame_elem.first->Name());

	for ( int i = 0; i < int_cases.size(); ++i )
		DumpIntCases(i);
	for ( int i = 0; i < uint_cases.size(); ++i )
		DumpUIntCases(i);
	for ( int i = 0; i < double_cases.size(); ++i )
		DumpDoubleCases(i);
	for ( int i = 0; i < str_cases.size(); ++i )
		DumpStrCases(i);

	for ( int i = 0; i < insts.size(); ++i )
		{
		printf("%d: ", i);
		insts[i].Dump(frame_denizens);
		}
	}

void ZAM::DumpIntCases(int i) const
	{
	printf("int switch table #%d:", i);
	for ( auto& m : int_cases[i] )
		printf(" %lld->%d", m.first, m.second);
	printf("\n");
	}

void ZAM::DumpUIntCases(int i) const
	{
	printf("uint switch table #%d:", i);
	for ( auto& m : uint_cases[i] )
		printf(" %llu->%d", m.first, m.second);
	printf("\n");
	}

void ZAM::DumpDoubleCases(int i) const
	{
	printf("double switch table #%d:", i);
	for ( auto& m : double_cases[i] )
		printf(" %lf->%d", m.first, m.second);
	printf("\n");
	}

void ZAM::DumpStrCases(int i) const
	{
	printf("str switch table #%d:", i);
	for ( auto& m : str_cases[i] )
		printf(" %s->%d", m.first.c_str(), m.second);
	printf("\n");
	}

const CompiledStmt ZAM::CompileInExpr(const NameExpr* n1,
				const NameExpr* n2, const ConstExpr* c2,
				const NameExpr* n3, const ConstExpr* c3)
	{
	auto op2 = n2 ? (Expr*) n2 : (Expr*) c2;
	auto op3 = n3 ? (Expr*) n3 : (Expr*) c3;

	ZOp a;

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

	ZInst z;

	if ( n2 )
		{
		if ( n3 )
			z = ZInst(a, s1, s2, s3);
		else
			z = ZInst(a, s1, s2, c3);
		}
	else
		z = ZInst(a, s1, s3, c2);

	BroType* stmt_type =
		c2 ? c2->Type().get() : (c3 ? c3->Type().get() : nullptr);

	if ( c2 )
		z.t = c2->Type().get();
	else if ( c3 )
		z.t = c3->Type().get();
	else
		z.t = n2->Type().get();

	return AddInst(z);
	}

const CompiledStmt ZAM::CompileInExpr(const NameExpr* n1, const ListExpr* l,
					const NameExpr* n2)
	{
	int n = l->Exprs().length();
	auto build_indices = InternalBuildVals(l);

	auto z = ZInst(OP_TRANSFORM_VAL_VEC_TO_LIST_VAL_VVV,
				build_indices, build_indices, n);
	z.op_type = OP_VVV_I3;
	AddInst(z);

	ZOp op =
		n2->Type()->Tag() == TYPE_VECTOR ?
			OP_INDEX_IS_IN_VECTOR_VVV : OP_LIST_IS_IN_TABLE_VVV;

	z = ZInst(op, FrameSlot(n1), FrameSlot(n2), build_indices);
	z.t = n2->Type().get();

	return AddInst(z);
	}

const CompiledStmt ZAM::CompileIndex(const NameExpr* n1, const NameExpr* n2,
					const ListExpr* l)
	{
	ZInst z;

	int n = l->Exprs().length();
	auto n2t = n2->Type();
	auto n2tag = n2t->Tag();

	if ( n == 1 )
		{
		auto ind = l->Exprs()[0];
		auto var_ind = ind->Tag() == EXPR_NAME;
		auto n3 = var_ind ? ind->AsNameExpr() : nullptr;
		bro_uint_t c = 0;

		if ( ! var_ind && ind->Type()->Tag() == TYPE_COUNT )
			c = ind->AsConstExpr()->Value()->AsCount();

		if ( n2tag == TYPE_STRING )
			{
			if ( n3 )
				z = ZInst(OP_INDEX_STRING_VVV, FrameSlot(n1),
						FrameSlot(n2), FrameSlot(n3));
			else
				{
				z = ZInst(OP_INDEX_STRINGC_VVV, FrameSlot(n1),
						FrameSlot(n2), c);
				z.op_type = OP_VVV_I3;
				}

			return AddInst(z);
			}

		if ( n2tag == TYPE_VECTOR && ! IsAny(n2) )
			{
			if ( n3 )
				z = ZInst(OP_INDEX_VEC_VVV, FrameSlot(n1),
						FrameSlot(n2), FrameSlot(n3));
			else
				{
				z = ZInst(OP_INDEX_VECC_VVV, FrameSlot(n1),
						FrameSlot(n2), c);
				z.op_type = OP_VVV_I3;
				}

			z.t = n2t.get();
			z.e = n2;
			return AddInst(z);
			}
		}

	auto build_indices = InternalBuildVals(l);
	z = ZInst(OP_TRANSFORM_VAL_VEC_TO_LIST_VAL_VVV,
				build_indices, build_indices, n);
	z.op_type = OP_VVV_I3;
	AddInst(z);

	auto indexes = l->Exprs();

	switch ( n2tag ) {
	case TYPE_VECTOR:
		{
		ZOp op =
			n == 1 ? OP_INDEX_VEC_VVL : OP_INDEX_VEC_SLICE_VVL;

		z = ZInst(op, FrameSlot(n1), FrameSlot(n2),
					build_indices);
		z.t = n2->Type().get();
		break;
		}

	case TYPE_TABLE:
		z = ZInst(OP_TABLE_INDEX_VVV, FrameSlot(n1),
					FrameSlot(n2), build_indices);
		z.t = n1->Type().get();
		break;

	case TYPE_STRING:
		z = ZInst(OP_INDEX_STRING_SLICE_VVL, FrameSlot(n1),
					FrameSlot(n2), build_indices);
		z.t = n1->Type().get();
		break;

	default:
		reporter->InternalError("bad aggregate type when compiling index");
	}

	z.CheckIfManaged(n1);
	return AddInst(z);
	}

const CompiledStmt ZAM::CompileSchedule(const NameExpr* n, const ConstExpr* c,
					int is_interval, EventHandler* h,
					const ListExpr* l)
	{
	int len = l->Exprs().length();
	auto build_indices = InternalBuildVals(l);

	ZInst z;

	if ( n )
		z = ZInst(OP_SCHEDULE_ViHL, FrameSlot(n),
					is_interval, build_indices);
	else
		z = ZInst(OP_SCHEDULE_CiHL, is_interval,
					build_indices, c);

	z.event_handler = h;

	return AddInst(z);
	}

const CompiledStmt ZAM::CompileEvent(EventHandler* h, const ListExpr* l)
	{
	int len = l->Exprs().length();
	auto build_indices = InternalBuildVals(l);

	ZInst z(OP_EVENT_HL, build_indices);
	z.event_handler = h;

	return AddInst(z);
	}

void ZAM::SyncGlobals(const BroObj* o)
	{
	// (Could cache the upon-entry DPs for globals for a modest
	// speed gain.)
	auto mgr = reducer->GetDefSetsMgr();
	auto entry_rds = mgr->GetPreMaxRDs(body);

	for ( auto g : pf->globals )
		SyncGlobal(g, o, entry_rds);
	}

void ZAM::SyncGlobal(ID* g, const BroObj* o,
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

void ZAM::ResolveGoTos(vector<int>& gotos, const CompiledStmt s)
	{
	for ( int i = 0; i < gotos.size(); ++i )
		SetGoTo(gotos[i], s);

	gotos.clear();
	}

CompiledStmt ZAM::GenGoTo(vector<int>& v)
	{
	auto g = GoTo();
	v.push_back(g.stmt_num);

	return g;
	}

CompiledStmt ZAM::GoTo()
	{
	ZInst z(OP_GOTO_V, 0);
	z.op_type = OP_V_I1;
	return AddInst(z);
	}

CompiledStmt ZAM::GoTo(const CompiledStmt s)
	{
	ZInst inst(OP_GOTO_V, s.stmt_num - 1);
	inst.op_type = OP_V_I1;
	return AddInst(inst);
	}

CompiledStmt ZAM::GoToTarget(const CompiledStmt s)
	{
	// We use one before the actual target due to pc increment
	// after the statement executes.
	return PrevStmt(s);
	}

CompiledStmt ZAM::GoToTargetBeyond(const CompiledStmt s)
	{
	// See above.
	return s;
	}

CompiledStmt ZAM::PrevStmt(const CompiledStmt s)
	{
	return CompiledStmt(s.stmt_num - 1);
	}

void ZAM::SetV1(CompiledStmt s, const CompiledStmt s1)
	{
	auto& inst = insts[s.stmt_num];
	inst.v1 = s1.stmt_num;
	ASSERT(inst.op_type == OP_V || inst.op_type == OP_V_I1);
	inst.op_type = OP_V_I1;
	}

void ZAM::SetV2(CompiledStmt s, const CompiledStmt s2)
	{
	auto& inst = insts[s.stmt_num];
	inst.v2 = s2.stmt_num;

	if ( inst.op_type == OP_VV )
		inst.op_type = OP_VV_I2;

	else if ( inst.op_type == OP_VVC )
		inst.op_type = OP_VVC_I2;

	else
		ASSERT(inst.op_type == OP_VV_I2 || inst.op_type == OP_VVC_I2);
	}

void ZAM::SetV3(CompiledStmt s, const CompiledStmt s2)
	{
	auto& inst = insts[s.stmt_num];
	inst.v3 = s2.stmt_num;
	ASSERT(inst.op_type == OP_VVV || inst.op_type == OP_VVV_I3 ||
		inst.op_type == OP_VVV_I2_I3);
	if ( inst.op_type != OP_VVV_I2_I3 )
		inst.op_type = OP_VVV_I3;
	}


ListVal* ZAM::ValVecToListVal(val_vec* v, int n) const
	{
	auto res = new ListVal(TYPE_ANY);

	for ( int i = 0; i < n; ++i )
		res->Append((*v)[i].release());

	delete v;

	return res;
	}

int ZAM::FrameSlot(const ID* id)
	{
	auto id_slot = frame_layout.find(id);

	if ( id_slot == frame_layout.end() )
		reporter->InternalError("ID %s missing from frame layout", id->Name());

	return id_slot->second;
	}

bool ZAM::HasFrameSlot(const ID* id) const
	{
	return frame_layout.find(id) != frame_layout.end();
	}

int ZAM::FrameSlot(const NameExpr* e)
	{
	return FrameSlot(e->AsNameExpr()->Id());
	}

int ZAM::NewSlot()
	{
	return frame_size++;
	}

int ZAM::RegisterSlot()
	{
	return register_slot;
	}

void ZAM::SpillVectors(ZAM_tracker_type* tracker) const
	{
	for ( auto vm : *tracker )
		vm->Spill();
	}

void ZAM::LoadVectors(ZAM_tracker_type* tracker) const
	{
	for ( auto vm : *tracker )
		vm->Freshen();
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
static void vec_exec(ZOp op, ZAMVectorMgr*& v1, const ZAMVectorMgr* v2)
	{
	// We could speed this up further still by gen'ing up an
	// instance of the loop inside each switch case (in which
	// case we might as well move the whole kit-and-caboodle
	// into the Exec method).  But that seems like a lot of
	// code bloat for only a very modest gain.

	auto& vec2 = *v2->ConstVec();

	if ( v1 )
		v1->ModVec()->resize(vec2.size());
	else
		v1 = new ZAMVectorMgr(make_shared<ZAM_vector>(vec2.size()), nullptr);

	auto& vec1 = *v1->ModVec();

	for ( unsigned int i = 0; i < vec2.size(); ++i )
		switch ( op ) {

#include "ZAM-Vec1EvalDefs.h"

		default:
			reporter->InternalError("bad invocation of VecExec");
		}
	}

// Binary vector operation of v1 = v2 <vec-op> v3.
static void vec_exec(ZOp op, ZAMVectorMgr*& v1, const ZAMVectorMgr* v2,
			const ZAMVectorMgr* v3)
	{
	// See comment above re further speed-up.

	auto& vec2 = *v2->ConstVec();
	auto& vec3 = *v3->ConstVec();

	if ( v1 )
		v1->ModVec()->resize(vec2.size());
	else
		v1 = new ZAMVectorMgr(make_shared<ZAM_vector>(vec2.size()), nullptr);

	auto& vec1 = *v1->ModVec();

	for ( unsigned int i = 0; i < vec2.size(); ++i )
		switch ( op ) {

#include "ZAM-Vec2EvalDefs.h"

		default:
			reporter->InternalError("bad invocation of VecExec");
		}
	}
