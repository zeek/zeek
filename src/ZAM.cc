// See the file "COPYING" in the main distribution directory for copyright.

#include "ZAM.h"
#include "CompHash.h"
#include "RE.h"
#include "Frame.h"
#include "Reduce.h"
#include "Scope.h"
#include "ProfileFunc.h"
#include "ScriptAnaly.h"
#include "Trigger.h"
#include "Desc.h"
#include "Reporter.h"
#include "Traverse.h"


// Count of how often each top of ZOP executed.
int ZOP_count[OP_NOP+1];

// Per-interpreted-expression.
std::unordered_map<const Expr*, double> expr_CPU;


void report_ZOP_profile()
	{
	for ( int i = 1; i <= OP_HOOK_BREAK_X; ++i )
		if ( ZOP_count[i] > 0 )
			printf("%s\t%d\n", ZOP_name(ZOp(i)), ZOP_count[i]);

	for ( auto& e : expr_CPU )
		printf("expr CPU %.06f %s\n", e.second, obj_desc(e.first));
	}


void ZAM_run_time_error(bool& error_flag, const Stmt* stmt, const char* msg)
	{
	if ( stmt->Tag() == STMT_EXPR )
		{
		auto e = stmt->AsExprStmt()->StmtExpr();
		reporter->ExprRuntimeError(e, "%s", msg);
		}
	else
		fprintf(stderr, "%s: %s\n", msg, obj_desc(stmt));

	error_flag = true;
	}

void ZAM_run_time_error(const char* msg, const BroObj* o,
				bool& error_flag)
	{
	fprintf(stderr, "%s: %s\n", msg, obj_desc(o));
	error_flag = true;
	}


class OpaqueVals {
public:
	OpaqueVals(int _n)	{ n = _n; }

	int n;
};


typedef enum {
	GS_UNLOADED,	// global hasn't been loaded
	GS_CLEAN,	// global has been loaded but not modified
	GS_DIRTY,	// loaded-and-modified
} GlobalState;


// Helper functions, to translate NameExpr*'s to slots.  Some aren't
// needed, but we provide a complete set mirroring those for ZInst
// for consistency.
ZInst GenInst(ZAM* m, ZOp op)
	{
	return ZInst(op);
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1)
	{
	return ZInst(op, m->Frame1Slot(v1, op));
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, int i)
	{
	return ZInst(op, m->Frame1Slot(v1, op), i);
	}

ZInst GenInst(ZAM* m, ZOp op, const ConstExpr* c, const NameExpr* v1, int i)
	{
	auto z = ZInst(op, m->Frame1Slot(v1, op), i, c);
	z.op_type = OP_VVC_I2;
	return z;
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const Expr* e)
	{
	return ZInst(op, m->Frame1Slot(v1, op), e);
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2)
	{
	int nv2 = m->FrameSlot(v2);
	return ZInst(op, m->Frame1Slot(v1, op), nv2);
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const NameExpr* v3)
	{
	int nv2 = m->FrameSlot(v2);
	int nv3 = m->FrameSlot(v3);
	return ZInst(op, m->Frame1Slot(v1, op), nv2, nv3);
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const NameExpr* v3, const NameExpr* v4)
	{
	int nv2 = m->FrameSlot(v2);
	int nv3 = m->FrameSlot(v3);
	int nv4 = m->FrameSlot(v4);
	return ZInst(op, m->Frame1Slot(v1, op), nv2, nv3, nv4);
	}

ZInst GenInst(ZAM* m, ZOp op, const ConstExpr* ce)
	{
	return ZInst(op, ce);
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* ce)
	{
	return ZInst(op, m->Frame1Slot(v1, op), ce);
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* ce,
		const NameExpr* v2)
	{
	int nv2 = m->FrameSlot(v2);
	return ZInst(op, m->Frame1Slot(v1, op), nv2, ce);
	}
ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const ConstExpr* ce)
	{
	int nv2 = m->FrameSlot(v2);
	return ZInst(op, m->Frame1Slot(v1, op), nv2, ce);
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const NameExpr* v3, const ConstExpr* ce)
	{
	int nv2 = m->FrameSlot(v2);
	int nv3 = m->FrameSlot(v3);
	return ZInst(op, m->Frame1Slot(v1, op), nv2, nv3, ce);
	}
ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const ConstExpr* ce, const NameExpr* v3)
	{
	// Note that here we reverse the order of the arguments; saves
	// us from needing to implement a redundant constructor.
	int nv2 = m->FrameSlot(v2);
	int nv3 = m->FrameSlot(v3);
	return ZInst(op, m->Frame1Slot(v1, op), nv2, nv3, ce);
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* c, int i)
	{
	auto z = ZInst(op, m->Frame1Slot(v1, op), i, c);
	z.op_type = OP_VVC_I2;
	return z;
	}
ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2, int i)
	{
	int nv2 = m->FrameSlot(v2);
	auto z = ZInst(op, m->Frame1Slot(v1, op), nv2, i);
	z.op_type = OP_VVV_I3;
	return z;
	}


ZAM::ZAM(const BroFunc* f, Scope* _scope, Stmt* _body,
		UseDefs* _ud, Reducer* _rd, ProfileFunc* _pf)
	{
	tag = STMT_COMPILED;
	func = f;
	scope = _scope;
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
	delete inst_count;
	delete CPU_time;
	delete ud;
	delete reducer;
	delete pf;
	}

Stmt* ZAM::CompileBody()
	{
	curr_stmt = nullptr;

	if ( func->Flavor() == FUNC_FLAVOR_HOOK )
		PushBreaks();

	(void) body->Compile(this);

	if ( LastStmt()->Tag() != STMT_RETURN )
		SyncGlobals(nullptr);

	if ( breaks.size() > 0 )
		{
		ASSERT(breaks.size() == 1);

		if ( func->Flavor() == FUNC_FLAVOR_HOOK )
			{
			// Rewrite the breaks.
			for ( auto b : breaks[0] )
				{
				auto& i = insts1[b.stmt_num];
				delete i;
				i = new ZInst(OP_HOOK_BREAK_X);
				}
			}

		else
			reporter->Error("\"break\" used without an enclosing \"for\" or \"switch\"");
		}

	if ( nexts.size() > 0 )
		reporter->Error("\"next\" used without an enclosing \"for\"");

	if ( fallthroughs.size() > 0 )
		reporter->Error("\"fallthrough\" used without an enclosing \"switch\"");

	if ( catches.size() > 0 )
		reporter->InternalError("untargeted inline return");

	OptimizeInsts();

	// Make sure we have a (pseudo-)instruction at the end so we
	// can use it as a branch label.
	if ( ! pending_inst )
		pending_inst = new ZInst();

	// Now concretize instruction numbers in inst1 so we can
	// easily move through the code.
	for ( auto i = 0; i < insts1.size(); ++i )
		insts1[i]->inst_num = i;

	// Move branches to dead code forward to their successor live code.
	for ( auto i = 0; i < insts1.size(); ++i )
		{
		auto inst = insts1[i];
		auto t = inst->target;

		if ( ! t || t->live )
			continue;

		int idx = t->inst_num;
		while ( idx < insts1.size() && ! insts1[idx]->live )
			++idx;

		if ( idx == insts1.size() )
			inst->target = pending_inst;
		else
			inst->target = insts1[idx];
		}

	// Construct the final program with the dead code eliminated
	// and branches resolved.

	// Make sure we don't include the empty pending-instruction,
	// if any.
	if ( pending_inst )
		pending_inst->live = false;

	for ( auto i = 0; i < insts1.size(); ++i )
		if ( insts1[i]->live )
			insts2.push_back(insts1[i]);

	// Re-concretize instruction numbers, and concretize GoTo's.
	for ( auto i = 0; i < insts2.size(); ++i )
		insts2[i]->inst_num = i;

	for ( auto i = 0; i < insts2.size(); ++i )
		{
		auto inst = insts2[i];

		if ( inst->target )
			{
			int t;	// instruction number of target

			if ( inst->target == pending_inst )
				t = insts2.size();
			else
				t = inst->target->inst_num;

			// Decrement because our model is the PC will be
			// incremented after executing the statement.
			--t;

			switch ( inst->target_slot ) {
			case 1:	inst->v1 = t; break;
			case 2:	inst->v2 = t; break;
			case 3:	inst->v3 = t; break;

			default:
				reporter->InternalError("bad GoTo target");
			}
			}
		}

	delete pending_inst;

	// Could erase insts1 here to recover memory, but it's handy
	// for debugging.

	if ( analysis_options.report_profile )
		{
		inst_count = new vector<int>;
		inst_CPU = new vector<double>;
		for ( auto i : insts2 )
			{
			inst_count->push_back(0);
			inst_CPU->push_back(0.0);
			}

		CPU_time = new double;
		*CPU_time = 0.0;
		}
	else
		inst_count = nullptr;

	return this;
	}

void ZAM::Init()
	{
	auto uds = ud->HasUsage(body) ? ud->GetUsage(body) : nullptr;
	auto args = scope->OrderedVars();
	auto nparam = func->FType()->Args()->NumFields();

	// Use slot 0 for the temporary register.  Note that this choice
	// interacts with tracking globals, which we assume are in slots
	// 1 .. num_globals.
	register_slot = frame_size++;
	frame_denizens.push_back(nullptr);

	num_globals = pf->globals.size();

	// Important that we added globals to the frame first, as we
	// assume we can loop from 1 .. num_globals to iterate over them.
	for ( auto g : pf->globals )
		(void) AddToFrame(g);

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

void ZAM::OptimizeInsts()
	{
	// Do accounting for targeted statements.
	for ( auto& i : insts1 )
		if ( i->target && i->target->live )
			++(i->target->num_labels);

	bool something_changed;

	do
		{
		something_changed = false;

		while ( RemoveDeadCode() )
			something_changed = true;
		while ( CollapseGoTos() )
			something_changed = true;

		if ( PruneGlobally() )
			something_changed = true;
		}
	while ( something_changed );
	}

bool ZAM::RemoveDeadCode()
	{
	bool did_removal = false;

	for ( int i = 0; i < int(insts1.size()) - 1; ++i )
		{
		auto i0 = insts1[i];
		auto i1 = insts1[i+1];

		if ( i0->live && i1->live && i0->DoesNotContinue() &&
		     i0->target != i1 && i1->num_labels == 0 )
			{
			did_removal = true;
			KillInst(i1);
			}
		}

	return did_removal;
	}

bool ZAM::CollapseGoTos()
	{
	bool did_collapse = false;

	for ( int i = 0; i < insts1.size(); ++i )
		{
		auto i0 = insts1[i];

		if ( ! i0->live )
			continue;

		auto t = i0->target;

		if ( t && t->IsUnconditionalBranch() )
			{ // Collapse branch-to-branch.
			did_collapse = true;
			do
				{
				ASSERT(t->live);

				--t->num_labels;
				t = t->target;
				i0->target = t;
				}
			while ( t->IsUnconditionalBranch() );
			}

		if ( i < insts1.size() - 1 && t == insts1[i+1] )
			{ // Collapse branch-to-next-statement.
			i0->live = false;
			--t->num_labels;
			}
		}

	return did_collapse;
	}

bool ZAM::PruneGlobally()
	{
	bool did_prune = false;

	for ( int i = 0; i < insts1.size(); ++i )
		{
		auto inst = insts1[i];

		if ( ! inst->live )
			continue;

		if ( inst->IsFrameStore() && ! VarIsAssigned(inst->v1) )
			{
			did_prune = true;
			KillInst(inst);
			}

		if ( inst->IsFrameLoad() && ! VarIsUsed(inst->v1) )
			{
			did_prune = true;
			KillInst(inst);
			}
		}

	return did_prune;
	}

bool ZAM::VarIsAssigned(int slot) const
	{
	for ( int i = 0; i < insts1.size(); ++i )
		{
		auto& inst = insts1[i];
		if ( inst->live && VarIsAssigned(slot, inst) )
			return true;
		}

	return false;
	}

bool ZAM::VarIsAssigned(int slot, const ZInst* i) const
	{
	return i->AssignsToSlot1() && i->v1 == slot &&
		! i->IsFrameSync();
	}

bool ZAM::VarIsUsed(int slot) const
	{
	for ( int i = 0; i < insts1.size(); ++i )
		{
		auto& inst = insts1[i];
		if ( inst->live && inst->UsesSlot(slot) )
			return true;
		}

	return false;
	}

void ZAM::KillInst(ZInst* i)
	{
	i->live = false;
	if ( i->target )
		--(i->target->num_labels);
	}

void ZAM::StmtDescribe(ODesc* d) const
	{
	d->AddSP("compiled");
	d->AddSP(func->Name());
	}

static void vec_exec(ZOp op, ZAMVectorMgr*& v1, const ZAMVectorMgr* v2,
			ZAM_tracker_type* tracker);

static void vec_exec(ZOp op, ZAMVectorMgr*& v1, const ZAMVectorMgr* v2,
			const ZAMVectorMgr* v3, ZAM_tracker_type* tracker);

// Vector coercion.
//
// ### Should check for underflow/overflow.
#define VEC_COERCE(tag, lhs_accessor, cast, rhs_accessor) \
	static ZAMVectorMgr* vec_coerce_##tag(ZAMVectorMgr* vec, ZAM_tracker_type* tracker) \
		{ \
		auto v = vec->ConstVec(); \
		auto res = make_shared<ZAM_vector>(); \
		for ( unsigned int i = 0; i < v->size(); ++i ) \
			(*res)[i].lhs_accessor = cast((*v)[i].rhs_accessor); \
		return new ZAMVectorMgr(res, nullptr, tracker); \
		}

VEC_COERCE(IU, int_val, bro_int_t, uint_val)
VEC_COERCE(ID, int_val, bro_int_t, double_val)
VEC_COERCE(UI, uint_val, bro_int_t, int_val)
VEC_COERCE(UD, uint_val, bro_uint_t, double_val)
VEC_COERCE(DI, double_val, double, int_val)
VEC_COERCE(DU, double_val, double, uint_val)

BroString* ZAM_to_lower(const BroString* bs)
	{
	const u_char* s = bs->Bytes();
	int n = bs->Len();
	u_char* lower_s = new u_char[n + 1];
	u_char* ls = lower_s;

	for ( int i = 0; i < n; ++i )
		{
		if ( isascii(s[i]) && isupper(s[i]) )
			*ls++ = tolower(s[i]);
		else
			*ls++ = s[i];
		}

	*ls++ = '\0';
		
	return new BroString(1, lower_s, n);
	}

BroString* ZAM_sub_bytes(const BroString* s, bro_uint_t start, bro_int_t n)
	{
        if ( start > 0 )
                --start;        // make it 0-based

        BroString* ss = s->GetSubstring(start, n);

	return ss ? ss : new BroString("");
	}

double curr_CPU_time()
	{
	struct timespec ts;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
	return double(ts.tv_sec) + double(ts.tv_nsec) / 1e9;
	}

IntrusivePtr<Val> ZAM::Exec(Frame* f, stmt_flow_type& flow) const
	{
	auto nv = num_Vals;
	auto ndv = num_del_Vals;

	double t = analysis_options.report_profile ? curr_CPU_time() : 0.0;

	auto val = DoExec(f, 0, flow);

	if ( analysis_options.report_profile )
		*CPU_time += curr_CPU_time() - t;

	auto dnv = num_Vals - nv;
	auto dndv = num_del_Vals - ndv;

	if ( /* dnv || dndv */ 0 )
		printf("%s vals: +%d -%d\n", func->Name(), dnv, dndv);

	return val;
	}

IntrusivePtr<Val> ZAM::DoExec(Frame* f, int start_pc,
						stmt_flow_type& flow) const
	{
	auto frame = new ZAMValUnion[frame_size];
	auto global_state = num_globals > 0 ?
					// We use +1 so we can index/loop
					// from 1 .. num_globals
					new GlobalState[num_globals + 1] :
					nullptr;
	int pc = start_pc;
	bool error_flag = false;
	int end_pc = insts2.size();

	// Memory management: all of the BroObj's that we have used
	// in interior values.  By managing them here rather than
	// per-frame-slot, we don't need to add frame state about
	// whether an object should be delete'd or not on reassignment.
	std::vector<IntrusivePtr<BroObj>> vals;
	vals.reserve(100);

#define TrackVal(v) (vals.push_back({AdoptRef{}, v}), v)
#define TrackValPtr(v) (vals.push_back(v), v.get())
#define BuildVal(v, t, s) (vals.push_back(v), ZAMValUnion(v.get(), t, &ZAM_VM_Tracker, s, error_flag))
#define CopyVal(v) (IsManagedType(z.t) ? BuildVal(v.ToVal(z.t), z.t, z.stmt) : v)

// Managed assignments to frame[s.v1].
#define AssignV1(v) AssignV1T(v, z.t)
#define AssignV1T(v, t) { if ( z.is_managed ) DeleteManagedType(frame[z.v1], t); frame[z.v1] = v; }

	ZAM_tracker_type ZAM_VM_Tracker;

	// Return value, or nil if none.
	const ZAMValUnion* ret_u;

	// Type of the return value.  If nil, then we don't have a value.
	BroType* ret_type = nullptr;

	// All globals start out unloaded.
	for ( auto i = 1; i <= num_globals; ++i )
		global_state[i] = GS_UNLOADED;

	// Clear slots for which we do explicit memory management.
	for ( auto s : managed_slots )
		frame[s].void_val = nullptr;

	flow = FLOW_RETURN;	// can be over-written by a Hook-Break

	while ( pc < end_pc && ! error_flag ) {
		auto& z = *insts2[pc];
		int profile_pc;
		double profile_CPU;
		const Expr* profile_expr;

		if ( 0 )
			{
			printf("executing %d: ", pc);
			z.Dump(frame_denizens);
			}

		if ( analysis_options.report_profile )
			{
			++ZOP_count[z.op];
			++(*inst_count)[pc];

			if ( z.op == OP_INTERPRET_EXPR_X ||
			     z.op == OP_INTERPRET_EXPR_V )
				profile_expr = z.e;
			else
				profile_expr = nullptr;

			profile_pc = pc;
			profile_CPU = curr_CPU_time();
			}

		switch ( z.op ) {
		case OP_NOP:
			break;

#include "ZAM-OpsEvalDefs.h"
		}

		if ( analysis_options.report_profile )
			{
			double dt = curr_CPU_time() - profile_CPU;
			(*inst_CPU)[profile_pc] += dt;

			if ( profile_expr )
				{
				auto ec = expr_CPU.find(profile_expr);
				if ( ec == expr_CPU.end() )
					expr_CPU[profile_expr] = dt;
				else
					ec->second += dt;
				}
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
	delete [] global_state;

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

bool ZAM::IsZAM_BuiltIn(const Expr* e)
	{
	// The expression is either directly a call (in which case there's
	// no return value), or an assignment to a call.
	const CallExpr* c;

	if ( e->Tag() == EXPR_CALL )
		c = e->AsCallExpr();
	else
		c = e->GetOp2()->AsCallExpr();

	auto func_expr = c->Func();
	if ( func_expr->Tag() != EXPR_NAME )
		return false;

	auto func_val = func_expr->AsNameExpr()->Id()->ID_Val();
	if ( ! func_val )
		return false;

	auto func = func_val->AsFunc();
	if ( func->GetKind() != BuiltinFunc::BUILTIN_FUNC )
		return false;

	auto& args = c->Args()->Exprs();

	const NameExpr* n;	// name to assign to, if any

	if ( e->Tag() == EXPR_CALL )
		n = nullptr;
	else
		n = e->GetOp1()->AsRefExpr()->GetOp1()->AsNameExpr();

	if ( streq(func->Name(), "sub_bytes") )
		return BuiltIn_sub_bytes(n, args);

	else if ( streq(func->Name(), "to_lower") )
		return BuiltIn_to_lower(n, args);

	return false;
	}

bro_uint_t ZAM::ConstArgsMask(const expr_list& args, int nargs) const
	{
	ASSERT(args.length() == nargs);

	bro_uint_t mask = 0;

	for ( int i = 0; i < nargs; ++i )
		{
		mask <<= 1;
		if ( args[i]->Tag() == EXPR_CONST )
			mask |= 1;
		}

	return mask;
	}

bool ZAM::BuiltIn_to_lower(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	auto arg_s = args[0]->AsNameExpr();
	int nslot = Frame1Slot(n, OP1_WRITE);

	AddInst(ZInst(OP_TO_LOWER_VV, nslot, FrameSlot(arg_s)));

	return true;
	}

bool ZAM::BuiltIn_sub_bytes(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	auto arg_s = args[0];
	auto arg_start = args[1];
	auto arg_n = args[2];

	int nslot = Frame1Slot(n, OP1_WRITE);

	int v2 = FrameSlotIfName(arg_s);
	int v3 = ConvertToCount(arg_start);
	int v4 = ConvertToInt(arg_n);

	auto c = arg_s->Tag() == EXPR_CONST ? arg_s->AsConstExpr() : nullptr;

	ZInst z;

	switch ( ConstArgsMask(args, 3) ) {
	case 0x0:	// all variable
		z = ZInst(OP_SUB_BYTES_VVVV, nslot, v2, v3, v4);
		z.op_type = OP_VVVV;
		break;

	case 0x1:	// last argument a constant
		z = ZInst(OP_SUB_BYTES_VVVi, nslot, v2, v3, v4);
		z.op_type = OP_VVVV_I4;
		break;

	case 0x2:	// 2nd argument a constant; flip!
		z = ZInst(OP_SUB_BYTES_VViV, nslot, v2, v4, v3);
		z.op_type = OP_VVVV_I3;
		break;

	case 0x3:	// both 2nd and third are constants
		z = ZInst(OP_SUB_BYTES_VVii, nslot, v2, v3, v4);
		z.op_type = OP_VVVV_I3_I4;
		break;

	case 0x4:	// first argument a constant
		z = ZInst(OP_SUB_BYTES_VVVC, nslot, v3, v4, c);
		z.op_type = OP_VVVC;
		break;

	case 0x5:	// first and third constant
		z = ZInst(OP_SUB_BYTES_VViC, nslot, v3, v4, c);
		z.op_type = OP_VVVC_I3;
		break;

	case 0x6:	// first and second constant - flip!
		z = ZInst(OP_SUB_BYTES_ViVC, nslot, v4, v3, c);
		z.op_type = OP_VVVC_I2;
		break;

	case 0x7:	// whole shebang
		z = ZInst(OP_SUB_BYTES_ViiC, nslot, v3, v4, c);
		z.op_type = OP_VVVC_I2_I3;
		break;

	default:
		reporter->InternalError("bad constant mask");
	}

	AddInst(z);

	return true;
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
	// We do this separately from FlushVars() because we have to
	// consider sync *all* the globals, whereas it only sync's those
	// explicitly present in the expression.
	ProfileFunc call_pf;
	c->Traverse(&call_pf);

	for ( auto l : call_pf.locals )
		StoreLocal(l);

	// Don't invoke GenInst for the first case since if n is a global
	// we don't want to dirty it prior to assignment
	auto a_s = n ? ZInst(OP_INTERPRET_EXPR_V, RawSlot(n), c) :
			ZInst(OP_INTERPRET_EXPR_X, c);

	if ( n )
		{
		a_s.t = n->Type().get();

		if ( n->Id()->IsGlobal() )
			{
			AddInst(a_s);
			a_s = ZInst(OP_DIRTY_GLOBAL_V, RawSlot(n));
			}
		}

	return AddInst(a_s);
	}

void ZAM::FlushVars(const Expr* e)
	{
	ProfileFunc expr_pf;
	e->Traverse(&expr_pf);

	SyncGlobals(expr_pf.globals, e);

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

	int op_slot = FrameSlot(op);
	auto zop = OP_RECORD_COERCE_VVV;
	ZInst z(zop, Frame1Slot(n, zop), op_slot, map_size);

	z.t = e->Type().get();
	z.op_type = OP_VVV_I3;
	z.int_ptr = map;

	return AddInst(z);
	}

const CompiledStmt ZAM::TableCoerce(const NameExpr* n, const Expr* e)
	{
	auto op = e->GetOp1()->AsNameExpr();

	int op_slot = FrameSlot(op);
	auto zop = OP_TABLE_COERCE_VV;
	ZInst z(zop, Frame1Slot(n, zop), op_slot);
	z.t = e->Type().get();

	return AddInst(z);
	}

const CompiledStmt ZAM::VectorCoerce(const NameExpr* n, const Expr* e)
	{
	auto op = e->GetOp1()->AsNameExpr();
	int op_slot = FrameSlot(op);

	auto zop = OP_VECTOR_COERCE_VV;
	ZInst z(zop, Frame1Slot(n, zop), op_slot);
	z.t = e->Type().get();

	return AddInst(z);
	}

const CompiledStmt ZAM::Is(const NameExpr* n, const Expr* e)
	{
	auto is = e->AsIsExpr();
	auto op = e->GetOp1()->AsNameExpr();
	int op_slot = FrameSlot(op);

	ZInst z(OP_IS_VV, Frame1Slot(n, OP_IS_VV), op_slot);
	z.e = op;
	z.t = is->TestType().get();

	return AddInst(z);
	}

const CompiledStmt ZAM::IfElse(const Expr* e, const Stmt* s1, const Stmt* s2)
	{
	CompiledStmt cond_stmt = EmptyStmt();
	int branch_v;

	if ( e->Tag() == EXPR_NAME )
		{
		auto n = e->AsNameExpr();

		ZOp op = (s1 && s2) ?
			OP_IF_ELSE_VV : (s1 ? OP_IF_VV : OP_IF_NOT_VV);

		ZInst cond(op, FrameSlot(n), 0);
		cond_stmt = AddInst(cond);
		branch_v = 2;
		}
	else
		cond_stmt = GenCond(e, branch_v);

	if ( s1 )
		{
		auto s1_end = s1->Compile(this);
		if ( s2 )
			{
			auto branch_after_s1 = GoToStub();
			auto s2_end = s2->Compile(this);
			SetV(cond_stmt, GoToTargetBeyond(branch_after_s1),
				branch_v);
			SetGoTo(branch_after_s1, GoToTargetBeyond(s2_end));

			return s2_end;
			}

		else
			{
			SetV(cond_stmt, GoToTargetBeyond(s1_end), branch_v);
			return s1_end;
			}
		}

	else
		{
		auto s2_end = s2->Compile(this);
		SetV(cond_stmt, GoToTargetBeyond(s2_end), branch_v);
		return s2_end;
		}
	}

const CompiledStmt ZAM::GenCond(const Expr* e, int& branch_v)
	{
	auto op1 = e->GetOp1();
	auto op2 = e->GetOp2();

	NameExpr* n1 = nullptr;
	NameExpr* n2 = nullptr;
	ConstExpr* c = nullptr;

	if ( op1->Tag() == EXPR_NAME )
		{
		n1 = op1->AsNameExpr();

		if ( op2->Tag() == EXPR_NAME )
			n2 = op2->AsNameExpr();
		else
			c = op2->AsConstExpr();
		}
	else
		{
		c = op1->AsConstExpr();
		n2 = op2->AsNameExpr();
		}

	if ( n1 && n2 )
		branch_v = 3;
	else
		branch_v = 2;

	switch ( e->Tag() ) {
#include "ZAM-Conds.h"

	default:
		reporter->InternalError("bad expression type in ZAM::GenCond");
	}

	// Not reached.
	}

const CompiledStmt ZAM::While(const Stmt* cond_stmt, const Expr* cond,
				const Stmt* body)
	{
	auto head = StartingBlock();

	if ( cond_stmt )
		(void) cond_stmt->Compile(this);

	CompiledStmt cond_IF = EmptyStmt();
	int branch_v;

	if ( cond->Tag() == EXPR_NAME )
		{
		auto n = cond->AsNameExpr();
		cond_IF = AddInst(ZInst(OP_IF_VV, FrameSlot(n), 0));
		branch_v = 2;
		}
	else
		cond_IF = GenCond(cond, branch_v);

	PushNexts();
	PushBreaks();

	if ( body && body->Tag() != STMT_NULL )
		(void) body->Compile(this);

	auto tail = GoTo(GoToTarget(head));

	auto beyond_tail = GoToTargetBeyond(tail);
	SetV(cond_IF, beyond_tail, branch_v);

	ResolveNexts(GoToTarget(head));
	ResolveBreaks(beyond_tail);

	return tail;
	}

const CompiledStmt ZAM::Loop(const Stmt* body)
	{
	PushNexts();
	PushBreaks();

	auto head = StartingBlock();
	(void) body->Compile(this);
	auto tail = GoTo(GoToTarget(head));

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

		z.v4 = is_return;
		}

	else
		{
		z = GenInst(this, OP_WHEN_VV);
		z.v1 = is_return;
		}

	z.non_const_e = cond;

	AddInst(z);

	auto branch_past_blocks = GoToStub();

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

	PushBreaks();

	if ( t != TYPE_ANY && t != TYPE_TYPE )
		return ValueSwitch(sw, n, c);
	else
		return TypeSwitch(sw, n, c);
	}

const CompiledStmt ZAM::ValueSwitch(const SwitchStmt* sw, const NameExpr* v,
					const ConstExpr* c)
	{
	int slot = v ? FrameSlot(v) : 0;

	if ( c )
		{
		// Weird to have a constant switch expression, enough
		// so that it doesn't seem worth optimizing.
		slot = RegisterSlot();
		auto z = ZInst(OP_ASSIGN_CONST_VC, slot, c);
		z.CheckIfManaged(c);
		(void) AddInst(z);
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
	auto body_end = sw_head;

	// Generate each of the cases.
	auto cases = sw->Cases();
	std::vector<InstLabel> case_start;

	PushFallThroughs();
	for ( auto c : *cases )
		{
		auto start = GoToTargetBeyond(body_end);
		ResolveFallThroughs(start);
		case_start.push_back(start);
		PushFallThroughs();
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
		auto case_body_start = case_start[*index];

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

	PushFallThroughs();
	for ( auto& i : *type_map )
		{
		auto id = i.first;
		auto type = id->Type();

		ZInst z;

		z = ZInst(OP_BRANCH_IF_NOT_TYPE_VV, slot, 0);
		z.t = type;
		auto case_test = AddInst(z);

		// Type cases that don't use "as" create a placeholder
		// ID with a null name.
		if ( id->Name() )
			{
			int id_slot = Frame1Slot(id, OP_CAST_ANY_VV);
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

		PushFallThroughs();
		}

	ResolveFallThroughs(GoToTargetBeyond(body_end));

	if ( def_ind >= 0 )
		{
		PushFallThroughs();

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

	PushNexts();
	PushBreaks();

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
	if ( IsZAM_BuiltIn(e->StmtExpr()) )
		return LastInst();

	auto uds = ud->GetUsageAfter(e);
	auto call = e->StmtExpr()->AsCallExpr();
	return DoCall(call, nullptr, uds);
	}

const CompiledStmt ZAM::AssignToCall(const ExprStmt* e)
	{
	if ( IsZAM_BuiltIn(e->StmtExpr()) )
		return LastInst();

	// This is a bit subtle.  Normally, we'd get the UDs *after* the
	// statement, since UDs reflect use-defs prior to statement execution.
	// However, this could be an assignment of the form "global = func()",
	// in which case whether there are UDs for "global" *after* the 
	// assignment aren't what's relevant - we still need to load
	// the global in order to do the assignment.  OTOH, the UDs *before*
	// this assignment statement will correctly capture the UDs after
	// it with the sole exception of what's being assigned.  Given
	// if what's being assigned is a global, it doesn't need to be loaded,
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
	auto indexes = index_assign->GetOp2()->AsListExpr()->Exprs();

	if ( indexes.length() > 1 )
		{
		// Vector slice assignment.  For now, punt to the interpreter.
		return InterpretExpr(e);
		}

	auto op2 = indexes[0];
	auto op3 = index_assign->GetOp3();

	auto lhs = op1->AsNameExpr();

	if ( op2->Tag() == EXPR_CONST && op3->Tag() == EXPR_CONST )
		{
		// Turn into a VVC assignment by assigning the index to
		// a temporary.
		auto tmp = RegisterSlot();
		AddInst(ZInst(OP_ASSIGN_VC, tmp, op2->AsConstExpr()));

		auto zop = OP_VECTOR_ELEM_ASSIGN_VVC;

		return AddInst(ZInst(zop, Frame1Slot(lhs, zop), tmp,
					op3->AsConstExpr()));
		}

	if ( op2->Tag() == EXPR_NAME )
		{
		CompiledStmt inst(0);

		if ( op3->Tag() == EXPR_NAME )
			inst = Vector_Elem_AssignVVV(lhs, op2->AsNameExpr(),
							op3->AsNameExpr());
		else
			inst = Vector_Elem_AssignVVC(lhs, op2->AsNameExpr(),
							op3->AsConstExpr());

		TopMainInst()->t = op3->Type().get();
		return inst;
		}

	else
		{
		auto c = op2->AsConstExpr();
		auto index = c->Value()->AsCount();

		auto inst = Vector_Elem_AssignVVi(lhs, op3->AsNameExpr(), index);

		TopMainInst()->t = op3->Type().get();
		return inst;
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
		z = ZInst(OP_ADD_VAR_TO_INIT_VV, FrameSlot(id), info);
		z.CheckIfManaged(id->Type());
		z.t = id->Type();
		init_end = AddInst(z);
		}

	auto iter_head = StartingBlock();
	if ( value_var )

		{
		z = ZInst(OP_NEXT_TABLE_ITER_VAL_VAR_VVV, FrameSlot(value_var),
				info, 0);
		z.CheckIfManaged(value_var->Type());
		z.op_type = OP_VVV_I3;
		}
	else
		{
		z = ZInst(OP_NEXT_TABLE_ITER_VV, info, 0);
		z.op_type = OP_VV_I2;
		}

	return FinishLoop(iter_head, z, f->LoopBody(), info);
	}

const CompiledStmt ZAM::LoopOverVector(const ForStmt* f, const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto loop_var = (*loop_vars)[0];

	auto info = NewSlot();
	auto z = ZInst(OP_INIT_VECTOR_LOOP_VV, info, FrameSlot(val));
	z.t = val->Type().get();
	auto init_end = AddInst(z);

	auto iter_head = StartingBlock();

	z = ZInst(OP_NEXT_VECTOR_ITER_VVV, FrameSlot(loop_var), info, 0);
	z.op_type = OP_VVV_I3;

	return FinishLoop(iter_head, z, f->LoopBody(), info);
	}

const CompiledStmt ZAM::LoopOverString(const ForStmt* f, const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto loop_var = (*loop_vars)[0];

	auto info = NewSlot();
	auto z = ZInst(OP_INIT_STRING_LOOP_VV, info, FrameSlot(val));
	z.CheckIfManaged(val);
	auto init_end = AddInst(z);

	auto iter_head = StartingBlock();

	z = ZInst(OP_NEXT_STRING_ITER_VVV, FrameSlot(loop_var), info, 0);
	z.CheckIfManaged(loop_var->Type());
	z.op_type = OP_VVV_I3;

	return FinishLoop(iter_head, z, f->LoopBody(), info);
	}

const CompiledStmt ZAM::FinishLoop(const CompiledStmt iter_head,
					ZInst iter_stmt, const Stmt* body,
					int info_slot)
	{
	auto loop_iter = AddInst(iter_stmt);
	auto body_end = body->Compile(this);

	auto loop_end = GoTo(GoToTarget(iter_head));
	auto final_stmt = AddInst(ZInst(OP_END_LOOP_V, info_slot));

	if ( iter_stmt.op_type == OP_VVV_I3 )
		SetV3(loop_iter, GoToTarget(final_stmt));
	else
		SetV2(loop_iter, GoToTarget(final_stmt));

	ResolveNexts(GoToTarget(iter_head));
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
	auto z = ZInst(OP_INIT_VECTOR_VV, FrameSlot(id), id->Offset());
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

const CompiledStmt ZAM::Return(const ReturnStmt* r)
	{
	auto e = r->StmtExpr();

	if ( retvars.size() == 0 )
		{ // a "true" return
		SyncGlobals(r);

		if ( e )
			{
			if ( e->Tag() == EXPR_NAME )
				return ReturnV(e->AsNameExpr());
			else
				return ReturnC(e->AsConstExpr());
			}

		else
			return ReturnX();
		}

	auto rv = retvars.back();
	if ( e && ! rv )
		reporter->InternalError("unexpected returned value inside inlined block");
	if ( ! e && rv )
		reporter->InternalError("expected returned value inside inlined block but none provider");

	if ( e )
		{
		if ( e->Tag() == EXPR_NAME )
			(void) AssignVV(rv, e->AsNameExpr());
		else
			(void) AssignVC(rv, e->AsConstExpr());
		}

	return CatchReturn();
	}

const CompiledStmt ZAM::CatchReturn(const CatchReturnStmt* cr)
	{
	retvars.push_back(cr->RetVar());

	PushCatchReturns();

	auto block_end = cr->Block()->Compile(this);
	retvars.pop_back();

	ResolveCatchReturns(GoToTargetBeyond(block_end));

	return block_end;
	}

const CompiledStmt ZAM::StartingBlock()
	{
	return CompiledStmt(insts1.size());
	}

const CompiledStmt ZAM::FinishBlock(const CompiledStmt /* start */)
	{
	return CompiledStmt(insts1.size() - 1);
	}

bool ZAM::NullStmtOK() const
	{
	// They're okay iff they're the entire statement body.
	return insts1.size() == 0;
	}

const CompiledStmt ZAM::EmptyStmt()
	{
	return CompiledStmt(insts1.size() - 1);
	}

const CompiledStmt ZAM::LastInst()
	{
	return CompiledStmt(insts1.size() - 1);
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
	ZInst* i;

	if ( pending_inst )
		{
		i = pending_inst;
		pending_inst = nullptr;
		}
	else
		i = new ZInst();

	*i = inst;

	insts1.push_back(i);

	top_main_inst = insts1.size() - 1;

	if ( mark_dirty < 0 )
		return CompiledStmt(top_main_inst);

	auto dirty_global_slot = mark_dirty;
	mark_dirty = -1;

	return AddInst(ZInst(OP_DIRTY_GLOBAL_V, dirty_global_slot));
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

const CompiledStmt ZAM::LoadGlobal(ID* id)
	{
	if ( id->AsType() )
		// We never operate on these directly, so don't bother
		// storing or loading them.
		return EmptyStmt();

	bool is_any = IsAny(id->Type());
	ZOp op;

	op = is_any ? OP_LOAD_ANY_GLOBAL_VC : OP_LOAD_GLOBAL_VC;

	auto slot = RawSlot(id);

	ZInst z(op, slot);
	z.c.id_val = id;
	z.t = id->Type();
	z.op_type = OP_VC_ID;

	return AddInst(z);
	}

int ZAM::AddToFrame(ID* id)
	{
	frame_layout[id] = frame_size;
	frame_denizens.push_back(id);
	return frame_size++;
	}

void ZAM::ProfileExecution() const
	{
	if ( inst_count->size() == 0 )
		{
		printf("%s has an empty body\n", func->Name());
		return;
		}

	if ( (*inst_count)[0] == 0 )
		{
		printf("%s did not execute\n", func->Name());
		return;
		}

	printf("%s CPU time: %.06f\n", func->Name(), *CPU_time);
	for ( int i = 0; i < inst_count->size(); ++i )
		printf("%s %d %s %d %.06f\n", func->Name(), i, ZOP_name(insts2[i]->op),
			(*inst_count)[i], (*inst_CPU)[i]);
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

	if ( insts2.size() > 0 )
		printf("Pre-removal of dead code:\n");

	for ( int i = 0; i < insts1.size(); ++i )
		{
		auto& inst = insts1[i];
		printf("%d%s: ", i, inst->live ? "" : " (dead)");
		inst->Dump(frame_denizens);
		}

	if ( insts2.size() > 0 )
		printf("Final code:\n");

	for ( int i = 0; i < insts2.size(); ++i )
		{
		auto& inst = insts2[i];
		printf("%d%s: ", i, inst->live ? "" : " (dead)");
		inst->Dump(frame_denizens);
		}
	}

void ZAM::DumpIntCases(int i) const
	{
	printf("int switch table #%d:", i);
	for ( auto& m : int_cases[i] )
		printf(" %lld->%d", m.first, m.second->inst_num);
	printf("\n");
	}

void ZAM::DumpUIntCases(int i) const
	{
	printf("uint switch table #%d:", i);
	for ( auto& m : uint_cases[i] )
		printf(" %llu->%d", m.first, m.second->inst_num);
	printf("\n");
	}

void ZAM::DumpDoubleCases(int i) const
	{
	printf("double switch table #%d:", i);
	for ( auto& m : double_cases[i] )
		printf(" %lf->%d", m.first, m.second->inst_num);
	printf("\n");
	}

void ZAM::DumpStrCases(int i) const
	{
	printf("str switch table #%d:", i);
	for ( auto& m : str_cases[i] )
		printf(" %s->%d", m.first.c_str(), m.second->inst_num);
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

	auto s2 = n2 ? FrameSlot(n2) : 0;
	auto s3 = n3 ? FrameSlot(n3) : 0;
	auto s1 = Frame1Slot(n1, a);

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
					const NameExpr* n2, const ConstExpr* c)
	{
	int n = l->Exprs().length();
	auto build_indices = InternalBuildVals(l);

	auto z = ZInst(OP_TRANSFORM_VAL_VEC_TO_LIST_VAL_VVV,
				build_indices, build_indices, n);
	z.op_type = n2 ? OP_VVV_I3 : OP_VVC_I2;
	AddInst(z);

	ZOp op;

	auto aggr = n2 ? (Expr*) n2 : (Expr*) c;

	if ( aggr->Type()->Tag() == TYPE_VECTOR )
		op = n2 ? OP_INDEX_IS_IN_VECTOR_VVV : OP_INDEX_IS_IN_VECTOR_VVC;
	else
		op = n2 ? OP_LIST_IS_IN_TABLE_VVV : OP_LIST_IS_IN_TABLE_VVC;

	if ( n2 )
		{
		int n2_slot = FrameSlot(n2);
		z = ZInst(op, Frame1Slot(n1, op), n2_slot, build_indices);
		z.t = n2->Type().get();
		}
	else
		z = ZInst(op, Frame1Slot(n1, op), build_indices, c);

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

		if ( ! var_ind )
			{
			if ( ind->Type()->Tag() == TYPE_COUNT )
				c = ind->AsConstExpr()->Value()->AsCount();
			else if ( ind->Type()->Tag() == TYPE_INT )
				c = ind->AsConstExpr()->Value()->AsInt();
			}

		if ( n2tag == TYPE_STRING )
			{
			int n2_slot = FrameSlot(n2);

			if ( n3 )
				{
				int n3_slot = FrameSlot(n3);
				auto zop = OP_INDEX_STRING_VVV;
				z = ZInst(zop, Frame1Slot(n1, zop),
						n2_slot, n3_slot);
				}
			else
				{
				auto zop = OP_INDEX_STRINGC_VVV;
				z = ZInst(zop, Frame1Slot(n1, zop), n2_slot, c);
				z.op_type = OP_VVV_I3;
				}

			return AddInst(z);
			}

		if ( n2tag == TYPE_VECTOR )
			{
			int n2_slot = FrameSlot(n2);

			if ( n3 )
				{
				int n3_slot = FrameSlot(n3);
				auto zop = OP_INDEX_VEC_VVV;
				z = ZInst(zop, Frame1Slot(n1, zop),
						n2_slot, n3_slot);
				}
			else
				{
				auto zop = OP_INDEX_VECC_VVV;
				z = ZInst(zop, Frame1Slot(n1, zop), n2_slot, c);
				z.op_type = OP_VVV_I3;
				}

			z.t = n1->Type().get();
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
	int n2_slot = FrameSlot(n2);

	ZOp op;

	switch ( n2tag ) {
	case TYPE_VECTOR:
		op = n == 1 ? OP_INDEX_VEC_VVL : OP_INDEX_VEC_SLICE_VVL;
		z = ZInst(op, Frame1Slot(n1, op), n2_slot, build_indices);
		z.t = n2->Type().get();
		break;

	case TYPE_TABLE:
		op = OP_TABLE_INDEX_VVV;
		z = ZInst(op, Frame1Slot(n1, op), n2_slot, build_indices);
		z.t = n1->Type().get();
		break;

	case TYPE_STRING:
		op = OP_INDEX_STRING_SLICE_VVL;
		z = ZInst(op, Frame1Slot(n1, op), n2_slot, build_indices);
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
	SyncGlobals(pf->globals, o);
	}

void ZAM::SyncGlobals(std::unordered_set<ID*>& g, const BroObj* o)
	{
	auto mgr = reducer->GetDefSetsMgr();
	auto entry_rds = mgr->GetPreMaxRDs(body);

	auto curr_rds = o ?
		mgr->GetPreMaxRDs(o) : mgr->GetPostMaxRDs(LastStmt());

	bool could_be_dirty = false;

	for ( auto g : g )
		{
		auto g_di = mgr->GetConstID_DI(g);
		auto entry_dps = entry_rds->GetDefPoints(g_di);
		auto curr_dps = curr_rds->GetDefPoints(g_di);

		if ( ! entry_rds->SameDefPoints(entry_dps, curr_dps) )
			could_be_dirty = true;
		}

	if ( could_be_dirty )
		(void) AddInst(ZInst(OP_SYNC_GLOBALS_X));
	}

const CompiledStmt  ZAM::AssignedToGlobal(const ID* global_id)
	{
	// We used to need this before adding ZAMOp1Flavor.  We keep
	// it as a structure since it potentially could be needed
	// in the future.
	return EmptyStmt();
	}

void ZAM::PushGoTos(GoToSets& gotos)
	{
	vector<CompiledStmt> vi;
	gotos.push_back(vi);
	}

void ZAM::ResolveGoTos(GoToSets& gotos, const InstLabel l)
	{
	auto& g = gotos.back();

	for ( int i = 0; i < g.size(); ++i )
		SetGoTo(g[i], l);

	gotos.pop_back();
	}

CompiledStmt ZAM::GenGoTo(GoToSet& v)
	{
	auto g = GoToStub();
	v.push_back(g.stmt_num);

	return g;
	}

CompiledStmt ZAM::GoToStub()
	{
	ZInst z(OP_GOTO_V, 0);
	z.op_type = OP_V_I1;
	return AddInst(z);
	}

CompiledStmt ZAM::GoTo(const InstLabel l)
	{
	ZInst inst(OP_GOTO_V, 0);
	inst.target = l;
	inst.target_slot = 1;
	inst.op_type = OP_V_I1;
	return AddInst(inst);
	}

InstLabel ZAM::GoToTarget(const CompiledStmt s)
	{
	return insts1[s.stmt_num];
	}

InstLabel ZAM::GoToTargetBeyond(const CompiledStmt s)
	{
	int n = s.stmt_num;

	if ( n == insts1.size() - 1 )
		{
		if ( ! pending_inst )
			pending_inst = new ZInst();

		return pending_inst;
		}

	return insts1[n+1];
	}

CompiledStmt ZAM::PrevStmt(const CompiledStmt s)
	{
	return CompiledStmt(s.stmt_num - 1);
	}

void ZAM::SetV1(CompiledStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	inst->target = l;
	inst->target_slot = 1;
	ASSERT(inst->op_type == OP_V || inst->op_type == OP_V_I1);
	inst->op_type = OP_V_I1;
	}

void ZAM::SetV2(CompiledStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	inst->target = l;
	inst->target_slot = 2;

	if ( inst->op_type == OP_VV )
		inst->op_type = OP_VV_I2;

	else if ( inst->op_type == OP_VVC )
		inst->op_type = OP_VVC_I2;

	else
		ASSERT(inst->op_type == OP_VV_I2 || inst->op_type == OP_VVC_I2);
	}

void ZAM::SetV3(CompiledStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	inst->target = l;
	inst->target_slot = 3;
	ASSERT(inst->op_type == OP_VVV || inst->op_type == OP_VVV_I3 ||
		inst->op_type == OP_VVV_I2_I3);
	if ( inst->op_type != OP_VVV_I2_I3 )
		inst->op_type = OP_VVV_I3;
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
	auto slot = RawSlot(id);

	if ( id->IsGlobal() )
		(void) LoadGlobal(frame_denizens[slot]);

	return slot;
	}

int ZAM::Frame1Slot(const ID* id, ZAMOp1Flavor fl)
	{
	auto slot = RawSlot(id);

	switch ( fl ) {
	case OP1_READ:
		if ( id->IsGlobal() )
			(void) LoadGlobal(frame_denizens[slot]);
		break;

	case OP1_WRITE:
		if ( id->IsGlobal() )
			mark_dirty = slot;
		break;

        case OP1_READ_WRITE:
		if ( id->IsGlobal() )
			{
			(void) LoadGlobal(frame_denizens[slot]);
			mark_dirty = slot;
			}
		break;

	case OP1_INTERNAL:
		break;
	}

	return slot;
	}

int ZAM::RawSlot(const ID* id)
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
static void vec_exec(ZOp op, ZAMVectorMgr*& v1, const ZAMVectorMgr* v2,
			ZAM_tracker_type* tracker)
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
		v1 = new ZAMVectorMgr(make_shared<ZAM_vector>(vec2.size()), nullptr, tracker);

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
			const ZAMVectorMgr* v3, ZAM_tracker_type* tracker)
	{
	// See comment above re further speed-up.

	auto& vec2 = *v2->ConstVec();
	auto& vec3 = *v3->ConstVec();

	if ( v1 )
		v1->ModVec()->resize(vec2.size());
	else
		v1 = new ZAMVectorMgr(make_shared<ZAM_vector>(vec2.size()), nullptr, tracker);

	auto& vec1 = *v1->ModVec();

	for ( unsigned int i = 0; i < vec2.size(); ++i )
		switch ( op ) {

#include "ZAM-Vec2EvalDefs.h"

		default:
			reporter->InternalError("bad invocation of VecExec");
		}
	}
