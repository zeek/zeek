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

// Needed for managing the corresponding values.
#include "File.h"
#include "Func.h"
#include "OpaqueVal.h"

// Just needed for BiFs.
#include "Net.h"
#include "logging/Manager.h"
#include "broker/Manager.h"

static BroType* log_ID_enum_type;


// Count of how often each top of ZOP executed, and how much CPU it
// cumulatively took.
int ZOP_count[OP_NOP+1];
double ZOP_CPU[OP_NOP+1];

// Per-interpreted-expression.
std::unordered_map<const Expr*, double> expr_CPU;


void report_ZOP_profile()
	{
	for ( int i = 1; i <= OP_NOP; ++i )
		if ( ZOP_count[i] > 0 )
			printf("%s\t%d\t%.06f\n", ZOP_name(ZOp(i)),
				ZOP_count[i], ZOP_CPU[i]);

	for ( auto& e : expr_CPU )
		printf("expr CPU %.06f %s\n", e.second, obj_desc(e.first));
	}


void ZAM_run_time_error(const Stmt* stmt, const char* msg)
	{
	if ( stmt->Tag() == STMT_EXPR )
		{
		auto e = stmt->AsExprStmt()->StmtExpr();
		reporter->ExprRuntimeError(e, "%s", msg);
		}
	else
		fprintf(stderr, "%s: %s\n", msg, obj_desc(stmt));

	ZAM_error = true;
	}

void ZAM_run_time_error(const char* msg, const BroObj* o)
	{
	fprintf(stderr, "%s: %s\n", msg, obj_desc(o));
	ZAM_error = true;
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
ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		int i1, int i2)
	{
	int nv2 = m->FrameSlot(v2);
	auto z = ZInst(op, m->Frame1Slot(v1, op), nv2, i1, i2);
	z.op_type = OP_VVVV_I3_I4;
	return z;
	}
ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v, const ConstExpr* c,
		int i1, int i2)
	{
	auto z = ZInst(op, m->Frame1Slot(v, op), i1, i2, c);
	z.op_type = OP_VVVC_I2_I3;
	return z;
	}

ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const NameExpr* v3, int i)
	{
	int nv2 = m->FrameSlot(v2);
	int nv3 = m->FrameSlot(v3);
	auto z = ZInst(op, m->Frame1Slot(v1, op), nv2, nv3, i);
	z.op_type = OP_VVVV_I4;
	return z;
	}
ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const ConstExpr* c, int i)
	{
	int nv2 = m->FrameSlot(v2);
	auto z = ZInst(op, m->Frame1Slot(v1, op), nv2, i, c);
	z.op_type = OP_VVVC_I3;
	return z;
	}
ZInst GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* c,
		const NameExpr* v2, int i)
	{
	int nv2 = m->FrameSlot(v2);
	auto z = ZInst(op, m->Frame1Slot(v1, op), nv2, i, c);
	z.op_type = OP_VVVC_I3;
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

	// Make sure we have a (pseudo-)instruction at the end so we
	// can use it as a branch label.
	if ( ! pending_inst )
		pending_inst = new ZInst();

	// Concretize instruction numbers in inst1 so we can
	// easily move through the code.
	for ( auto i = 0; i < insts1.size(); ++i )
		insts1[i]->inst_num = i;

	// Compute which instructions are inside loops.
	for ( auto i = 0; i < insts1.size(); ++i )
		{
		auto inst = insts1[i];

		auto t = inst->target;
		if ( ! t || t == pending_inst )
			continue;

		if ( t->inst_num < i )
			// Backward branch.
			for ( auto j = t->inst_num; j <= i; ++j )
				insts1[j]->inside_loop = true;
		}

	if ( ! analysis_options.no_ZAM_opt )
		OptimizeInsts();

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

	// Complain about unused aggregates ... but not if we're inlining,
	// as that can lead to optimizations where they wind up being unused
	// but the original logic for using them was sound.
	if ( ! analysis_options.inliner )
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

#define TALLY_SWITCH_TARGETS(switches) \
	for ( auto& targs : switches ) \
		for ( auto& targ : targs ) \
			++(targ.second->num_labels);

	TALLY_SWITCH_TARGETS(int_cases);
	TALLY_SWITCH_TARGETS(uint_cases);
	TALLY_SWITCH_TARGETS(double_cases);
	TALLY_SWITCH_TARGETS(str_cases);

	bool something_changed;

	do
		{
		something_changed = false;

		while ( RemoveDeadCode() )
			something_changed = true;

		while ( CollapseGoTos() )
			something_changed = true;

		ComputeFrameLifetimes();

#if 0
		printf("current code:\n");
		for ( int i = 0; i < insts1.size(); ++i )
			{
			auto& inst = insts1[i];
			printf("%d%s%s: ", i, inst->live ? "" : " (dead)",
				inst->inside_loop ? " (loop)" : "");
			inst->Dump(frame_denizens);
			}

		printf("denizens for %s\n", func->Name());
		for ( auto i = 1; i < frame_denizens.size(); ++i )
			{
			auto id = frame_denizens[i];
			printf("denizen%s %s begins at %d, ends at %d\n",
				id->IsGlobal() ? " (global)" : "",
				id->Name(),
				denizen_beginning.count(i) ?
					denizen_beginning[i]->inst_num : -1,
				denizen_ending.count(i) ?
					denizen_ending[i]->inst_num : -1);
			}
#endif

		if ( PruneGlobally() )
			something_changed = true;
		}
	while ( something_changed );

	ReMapFrame();
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
		if ( ! t )
			continue;

		if ( t->IsUnconditionalBranch() )
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

		// Collapse branch-to-next-statement, taking into
		// account dead code.
		int j = i + 1;

		bool branches_into_dead = false;
		while ( j < insts1.size() && ! insts1[j]->live )
			{
			++j;
			if ( t == insts1[j] )
				branches_into_dead = true;
			}

		// j now points to the first live instruction after i.
		if ( branches_into_dead ||
		     (j < insts1.size() && t == insts1[j]) )
			{ // i0 is branch-to-next-statement
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

		if ( inst->AssignsToSlot1() && ! inst->HasSideEffects() )
			{
			int slot = inst->v1;
			if ( slot > 0 && slot < frame_denizens.size() &&
			     ! frame_denizens[slot]->IsGlobal() &&
			     denizen_ending.count(slot) == 0 )
				{
				did_prune = true;
				// We don't use this assignment.
				KillInst(inst);
				}
			}
		}

	return did_prune;
	}

void ZAM::ComputeFrameLifetimes()
	{
	// Start analysis from scratch, since we can do this repeatedly.
	inst_beginnings.clear();
	inst_endings.clear();

	denizen_beginning.clear();
	denizen_ending.clear();

	for ( auto i = 0; i < insts1.size(); ++i )
		{
		auto inst = insts1[i];
		if ( ! inst->live )
			continue;

		if ( inst->AssignsToSlot1() )
			CheckSlotAssignment(inst->v1, inst);

		if ( inst->op == OP_NEXT_TABLE_ITER_VAL_VAR_VVV ||
		     inst->op == OP_NEXT_TABLE_ITER_VV )
			{
			// Sigh, need to special-case these as they
			// assign to an arbitrary long list of variables.
			auto iter_vars = inst->c.iter_info;
			for ( auto v : iter_vars->loop_vars )
				CheckSlotAssignment(v, inst);

			// No need to check the additional "var" associated
			// with OP_NEXT_TABLE_ITER_VAL_VAR_VVV as that's
			// a slot-1 assignment.
			}

		if ( inst->op == OP_SYNC_GLOBALS_X )
			{
			// Extend the lifetime of any modified globals.
			for ( auto g : modified_globals )
				{
				int gs = frame_layout[g];
				if ( denizen_beginning.count(gs) == 0 )
					// Global hasn't been loaded yet.
					continue;

				ExtendLifetime(gs, EndOfLoop(inst));
				}
			}

		int s1, s2, s3, s4;

		if ( ! inst->UsesSlots(s1, s2, s3, s4) )
			continue;

		CheckSlotUse(s1, inst);
		CheckSlotUse(s2, inst);
		CheckSlotUse(s3, inst);
		CheckSlotUse(s4, inst);
		}
	}

void ZAM::ReMapFrame()
	{
	// Note, we manage the remapping as 0-based.  This ultimately
	// needs to be translated into 1-based due to the assumption
	// that the "temporary register" slot is zero.  Eventually we
	// should just treat it and the "extra" slots as we do any other
	// identifier.
	
	// General approach: go sequentially through the instructions,
	// see which variables begin their lifetime at each, and at
	// that point remap the variables to a suitable frame slot.

#if 1
	printf("%s denizens:\n", func->Name());
	for ( auto i = 1; i < frame_denizens.size(); ++i )
		{
		auto id = frame_denizens[i];
		printf("denizen%s %s begins at %d, ends at %d\n",
			id->IsGlobal() ? " (global)" : "",
			id->Name(),
			denizen_beginning.count(i) ?
				denizen_beginning[i]->inst_num : -1,
			denizen_ending.count(i) ?
				denizen_ending[i]->inst_num : -1);
		}

	printf("%s inst structures:\n", func->Name());
	for ( auto i = 0; i < insts1.size(); ++i )
		{
		auto inst = insts1[i];

		if ( inst_beginnings.count(inst) > 0 )
			{
			printf("%d:", i);

			auto vars = inst_beginnings[inst];
			for ( auto v : vars )
				printf(" %s", v->Name());

			printf("\n");
			}
		}
#endif

	for ( auto i = 0; i < insts1.size(); ++i )
		{
		auto inst = insts1[i];

		if ( inst_beginnings.count(inst) == 0 )
			continue;

		auto vars = inst_beginnings[inst];
		for ( auto v : vars )
			{
			// Don't remap variables whose values aren't actually
			// used.
			int slot = frame_layout[v];
			if ( denizen_ending.count(slot) > 0 )
				ReMapVar(v, slot, i);
			}
		}

	printf("%s frame remapping:\n", func->Name());

	for ( auto frame_elem : frame_layout )
		printf("frame[%d] = %s\n", frame_elem.second, frame_elem.first->Name());
	for ( auto i = 0; i < shared_frame_denizens.size(); ++i )
		{
		auto& s = shared_frame_denizens[i];
		printf("*%d (%s) %lu #%d->#%d:",
			i, s.is_managed ? "M" : "N",
			s.ids.size(), s.id_start[0], s.scope_end);

		for ( auto j = 0; j < s.ids.size(); ++j )
			printf(" %s (%d)", s.ids[j]->Name(), s.id_start[j]);

		printf("\n");
		}
	}

void ZAM::ReMapVar(const ID* id, int slot, int inst)
	{
	// Greedy algorithm: find the first suitable frame.  In principle
	// we could perhaps do better using a more powerful allocation
	// method like graph coloring, but far and away the bulk of our
	// variables are short-lived temporaries, for which greedy should
	// work fine.
	bool is_managed = IsManagedType(id->Type());

	int i;
	for ( i = 0; i < shared_frame_denizens.size(); ++i )
		{
		auto& s = shared_frame_denizens[i];

		// Note that the following test is <= rather than <.
		// This is because assignment in instructions happens
		// after using any variables to compute the value
		// to assign.  ZAM instructions are careful to
		// allow operands and assignment destinations to
		// refer to the same slot.

		if ( s.scope_end <= inst && s.is_managed == is_managed )
			// It's compatible.
			break;
		}

	int scope_end = denizen_ending[slot]->inst_num;

	if ( i == shared_frame_denizens.size() )
		{
		// No compatible existing slot.  Create a new one.
		FrameSharingInfo info;
		info.ids.push_back(id);
		info.id_start.push_back(inst);
		info.scope_end = scope_end;
		info.is_managed = is_managed;
		shared_frame_denizens.push_back(info);
		}

	else
		{
		// Add to existing slot.
		auto& s = shared_frame_denizens[i];

		s.ids.push_back(id);
		s.id_start.push_back(inst);
		s.scope_end = scope_end;
		}
	}

void ZAM::CheckSlotAssignment(int slot, const ZInst* inst)
	{
	if ( slot <= 0 )
		// Either no slot, or the temporary slot.
		return;

	if ( slot >= frame_denizens.size() )
		// One of the "extra" slots.  We need to consolidate
		// these, too, but for now we defer on doing so.
		return;

	// We construct temporaries such that their values are never
	// used earlier than their definitions in loop bodies.  For
	// other denizens, however, they can be, so in those cases
	// we expand the lifetime beginning to the start of any loop
	// region.
	if ( ! reducer->IsTemporary(frame_denizens[slot]) )
		inst = BeginningOfLoop(inst);

	SetLifetimeStart(slot, inst);
	}

void ZAM::SetLifetimeStart(int slot, const ZInst* inst)
	{
	if ( denizen_beginning.count(slot) > 0 )
		{
		// Beginning of denizen's lifetime already seen, nothing
		// more to do other than check for consistency.
		ASSERT(denizen_beginning[slot]->inst_num <= inst->inst_num);
		}

	else
		{ // denizen begins here
		denizen_beginning[slot] = inst;

		if ( inst_beginnings.count(inst) == 0 )
			{
			// Need to create a set to track the denizens
			// beginning at the instruction.
			std::unordered_set<const ID*> denizens;
			inst_beginnings[inst] = denizens;
			}

		inst_beginnings[inst].insert(frame_denizens[slot]);
		}
	}

void ZAM::CheckSlotUse(int slot, const ZInst* inst)
	{
	if ( slot <= 0 )
		// Either no slot, or the temporary slot.
		return;

	if ( slot >= frame_denizens.size() )
		// One of the "extra" slots.  We need to consolidate
		// these, too, but for now we defer on doing so.
		return;

	// See comment above about temporaries not having their values
	// extend around loop bodies.
	if ( ! reducer->IsTemporary(frame_denizens[slot]) )
		inst = EndOfLoop(inst);

	ExtendLifetime(slot, inst);
	}

void ZAM::ExtendLifetime(int slot, const ZInst* inst)
	{
	if ( denizen_ending.count(slot) > 0 )
		{
		// End of denizen's lifetime already seen.  Check for
		// consistency and then extend as needed.
		auto old_inst = denizen_ending[slot];
		ASSERT(old_inst->inst_num <= inst->inst_num);

		if ( old_inst->inst_num < inst->inst_num )
			{
			// Extend.
			inst_endings[old_inst].erase(frame_denizens[slot]);

			if ( inst_endings.count(inst) == 0 )
				{
				std::unordered_set<const ID*> denizens;
				inst_endings[inst] = denizens;
				}

			inst_endings[inst].insert(frame_denizens[slot]);
			denizen_ending.at(slot) = inst;
			}
		}

	else
		{ // first time seeing a use of this denizen
		denizen_ending[slot] = inst;

		if ( inst_endings.count(inst) == 0 )
			{
			std::unordered_set<const ID*> denizens;
			inst_endings[inst] = denizens;
			}

		inst_endings[inst].insert(frame_denizens[slot]);
		}
	}

const ZInst* ZAM::BeginningOfLoop(const ZInst* inst) const
	{
	auto i = inst->inst_num;

	while ( i >= 0 && insts1[i]->inside_loop )
		--i;

	if ( i == inst->inst_num )
		return inst;

	// We moved backwards to just beyond a loop that inst
	// is part of.  Move to that loop's (live) beginning.
	++i;
	while ( i != inst->inst_num && ! insts1[i]->live )
		++i;

	return insts1[i];
	}

const ZInst* ZAM::EndOfLoop(const ZInst* inst) const
	{
	auto i = inst->inst_num;

	while ( i < insts1.size() && insts1[i]->inside_loop )
		++i;

	if ( i == inst->inst_num )
		return inst;

	// We moved forwards to just beyond a loop that inst
	// is part of.  Move to that loop's (live) end.
	--i;
	while ( i != inst->inst_num && ! insts1[i]->live )
		--i;

	return insts1[i];
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
	// Special-case for table iterators, which assign to a bunch
	// of variables but they're not immediately visible in the
	// instruction layout.
	if ( i->op == OP_NEXT_TABLE_ITER_VAL_VAR_VVV ||
	     i->op == OP_NEXT_TABLE_ITER_VV )
		{
		auto iter_vars = i->c.iter_info;
		for ( auto v : iter_vars->loop_vars )
			if ( v == slot )
				return true;

		if ( i->op != OP_NEXT_TABLE_ITER_VAL_VAR_VVV )
			return false;

		// Otherwise fall through, since that flavor of iterate
		// *does* also assign to slot 1.
		}

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

// Unary vector operations never work on managed types, so no need
// to pass in the type ...  However, the RHS, which normally would
// be const, needs to be non-const so we can use its Type() method
// to get at a shareable VectorType.
static void vec_exec(ZOp op, VectorVal*& v1, VectorVal* v2);

// Binary ones *can* have managed types (strings).
static void vec_exec(ZOp op, BroType* t, VectorVal*& v1, VectorVal* v2,
			const VectorVal* v3);

// Vector coercion.
//
// ### Should check for underflow/overflow.
#define VEC_COERCE(tag, lhs_type, lhs_accessor, cast, rhs_accessor) \
	static VectorVal* vec_coerce_##tag(VectorVal* vec) \
		{ \
		auto& v = vec->RawVector()->ConstVec(); \
		auto yt = new VectorType(base_type(lhs_type)); \
		auto res_zv = new VectorVal(yt); \
		auto n = v.size(); \
		auto& res = res_zv->RawVector()->InitVec(n); \
		for ( unsigned int i = 0; i < n; ++i ) \
			res[i].lhs_accessor = cast(v[i].rhs_accessor); \
		return res_zv; \
		}

VEC_COERCE(IU, TYPE_INT, int_val, bro_int_t, uint_val)
VEC_COERCE(ID, TYPE_INT, int_val, bro_int_t, double_val)
VEC_COERCE(UI, TYPE_COUNT, uint_val, bro_int_t, int_val)
VEC_COERCE(UD, TYPE_COUNT, uint_val, bro_uint_t, double_val)
VEC_COERCE(DI, TYPE_DOUBLE, double_val, double, int_val)
VEC_COERCE(DU, TYPE_DOUBLE, double_val, double, uint_val)

StringVal* ZAM_to_lower(const StringVal* sv)
	{
	auto bs = sv->AsString();
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
		
	return new StringVal(new BroString(1, lower_s, n));
	}

StringVal* ZAM_sub_bytes(const StringVal* s, bro_uint_t start, bro_int_t n)
	{
        if ( start > 0 )
                --start;        // make it 0-based

        BroString* ss = s->AsString()->GetSubstring(start, n);

	return new StringVal(ss ? ss : new BroString(""));
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
	int end_pc = insts2.size();

#define BuildVal(v, t) ZAMValUnion(v, t)
#define CopyVal(v) (IsManagedType(z.t) ? BuildVal(v.ToVal(z.t), z.t) : v)

// Managed assignments to frame[s.v1].
#define AssignV1(v) AssignV1T(v, z.t)
#define AssignV1T(v, t) { if ( z.is_managed ) DeleteManagedType(frame[z.v1], t); frame[z.v1] = v; }

	// Return value, or nil if none.
	const ZAMValUnion* ret_u;

	// Type of the return value.  If nil, then we don't have a value.
	BroType* ret_type = nullptr;

	bool do_profile = analysis_options.report_profile;

	// All globals start out unloaded.
	for ( auto i = 1; i <= num_globals; ++i )
		global_state[i] = GS_UNLOADED;

	// Clear slots for which we do explicit memory management.
	for ( auto s : managed_slots )
		frame[s].managed_val = nullptr;

	flow = FLOW_RETURN;	// can be over-written by a Hook-Break

	while ( pc < end_pc && ! ZAM_error ) {
		auto& z = *insts2[pc];
		int profile_pc;
		double profile_CPU;
		const Expr* profile_expr;

		if ( 0 )
			{
			printf("executing %d: ", pc);
			z.Dump(frame_denizens);
			}

		if ( do_profile )
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

		if ( do_profile )
			{
			double dt = curr_CPU_time() - profile_CPU;
			(*inst_CPU)[profile_pc] += dt;
			ZOP_CPU[z.op] += dt;

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
		DeleteManagedType(v, nullptr);
		// DeleteManagedType(v, managed_slot_types[i]);
		}

	delete [] frame;
	delete [] global_state;

	// Clear any error state.
	ZAM_error = false;

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
	bool is_any = IsAny(n->Type());
	return AddInst(GenInst(this, is_any ? OP_INTERPRET_EXPR_ANY_V :
						OP_INTERPRET_EXPR_V, n, e));
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

	else if ( streq(func->Name(), "Log::__write") )
		return BuiltIn_Log__write(n, args);

	else if ( streq(func->Name(), "Broker::__flush_logs") )
		return BuiltIn_Broker__flush_logs(n, args);

	else if ( streq(func->Name(), "get_port_transport_proto") )
		return BuiltIn_get_port_etc(n, args);

	else if ( streq(func->Name(), "reading_live_traffic") )
		return BuiltIn_reading_live_traffic(n, args);

	else if ( streq(func->Name(), "reading_traces") )
		return BuiltIn_reading_traces(n, args);

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
		z.op_type = OP_VVVV_I4;
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
		z.op_type = OP_VVVC_I3;
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

bool ZAM::BuiltIn_Log__write(const NameExpr* n, const expr_list& args)
	{
	if ( ! log_ID_enum_type )
		{
		auto log_ID_type = lookup_ID("ID", "Log");
		ASSERT(log_ID_type);
		log_ID_enum_type = log_ID_type->Type()->AsEnumType();
		}

	auto id = args[0];
	auto columns = args[1];

	if ( columns->Tag() != EXPR_NAME )
		return false;

	int nslot = n ? Frame1Slot(n, OP1_WRITE) : RegisterSlot();
	auto columns_n = columns->AsNameExpr();
	auto col_slot = FrameSlot(columns_n);

	ZInst z;

	if ( id->Tag() == EXPR_CONST )
		z = ZInst(OP_LOG_WRITE_VVC, nslot, col_slot, id->AsConstExpr());
	else
		z = ZInst(OP_LOG_WRITE_VVV, nslot, FrameSlot(id->AsNameExpr()),
				col_slot);

	z.SetType(columns_n->Type());

	AddInst(z);

	return true;
	}

bool ZAM::BuiltIn_Broker__flush_logs(const NameExpr* n, const expr_list& args)
	{
	int nslot = n ? Frame1Slot(n, OP1_WRITE) : RegisterSlot();
	AddInst(ZInst(OP_BROKER_FLUSH_LOGS_V, nslot));
	return true;
	}

bool ZAM::BuiltIn_get_port_etc(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	auto p = args[0];

	if ( p->Tag() != EXPR_NAME )
		return false;

	auto pn = p->AsNameExpr();
	int nslot = Frame1Slot(n, OP1_WRITE);

	AddInst(ZInst(OP_GET_PORT_TRANSPORT_PROTO_VV, nslot, FrameSlot(pn)));

	return true;
	}

bool ZAM::BuiltIn_reading_live_traffic(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	int nslot = Frame1Slot(n, OP1_WRITE);

	AddInst(ZInst(OP_READING_LIVE_TRAFFIC_V, nslot));

	return true;
	}

bool ZAM::BuiltIn_reading_traces(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	int nslot = Frame1Slot(n, OP1_WRITE);

	AddInst(ZInst(OP_READING_TRACES_V, nslot));

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
		a_s.SetType(n->Type());

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

	z.SetType(e->Type());
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
	z.SetType(e->Type());

	return AddInst(z);
	}

const CompiledStmt ZAM::VectorCoerce(const NameExpr* n, const Expr* e)
	{
	auto op = e->GetOp1()->AsNameExpr();
	int op_slot = FrameSlot(op);

	auto zop = OP_VECTOR_COERCE_VV;
	ZInst z(zop, Frame1Slot(n, zop), op_slot);
	z.SetType(e->Type());

	return AddInst(z);
	}

const CompiledStmt ZAM::Is(const NameExpr* n, const Expr* e)
	{
	auto is = e->AsIsExpr();
	auto op = e->GetOp1()->AsNameExpr();
	int op_slot = FrameSlot(op);

	ZInst z(OP_IS_VV, Frame1Slot(n, OP_IS_VV), op_slot);
	z.e = op;
	z.SetType(is->TestType());

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
			{
			z = GenInst(this, OP_WHEN_VVVC, timeout->AsConstExpr());
			z.op_type = OP_VVVC_I1_I2_I3;
			z.v3 = is_return;
			}
		else
			{
			z = GenInst(this, OP_WHEN_VVVV, timeout->AsNameExpr());
			z.op_type = OP_VVVV_I2_I3_I4;
			z.v4 = is_return;
			}
		}

	else
		{
		z = GenInst(this, OP_WHEN_VV);
		z.op_type = OP_VV_I1_I2;
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

		if ( timeout->Tag() == EXPR_CONST )
			{
			z.v1 = branch_past_blocks.stmt_num + 1;
			z.v2 = when_done.stmt_num + 1;
			}
		else
			{
			z.v2 = branch_past_blocks.stmt_num + 1;
			z.v3 = when_done.stmt_num + 1;
			}

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
		z.SetType(type);
		auto case_test = AddInst(z);

		// Type cases that don't use "as" create a placeholder
		// ID with a null name.
		if ( id->Name() )
			{
			int id_slot = Frame1Slot(id, OP_CAST_ANY_VV);
			z = ZInst(OP_CAST_ANY_VV, id_slot, slot);
			z.SetType(type);
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
	auto op3 = index_assign->GetOp3();
	auto any_val = IsAny(op3->Type());

	auto lhs = op1->AsNameExpr();
	auto lt = lhs->Type();

	if ( IsAnyVec(lt) )
		{
		ZInst z;

		if ( any_val )
			// No need to set the type, as it's retrieved
			// dynamically.
			z = GenInst(this, OP_TRANSFORM_ANY_VEC2_VV, lhs,
					op3->AsNameExpr());
		else
			{
			z = GenInst(this, OP_TRANSFORM_ANY_VEC_V, lhs);
			z.SetType(op3->Type());
			}

		AddInst(z);
		}

	auto indexes = index_assign->GetOp2()->AsListExpr()->Exprs();

	if ( indexes.length() > 1 )
		{
		// Vector slice assignment.  For now, punt to the interpreter.
		return InterpretExpr(e);
		}

	auto op2 = indexes[0];

	if ( op2->Tag() == EXPR_CONST && op3->Tag() == EXPR_CONST )
		{
		// Turn into a VVC assignment by assigning the index to
		// a temporary.
		auto tmp = RegisterSlot();
		auto c = op2->AsConstExpr();
		auto z = ZInst(OP_ASSIGN_CONST_VC, tmp, c);
		z.CheckIfManaged(c);

		AddInst(z);

		auto zop = OP_VECTOR_ELEM_ASSIGN_VVC;

		return AddInst(ZInst(zop, Frame1Slot(lhs, zop), tmp,
					op3->AsConstExpr()));
		}

	if ( op2->Tag() == EXPR_NAME )
		{
		CompiledStmt inst(0);

		if ( op3->Tag() == EXPR_NAME )
			inst = any_val ? Vector_Elem_Assign_AnyVVV(lhs,
							op2->AsNameExpr(),
							op3->AsNameExpr()) :
					Vector_Elem_AssignVVV(lhs,
							op2->AsNameExpr(),
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

		auto inst = any_val ? Vector_Elem_Assign_AnyVVi(lhs,
						op3->AsNameExpr(), index) :
					Vector_Elem_AssignVVi(lhs,
						op3->AsNameExpr(), index);

		TopMainInst()->t = op3->Type().get();
		return inst;
		}
	}

const CompiledStmt ZAM::LoopOverTable(const ForStmt* f, const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto value_var = f->ValueVar();

	auto ii = new IterInfo();

	for ( int i = 0; i < loop_vars->length(); ++i )
		{
		auto id = (*loop_vars)[i];
		ii->loop_vars.push_back(FrameSlot(id));
		ii->loop_var_types.push_back(id->Type());
		}

	ZAMValUnion ii_val;
	ii_val.iter_info = ii;

	auto info = NewSlot();
	auto z = ZInst(OP_INIT_TABLE_LOOP_VVC, info, FrameSlot(val));
	z.c = ii_val;
	z.op_type = OP_VVc;
	z.SetType(value_var ? value_var->Type() : nullptr);
	auto init_end = AddInst(z);

	auto iter_head = StartingBlock();
	if ( value_var )
		{
		z = ZInst(OP_NEXT_TABLE_ITER_VAL_VAR_VVV, FrameSlot(value_var),
				info, 0);
		z.c = ii_val;
		z.CheckIfManaged(value_var->Type());
		z.op_type = OP_VVV_I3;
		}
	else
		{
		z = ZInst(OP_NEXT_TABLE_ITER_VV, info, 0);
		z.c = ii_val;
		z.op_type = OP_VV_I2;
		}

	return FinishLoop(iter_head, z, f->LoopBody(), info);
	}

const CompiledStmt ZAM::LoopOverVector(const ForStmt* f, const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto loop_var = (*loop_vars)[0];

	auto ii = new IterInfo();
	ii->vec_type = val->Type()->AsVectorType();
	ii->yield_type = ii->vec_type->YieldType();

	ZAMValUnion ii_val;
	ii_val.iter_info = ii;

	auto info = NewSlot();
	auto z = ZInst(OP_INIT_VECTOR_LOOP_VV, info, FrameSlot(val));
	z.c = ii_val;
	z.op_type = OP_VVc;

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

	ZAMValUnion ii_val;
	ii_val.iter_info = new IterInfo();

	auto info = NewSlot();
	auto z = ZInst(OP_INIT_STRING_LOOP_VV, info, FrameSlot(val));
	z.c = ii_val;
	z.op_type = OP_VVc;

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

	return final_stmt;
	}

const CompiledStmt ZAM::InitRecord(ID* id, RecordType* rt)
	{
	auto z = ZInst(OP_INIT_RECORD_V, FrameSlot(id));
	z.SetType(rt);
	return AddInst(z);
	}

const CompiledStmt ZAM::InitVector(ID* id, VectorType* vt)
	{
	auto z = ZInst(OP_INIT_VECTOR_V, FrameSlot(id));
	z.SetType(vt);
	return AddInst(z);
	}

const CompiledStmt ZAM::InitTable(ID* id, TableType* tt, Attributes* attrs)
	{
	auto z = ZInst(OP_INIT_TABLE_V, FrameSlot(id));
	z.SetType(tt);
	z.attrs = attrs;
	return AddInst(z);
	}

const CompiledStmt ZAM::Return(const ReturnStmt* r)
	{
	auto e = r->StmtExpr();

	// We could consider only doing this sync for "true" returns
	// and not for catch-return's.  To make that work, however,
	// would require propagating the "dirty" status of globals
	// modified inside an inlined function.  These changes aren't
	// visible because RDs don't propagate across return's, even
	// inlined ones.  See the coment in for STMT_RETURN's in
	// RD_Decorate::PostStmt for why we can't simply propagate
	// RDs in this case.
	//
	// In addition, by sync'ing here rather than deferring we
	// provide opportunities to double-up the frame slot used
	// by the global.
	SyncGlobals(r);

	if ( retvars.size() == 0 )
		{ // a "true" return
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
			(void) AssignXV(rv, e->AsNameExpr());
		else
			(void) AssignXC(rv, e->AsConstExpr());
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

		as.SetType(e->Type());
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
	z.SetType(id->Type());
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
	z.SetType(id->Type());
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

	// Determine the portion of CPU time spent interpreting expressions.
	double interp_CPU = 0.0;
	for ( int i = 0; i < inst_count->size(); ++i )
		{
		auto op = insts2[i]->op;
		if ( op == OP_INTERPRET_EXPR_X || op == OP_INTERPRET_EXPR_V ||
		     op == OP_INTERPRET_EXPR_ANY_V )
			interp_CPU += (*inst_CPU)[i];
		}

	printf("%s CPU time: %.06f %.06f\n", func->Name(), *CPU_time,
		*CPU_time - interp_CPU);

	for ( int i = 0; i < inst_count->size(); ++i )
		{
		printf("%s %d %d %.06f ", func->Name(), i,
			(*inst_count)[i], (*inst_CPU)[i]);
		insts2[i]->Dump(frame_denizens);
		}
	}

void ZAM::Dump()
	{
	for ( auto frame_elem : frame_layout )
		printf("frame[%d] = %s\n", frame_elem.second, frame_elem.first->Name());

	if ( insts2.size() > 0 )
		printf("Pre-removal of dead code:\n");

	for ( int i = 0; i < insts1.size(); ++i )
		{
		auto& inst = insts1[i];
		printf("%d%s%s: ", i, inst->live ? "" : " (dead)",
			inst->inside_loop ? " (loop)" : "");
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

	for ( int i = 0; i < int_cases.size(); ++i )
		DumpIntCases(i);
	for ( int i = 0; i < uint_cases.size(); ++i )
		DumpUIntCases(i);
	for ( int i = 0; i < double_cases.size(); ++i )
		DumpDoubleCases(i);
	for ( int i = 0; i < str_cases.size(); ++i )
		DumpStrCases(i);
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

	BroType* zt;

	if ( c2 )
		zt = c2->Type().get();
	else if ( c3 )
		zt = c3->Type().get();
	else
		zt = n2->Type().get();

	z.SetType(zt);

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
		z.SetType(n2->Type());
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

			z.SetType(n1->Type());
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
		z.SetType(n2->Type());
		break;

	case TYPE_TABLE:
		op = OP_TABLE_INDEX_VVV;
		z = ZInst(op, Frame1Slot(n1, op), n2_slot, build_indices);
		z.SetType(n1->Type());
		break;

	case TYPE_STRING:
		op = OP_INDEX_STRING_SLICE_VVL;
		z = ZInst(op, Frame1Slot(n1, op), n2_slot, build_indices);
		z.SetType(n1->Type());
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

void ZAM::SyncGlobals(std::unordered_set<ID*>& globals, const BroObj* o)
	{
	auto mgr = reducer->GetDefSetsMgr();
	auto entry_rds = mgr->GetPreMaxRDs(body);

	auto curr_rds = o ?
		mgr->GetPreMaxRDs(o) : mgr->GetPostMaxRDs(LastStmt());

	bool could_be_dirty = false;

	for ( auto g : globals )
		{
		auto g_di = mgr->GetConstID_DI(g);
		auto entry_dps = entry_rds->GetDefPoints(g_di);
		auto curr_dps = curr_rds->GetDefPoints(g_di);

		if ( ! entry_rds->SameDefPoints(entry_dps, curr_dps) )
			{
			modified_globals.insert(g);
			could_be_dirty = true;
			}
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

bool ZAM::CheckAnyType(const BroType* any_type, const BroType* expected_type,
			const Stmt* associated_stmt) const
	{
	if ( IsAny(expected_type) )
		return true;

	if ( ! same_type(any_type, expected_type, false, false) )
		{
		auto at = any_type->Tag();
		auto et = expected_type->Tag();

		if ( at == TYPE_RECORD && et == TYPE_RECORD )
			{
			auto at_r = any_type->AsRecordType();
			auto et_r = expected_type->AsRecordType();

			if ( record_promotion_compatible(et_r, at_r) )
				return true;
			}

		char buf[8192];
		snprintf(buf, sizeof buf, "run-time type clash (%s/%s)",
			type_name(at), type_name(et));

		reporter->Error(buf, associated_stmt);
		return false;
		}

	return true;
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
static void vec_exec(ZOp op, VectorVal*& v1, VectorVal* v2)
	{
	// We could speed this up further still by gen'ing up an
	// instance of the loop inside each switch case (in which
	// case we might as well move the whole kit-and-caboodle
	// into the Exec method).  But that seems like a lot of
	// code bloat for only a very modest gain.

	auto& vec2 = v2->RawVector()->ConstVec();
	bool needs_management;

	if ( ! v1 )
		{
		auto vt = v2->Type()->AsVectorType();
		::Ref(vt);
		v1 = new VectorVal(vt);
		}

	v1->RawVector()->Resize(vec2.size());

	auto& vec1 = v1->RawVector()->ModVec();

	for ( unsigned int i = 0; i < vec2.size(); ++i )
		switch ( op ) {

#include "ZAM-Vec1EvalDefs.h"

		default:
			reporter->InternalError("bad invocation of VecExec");
		}
	}

// Binary vector operation of v1 = v2 <vec-op> v3.
static void vec_exec(ZOp op, BroType* yt, VectorVal*& v1,
			VectorVal* v2, const VectorVal* v3)
	{
	// See comment above re further speed-up.

	auto& vec2 = v2->RawVector()->ConstVec();
	auto& vec3 = v3->RawVector()->ConstVec();

	BroType* needs_management = v1 ? yt : nullptr;

	if ( ! v1 )
		{
		auto vt = v2->Type()->AsVectorType();
		::Ref(vt);
		v1 = new VectorVal(vt);
		}

	// ### This leaks if it's a vector-of-string becoming smaller.
	v1->RawVector()->Resize(vec2.size());

	auto& vec1 = v1->RawVector()->ModVec();

	for ( unsigned int i = 0; i < vec2.size(); ++i )
		switch ( op ) {

#include "ZAM-Vec2EvalDefs.h"

		default:
			reporter->InternalError("bad invocation of VecExec");
		}
	}
