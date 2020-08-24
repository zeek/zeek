// See the file "COPYING" in the main distribution directory for copyright.

// This file factors out of ZAM the logic associated with low-level
// optimization, i.e., code improvement that's done after the compiler
// has generated an initial, complete intermediary function body.

#include "ZAM.h"
#include "Reduce.h"
#include "ScriptAnaly.h"
#include "Reporter.h"
#include "input.h"


// Tracks per function its maximum remapped interpreter frame size.  We
// can't do this when compiling individual functions since for event handlers
// and hooks it needs to be computed across all of their bodies.
//
// Note, this is now not really needed, because we no longer use any
// interpreter frame entries other than those for the function's arguments.
// We keep the code in case that changes, for example when deciding to
// compile functions that include "when" conditions.
std::unordered_map<const Func*, int> remapped_intrp_frame_sizes;

void finalize_functions(const std::vector<FuncInfo*>& funcs)
	{
	// Given we've now compiled all of the function bodies, we
	// can reset the interpreter frame sizes of each function
	// to be the maximum needed to accommodate all of its
	// remapped bodies.

	// Find any functions with bodies that weren't compiled and
	// make sure we don't reduce their frame size.  For any loaded
	// from ZAM save files, use the associated maximum interpreter
	// frame size as a minimum.
	for ( auto& f : funcs )
		{
		auto func = f->func;

		// First, check for a maximum seen in ZAM save files.
		if ( f->body->Tag() == STMT_COMPILED &&
		     ZAM_interp_frame.count(func) > 0 )
			{
			int size = ZAM_interp_frame[func];

			// If we haven't done remapping for one of its
			// function bodies - or if we have but to a smaller
			// value - then use this value.
			if ( remapped_intrp_frame_sizes.count(func) == 0 ||
			     remapped_intrp_frame_sizes[func] < size )
				remapped_intrp_frame_sizes[func] = size;
			}

		// If we have non-compiled versions of the function's body,
		// preserve the size they need.
		int size = func->FrameSize();

		if ( f->body->Tag() != STMT_COMPILED &&
		     remapped_intrp_frame_sizes.count(func) > 0 &&
		     size > remapped_intrp_frame_sizes[func] )
			remapped_intrp_frame_sizes[func] = size;
		}

	for ( auto& f : funcs )
		{
		auto func = f->func;

		if ( remapped_intrp_frame_sizes.count(func) == 0 )
			// No entry for this function, keep current frame size.
			continue;

		// Note, functions with multiple bodies appear in "funcs"
		// multiple times, but the following doesn't hurt to do
		// more than once.
		func->SetFrameSize(remapped_intrp_frame_sizes[func]);

		if ( f->body->Tag() == STMT_COMPILED && f->save_file )
			{
			auto zb = f->body->AsZBody();
			auto sf = fopen(f->save_file, "w");
			if ( ! sf )
				{
				fprintf(stderr, "cannot create ZAM save file %s: %s\n",
					f->save_file, strerror(errno));
				exit(1);
				}
			else
				{
				zb->SaveTo(sf, func->FrameSize());
				fclose(sf);
				}
			}
		}
	}


void ZAM::OptimizeInsts()
	{
	// Do accounting for targeted statements.
	for ( auto& i : insts1 )
		{
		if ( i->target && i->target->live )
			++(i->target->num_labels);
		if ( i->target2 && i->target2->live )
			++(i->target2->num_labels);
		}

#define TALLY_SWITCH_TARGETS(switches) \
	for ( auto& targs : switches ) \
		for ( auto& targ : targs ) \
			++(targ.second->num_labels);

	TALLY_SWITCH_TARGETS(int_casesI);
	TALLY_SWITCH_TARGETS(uint_casesI);
	TALLY_SWITCH_TARGETS(double_casesI);
	TALLY_SWITCH_TARGETS(str_casesI);

	bool something_changed;

	do
		{
		something_changed = false;

		while ( RemoveDeadCode() )
			something_changed = true;

		while ( CollapseGoTos() )
			something_changed = true;

		ComputeFrameLifetimes();

		if ( PruneUnused() )
			something_changed = true;
		}
	while ( something_changed );

	ReMapFrame();
	ReMapInterpreterFrame();
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

	for ( unsigned int i = 0; i < insts1.size(); ++i )
		{
		auto i0 = insts1[i];

		if ( ! i0->live )
			continue;

		auto t = i0->target;
		if ( ! t )
			continue;

		// Note, we don't bother optimizing target2 if present,
		// as those are very rare.

		if ( t->IsUnconditionalBranch() )
			{ // Collapse branch-to-branch.
			did_collapse = true;
			do
				{
				ASSERT(t->live);

				--t->num_labels;
				t = t->target;
				i0->target = t;
				++t->num_labels;
				}
			while ( t->IsUnconditionalBranch() );
			}

		// Collapse branch-to-next-statement, taking into
		// account dead code.
		unsigned int j = i + 1;

		bool branches_into_dead = false;
		while ( j < insts1.size() && ! insts1[j]->live )
			{
			if ( t == insts1[j] )
				branches_into_dead = true;
			++j;
			}

		// j now points to the first live instruction after i.
		if ( branches_into_dead ||
		     (j < insts1.size() && t == insts1[j]) ||
		     (j == insts1.size() && t == pending_inst) )
			{ // i0 is branch-to-next-statement
			if ( t != pending_inst )
				--t->num_labels;

			if ( i0->IsUnconditionalBranch() )
				// no point in keeping the branch
				i0->live = false;

			else if ( j < insts1.size() )
				{
				// Update i0 to target the live instruction.
				i0->target = insts1[j];
				++i0->target->num_labels;
				}
			}
		}

	return did_collapse;
	}

bool ZAM::PruneUnused()
	{
	bool did_prune = false;

	for ( unsigned int i = 0; i < insts1.size(); ++i )
		{
		auto inst = insts1[i];

		if ( ! inst->live )
			continue;

		if ( inst->IsFrameStore() && ! VarIsAssigned(inst->v1) )
			{
			did_prune = true;
			KillInst(inst);
			}

		if ( inst->IsLoad() && ! VarIsUsed(inst->v1) )
			{
			did_prune = true;
			KillInst(inst);
			}

		if ( ! inst->AssignsToSlot1() )
			continue;

		int slot = inst->v1;
		if ( denizen_ending.count(slot) > 0 )
			continue;

		if ( frame_denizens[slot]->IsGlobal() )
			{
			// Extend the global's range to the end of the
			// function.  Strictly speaking, we could extend
			// it only to a SYNC_GLOBALS that it's guaranteed
			// to reach, but that's tricky to confidently compute
			// and will only rarely provide much benefit.
			denizen_ending[slot] = insts1.back();
			continue;
			}

		// Assignment to a local that isn't otherwise used.
		if ( ! inst->HasSideEffects() )
			{
			did_prune = true;
			// We don't use this assignment.
			KillInst(inst);
			continue;
			}

		// Transform the instruction into its flavor that doesn't
		// make an assignment.
		switch ( inst->op ) {
		case OP_LOG_WRITE_VVV:
			inst->op = OP_LOG_WRITE_VV;
			inst->op_type = OP_VV;
			inst->v1 = inst->v2;
			inst->v2 = inst->v3;
			break;

		case OP_LOG_WRITEC_VV:
			inst->op = OP_LOG_WRITEC_V;
			inst->op_type = OP_V;
			inst->v1 = inst->v2;
			break;

		case OP_BROKER_FLUSH_LOGS_V:
			inst->op = OP_BROKER_FLUSH_LOGS_X;
			inst->op_type = OP_X;
			break;

		default:
			if ( assignmentless_op.count(inst->op) > 0 )
				{
				inst->op_type = assignmentless_op_type[inst->op];
				inst->op = assignmentless_op[inst->op];

				inst->v1 = inst->v2;
				inst->v2 = inst->v3;
				inst->v3 = inst->v4;
				}
			else
				reporter->InternalError("inconsistency in re-flavoring instruction with side effects");
		}

		// While we didn't prune the instruction,
		// we did prune the assignment, so we'll
		// want to reassess variable lifetimes.
		did_prune = true;
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

	for ( unsigned int i = 0; i < insts1.size(); ++i )
		{
		auto inst = insts1[i];
		if ( ! inst->live )
			continue;

		if ( inst->AssignsToSlot1() )
			CheckSlotAssignment(inst->v1, inst);

		// Some special-casing.
		switch ( inst->op ) {
		case OP_NEXT_TABLE_ITER_VV:
		case OP_NEXT_TABLE_ITER_VAL_VAR_VVV:
			{
			// These assign to an arbitrary long list of variables.
			auto iter_vars = inst->aux->iter_info;
			auto depth = inst->loop_depth;

			for ( auto v : iter_vars->loop_vars )
				{
				CheckSlotAssignment(v, inst);

				// Also mark it as usage throughout the
				// loop.  Otherwise, we risk pruning the
				// variable if it happens to not be used
				// (which will mess up the iteration logic)
				// or doubling it up with some other value
				// inside the loop (which will fail when
				// the loop var has memory management
				// associated with it).
				ExtendLifetime(v, EndOfLoop(inst, depth));
				}

			// No need to check the additional "var" associated
			// with OP_NEXT_TABLE_ITER_VAL_VAR_VVV as that's
			// a slot-1 assignment.  However, similar to other
			// loop variables, mark this as a usage.
			if ( inst->op == OP_NEXT_TABLE_ITER_VAL_VAR_VVV )
				ExtendLifetime(inst->v1, EndOfLoop(inst, depth));
			}
			break;

		case OP_NEXT_TABLE_ITER_NO_VARS_VV:
		case OP_NEXT_TABLE_ITER_VAL_VAR_NO_VARS_VVV:
			{
			auto iter_vars = inst->aux->iter_info;
			auto depth = inst->loop_depth;

			if ( inst->op == OP_NEXT_TABLE_ITER_VAL_VAR_NO_VARS_VVV )
				ExtendLifetime(inst->v1, EndOfLoop(inst, depth));
			}
			break;

		case OP_NEXT_VECTOR_ITER_VVV:
		case OP_NEXT_STRING_ITER_VVV:
			// Sometimes loops are written that don't actually
			// use the iteration variable.  However, we still
			// need to mark the variable as having usage
			// throughout the loop, lest we elide the iteration
			// instruction.  An alternative would be to transform
			// such iterators into variable-less versions.  That
			// optimization hardly seems worth the trouble, though,
			// given the presumed rarity of such loops.
			ExtendLifetime(inst->v1,
					EndOfLoop(inst, inst->loop_depth));
			break;

		case OP_SYNC_GLOBALS_X:
			{
			// Extend the lifetime of any modified globals.
			for ( auto g : modified_globals )
				{
				int gs = frame_layout1[g];
				if ( denizen_beginning.count(gs) == 0 )
					// Global hasn't been loaded yet.
					continue;

				ExtendLifetime(gs, EndOfLoop(inst, 1));
				}
			}
			break;

		case OP_INIT_TABLE_LOOP_VV:
		case OP_INIT_VECTOR_LOOP_VV:
		case OP_INIT_STRING_LOOP_VV:
			{
			// For all of these, the scope of the aggregate
			// being looped over is the entire loop, even
			// if it doesn't directly appear in it, and not
			// just the initializer.  For all three, the
			// aggregate is in v2.
			ASSERT(i < insts1.size() - 1);
			auto succ = insts1[i+1];
			ASSERT(succ->live);
			auto depth = succ->loop_depth;
			ExtendLifetime(inst->v2, EndOfLoop(succ, depth));

			// Important: we skip the usual UsesSlots analysis
			// below since we've already set it, and don't want
			// to perturb ExtendLifetime's consistency check.
			continue;
			}

		default:
			// Look for slots in auxiliary information.
			auto aux = inst->aux;
			if ( ! aux || ! aux->slots )
				break;

			for ( auto j = 0; j < aux->n; ++j )
				{
				if ( aux->slots[j] < 0 )
					continue;

				ExtendLifetime(aux->slots[j],
						EndOfLoop(inst, 1));
				}
			break;
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
	// General approach: go sequentially through the instructions,
	// see which variables begin their lifetime at each, and at
	// that point remap the variables to a suitable frame slot.

	frame1_to_frame2.resize(frame_layout1.size(), -1);
	managed_slotsI.clear();

	for ( unsigned int i = 0; i < insts1.size(); ++i )
		{
		auto inst = insts1[i];

		if ( inst_beginnings.count(inst) == 0 )
			continue;

		auto vars = inst_beginnings[inst];
		for ( auto v : vars )
			{
			// Don't remap variables whose values aren't actually
			// used.
			int slot = frame_layout1[v];
			if ( denizen_ending.count(slot) > 0 )
				ReMapVar(v, slot, i);
			}
		}

#if 0
	printf("%s frame remapping:\n", func->Name());

	for ( unsigned int i = 0; i < shared_frame_denizens.size(); ++i )
		{
		auto& s = shared_frame_denizens[i];
		printf("*%d (%s) %lu [%d->%d]:",
			i, s.is_managed ? "M" : "N",
			s.ids.size(), s.id_start[0], s.scope_end);

		for ( auto j = 0; j < s.ids.size(); ++j )
			printf(" %s (%d)", s.ids[j]->Name(), s.id_start[j]);

		printf("\n");
		}
#endif

	// Update the globals we track, where we prune globals that
	// didn't wind up being used.  (This can happen because they're
	// only used in interpreted expressions.)
	std::vector<GlobalInfo> used_globals;
	std::vector<int> remapped_globals;

	for ( unsigned int i = 0; i < globalsI.size(); ++i )
		{
		auto& g = globalsI[i];
		g.slot = frame1_to_frame2[g.slot];
		if ( g.slot >= 0 )
			{
			remapped_globals.push_back(used_globals.size());
			used_globals.push_back(g);
			}
		else
			remapped_globals.push_back(-1);
		}

	globalsI = used_globals;

	// Gulp - now rewrite every instruction to update its slot usage.
	// In the process, if an instruction becomes a direct assignment
	// of <slot-n> = <slot-n>, then we remove it.

	int n1_slots = frame1_to_frame2.size();

	for ( unsigned int i = 0; i < insts1.size(); ++i )
		{
		auto inst = insts1[i];

		if ( ! inst->live )
			continue;

		if ( inst->AssignsToSlot1() )
			{
			auto v1 = inst->v1;
			ASSERT(v1 >= 0 && v1 < n1_slots);
			inst->v1 = frame1_to_frame2[v1];
			}

		// Handle special cases.
		switch ( inst->op ) {
		case OP_NEXT_TABLE_ITER_VV:
		case OP_NEXT_TABLE_ITER_VAL_VAR_VVV:
			{
			// Rewrite iteration variables.
			auto iter_vars = inst->aux->iter_info;
			for ( auto& v : iter_vars->loop_vars )
				{
				ASSERT(v >= 0 && v < n1_slots);
				v = frame1_to_frame2[v];
				}
			}
			break;

		case OP_DIRTY_GLOBAL_V:
			{
			// Slot v1 of this is an index into globals[]
			// rather than a frame.
			int g = inst->v1;
			ASSERT(remapped_globals[g] >= 0);
			inst->v1 = remapped_globals[g];

			// We *don't* want to UpdateSlots below as
			// that's based on interpreting v1 as slots
			// rather than an index into globals
			continue;
			}

		default:
			// Update slots in auxiliary information.
			auto aux = inst->aux;
			if ( ! aux || ! aux->slots )
				break;

			for ( auto j = 0; j < aux->n; ++j )
				{
				auto& slot = aux->slots[j];

				if ( slot < 0 )
					continue;

				slot = frame1_to_frame2[slot];
				}
			break;
		}

		if ( inst->IsGlobalLoad() )
			{
			// Slot v2 of these is the index into globals[]
			// rather than a frame.
			int g = inst->v2;
			ASSERT(remapped_globals[g] >= 0);
			inst->v2 = remapped_globals[g];

			// We *don't* want to UpdateSlots below as
			// that's based on interpreting v2 as slots
			// rather than an index into globals.
			continue;
			}

		inst->UpdateSlots(frame1_to_frame2);

		if ( inst->IsDirectAssignment() && inst->v1 == inst->v2 )
			KillInst(inst);
		}

	frame_sizeI = shared_frame_denizens.size();
	}

void ZAM::ReMapInterpreterFrame()
	{
	// First, track function parameters.  We could elide this
	// if we decide to alter the calling sequence for compiled
	// functions.
	auto args = scope->OrderedVars();
	auto nparam = func->FType()->Args()->NumFields();
	int next_interp_slot = 0;

	for ( const auto& a : args )
		{
		if ( --nparam < 0 )
			break;

		ASSERT(a->Offset() == next_interp_slot);
		++next_interp_slot;
		}

	// Update frame sizes for functions that might have more than
	// one body.
	if ( remapped_intrp_frame_sizes.count(func) == 0 ||
	     remapped_intrp_frame_sizes[func] < next_interp_slot )
		remapped_intrp_frame_sizes[func] = next_interp_slot;
	}

void ZAM::ReMapVar(ID* id, int slot, int inst)
	{
	// A greedy algorithm for this is to simply find the first suitable
	// frame slot.  We do that with one twist: we also look for a
	// compatible slot for which its current end-of-scope is exactly
	// the start-of-scope for the new identifier.  The advantage of
	// doing so is that this commonly occurs for code like "a.1 = a"
	// from resolving parameters to inlined functions, and if "a.1" and
	// "a" share the same slot then we can elide the assignment.
	//
	// In principle we could perhaps do better than greedy using a more
	// powerful allocation method like graph coloring.  However, far and
	// away the bulk of our variables are short-lived temporaries,
	// for which greedy should work fine.
	bool is_managed = IsManagedType(id->Type());

	int apt_slot = -1;
	for ( unsigned int i = 0; i < shared_frame_denizens.size(); ++i )
		{
		auto& s = shared_frame_denizens[i];

		// Note that the following test is <= rather than <.
		// This is because assignment in instructions happens
		// after using any variables to compute the value
		// to assign.  ZAM instructions are careful to
		// allow operands and assignment destinations to
		// refer to the same slot.

		if ( s.scope_end <= inst && s.is_managed == is_managed )
			{
			// It's compatible.

			if ( s.scope_end == inst )
				{
				// It ends right on the money.
				apt_slot = i;
				break;
				}

			else if ( apt_slot < 0 )
				// We haven't found a candidate yet, take
				// this one, but keep looking.
				apt_slot = i;
			}
		}

	int scope_end = denizen_ending[slot]->inst_num;

	if ( apt_slot < 0 )
		{
		// No compatible existing slot.  Create a new one.
		apt_slot = shared_frame_denizens.size();

		FrameSharingInfo info;
		info.is_managed = is_managed;
		shared_frame_denizens.push_back(info);

		if ( is_managed )
			managed_slotsI.push_back(apt_slot);
		}

	auto& s = shared_frame_denizens[apt_slot];

	s.ids.push_back(id);
	s.id_start.push_back(inst);
	s.scope_end = scope_end;

	frame1_to_frame2[slot] = apt_slot;
	}

void ZAM::CheckSlotAssignment(int slot, const ZInstI* inst)
	{
	ASSERT(slot >= 0 && slot < frame_denizens.size());

	// We construct temporaries such that their values are never
	// used earlier than their definitions in loop bodies.  For
	// other denizens, however, they can be, so in those cases
	// we expand the lifetime beginning to the start of any loop
	// region.
	if ( ! reducer->IsTemporary(frame_denizens[slot]) )
		inst = BeginningOfLoop(inst, 1);

	SetLifetimeStart(slot, inst);
	}

void ZAM::SetLifetimeStart(int slot, const ZInstI* inst)
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
			std::unordered_set<ID*> denizens;
			inst_beginnings[inst] = denizens;
			}

		inst_beginnings[inst].insert(frame_denizens[slot]);
		}
	}

void ZAM::CheckSlotUse(int slot, const ZInstI* inst)
	{
	if ( slot < 0 )
		return;

	ASSERT(slot < frame_denizens.size());

	// See comment above about temporaries not having their values
	// extend around loop bodies.  HOWEVER if a temporary is
	// defined at a lower loop depth than that for this instruction,
	// then we extend its lifetime to the end of this instruction's
	// loop.
	if ( reducer->IsTemporary(frame_denizens[slot]) )
		{
		ASSERT(denizen_beginning.count(slot) > 0);
		int definition_depth = denizen_beginning[slot]->loop_depth;

		if ( inst->loop_depth > definition_depth )
			inst = EndOfLoop(inst, inst->loop_depth);
		}
	else
		inst = EndOfLoop(inst, 1);

	ExtendLifetime(slot, inst);
	}

void ZAM::ExtendLifetime(int slot, const ZInstI* inst)
	{
	if ( denizen_ending.count(slot) > 0 )
		{
		// End of denizen's lifetime already seen.  Check for
		// consistency and then extend as needed.

		auto old_inst = denizen_ending[slot];

		// Don't complain for temporaries that already have
		// extended lifetimes, as that can happen if they're
		// used as a "for" loop-over target, which already
		// extends lifetime across the body of the loop.
		if ( inst->loop_depth > 0 &&
		     reducer->IsTemporary(frame_denizens[slot]) &&
		     old_inst->inst_num >= inst->inst_num )
			return;

		// We expect to only be extending the slot's lifetime ...
		// *unless* we're inside a nested loop, in which case 
		// the slot might have already been extended to the
		// end of the outer loop.
		ASSERT(old_inst->inst_num <= inst->inst_num ||
			inst->loop_depth > 1);

		if ( old_inst->inst_num < inst->inst_num )
			{
			// Extend.
			inst_endings[old_inst].erase(frame_denizens[slot]);

			if ( inst_endings.count(inst) == 0 )
				{
				std::unordered_set<ID*> denizens;
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
			std::unordered_set<ID*> denizens;
			inst_endings[inst] = denizens;
			}

		inst_endings[inst].insert(frame_denizens[slot]);
		}
	}

const ZInstI* ZAM::BeginningOfLoop(const ZInstI* inst, int depth) const
	{
	auto i = inst->inst_num;

	while ( i >= 0 && insts1[i]->loop_depth >= depth )
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

const ZInstI* ZAM::EndOfLoop(const ZInstI* inst, int depth) const
	{
	auto i = inst->inst_num;

	while ( i < int(insts1.size()) && insts1[i]->loop_depth >= depth )
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
	for ( unsigned int i = 0; i < insts1.size(); ++i )
		{
		auto& inst = insts1[i];
		if ( inst->live && VarIsAssigned(slot, inst) )
			return true;
		}

	return false;
	}

bool ZAM::VarIsAssigned(int slot, const ZInstI* i) const
	{
	// Special-case for table iterators, which assign to a bunch
	// of variables but they're not immediately visible in the
	// instruction layout.
	if ( i->op == OP_NEXT_TABLE_ITER_VAL_VAR_VVV ||
	     i->op == OP_NEXT_TABLE_ITER_VV )
		{
		auto iter_vars = i->aux->iter_info;
		for ( auto v : iter_vars->loop_vars )
			if ( v == slot )
				return true;

		if ( i->op != OP_NEXT_TABLE_ITER_VAL_VAR_VVV )
			return false;

		// Otherwise fall through, since that flavor of iterate
		// *does* also assign to slot 1.
		}

	if ( i->op_type == OP_VV_FRAME )
		// We don't want to consider these as assigning to the
		// variable, since the point of this method is to figure
		// out which variables don't need storing to the frame
		// because their internal value is never modified.
		return false;

	return i->AssignsToSlot1() && i->v1 == slot;
	}

bool ZAM::VarIsUsed(int slot) const
	{
	for ( unsigned int i = 0; i < insts1.size(); ++i )
		{
		auto& inst = insts1[i];
		if ( inst->live && inst->UsesSlot(slot) )
			return true;

		auto aux = inst->aux;
		if ( aux && aux->slots )
			{
			for ( int j = 0; j < aux->n; ++j )
				if ( aux->slots[j] == slot )
					return true;
			}
		}

	return false;
	}

void ZAM::KillInst(ZInstI* i)
	{
	i->live = false;
	if ( i->target )
		--(i->target->num_labels);
	if ( i->target2 )
		--(i->target2->num_labels);
	}

ZInstI* ZAM::FindLiveTarget(ZInstI* goto_target)
	{
	if ( goto_target == pending_inst )
		return goto_target;

	int idx = goto_target->inst_num;
	ASSERT(idx >= 0 && idx <= insts1.size());

	while ( idx < int(insts1.size()) && ! insts1[idx]->live )
		++idx;

	if ( idx == int(insts1.size()) )
		return pending_inst;
	else
		return insts1[idx];
	}

void ZAM::RetargetBranch(ZInstI* inst, ZInstI* target, int target_slot)
	{
	int t;	// instruction number of target

	if ( target == pending_inst )
		t = insts2.size();
	else
		t = target->inst_num;

	switch ( target_slot ) {
	case 1:	inst->v1 = t; break;
	case 2:	inst->v2 = t; break;
	case 3:	inst->v3 = t; break;
	case 4:	inst->v4 = t; break;

	default:
		reporter->InternalError("bad GoTo target");
	}
	}
