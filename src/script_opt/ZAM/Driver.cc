// See the file "COPYING" in the main distribution directory for copyright.

// Driver (and other high-level) methods for ZAM compilation.

#include "zeek/CompHash.h"
#include "zeek/RE.h"
#include "zeek/Frame.h"
#include "zeek/module_util.h"
#include "zeek/Scope.h"
#include "zeek/Reporter.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/ZAM/Compile.h"


namespace zeek::detail {


ZAMCompiler::ZAMCompiler(ScriptFunc* f, std::shared_ptr<ProfileFunc> _pf,
                         ScopePtr _scope, StmtPtr _body,
                         std::shared_ptr<UseDefs> _ud,
                         std::shared_ptr<Reducer> _rd)
	{
	func = f;
	pf = std::move(_pf);
	scope = std::move(_scope);
	body = std::move(_body);
	ud = std::move(_ud);
	reducer = std::move(_rd);
	frame_sizeI = 0;

	Init();
	}

void ZAMCompiler::Init()
	{
	InitGlobals();
	InitArgs();
	InitLocals();

#if 0
	// Complain about unused aggregates ... but not if we're inlining,
	// as that can lead to optimizations where they wind up being unused
	// but the original logic for using them was sound.
	if ( ! analysis_options.inliner )
		for ( auto a : pf->Inits() )
			{
			if ( pf->Locals().find(a) == pf->Locals().end() )
				reporter->Warning("%s unused", a->Name());
			}
#endif

	TrackMemoryManagement();

	non_recursive = non_recursive_funcs.count(func) > 0;
	}

void ZAMCompiler::InitGlobals()
	{
	for ( auto g : pf->Globals() )
		{
		auto non_const_g = const_cast<ID*>(g);

		GlobalInfo info;
		info.id = {NewRef{}, non_const_g};
		info.slot = AddToFrame(non_const_g);
		global_id_to_info[non_const_g] = globalsI.size();
		globalsI.push_back(info);
		}
	}

void ZAMCompiler::InitArgs()
	{
	auto uds = ud->HasUsage(body.get()) ? ud->GetUsage(body.get()) :
	                                      nullptr;

	auto args = scope->OrderedVars();
	int nparam = func->GetType()->Params()->NumFields();

	push_existing_scope(scope);

	for ( auto& a : args )
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
	}

void ZAMCompiler::InitLocals()
	{
	// Assign slots for locals (which includes temporaries).
	for ( auto l : pf->Locals() )
		{
		auto non_const_l = const_cast<ID*>(l);
		// Don't add locals that were already added because they're
		// parameters.
		//
		// Don't worry about unused variables, those will get
		// removed during low-level ZAM optimization.
		if ( ! HasFrameSlot(non_const_l) )
			(void) AddToFrame(non_const_l);
		}
	}

void ZAMCompiler::TrackMemoryManagement()
	{
	for ( auto& slot : frame_layout1 )
		{
		// Look for locals with values of types for which
		// we do explicit memory management on (re)assignment.
		auto t = slot.first->GetType();
		if ( ZVal::IsManagedType(t) )
			managed_slotsI.push_back(slot.second);
		}
	}

StmtPtr ZAMCompiler::CompileBody()
	{
	curr_stmt = nullptr;

	if ( func->Flavor() == FUNC_FLAVOR_HOOK )
		PushBreaks();

	(void) CompileStmt(body);

	if ( reporter->Errors() > 0 )
		return nullptr;

	ResolveHookBreaks();

	if ( ! nexts.empty() )
		reporter->Error("\"next\" used without an enclosing \"for\"");

	if ( ! fallthroughs.empty() )
		reporter->Error("\"fallthrough\" used without an enclosing \"switch\"");

	if ( ! catches.empty() )
		reporter->InternalError("untargeted inline return");

	// Make sure we have a (pseudo-)instruction at the end so we
	// can use it as a branch label.
	if ( ! pending_inst )
		pending_inst = new ZInstI();

	// Concretize instruction numbers in inst1 so we can
	// easily move through the code.
	for ( auto i = 0U; i < insts1.size(); ++i )
		insts1[i]->inst_num = i;

	ComputeLoopLevels();

	if ( ! analysis_options.no_ZAM_opt )
		OptimizeInsts();

	AdjustBranches();

	// Construct the final program with the dead code eliminated
	// and branches resolved.

	// Make sure we don't include the empty pending-instruction, if any.
	if ( pending_inst )
		pending_inst->live = false;

	// Maps inst1 instructions to where they are in inst2.
	// Dead instructions map to -1.
	std::vector<int> inst1_to_inst2;

	for ( auto& i1 : insts1 )
		{
		if ( i1->live )
			{
			inst1_to_inst2.push_back(insts2.size());
			insts2.push_back(i1);
			}
		else
			inst1_to_inst2.push_back(-1);
		}

	// Re-concretize instruction numbers, and concretize GoTo's.
	for ( auto i = 0U; i < insts2.size(); ++i )
		insts2[i]->inst_num = i;

	RetargetBranches();

	// If we have remapped frame denizens, update them.  If not,
	// create them.
	if ( ! shared_frame_denizens.empty() )
		RemapFrameDenizens(inst1_to_inst2);

	else
		CreateSharedFrameDenizens();

	delete pending_inst;

	ConcretizeSwitches();

	// Could erase insts1 here to recover memory, but it's handy
	// for debugging.

#if 0
	if ( non_recursive )
		func->UseStaticFrame();
#endif

	auto zb = make_intrusive<ZBody>(func->Name(), this);
	zb->SetInsts(insts2);

	return zb;
	}

void ZAMCompiler::ResolveHookBreaks()
	{
	if ( ! breaks.empty() )
		{
		ASSERT(breaks.size() == 1);

		if ( func->Flavor() == FUNC_FLAVOR_HOOK )
			{
			// Rewrite the breaks.
			for ( auto& b : breaks[0] )
				{
				auto& i = insts1[b.stmt_num];
				delete i;
				i = new ZInstI(OP_HOOK_BREAK_X);
				}
			}

		else
			reporter->Error("\"break\" used without an enclosing \"for\" or \"switch\"");
		}
	}

void ZAMCompiler::ComputeLoopLevels()
	{
	// Compute which instructions are inside loops.
	for ( auto i = 0; i < int(insts1.size()); ++i )
		{
		auto inst = insts1[i];

		auto t = inst->target;
		if ( ! t || t == pending_inst )
			continue;

		if ( t->inst_num < i )
			{
			auto j = t->inst_num;

			if ( ! t->loop_start )
				{
				// Loop is newly discovered.
				t->loop_start = true;
				}
			else
				{
				// We're extending an existing loop.  Find
				// its current end.
				auto depth = t->loop_depth;
				while ( j < i &&
				        insts1[j]->loop_depth == depth )
					++j;

				ASSERT(insts1[j]->loop_depth == depth - 1);
				}

			// Run from j's current position to i, bumping
			// the loop depth.
			while ( j <= i )
				{
				++insts1[j]->loop_depth;
				++j;
				}
			}
		}
	}

void ZAMCompiler::AdjustBranches()
	{
	// Move branches to dead code forward to their successor live code.
	for ( auto& inst : insts1 )
		{
		if ( ! inst->live )
			continue;

		if ( auto t = inst->target )
			inst->target = FindLiveTarget(t);
		}
	}

void ZAMCompiler::RetargetBranches()
	{
	for ( auto& inst : insts2 )
		if ( inst->target )
			ConcretizeBranch(inst, inst->target, inst->target_slot);
	}

void ZAMCompiler::RemapFrameDenizens(const std::vector<int>& inst1_to_inst2)
	{
	for ( auto& info : shared_frame_denizens )
		{
		for ( auto& start : info.id_start )
			{
			// It can happen that the identifier's
			// origination instruction was optimized
			// away, if due to slot sharing it's of
			// the form "slotX = slotX".  In that
			// case, look forward for the next viable
			// instruction.
			while ( start < int(insts1.size()) &&
				inst1_to_inst2[start] == -1 )
				++start;

			ASSERT(start < insts1.size());
			start = inst1_to_inst2[start];
			}

		shared_frame_denizens_final.push_back(info);
		}
	}

void ZAMCompiler::CreateSharedFrameDenizens()
	{
	for ( auto& fd : frame_denizens )
		{
		FrameSharingInfo info;
		info.ids.push_back(fd);
		info.id_start.push_back(0);
		info.scope_end = insts2.size();

		// The following doesn't matter since the value
		// is only used during compiling, not during
		// execution.
		info.is_managed = false;

		shared_frame_denizens_final.push_back(info);
		}
	}

void ZAMCompiler::ConcretizeSwitches()
	{
	// Create concretized versions of any case tables.
	ConcretizeSwitchTables(int_casesI, int_cases);
	ConcretizeSwitchTables(uint_casesI, uint_cases);
	ConcretizeSwitchTables(double_casesI, double_cases);
	ConcretizeSwitchTables(str_casesI, str_cases);
	}

template <typename T>
void ZAMCompiler::ConcretizeSwitchTables(const CaseMapsI<T>& abstract_cases,
			                 CaseMaps<T>& concrete_cases)
	{
	for ( auto& targs : abstract_cases )
		{
		CaseMap<T> cm;
		for ( auto& targ : targs )
			cm[targ.first] = targ.second->inst_num;
		concrete_cases.emplace_back(cm);
		}
	}


#include "ZAM-MethodDefs.h"


void ZAMCompiler::Dump()
	{
	bool remapped_frame = ! analysis_options.no_ZAM_opt;

	if ( remapped_frame )
		printf("Original frame for %s:\n", func->Name());

	for ( auto elem : frame_layout1 )
		printf("frame[%d] = %s\n", elem.second, elem.first->Name());

	if ( remapped_frame )
		{
		printf("Final frame for %s:\n", func->Name());

		for ( auto i = 0U; i < shared_frame_denizens.size(); ++i )
			{
			printf("frame2[%d] =", i);
			for ( auto& id : shared_frame_denizens[i].ids )
				printf(" %s", id->Name());
			printf("\n");
			}
		}

	if ( ! insts2.empty() )
		printf("Pre-removal of dead code for %s:\n", func->Name());

	auto remappings = remapped_frame ? &shared_frame_denizens : nullptr;

	DumpInsts1(remappings);

	if ( ! insts2.empty() )
		printf("Final intermediary code for %s:\n", func->Name());

	remappings = remapped_frame ? &shared_frame_denizens_final : nullptr;

	for ( auto i = 0U; i < insts2.size(); ++i )
		{
		auto& inst = insts2[i];
		std::string liveness, depth;

		if ( inst->live )
			liveness = util::fmt("(labels %d)", inst->num_labels);
		else
			liveness = "(dead)";

		if ( inst->loop_depth )
			depth = util::fmt(" (loop %d)", inst->loop_depth);

		printf("%d %s%s: ", i, liveness.c_str(), depth.c_str());

		inst->Dump(&frame_denizens, remappings);
		}

	if ( ! insts2.empty() )
		printf("Final code for %s:\n", func->Name());

	for ( auto i = 0U; i < insts2.size(); ++i )
		{
		auto& inst = insts2[i];
		printf("%d: ", i);
		inst->Dump(&frame_denizens, remappings);
		}

	DumpCases(int_casesI, "int");
	DumpCases(uint_casesI, "uint");
	DumpCases(double_casesI, "double");
	DumpCases(str_casesI, "str");
	}

template <typename T>
void ZAMCompiler::DumpCases(const T& cases, const char* type_name) const
	{
	for ( auto i = 0U; i < cases.size(); ++i )
		{
		printf("%s switch table #%d:", type_name, i);
		for ( auto& m : cases[i] )
			{
			std::string case_val;
			if constexpr ( std::is_same_v<T, std::string> )
				case_val = m.first;
			else if constexpr ( std::is_same_v<T, bro_int_t> ||
			                    std::is_same_v<T, bro_uint_t> ||
			                    std::is_same_v<T, double> )
				case_val = std::to_string(m.first);

			printf(" %s->%d", case_val.c_str(), m.second->inst_num);
			}
		printf("\n");
		}
	}

void ZAMCompiler::DumpInsts1(const FrameReMap* remappings)
	{
	for ( auto i = 0U; i < insts1.size(); ++i )
		{
		auto& inst = insts1[i];

		if ( inst->target )
			// To get meaningful branch information in the dump,
			// we need to concretize the branch slots
                        ConcretizeBranch(inst, inst->target, inst->target_slot);

		std::string liveness, depth;

		if ( inst->live )
			liveness = util::fmt("(labels %d)", inst->num_labels);
		else
			liveness = "(dead)";

		if ( inst->loop_depth )
			depth = util::fmt(" (loop %d)", inst->loop_depth);

		printf("%d %s%s: ", i, liveness.c_str(), depth.c_str());

		inst->Dump(&frame_denizens, remappings);
		}
	}


} // zeek::detail
