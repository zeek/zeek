// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ScriptProfile.h"

namespace zeek
	{

namespace detail
	{

void ScriptProfile::StartActivation()
	{
	NewCall();

	uint64_t start_memory;
	util::get_memory_usage(&start_memory, nullptr);
	start_stats.SetStats(util::curr_CPU_time(), start_memory);
	}

void ScriptProfile::EndActivation(const std::string& stack)
	{
	uint64_t end_memory;
	util::get_memory_usage(&end_memory, nullptr);

	delta_stats.SetStats(util::curr_CPU_time() - start_stats.CPUTime(),
	                     end_memory - start_stats.Memory());

	AddIn(&delta_stats, false, stack);
	}

void ScriptProfile::ChildFinished(const ScriptProfile* child)
	{
	child_stats.AddIn(child->DeltaCPUTime(), child->DeltaMemory());
	}

void ScriptProfile::Report(FILE* f, bool with_traces) const
	{
	std::string l;

	if ( loc.first_line == 0 )
		// Rather than just formatting the no-location loc, we'd like
		// a version that doesn't have a funky "line 0" in it, nor
		// an embedded blank.
		l = "<no-location>";
	else
		l = std::string(loc.filename) + ":" + std::to_string(loc.first_line);

	std::string ftype = is_BiF ? "BiF" : func->GetType()->FlavorString();
	std::string call_stacks;

	if ( with_traces )
		{
		std::string calls, counts, cpu, memory;

		for ( const auto& [s, stats] : Stacks() )
			{
			calls += util::fmt("%s|", s.c_str());
			counts += util::fmt("%d|", stats.call_count);
			cpu += util::fmt("%f|", stats.cpu_time);
			memory += util::fmt("%" PRIu64 "|", stats.memory);
			}

		calls.pop_back();
		counts.pop_back();
		cpu.pop_back();
		memory.pop_back();

		call_stacks = util::fmt("\t%s\t%s\t%s\t%s", calls.c_str(), counts.c_str(), cpu.c_str(),
		                        memory.c_str());
		}

	fprintf(f, "%s\t%s\t%s\t%d\t%.06f\t%.06f\t%" PRIu64 "\t%" PRIu64 "\t%s\n", Name().c_str(),
	        l.c_str(), ftype.c_str(), NumCalls(), CPUTime(), child_stats.CPUTime(), Memory(),
	        child_stats.Memory(), call_stacks.c_str());
	}

void ScriptProfileStats::AddIn(const ScriptProfileStats* eps, bool bump_num_calls,
                               const std::string& stack)
	{
	if ( bump_num_calls )
		ncalls += eps->NumCalls();

	CPU_time += eps->CPUTime();
	memory += eps->Memory();

	if ( ! stack.empty() )
		{
		auto& data = stacks[stack];
		data.call_count++;
		data.cpu_time += eps->CPUTime();
		data.memory += eps->Memory();
		}
	}

ScriptProfileMgr::ScriptProfileMgr(FILE* _f) : f(_f), non_scripts()
	{
	non_scripts.StartActivation();
	}

ScriptProfileMgr::~ScriptProfileMgr()
	{
	ASSERT(call_stack.empty());

	non_scripts.EndActivation();

	ScriptProfileStats total_stats;
	ScriptProfileStats BiF_stats;
	std::unordered_map<const Func*, ScriptProfileStats> func_stats;

	std::string call_stack_header;
	std::string call_stack_types;
	std::string call_stack_nulls;

	if ( with_traces )
		{
		call_stack_header = "\tstacks\tstack_calls\tstack_CPU\tstack_memory";
		call_stack_types = "\tstring\tstring\tstring\tstring";
		call_stack_nulls = "\t-\t-\t-\t-";
		}

	fprintf(f,
	        "#fields\tfunction\tlocation\ttype\tncall\ttot_CPU\tchild_CPU\ttot_Mem\tchild_"
	        "Mem%s\n",
	        call_stack_header.c_str());
	fprintf(f, "#types\tstring\tstring\tstring\tcount\tinterval\tinterval\tcount\tcount%s\n",
	        call_stack_types.c_str());

	for ( auto o : objs )
		{
		auto p = profiles[o].get();
		profiles[o]->Report(f, with_traces);

		total_stats.AddInstance();
		total_stats.AddIn(p);

		if ( p->IsBiF() )
			{
			BiF_stats.AddInstance();
			BiF_stats.AddIn(p);
			}
		else
			{
			ASSERT(body_to_func.count(o) > 0);
			auto func = body_to_func[o];

			if ( func_stats.count(func) == 0 )
				func_stats[func] = ScriptProfileStats(func->Name());

			func_stats[func].AddIn(p);
			}
		}

	for ( auto& fs : func_stats )
		{
		auto func = fs.first;
		auto& fp = fs.second;
		auto n = func->GetBodies().size();
		if ( n > 1 )
			fprintf(f, "%s\t%zu-locations\t%s\t%d\t%.06f\t%0.6f\t%" PRIu64 "\t%lld%s\n",
			        fp.Name().c_str(), n, func->GetType()->FlavorString().c_str(), fp.NumCalls(),
			        fp.CPUTime(), 0.0, fp.Memory(), 0LL, call_stack_nulls.c_str());
		}

	fprintf(f, "all-BiFs\t%d-locations\tBiF\t%d\t%.06f\t%.06f\t%" PRIu64 "\t%lld%s\n",
	        BiF_stats.NumInstances(), BiF_stats.NumCalls(), BiF_stats.CPUTime(), 0.0,
	        BiF_stats.Memory(), 0LL, call_stack_nulls.c_str());

	fprintf(f, "total\t%d-locations\tTOTAL\t%d\t%.06f\t%.06f\t%" PRIu64 "\t%lld%s\n",
	        total_stats.NumInstances(), total_stats.NumCalls(), total_stats.CPUTime(), 0.0,
	        total_stats.Memory(), 0LL, call_stack_nulls.c_str());

	fprintf(f, "non-scripts\t<no-location>\tTOTAL\t%d\t%.06f\t%.06f\t%" PRIu64 "\t%lld%s\n",
	        non_scripts.NumCalls(), non_scripts.CPUTime(), 0.0, non_scripts.Memory(), 0LL,
	        call_stack_nulls.c_str());

	if ( f != stdout )
		fclose(f);
	}

void ScriptProfileMgr::StartInvocation(const Func* f, const detail::StmtPtr& body)
	{
	if ( call_stack.empty() )
		non_scripts.EndActivation();

	const Obj* o = body ? static_cast<Obj*>(body.get()) : f;
	auto associated_prof = profiles.find(o);
	ScriptProfile* ep;

	if ( associated_prof == profiles.end() )
		{
		auto new_ep = std::make_unique<ScriptProfile>(f, body);
		ep = new_ep.get();
		profiles[o] = std::move(new_ep);
		objs.push_back(o);

		if ( body )
			body_to_func[o] = f;
		}
	else
		ep = associated_prof->second.get();

	ep->StartActivation();
	call_stack.push_back(ep);
	}

void ScriptProfileMgr::EndInvocation()
	{
	ASSERT(! call_stack.empty());
	auto ep = call_stack.back();

	call_stack.pop_back();

	std::string stack_string = ep->Name();
	for ( const auto& sep : call_stack )
		{
		stack_string.append(";");
		stack_string.append(sep->Name());
		}

	ep->EndActivation(stack_string);

	if ( call_stack.empty() )
		non_scripts.StartActivation();
	else
		{
		auto parent = call_stack.back();
		parent->ChildFinished(ep);
		}
	}

std::unique_ptr<ScriptProfileMgr> spm;

	} // namespace zeek::detail

void activate_script_profiling(const char* fn, bool with_traces)
	{
	FILE* f;

	if ( fn )
		{
		f = fopen(fn, "w");
		if ( ! f )
			{
			fprintf(stderr, "ERROR: Can't open %s to record scripting profile\n", fn);
			exit(1);
			}
		}
	else
		f = stdout;

	detail::spm = std::make_unique<detail::ScriptProfileMgr>(f);

	if ( with_traces )
		detail::spm->EnableTraces();
	}

	} // namespace zeek
