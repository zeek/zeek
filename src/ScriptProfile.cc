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

void ScriptProfile::EndActivation()
	{
	uint64_t end_memory;
	util::get_memory_usage(&end_memory, nullptr);

	delta_stats.SetStats(util::curr_CPU_time() - start_stats.CPUTime(),
	                     end_memory - start_stats.Memory());

	AddIn(&delta_stats, false);
	}

void ScriptProfile::ChildFinished(const ScriptProfile* child)
	{
	child_stats.AddIn(child->DeltaCPUTime(), child->DeltaMemory());
	}

void ScriptProfile::Report(FILE* f) const
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

	fprintf(f, "%s\t%s\t%s\t%d\t%.06f\t%.06f\t%" PRIu64 "\t%" PRIu64 "\n", Name().c_str(),
	        l.c_str(), ftype.c_str(), NumCalls(), CPUTime(), child_stats.CPUTime(), Memory(),
	        child_stats.Memory());
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

	fprintf(f,
	        "#fields\tfunction\tlocation\ttype\tncall\ttot_CPU\tchild_CPU\ttot_Mem\tchild_Mem\n");
	fprintf(f, "#types\tstring\tstring\tstring\tcount\tinterval\tinterval\tcount\tcount\n");

	for ( auto o : objs )
		{
		auto p = profiles[o].get();
		profiles[o]->Report(f);

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
			fprintf(f, "%s\t%lu-locations\t%s\t%d\t%.06f\t%0.6f\t%" PRIu64 "\t%lld\n",
			        fp.Name().c_str(), n, func->GetType()->FlavorString().c_str(), fp.NumCalls(),
			        fp.CPUTime(), 0.0, fp.Memory(), 0LL);
		}

	fprintf(f, "all-BiFs\t%d-locations\tBiF\t%d\t%.06f\t%.06f\t%" PRIu64 "\t%lld\n",
	        BiF_stats.NumInstances(), BiF_stats.NumCalls(), BiF_stats.CPUTime(), 0.0,
	        BiF_stats.Memory(), 0LL);

	fprintf(f, "total\t%d-locations\tTOTAL\t%d\t%.06f\t%.06f\t%" PRIu64 "\t%lld\n",
	        total_stats.NumInstances(), total_stats.NumCalls(), total_stats.CPUTime(), 0.0,
	        total_stats.Memory(), 0LL);

	fprintf(f, "non-scripts\t<no-location>\tTOTAL\t%d\t%.06f\t%.06f\t%" PRIu64 "\t%lld\n",
	        non_scripts.NumCalls(), non_scripts.CPUTime(), 0.0, non_scripts.Memory(), 0LL);

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

	ep->EndActivation();

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

void activate_script_profiling(const char* fn)
	{
	FILE* f;

	if ( fn )
		{
		f = fopen(fn, "w");
		if ( ! f )
			reporter->FatalError("can't open %s to record scripting profile", fn);
		}
	else
		f = stdout;

	detail::spm = std::make_unique<detail::ScriptProfileMgr>(f);
	}

	} // namespace zeek
