// See the file "COPYING" in the main distribution directory for copyright.

// Classes for profiling CPU & memory usage by scripts.

#pragma once

#include <string>

#include "zeek/Func.h"
#include "zeek/Stmt.h"

namespace zeek
	{

namespace detail
	{

// Base class for tracking an instance of profile information.  The instance
// can be a single function body (equivalently, event handler or hook body),
// or an aggregate that includes multiple function bodies.

class ScriptProfileStats
	{
public:
	ScriptProfileStats() = default;
	ScriptProfileStats(std::string arg_name) : name(std::move(arg_name)) { }

	virtual ~ScriptProfileStats() = default;

	ScriptProfileStats(ScriptProfileStats&&) = default;
	ScriptProfileStats(const ScriptProfileStats&) = default;

	ScriptProfileStats& operator=(ScriptProfileStats&&) = default;
	ScriptProfileStats& operator=(const ScriptProfileStats&) = default;

	const auto Name() const { return name; }

	// Number of instances included in an aggregate (like for "all BiFs").
	// This is 1 for non-aggregates.
	int NumInstances() const { return ninstances; }

	// How many calls were profiled for this instance.
	int NumCalls() const { return ncalls; }

	// CPU & memory accumulated by the calls.
	double CPUTime() const { return CPU_time; }
	uint64_t Memory() const { return memory; }

	// Used to count instances in an aggregate.
	void AddInstance() { ++ninstances; }

	// Fold into this profile another profile.  Second argument controls
	// whether the folding should include increasing the number of calls.
	void AddIn(const ScriptProfileStats* eps, bool bump_num_calls = true)
		{
		if ( bump_num_calls )
			ncalls += eps->NumCalls();

		CPU_time += eps->CPUTime();
		memory += eps->Memory();
		}

	// Accumulate a single instance of CPU & memory usage.
	void AddIn(double delta_CPU_time, uint64_t delta_memory)
		{
		CPU_time += delta_CPU_time;
		memory += delta_memory;
		}

	// Directly specify the total CPU & memory usage.
	void SetStats(double arg_CPU_time, uint64_t arg_memory)
		{
		CPU_time = arg_CPU_time;
		memory = arg_memory;
		}

	// Track that the instance has had another call.
	void NewCall() { ++ncalls; }

private:
	std::string name;
	int ninstances = 0;
	int ncalls = 0;
	double CPU_time = 0.0;
	uint64_t memory = 0;
	};

// Manages all of the profile instances associated with a given script.

class ScriptProfile : public ScriptProfileStats
	{
public:
	ScriptProfile(const Func* _func, const detail::StmtPtr& body)
		: ScriptProfileStats(_func->Name())
		{
		func = {NewRef{}, const_cast<Func*>(_func)};
		is_BiF = body == nullptr;

		if ( is_BiF )
			loc = *func->GetLocationInfo();
		else
			loc = *body->GetLocationInfo();
		}

	// Constructor used for the special case of non-script accounting.
	ScriptProfile() : ScriptProfileStats("non-scripts")
		{
		func = nullptr;
		is_BiF = false;
		}

	// Called to register the beginning/end of an execution instance.
	void StartActivation();
	void EndActivation();

	// Called when a child instance finishes.
	void ChildFinished(const ScriptProfile* child);

	bool IsBiF() const { return is_BiF; }
	double DeltaCPUTime() const { return delta_stats.CPUTime(); }
	uint64_t DeltaMemory() const { return delta_stats.Memory(); }

	// Write the profile to the given file.
	void Report(FILE* f) const;

private:
	// We store "func" as a FuncPtr to ensure it sticks around when
	// it would otherwise be ephemeral (i.e., for lambdas).
	FuncPtr func;
	bool is_BiF;
	detail::Location loc;

	// Profile associated with child instances (functions or hooks
	// that this instance calls - does not include events that this
	// instance generates).
	ScriptProfileStats child_stats;

	// These are ephemeral, only relevant between Start and End activations.
	ScriptProfileStats start_stats;

	// Defined for the last activation period.
	ScriptProfileStats delta_stats;
	};

// Manages the entire script profiling process.
class ScriptProfileMgr
	{
public:
	// Argument specifies the file to write the profile to.
	ScriptProfileMgr(FILE* f);

	// Destructor generates the actual profile.
	~ScriptProfileMgr();

	// Mark that the given function body has begun/finished.  "body" is
	// nil for BiFs.
	void StartInvocation(const Func* f, const detail::StmtPtr& body = nullptr);
	void EndInvocation();

private:
	FILE* f; // where to write the profile

	// Separate "script" profile that tracks resource impact of non-script
	// execution.
	ScriptProfile non_scripts;

	// Currently active instances.
	std::vector<ScriptProfile*> call_stack;

	// Maps a given object (either a function body, for scripts, or the
	// function itself, for BiFs) to its profile.
	std::unordered_map<const Obj*, std::unique_ptr<ScriptProfile>> profiles;

	// Maps script bodies to their function - used for functions with
	// multiple bodies.
	std::unordered_map<const Obj*, const Func*> body_to_func;

	// Tracks the objects encountered.  Used to generate a consistent
	// and more natural printing order.
	std::vector<const Obj*> objs;
	};

// If non-nil, script profiling is active.
extern std::unique_ptr<ScriptProfileMgr> spm;

	} // namespace zeek::detail

// Called to turn on script profiling to the given file.  If nil, writes
// the profile to stdout.
extern void activate_script_profiling(const char* fn);

	} // namespace zeek
