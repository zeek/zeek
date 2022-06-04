// See the file "COPYING" in the main distribution directory for copyright.

// Classes for analyzing the usage of functions, hooks & events in order
// to locate any that cannot actually be invoked.

#pragma once

#include "zeek/Traverse.h"
#include "zeek/script_opt/ScriptOpt.h"

namespace zeek::detail
	{

class UsageAnalyzer : public TraversalCallback
	{
public:
	// "funcs" contains the entire set of ASTs.
	UsageAnalyzer(std::vector<FuncInfo>& funcs);

private:
	using IDSet = std::unordered_set<const ID*>;

	// Finds the set of identifiers that serve as a starting point of
	// what's-known-to-be-used.  An identifier qualifies as such if it is
	// (1) an event that was newly introduced by scripting (so, known to
	// the event engine), or (2) a function or hook that's either global
	// in scope, or exported from its module (so clearly meant for use
	// by other scripts), or (3) marked as either &is_used or &deprecated
	// (the latter as a way to flag identifiers that in fact are not used
	// and will be removed in the future).
	void FindSeeds(IDSet& seeds) const;

	// Given an identifier, return its corresponding script function,
	// or nil if that's not applicable.
	const Func* GetFuncIfAny(const ID* id) const;
	const Func* GetFuncIfAny(const IDPtr& id) const { return GetFuncIfAny(id.get()); }

	// Iteratively follows reachability across the set of reachable
	// identifiers (starting with the seeds) until there's no more to reap.
	void FullyExpandReachables();

	// Populates new_reachables with identifiers newly reachable (directly)
	// from curr_r.
	bool ExpandReachables(const IDSet& curr_r);

	// For a given identifier, populates new_reachables with new
	// identifiers directly reachable from it.
	void Expand(const ID* f);

	// Hooks into AST traversal to find reachable functions/hooks/events.
	TraversalCode PreID(const ID* id) override;

	// We traverse types, too, as their attributes can include lambdas
	// that we need to incorporate.
	TraversalCode PreType(const Type* t) override;

	// The identifiers we've currently determined are (ultimately)
	// reachable from the seeds.
	IDSet reachables;

	// Newly-reachable identifiers-of-interest.  This is a member variable
	// rather than a parameter to ExpandReachables() because the coupling
	// to populating it is indirect, via AST traversal.
	IDSet new_reachables;

	// The following are used to avoid redundant computation.  Note that
	// they differ in that the first is per-traversal, while the second
	// is global across all our analyses.  See Expand() for a discussion
	// of why the first needs to be per-traversal.

	// All of the identifiers we've analyzed during the current traversal.
	std::unordered_set<const ID*> analyzed_IDs;

	// All of the types we've analyzed to date.
	std::unordered_set<const Type*> analyzed_types;
	};

// Marks a given identifier as referring to a script-level event (one
// not previously known before its declaration in a script).
extern void register_new_event(const IDPtr& id);

	} // namespace zeek::detail
