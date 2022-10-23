// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/UsageAnalyzer.h"

#include "zeek/EventRegistry.h"
#include "zeek/module_util.h"
#include "zeek/script_opt/IDOptInfo.h"

namespace zeek::detail
	{

// The names of identifiers that correspond to events not-previously-known
// before their declaration in the scripts.
std::unordered_set<std::string> script_events;

void register_new_event(const IDPtr& id)
	{
	script_events.insert(id->Name());
	}

UsageAnalyzer::UsageAnalyzer(std::vector<FuncInfo>& funcs)
	{
	// First, prune the script events to only those that were never
	// registered in a non-script context.
	auto script_events_orig = script_events;
	script_events.clear();

	for ( auto& ev : script_events_orig )
		if ( ! event_registry->NotOnlyRegisteredFromScript(ev) )
			script_events.insert(ev);

	// Setting a scope cues ID::Traverse to delve into function values.
	current_scope = global_scope();

	FindSeeds(reachables);
	FullyExpandReachables();

	// At this point, we've done the complete reachability analysis.
	// Report out on unreachables.  We do this in two steps: first,
	// unreachable events/hooks, and then unreachable functions.  We
	// split the two because we don't want to ding a function as being
	// unreachable if there's an (unreachable) event-or-hook that calls
	// it, since presumably the real problem is the latter being an
	// orphan, rather than the function.

	auto& globals = global_scope()->Vars();

	for ( auto& gpair : globals )
		{
		auto id = gpair.second.get();
		auto& t = id->GetType();

		if ( t->Tag() != TYPE_FUNC )
			continue;

		if ( t->AsFuncType()->Flavor() == FUNC_FLAVOR_FUNCTION )
			continue;

		if ( reachables.count(id) > 0 )
			continue;

		auto flavor = t->AsFuncType()->FlavorString();
		auto loc = id->GetLocationInfo();

		id->Warn(util::fmt("handler for non-existing %s cannot be invoked", flavor.c_str()));

		// Don't ding any functions that are reachable via this
		// identifier.  This will also suppress flagging other events
		// and hooks, depending on order-of-traversal.  That seems
		// fine, as the key is to find the root of such issues.
		reachables.insert(id);
		Expand(id);
		}

	// Now make a second pass, focusing solely on functions.
	for ( auto& gpair : globals )
		{
		auto& id = gpair.second;

		if ( reachables.count(id.get()) > 0 )
			continue;

		auto f = GetFuncIfAny(id);
		if ( ! f )
			continue;

		auto loc = id->GetLocationInfo();

		id->Warn("non-exported function does not have any callers");

		// Unlike for events/hooks above, we don't add the function to
		// the reachables.  This is because an orphan function is a
		// somewhat more significant potential error than an orphan
		// event handler or hook, as the latter can arise from simple
		// typos (because there will be a declaration elsewhere that
		// they're supposed to match), whereas orphan functions in
		// general will not.
		}
	}

void UsageAnalyzer::FindSeeds(IDSet& seeds) const
	{
	for ( auto& gpair : global_scope()->Vars() )
		{
		auto& id = gpair.second;

		if ( id->GetAttr(ATTR_IS_USED) || id->GetAttr(ATTR_DEPRECATED) )
			{
			seeds.insert(id.get());
			continue;
			}

		auto f = GetFuncIfAny(id);

		if ( f && id->GetType<FuncType>()->Flavor() == FUNC_FLAVOR_EVENT )
			{
			if ( script_events.count(f->Name()) == 0 )
				seeds.insert(id.get());

			continue;
			}

		// If the global is exported, or has global scope, we assume
		// it's meant to be used, even if the current scripts don't
		// use it.
		if ( id->IsExport() || id->ModuleName() == "GLOBAL" )
			seeds.insert(id.get());
		}
	}

const Func* UsageAnalyzer::GetFuncIfAny(const ID* id) const
	{
	auto& t = id->GetType();
	if ( t->Tag() != TYPE_FUNC )
		return nullptr;

	auto fv = cast_intrusive<FuncVal>(id->GetVal());
	if ( ! fv )
		return nullptr;

	auto func = fv->Get();
	return func->GetKind() == Func::SCRIPT_FUNC ? func : nullptr;
	}

void UsageAnalyzer::FullyExpandReachables()
	{
	// We use the following structure to avoid having to copy
	// the initial set of reachables, which can be quite large.
	if ( ExpandReachables(reachables) )
		{
		auto r = new_reachables;
		reachables.insert(r.begin(), r.end());

		while ( ExpandReachables(r) )
			{
			r = new_reachables;
			reachables.insert(r.begin(), r.end());
			}
		}
	}

bool UsageAnalyzer::ExpandReachables(const IDSet& curr_r)
	{
	new_reachables.clear();

	for ( auto r : curr_r )
		Expand(r);

	return ! new_reachables.empty();
	}

void UsageAnalyzer::Expand(const ID* id)
	{
	// A subtle problem arises for exported globals that refer to functions
	// that themselves generate events.  Because for identifiers we don't
	// traverse their values (since there's no Traverse infrastructure for
	// Val classes), we can see those identifiers initially in a seeding
	// context, where we can't associate them with their functions; and
	// then again when actually analyzing that function.
	//
	// It might be tempting to special-case the seeding phase, but that
	// gets hard if the global doesn't directly refer to the function,
	// but instead ultimately incorporates a type with an attribute that
	// uses the function.  So instead we allow re-visiting of identifiers
	// and just suppress them once-per-analysis traversal (to save a bunch
	// of computation).
	analyzed_IDs.clear();

	id->Traverse(this);
	}

TraversalCode UsageAnalyzer::PreID(const ID* id)
	{
	if ( analyzed_IDs.count(id) > 0 )
		// No need to repeat the analysis.
		return TC_ABORTSTMT;

	// Mark so that we avoid redundant re-traversal.
	analyzed_IDs.insert(id);

	auto f = GetFuncIfAny(id);

	if ( f && reachables.count(id) == 0 )
		// Haven't seen this function before.
		new_reachables.insert(id);

	id->GetType()->Traverse(this);

	auto& attrs = id->GetAttrs();
	if ( attrs )
		attrs->Traverse(this);

	// Initialization expressions can have function calls or lambdas that
	// themselves link to other identifiers.
	for ( auto& ie : id->GetOptInfo()->GetInitExprs() )
		if ( ie )
			ie->Traverse(this);

	return TC_CONTINUE;
	}

TraversalCode UsageAnalyzer::PreType(const Type* t)
	{
	if ( analyzed_types.count(t) > 0 )
		return TC_ABORTSTMT;

	// Save processing by avoiding a re-traversal of this type.
	analyzed_types.insert(t);
	return TC_CONTINUE;
	}

	} // namespace zeek::detail
