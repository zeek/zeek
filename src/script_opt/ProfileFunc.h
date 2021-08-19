// See the file "COPYING" in the main distribution directory for copyright.

// Classes for traversing functions and their body ASTs to build up profiles
// of the various elements (types, globals, locals, lambdas, etc.) that appear.
// These profiles enable script optimization to make decisions regarding
// compilability and how to efficiently provide run-time components.
// For all of the following, we use the term "function" to refer to a single
// ScriptFunc/body pair, so an event handler or hook with multiple bodies
// is treated as multiple distinct "function"'s.
//
// One key element of constructing profiles concerns computing hashes over
// both the Zeek scripting types present in the functions, and over entire
// functions (which means computing hashes over each of the function's
// components).  Hashes need to be (1) distinct (collision-free in practice)
// and (2) deterministic (across Zeek invocations, the same components always
// map to the same hashes).  We need these properties because we use hashes
// to robustly identify identical instances of the same function, for example
// so we can recognize that an instance of the function definition seen in
// a script matches a previously compiled function body, so we can safely
// replace the function's AST with the compiled version).
//
// We profile functions collectively (via the ProfileFuncs class), rather
// than in isolation, because doing so (1) allows us to share expensive
// profiling steps (in particular, computing the hashes of types, as some
// of the Zeek script records get huge, and occur frequently), and (2) enables
// us to develop a global picture of all of the components germane to a set
// of functions.  The global profile is built up in terms of individual
// profiles (via the ProfileFunc class), which identify each function's
// basic components, and then using these as starting points to build out
// the global profile and compute the hashes of functions and types.

#pragma once

#include <string_view>

#include "zeek/Expr.h"
#include "zeek/Stmt.h"
#include "zeek/Traverse.h"
#include "zeek/script_opt/ScriptOpt.h"

namespace zeek::detail {

// The type used to represent hashes.  We use the mnemonic "p_hash" as
// short for "profile hash", to avoid confusion with hashes used elsehwere
// in Zeek (which are for the most part keyed, a property we explicitly
// do not want).
using p_hash_type = unsigned long long;

// Helper functions for computing/managing hashes.

inline p_hash_type p_hash(int val)
	{ return std::hash<int>{}(val); }

inline p_hash_type p_hash(std::string_view val)
	{ return std::hash<std::string_view>{}(val); }

extern p_hash_type p_hash(const Obj* o);
inline p_hash_type p_hash(const IntrusivePtr<Obj>& o)
	{ return p_hash(o.get()); }

inline p_hash_type merge_p_hashes(p_hash_type h1, p_hash_type h2)
	{
	// Taken from Boost.  See for example
	// https://www.boost.org/doc/libs/1_35_0/doc/html/boost/hash_combine_id241013.html
	// or
	// https://stackoverflow.com/questions/4948780/magic-number-in-boosthash-combine
	return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
	}

// Returns a filename associated with the given function body.  Used to 
// provide distinctness to identical function bodies seen in separate,
// potentially conflicting incremental compilations.  This is only germane
// for allowing incremental compilation of subsets of the test suite, so
// if we decide to forgo that capability, we can remove this.
extern std::string script_specific_filename(const StmtPtr& body);

// Returns a incremental-compilation-specific hash for the given function
// body, given it's non-specific hash is "generic_hash".
extern p_hash_type script_specific_hash(const StmtPtr& body, p_hash_type generic_hash);


// Class for profiling the components of a single function (or expression).
class ProfileFunc : public TraversalCallback {
public:
	// Constructor used for the usual case of profiling a script
	// function and one of its bodies.
	ProfileFunc(const Func* func, const StmtPtr& body, bool abs_rec_fields);

	// Constructors for profiling an AST statement expression.  These exist
	// to support (1) profiling lambda expressions and loop bodies, and
	// (2) traversing attribute expressions (such as &default=expr)
	// to discover what components they include.
	ProfileFunc(const Stmt* body, bool abs_rec_fields = false);
	ProfileFunc(const Expr* func, bool abs_rec_fields = false);

	// See the comments for the associated member variables for each
	// of these accessors.
	const std::unordered_set<const ID*>& Globals() const
		{ return globals; }
	const std::unordered_set<const ID*>& AllGlobals() const
		{ return all_globals; }
	const std::unordered_set<const ID*>& Locals() const
		{ return locals; }
	const std::unordered_set<const ID*>& Params() const
		{ return params; }
	const std::unordered_map<const ID*, int>& Assignees() const
		{ return assignees; }
	const std::unordered_set<const ID*>& Inits() const
		{ return inits; }
	const std::vector<const Stmt*>& Stmts() const
		{ return stmts; }
	const std::vector<const Expr*>& Exprs() const
		{ return exprs; }
	const std::vector<const LambdaExpr*>& Lambdas() const
		{ return lambdas; }
	const std::vector<const ConstExpr*>& Constants() const
		{ return constants; }
	const std::unordered_set<const ID*>& UnorderedIdentifiers() const
		{ return ids; }
	const std::vector<const ID*>& OrderedIdentifiers() const
		{ return ordered_ids; }
	const std::unordered_set<const Type*>& UnorderedTypes() const
		{ return types; }
	const std::vector<const Type*>& OrderedTypes() const
		{ return ordered_types; }
	const std::unordered_set<ScriptFunc*>& ScriptCalls() const
		{ return script_calls; }
	const std::unordered_set<const ID*>& BiFGlobals() const
		{ return BiF_globals; }
	const std::unordered_set<ScriptFunc*>& WhenCalls() const
		{ return when_calls; }
	const std::unordered_set<std::string>& Events() const
		{ return events; }
	const std::unordered_set<const Attributes*>& ConstructorAttrs() const
		{ return constructor_attrs; }
	const std::unordered_set<const SwitchStmt*>& ExprSwitches() const
		{ return expr_switches; }
	const std::unordered_set<const SwitchStmt*>& TypeSwitches() const
		{ return type_switches; }

	bool DoesIndirectCalls()		{ return does_indirect_calls; }

	int NumParams() const		{ return num_params; }
	int NumLambdas() const		{ return lambdas.size(); }
	int NumWhenStmts() const	{ return num_when_stmts; }

	const std::vector<p_hash_type>& AdditionalHashes() const
		{ return addl_hashes; }

	// Set this function's hash to the given value; retrieve that value.
	void SetHashVal(p_hash_type hash)	{ hash_val = hash; }
	p_hash_type HashVal() const	{ return hash_val; }

protected:
	// Construct the profile for the given function signature and body.
	void Profile(const FuncType* ft, const StmtPtr& body);

	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;
	TraversalCode PreID(const ID*) override;

	// Take note of the presence of a given type.
	void TrackType(const Type* t);
	void TrackType(const TypePtr& t)	{ TrackType(t.get()); }

	// Take note of the presence of an identifier.
	void TrackID(const ID* id);

	// Take note of an assignment to an identifier.
	void TrackAssignment(const ID* id);

	// Globals seen in the function.
	//
	// Does *not* include globals solely seen as the function being
	// called in a call.
	std::unordered_set<const ID*> globals;

	// Same, but also includes globals only seen as called functions.
	std::unordered_set<const ID*> all_globals;

	// Locals seen in the function.
	std::unordered_set<const ID*> locals;

	// The function's parameters.  Empty if our starting point was
	// profiling an expression.
	std::unordered_set<const ID*> params;

	// How many parameters the function has.  The default value flags
	// that we started the profile with an expression rather than a
	// function.
	int num_params = -1;

	// Maps identifiers (globals, locals, parameters) to how often
	// they are assigned to (no entry if never).  Does not include
	// implicit assignments due to initializations, which are instead
	// captured in "inits".
	std::unordered_map<const ID*, int> assignees;

	// Same for locals seen in initializations, so we can find,
	// for example, unused aggregates.
	std::unordered_set<const ID*> inits;

	// Statements seen in the function.  Does not include indirect
	// statements, such as those in lambda bodies.
	std::vector<const Stmt*> stmts;

	// Expressions seen in the function.  Does not include indirect
	// expressions (such as those appearing in attributes of types).
	std::vector<const Expr*> exprs;

	// Lambdas seen in the function.  We don't profile lambda bodies,
	// but rather make them available for separate profiling if
	// appropriate.
	std::vector<const LambdaExpr*> lambdas;

	// If we're profiling a lambda function, this holds the captures.
	std::unordered_set<const ID*> captures;

	// Constants seen in the function.
	std::vector<const ConstExpr*> constants;

	// Identifiers seen in the function.
	std::unordered_set<const ID*> ids;

	// The same, but in a deterministic order.
	std::vector<const ID*> ordered_ids;

	// Types seen in the function.  A set rather than a vector because
	// the same type can be seen numerous times.
	std::unordered_set<const Type*> types;

	// The same, but in a deterministic order, with duplicates removed.
	std::vector<const Type*> ordered_types;

	// Script functions that this script calls.
	std::unordered_set<ScriptFunc*> script_calls;

	// Same for BiF's, though for them we record the corresponding global
	// rather than the BuiltinFunc*.
	std::unordered_set<const ID*> BiF_globals;

	// Script functions appearing in "when" clauses.
	std::unordered_set<ScriptFunc*> when_calls;

	// Names of generated events.
	std::unordered_set<std::string> events;

	// Attributes seen in set or table constructors.
	std::unordered_set<const Attributes*> constructor_attrs;

	// Switch statements with either expression cases or type cases.
	std::unordered_set<const SwitchStmt*> expr_switches;
	std::unordered_set<const SwitchStmt*> type_switches;

	// True if the function makes a call through an expression rather
	// than simply a function's (global) name.
	bool does_indirect_calls = false;

	// Additional values present in the body that should be factored
	// into its hash.
	std::vector<p_hash_type> addl_hashes;

	// Associated hash value.
	p_hash_type hash_val = 0;

	// How many when statements appear in the function body.  We could
	// track these individually, but to date all that's mattered is
	// whether a given body contains any.
	int num_when_stmts = 0;

	// Whether we should treat record field accesses as absolute
	// (integer offset) or relative (name-based).
	bool abs_rec_fields;

	// Whether we're separately processing a "when" condition to
	// mine out its script calls.
	bool in_when = false;
};

// Function pointer for a predicate that determines whether a given
// profile is compilable.  Alternatively we could derive subclasses
// from ProfileFuncs and use a virtual method for this, but that seems
// heavier-weight for what's really a simple notion.
using is_compilable_pred = bool (*)(const ProfileFunc*, const char** reason);

// Collectively profile an entire collection of functions.
class ProfileFuncs {
public:
	// Updates entries in "funcs" to include profiles.  If pred is
	// non-nil, then it is called for each profile to see whether it's
	// compilable, and, if not, the FuncInfo is marked as ShouldSkip().
	// "full_record_hashes" controls whether the hashes for extended
	// records covers their final, full form, or should only their
	// original fields.
	ProfileFuncs(std::vector<FuncInfo>& funcs,
	             is_compilable_pred pred, bool full_record_hashes);

	// The following accessors provide a global profile across all of
	// the (non-skipped) functions in "funcs".  See the comments for
	// the associated member variables for documentation.
	const std::unordered_set<const ID*>& Globals() const
		{ return globals; }
	const std::unordered_set<const ID*>& AllGlobals() const
		{ return all_globals; }
	const std::unordered_set<const ConstExpr*>& Constants() const
		{ return constants; }
	const std::vector<const Type*>& MainTypes() const
		{ return main_types; }
	const std::vector<const Type*>& RepTypes() const
		{ return rep_types; }
	const std::unordered_set<ScriptFunc*>& ScriptCalls() const
		{ return script_calls; }
	const std::unordered_set<const ID*>& BiFGlobals() const
		{ return BiF_globals; }
	const std::unordered_set<const LambdaExpr*>& Lambdas() const
		{ return lambdas; }
	const std::unordered_set<std::string>& Events() const
		{ return events; }

	std::shared_ptr<ProfileFunc> FuncProf(const ScriptFunc* f)
		{ return func_profs[f]; }

	// This is only externally germane for LambdaExpr's.
	std::shared_ptr<ProfileFunc> ExprProf(const Expr* e)
		{ return expr_profs[e]; }

	// Returns the "representative" Type* for the hash associated with
	// the parameter (which might be the parameter itself).
	const Type* TypeRep(const Type* orig)
		{
		auto it = type_to_rep.find(orig);
		ASSERT(it != type_to_rep.end());
		return it->second;
		}

	// Returns the hash associated with the given type, computing it
	// if necessary.
	p_hash_type HashType(const TypePtr& t)	{ return HashType(t.get()); }
	p_hash_type HashType(const Type* t);

	p_hash_type HashAttrs(const AttributesPtr& attrs);

protected:
	// Incorporate the given function profile into the global profile.
	void MergeInProfile(ProfileFunc* pf);

	// Recursively traverse a (possibly aggregate) value to extract
	// all of the types its elements use.
	void TraverseValue(const ValPtr& v);

	// When traversing types, Zeek records can have attributes that in
	// turn have expressions associated with them.  The expressions can
	// in turn have types, which might be records with further attribute
	// expressions, etc.  This method iteratively processes the list
	// expressions we need to analyze until no new ones are added.
	void DrainPendingExprs();

	// Compute hashes for the given set of types.  Potentially recursive
	// upon discovering additional types.
	void ComputeTypeHashes(const std::vector<const Type*>& types);

	// Compute hashes to associate with each function
	void ComputeBodyHashes(std::vector<FuncInfo>& funcs);

	// Compute the hash associated with a single function profile.
	void ComputeProfileHash(std::shared_ptr<ProfileFunc> pf);

	// Analyze the expressions and lambdas appearing in a set of
	// attributes.
	void AnalyzeAttrs(const Attributes* Attrs);

	// Globals seen across the functions, other than those solely seen
	// as the function being called in a call.
	std::unordered_set<const ID*> globals;

	// Same, but also includes globals only seen as called functions.
	std::unordered_set<const ID*> all_globals;

	// Constants seen across the functions.
	std::unordered_set<const ConstExpr*> constants;

	// Types seen across the functions.  Does not include subtypes.
	// Deterministically ordered.
	std::vector<const Type*> main_types;

	// "Representative" types seen across the functions.  Includes
	// subtypes.  These all have unique hashes, and are returned by
	// calls to TypeRep().  Deterministically ordered.
	std::vector<const Type*> rep_types;

	// Maps a type to its representative (which might be itself).
	std::unordered_map<const Type*, const Type*> type_to_rep;

	// Script functions that get called.
	std::unordered_set<ScriptFunc*> script_calls;

	// Same for BiF's.
	std::unordered_set<const ID*> BiF_globals;

	// And for lambda's.
	std::unordered_set<const LambdaExpr*> lambdas;

	// Names of generated events.
	std::unordered_set<std::string> events;

	// Maps script functions to associated profiles.  This isn't
	// actually well-defined in the case of event handlers and hooks,
	// which can have multiple bodies.  However, the need for this
	// is temporary (it's for skipping compilation of functions that
	// appear in "when" clauses), and in that context it suffices.
	std::unordered_map<const ScriptFunc*, std::shared_ptr<ProfileFunc>> func_profs;

	// Maps expressions to their profiles.  This is only germane
	// externally for LambdaExpr's, but internally it abets memory
	// management.
	std::unordered_map<const Expr*, std::shared_ptr<ProfileFunc>> expr_profs;

	// These remaining member variables are only used internally,
	// not provided via accessors:

	// Maps types to their hashes.
	std::unordered_map<const Type*, p_hash_type> type_hashes;

	// An inverse mapping, to a representative for each distinct hash.
	std::unordered_map<p_hash_type, const Type*> type_hash_reps;

	// For types with names, tracks the ones we've already hashed,
	// so we can avoid work for distinct pointers that refer to the
	// same underlying type.
	std::unordered_map<std::string, const Type*> seen_type_names;

	// Expressions that we've discovered that we need to further
	// profile.  These can arise for example due to lambdas or
	// record attributes.
	std::vector<const Expr*> pending_exprs;

	// Whether the hashes for extended records should cover their final,
	// full form, or only their original fields.
	bool full_record_hashes;
};


} // namespace zeek::detail
