// See the file "COPYING" in the main distribution directory for copyright.

// Classes for traversing functions and their body ASTs to build up profiles
// of the various elements (types, globals, locals, lambdas, etc.) that appear.
// These profiles enable script optimization to make decisions regarding
// compatibility and how to efficiently provide run-time components.
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
// short for "profile hash", to avoid confusion with hashes used elsewhere
// in Zeek (which are for the most part keyed, a property we explicitly
// do not want).
using p_hash_type = unsigned long long;

// Helper functions for computing/managing hashes.

inline p_hash_type p_hash(int val) { return std::hash<int>{}(val); }

inline p_hash_type p_hash(std::string_view val) { return std::hash<std::string_view>{}(val); }

extern p_hash_type p_hash(const Obj* o);
inline p_hash_type p_hash(const IntrusivePtr<Obj>& o) { return p_hash(o.get()); }

inline p_hash_type merge_p_hashes(p_hash_type h1, p_hash_type h2) {
    // Taken from Boost.  See for example
    // https://www.boost.org/doc/libs/1_35_0/doc/html/boost/hash_combine_id241013.html
    // or
    // https://stackoverflow.com/questions/4948780/magic-number-in-boosthash-combine
    return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
}

using AttrSet = std::unordered_set<const Attr*>;
using AttrVec = std::vector<const Attr*>;

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

    // Returns the function, body, or expression profiled.  Each can be
    // null depending on the constructor used.
    const Func* ProfiledFunc() const { return profiled_func; }
    const ScopePtr& ProfiledScope() const { return profiled_scope; }
    const Stmt* ProfiledBody() const { return profiled_body; }
    const Expr* ProfiledExpr() const { return profiled_expr; }

    // See the comments for the associated member variables for each
    // of these accessors.
    const IDSet& Globals() const { return globals; }
    const IDSet& AllGlobals() const { return all_globals; }
    const IDSet& Locals() const { return locals; }
    const IDSet& Captures() const { return captures; }
    const auto& CapturesOffsets() const { return captures_offsets; }
    const IDSet& WhenLocals() const { return when_locals; }
    const IDSet& Params() const { return params; }
    const std::unordered_map<const ID*, int>& Assignees() const { return assignees; }
    const IDSet& NonLocalAssignees() const { return non_local_assignees; }
    const auto& TableRefs() const { return tbl_refs; }
    const auto& AggrMods() const { return aggr_mods; }
    const IDSet& Inits() const { return inits; }
    const std::vector<const Stmt*>& Stmts() const { return stmts; }
    const std::vector<const Expr*>& Exprs() const { return exprs; }
    const std::vector<const LambdaExpr*>& Lambdas() const { return lambdas; }
    const std::vector<const ConstExpr*>& Constants() const { return constants; }
    const IDSet& UnorderedIdentifiers() const { return ids; }
    const std::vector<const ID*>& OrderedIdentifiers() const { return ordered_ids; }
    const TypeSet& UnorderedTypes() const { return types; }
    const std::vector<const Type*>& OrderedTypes() const { return ordered_types; }
    const auto& TypeAliases() const { return type_aliases; }
    const std::unordered_set<ScriptFunc*>& ScriptCalls() const { return script_calls; }
    const IDSet& BiFGlobals() const { return BiF_globals; }
    const std::unordered_set<std::string>& Events() const { return events; }
    const std::unordered_map<const Attributes*, TypePtr>& ConstructorAttrs() const { return constructor_attrs; }
    const std::unordered_map<const Type*, std::set<const Attributes*>>& RecordConstructorAttrs() const {
        return rec_constructor_attrs;
    }
    const std::unordered_set<const SwitchStmt*>& ExprSwitches() const { return expr_switches; }
    const std::unordered_set<const SwitchStmt*>& TypeSwitches() const { return type_switches; }

    bool DoesIndirectCalls() const { return does_indirect_calls; }
    const IDSet& IndirectFuncs() const { return indirect_funcs; }

    int NumParams() const { return num_params; }
    int NumLambdas() const { return lambdas.size(); }
    int NumWhenStmts() const { return num_when_stmts; }

    const std::vector<p_hash_type>& AdditionalHashes() const { return addl_hashes; }

    // Set this function's hash to the given value; retrieve that value.
    void SetHashVal(p_hash_type hash) { hash_val = hash; }
    p_hash_type HashVal() const {
        ASSERT(hash_val);
        return *hash_val;
    }
    bool HasHashVal() const { return bool(hash_val); }

protected:
    // Construct the profile for the given function signature and body.
    void Profile(const FuncType* ft, const StmtPtr& body);

    TraversalCode PreStmt(const Stmt*) override;
    TraversalCode PreExpr(const Expr*) override;
    TraversalCode PreID(const ID*) override;
    TraversalCode PreType(const Type*) override;

    // Take note of the presence of a given type.
    void TrackType(const Type* t);
    void TrackType(const TypePtr& t) { TrackType(t.get()); }

    // Take note of the presence of an identifier.
    void TrackID(const ID* id);

    // Take note of an assignment to an identifier.
    void TrackAssignment(const ID* id);

    // Extracts attributes of a record type used in a constructor (or implicit
    // initialization, or coercion, which does an implicit construction).
    void CheckRecordConstructor(TypePtr t);

    // The function, body, or expression profiled.  Can be null
    // depending on which constructor was used.
    const Func* profiled_func = nullptr;
    ScopePtr profiled_scope;     // null when not in a full function context
    FuncTypePtr profiled_func_t; // null when not in a full function context
    const Stmt* profiled_body = nullptr;
    const Expr* profiled_expr = nullptr;

    // Globals seen in the function.
    //
    // Does *not* include globals solely seen as the function being
    // called in a call.
    IDSet globals;

    // Same, but also includes globals only seen as called functions.
    IDSet all_globals;

    // Locals seen in the function.
    IDSet locals;

    // Same, but for those declared in "when" expressions.
    IDSet when_locals;

    // The function's parameters.  Empty if our starting point was
    // profiling an expression.
    IDSet params;

    // How many parameters the function has.  The default value flags
    // that we started the profile with an expression rather than a
    // function.
    int num_params = -1;

    // Maps identifiers (globals, locals, parameters) to how often
    // they are assigned to (no entry if never).  Does not include
    // implicit assignments due to initializations, which are instead
    // captured in "inits".
    std::unordered_map<const ID*, int> assignees;

    // A subset of assignees reflecting those that are globals or captures.
    IDSet non_local_assignees;

    // TableType's that are used in table references (i.e., index operations).
    TypeSet tbl_refs;

    // Types corresponding to aggregates that are modified.
    TypeSet aggr_mods;

    // Same for locals seen in initializations, so we can find,
    // for example, unused aggregates.
    IDSet inits;

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
    IDSet captures;

    // This maps capture identifiers to their offsets.
    std::map<const ID*, int> captures_offsets;

    // Constants seen in the function.
    std::vector<const ConstExpr*> constants;

    // Identifiers seen in the function.
    IDSet ids;

    // The same, but in a deterministic order.
    std::vector<const ID*> ordered_ids;

    // Types seen in the function.  A set rather than a vector because
    // the same type can be seen numerous times.
    TypeSet types;

    // The same, but in a deterministic order, with duplicates removed.
    std::vector<const Type*> ordered_types;

    // For a given type (seen in an attribute), tracks other types that
    // are effectively aliased with it via coercions.
    std::unordered_map<const Type*, std::set<const Type*>> type_aliases;

    // Script functions that this script calls.  Includes calls made
    // by lambdas and when bodies, as the goal is to identify recursion.
    std::unordered_set<ScriptFunc*> script_calls;

    // Same for BiF's, though for them we record the corresponding global
    // rather than the BuiltinFunc*.
    IDSet BiF_globals;

    // Script functions appearing in "when" clauses.
    std::unordered_set<ScriptFunc*> when_calls;

    // Names of generated events.
    std::unordered_set<std::string> events;

    // Attributes seen in set, table, or record constructors, mapped back
    // to the type where they appear.
    std::unordered_map<const Attributes*, TypePtr> constructor_attrs;

    // Attributes associated with record constructors. There can be several,
    // so we use a set.
    std::unordered_map<const Type*, std::set<const Attributes*>> rec_constructor_attrs;

    // Switch statements with either expression cases or type cases.
    std::unordered_set<const SwitchStmt*> expr_switches;
    std::unordered_set<const SwitchStmt*> type_switches;

    // True if the function makes a call through an expression rather
    // than simply a function's (global) name.
    bool does_indirect_calls = false;

    // Functions (not hooks or event handlers) that are referred to in
    // a context other than being called. These might be used elsewhere
    // for indirect calls.
    IDSet indirect_funcs;

    // Additional values present in the body that should be factored
    // into its hash.
    std::vector<p_hash_type> addl_hashes;

    // Associated hash value.
    std::optional<p_hash_type> hash_val;

    // How many when statements appear in the function body.  We could
    // track these individually, but to date all that's mattered is
    // whether a given body contains any.
    int num_when_stmts = 0;

    // Whether we should treat record field accesses as absolute
    // (integer offset) or relative (name-based).
    bool abs_rec_fields;
};

// Describes an operation for which some forms of access can lead to state
// modifications.
class SideEffectsOp {
public:
    // Access types correspond to:
    //	NONE - there are no side effects
    //	CALL - relevant for function calls
    //	CONSTRUCTION - relevant for constructing/coercing a record
    //	READ - relevant for reading a table element
    //	WRITE - relevant for modifying a table element
    enum AccessType { NONE, CALL, CONSTRUCTION, READ, WRITE };

    SideEffectsOp(AccessType at = NONE, const Type* t = nullptr) : access(at), type(t) {}

    auto GetAccessType() const { return access; }
    const Type* GetType() const { return type; }

    void SetUnknownChanges() { has_unknown_changes = true; }
    bool HasUnknownChanges() const { return has_unknown_changes; }

    void AddModNonGlobal(IDSet ids) { mod_non_locals.insert(ids.begin(), ids.end()); }
    void AddModAggrs(TypeSet types) { mod_aggrs.insert(types.begin(), types.end()); }

    const auto& ModNonLocals() const { return mod_non_locals; }
    const auto& ModAggrs() const { return mod_aggrs; }

private:
    AccessType access;
    const Type* type; // type for which some operations alter state

    // Globals and/or captures that the operation potentially modifies.
    IDSet mod_non_locals;

    // Aggregates (specified by types) that potentially modified.
    TypeSet mod_aggrs;

    // Sometimes the side effects are not known (such as when making
    // indirect function calls, so we can't know statically what function
    // will be called). We refer to as Unknown, and their implications are
    // presumed to be worst-case - any non-local or aggregate is potentially
    // affected.
    bool has_unknown_changes = false;
};

// Function pointer for a predicate that determines whether a given
// profile is compilable.  Alternatively we could derive subclasses
// from ProfileFuncs and use a virtual method for this, but that seems
// heavier-weight for what's really a simple notion.
using is_compilable_pred = bool (*)(const ProfileFunc*, const char** reason);

// Collectively profile an entire collection of functions.
class ProfileFuncs {
public:
    // Updates entries in "funcs" to include profiles.  If pred is non-nil,
    // then it is called for each profile to see whether it's compilable,
    // and, if not, the FuncInfo is marked as ShouldSkip().
    // "compute_func_hashes" governs whether we compute hashes for the
    // FuncInfo entries, or keep their existing ones.  "full_record_hashes"
    // controls whether the hashes for extended records covers their final,
    // full form, or should only their original fields.
    ProfileFuncs(std::vector<FuncInfo>& funcs, is_compilable_pred pred, bool compute_func_hashes,
                 bool full_record_hashes);

    // The following accessors provide a global profile across all of
    // the (non-skipped) functions in "funcs".  See the comments for
    // the associated member variables for documentation.
    const IDSet& Globals() const { return globals; }
    const IDSet& AllGlobals() const { return all_globals; }
    const std::unordered_set<const ConstExpr*>& Constants() const { return constants; }
    const std::vector<const Type*>& MainTypes() const { return main_types; }
    const std::vector<const Type*>& RepTypes() const { return rep_types; }
    const std::unordered_set<ScriptFunc*>& ScriptCalls() const { return script_calls; }
    const IDSet& BiFGlobals() const { return BiF_globals; }
    const std::unordered_set<const LambdaExpr*>& Lambdas() const { return lambdas; }
    const std::unordered_set<std::string>& Events() const { return events; }

    const auto& FuncProfs() const { return func_profs; }

    // Profiles associated with LambdaExpr's and expressions appearing in
    // attributes.
    std::shared_ptr<ProfileFunc> ExprProf(const Expr* e) { return expr_profs[e]; }

    // Returns true if the given type corresponds to a table that has a
    // &default attribute that returns an aggregate value.
    bool IsTableWithDefaultAggr(const Type* t);

    // Returns true if the given operation has non-zero side effects.
    bool HasSideEffects(SideEffectsOp::AccessType access, const TypePtr& t) const;

    // Retrieves the side effects of the given operation, updating non_local_ids
    // and aggrs with identifiers and aggregate types that are modified.
    //
    // A return value of true means the side effects are Unknown. If false,
    // then there are side effects iff either (or both) of non_local_ids
    // or aggrs are non-empty.
    bool GetSideEffects(SideEffectsOp::AccessType access, const Type* t, IDSet& non_local_ids, TypeSet& aggrs) const;

    // Retrieves the side effects of calling the function corresponding to
    // the NameExpr, updating non_local_ids and aggrs with identifiers and
    // aggregate types that are modified. is_unknown is set to true if the
    // call has Unknown side effects (which overrides the relevance of the
    // updates to the sets).
    //
    // A return value of true means that side effects cannot yet be determined,
    // due to dependencies on other side effects. This can happen when
    // constructing a ProfileFuncs, but should not happen once its constructed.
    bool GetCallSideEffects(const NameExpr* n, IDSet& non_local_ids, TypeSet& aggrs, bool& is_unknown);

    // Returns the "representative" Type* for the hash associated with
    // the parameter (which might be the parameter itself).
    const Type* TypeRep(const Type* orig) {
        auto it = type_to_rep.find(orig);
        ASSERT(it != type_to_rep.end());
        return it->second;
    }

    // Returns the hash associated with the given type, computing it
    // if necessary.
    p_hash_type HashType(const TypePtr& t) { return HashType(t.get()); }
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
    // attributes, in the context of a given type.
    void AnalyzeAttrs(const Attributes* attrs, const Type* t);

    // In the abstract, computes side-effects associated with operations other
    // than explicit function calls. Currently, this means tables and records
    // that can implicitly call functions that have side effects due to
    // attributes such as &default. The machinery also applies to assessing
    // the side effects of explicit function calls, which is done by
    // (the two versions of) GetCallSideEffects().
    void ComputeSideEffects();

    // True if the given expression for sure has no side effects, which is
    // almost always the case. False if the expression *may* have side effects
    // and requires further analysis.
    bool DefinitelyHasNoSideEffects(const ExprPtr& e) const;

    // Records the side effects associated with the given attribute.
    void SetSideEffects(const Attr* a, IDSet& non_local_ids, TypeSet& aggrs, bool is_unknown);

    // Returns the attributes associated with the given type *and its aliases*.
    AttrVec AssociatedAttrs(const Type* t);

    // For a given set of attributes, assesses which ones are associated with
    // the given type or its aliases and adds them to the given vector.
    void FindAssociatedAttrs(const AttrSet& candidate_attrs, const Type* t, AttrVec& assoc_attrs);

    // Assesses the side effects associated with the given expression. Returns
    // true if a complete assessment was possible, false if not because the
    // results depend on resolving other potential side effects first.
    bool AssessSideEffects(const ExprPtr& e, IDSet& non_local_ids, TypeSet& types, bool& is_unknown);

    // Same, but for the given profile.
    bool AssessSideEffects(const ProfileFunc* pf, IDSet& non_local_ids, TypeSet& types, bool& is_unknown);

    // Same but for the particular case of a relevant access to an aggregate
    // (which can be constructing a record; reading a table element; or
    // modifying a table element).
    bool AssessAggrEffects(SideEffectsOp::AccessType access, const Type* t, IDSet& non_local_ids, TypeSet& aggrs,
                           bool& is_unknown);

    // For a given set of side effects, determines whether the given aggregate
    // access applies. If so, updates non_local_ids and aggrs and returns true
    // if there are Unknown side effects; otherwise returns false.
    bool AssessSideEffects(const SideEffectsOp* se, SideEffectsOp::AccessType access, const Type* t,
                           IDSet& non_local_ids, TypeSet& aggrs) const;

    // Returns nil if side effects are not available. That should never be
    // the case after we've done our initial analysis, but is provided
    // as a signal so that this method can also be used during that analysis.
    std::shared_ptr<SideEffectsOp> GetCallSideEffects(const ScriptFunc* f);

    // Globals seen across the functions, other than those solely seen
    // as the function being called in a call.
    IDSet globals;

    // Same, but also includes globals only seen as called functions.
    IDSet all_globals;

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

    // For a given type, tracks which other types are aliased to it.
    // Alias occurs via operations that can propagate attributes, which
    // are various forms of aggregate coercions.
    std::unordered_map<const Type*, std::set<const Type*>> type_aliases;

    // Script functions that get called.
    std::unordered_set<ScriptFunc*> script_calls;

    // Same for BiF's.
    IDSet BiF_globals;

    // And for lambda's.
    std::unordered_set<const LambdaExpr*> lambdas;

    // Names of generated events.
    std::unordered_set<std::string> events;

    // Maps script functions to associated profiles.  This isn't actually
    // well-defined in the case of event handlers and hooks, which can have
    // multiple bodies.  However, we only use this in the context of calls
    // to regular functions, and for that it suffices.
    std::unordered_map<const ScriptFunc*, std::shared_ptr<ProfileFunc>> func_profs;

    // Map lambda names to their primary functions
    std::unordered_map<std::string, const ScriptFunc*> lambda_primaries;

    // Tracks side effects associated with script functions. If we decide in
    // the future to associate richer side-effect information with BiFs then
    // we could expand this to track Func*'s instead.
    std::unordered_map<const ScriptFunc*, std::shared_ptr<SideEffectsOp>> func_side_effects;

    // Maps expressions to their profiles.
    std::unordered_map<const Expr*, std::shared_ptr<ProfileFunc>> expr_profs;

    // These remaining member variables are only used internally,
    // not provided via accessors:

    // Maps expression-valued attributes to a collection of types in which
    // the attribute appears. Usually there's just one type, but there are
    // some scripting constructs that can result in the same attribute being
    // shared across multiple distinct (though compatible) types.
    std::unordered_map<const Attr*, std::vector<const Type*>> expr_attrs;

    // Tracks whether a given TableType has a &default that returns an
    // aggregate. Expressions involving indexing tables with such types
    // cannot be optimized out using CSE because each returned value is
    // distinct.
    std::unordered_map<const Type*, bool> tbl_has_aggr_default;

    // For a given attribute, maps it to side effects associated with aggregate
    // operations (table reads/writes).
    std::unordered_map<const Attr*, std::vector<std::shared_ptr<SideEffectsOp>>> aggr_side_effects;

    // The same, but for record constructors.
    std::unordered_map<const Attr*, std::vector<std::shared_ptr<SideEffectsOp>>> record_constr_with_side_effects;

    // The set of attributes that may have side effects but we haven't yet
    // resolved if that's the case. Empty after we're done analyzing for
    // side effects.
    AttrSet candidates;

    // The current candidate we're analyzing. We track this to deal with
    // the possibility of the candidate's side effects recursively referring
    // to the candidate itself.
    const Attr* curr_candidate;

    // The set of attributes that definitely have side effects.
    AttrSet attrs_with_side_effects;

    // The full collection of operations with side effects.
    std::vector<std::shared_ptr<SideEffectsOp>> side_effects_ops;

    // Which function profiles we are currently analyzing. Used to detect
    // recursion and prevent it from leading to non-termination of the analysis.
    std::unordered_set<std::shared_ptr<ProfileFunc>> active_func_profiles;

    // Maps types to their hashes.
    std::unordered_map<const Type*, p_hash_type> type_hashes;

    // An inverse mapping, to a representative for each distinct hash.
    std::unordered_map<p_hash_type, const Type*> type_hash_reps;

    // For types with names, tracks the ones we've already hashed, so we can
    // avoid work for distinct pointers that refer to the same underlying type.
    std::unordered_map<std::string, const Type*> seen_type_names;

    // Expressions that we've discovered that we need to further profile.
    // These can arise for example due to lambdas or record attributes.
    std::vector<const Expr*> pending_exprs;

    // Whether to compute new hashes for the FuncInfo entries. If the FuncInfo
    // doesn't have a hash, it will always be computed.
    bool compute_func_hashes;

    // Whether the hashes for extended records should cover their final,
    // full form, or only their original fields.
    bool full_record_hashes;
};

// Updates the line numbers associated with an AST node to reflect its
// full block (i.e., correct "first" and "last" for multi-line and compound
// statements).
class SetBlockLineNumbers : public TraversalCallback {
public:
    // Note, these modify the location information of their "const" arguments.
    // It would be cleaner if Obj provided an interface for doing so (by making
    // SetLocationInfo be a "const" method), but unfortunately it's virtual
    // (unclear why) so we don't know how it might be overridden in user code.
    TraversalCode PreStmt(const Stmt*) override;
    TraversalCode PostStmt(const Stmt*) override;
    TraversalCode PreExpr(const Expr*) override;

private:
    void UpdateLocInfo(Location* loc);

    // A stack of block ranges. Each entry in the vector corresponds to a
    // statement block, managed in a LIFO manner reflecting statement nesting.
    // We start building up a given block's range during pre-traversal and
    // finish it during post-traversal, propagating the updates to the
    // nesting parent.
    std::vector<std::pair<int, int>> block_line_range;
};

// Goes through all of the functions to associate full location information
// with each AST node.
class ASTBlockAnalyzer : public TraversalCallback {
public:
    ASTBlockAnalyzer(std::vector<FuncInfo>& funcs);

    TraversalCode PreStmt(const Stmt*) override;
    TraversalCode PostStmt(const Stmt*) override;
    TraversalCode PreExpr(const Expr*) override;

    // For a given location, returns its full local description (not
    // including its parent).
    std::string GetDesc(const Location* loc) const {
        auto e_d = exp_desc.find(LocKey(loc));
        if ( e_d == exp_desc.end() )
            return LocWithFunc(loc);
        else
            return e_d->second;
    }

    // Whether we've created a description for the given location. This
    // should always be true other than for certain functions with empty
    // bodies that are created post-parsing. Available for debugging so
    // we can assert we have these.
    bool HaveExpDesc(const Location* loc) const { return exp_desc.count(LocKey(loc)) > 0; }

private:
    // Construct the full expanded description associated with the given
    // location (if not already cached) and return it. This is the "static"
    // view; if we reach the location via a non-inlined call, we will
    // prepend that expansion when reporting the corresponding profile.
    std::string BuildExpandedDescription(const Location* loc);

    // Return the key used to associate a Location object with its full
    // descriptiion.
    std::string LocKey(const Location* loc) const {
        return std::string(loc->filename) + ":" + std::to_string(loc->first_line) + "-" +
               std::to_string(loc->last_line);
    }

    // Return the description of a location including its the function
    // in which it's embedded.
    std::string LocWithFunc(const Location* loc) const {
        auto res = func_name_prefix + std::to_string(loc->first_line);

        if ( loc->first_line != loc->last_line )
            res += "-" + std::to_string(loc->last_line);

        return res;
    }

    // The function whose body we are analyzing, in a form convenient
    // for adding it as a prefix (i.e., with a trailing ':').
    std::string func_name_prefix;

    // Stack of expanded descriptions of parent blocks. Each entry is
    // a pair of the parent's own description plus the full descriptor
    // up to that point.
    std::vector<std::pair<std::string, std::string>> parents;

    // Maps a statement's location key to its expanded description.
    std::unordered_map<std::string, std::string> exp_desc;
};

// If we're profiling, this provides the analysis of how low-level location
// information relates to higher-level statement blocks.
extern std::unique_ptr<ASTBlockAnalyzer> AST_blocks;

// Returns the full name of a function at a given location, including its
// associated module (even for event handlers that don't actually have
// modules in their names), so we can track overall per-module resource
// usage.
extern std::string func_name_at_loc(std::string fname, const Location* loc);

} // namespace zeek::detail
