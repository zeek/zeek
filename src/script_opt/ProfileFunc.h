// See the file "COPYING" in the main distribution directory for copyright.

// Class for traversing a function body's AST to build up a profile
// of its various elements.

#pragma once

#include "Expr.h"
#include "Stmt.h"
#include "Traverse.h"

namespace zeek::detail {

class ProfileFunc : public TraversalCallback {
public:
	ProfileFunc(bool _compute_hash = false)
		{ compute_hash = _compute_hash; }

	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;

	// Globals seen in the function.  Non-const solely to support
	// methods returning non-const values that can be Ref'd.  I.e.,
	// this could all be IntrusivePtr-ified with enough elbow grease.
	//
	// Does *not* include globals solely seen as the function in a call.
	std::unordered_set<const ID*> globals;

	// Same for locals.
	std::unordered_set<const ID*> locals;

	// Same for locals seen in initializations, so we can find
	// unused aggregates.
	std::unordered_set<const ID*> inits;

	// Script functions this script calls.
	std::unordered_set<ScriptFunc*> script_calls;

	// Same for BiF's.
	std::unordered_set<Func*> BiF_calls;

	// Names of generated events.
	std::unordered_set<const char*> events;

	// Script functions appearing in "when" clauses.
	std::unordered_set<ScriptFunc*> when_calls;

	// True if makes a call through an expression.
	bool does_indirect_calls;

	// Hash value.  Only valid if constructor requested it.
	std::size_t hash_val = 0;

	int num_stmts = 0;
	int num_when_stmts = 0;
	int num_lambdas = 0;
	int num_exprs = 0;

protected:
	// Whether we're separately processing a "when" condition to
	// mine out its script calls.
	bool in_when = false;

	// We only compute a hash over the function if requested, since
	// it's somewhat expensive.
	bool compute_hash;

	// The following are for computing a consistent hash that isn't
	// too profligate in how much it needs to compute over.

	// Checks whether we've already noted this type, and, if not,
	// updates the hash with it.
	void CheckType(const TypePtr& t);

	void UpdateHash(int val)
		{
		auto h = std::hash<int>{}(val);
		MergeInHash(h);
		}

	void UpdateHash(const zeek::Obj* o);
	void UpdateHash(const IntrusivePtr<Obj>& o)
		{ UpdateHash(o.get()); }

	void MergeInHash(std::size_t h)
		{
		// Taken from Boost.
		hash_val = h + 0x9e3779b9 + (hash_val << 6) + (hash_val >> 2);
		}

	// Types we've already processed, so we don't add clutter "types"
	// with redundant entries.  We use two forms, one by name
	// (if available) and one by raw pointer (if not).
	std::unordered_set<std::string> seen_types;
	std::unordered_set<const Type*> seen_type_ptrs;
};


} // namespace zeek::detail
