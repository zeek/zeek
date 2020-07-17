// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Expr.h"
#include "StmtBase.h"
#include "Traverse.h"

class ProfileFunc : public TraversalCallback {
public:
	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;

	// Globals seen in the function.  Non-const solely to support
	// methods returning non-const values that can be Ref'd.  I.e.,
	// this could all be IntrusivePtr-ified with enough elbow grease.
	//
	// Does *not* include globals solely seen as the function in a call.
	std::unordered_set<ID*> globals;

	// Same for locals.
	std::unordered_set<ID*> locals;

	// Same for locals seen in initializations, so we can find
	// unused aggregates.
	std::unordered_set<ID*> inits;

	// Script functions this script calls.
	std::unordered_set<BroFunc*> script_calls;

	// Same for BiF's.
	std::unordered_set<Func*> BiF_calls;

	// Names of generated events.
	std::unordered_set<const char*> events;

	// Script functions appearing in "when" clauses.
	std::unordered_set<BroFunc*> when_calls;

	// True if makes a call through an expression.
	bool does_indirect_calls;

	int num_stmts = 0;
	int num_when_stmts = 0;
	int num_lambdas = 0;
	int num_exprs = 0;

protected:
	// Whether we're separately processing a "when" condition to
	// mine out its script calls.
	bool in_when = false;
};
