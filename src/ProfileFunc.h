// See the file "COPYING" in the main distribution directory for copyright.

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
	std::unordered_set<ID*> globals;

	// Same for locals.
	std::unordered_set<ID*> locals;

	int num_stmts = 0;
	int num_when_stmts = 0;
	int num_lambdas = 0;
	int num_exprs = 0;
};
