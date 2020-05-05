// See the file "COPYING" in the main distribution directory for copyright.

#include "Expr.h"
#include "StmtBase.h"
#include "Traverse.h"

class ProfileFunc : public TraversalCallback {
public:
	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;

	// Globals seen in the function.
	std::unordered_set<const ID*> globals;

	int num_stmts = 0;
	int num_when_stmts = 0;
	int num_lambdas = 0;
	int num_exprs = 0;
};
