// See the file "COPYING" in the main distribution directory for copyright.

#ifndef traverse_h
#define traverse_h

#include "Obj.h"
#include "Stmt.h"
#include "Expr.h"
#include "ID.h"
#include "Scope.h"

#include "TraverseTypes.h"

class TraversalCallback {
public:
	TraversalCallback()	{ current_scope = 0; }
	virtual ~TraversalCallback() {}

	virtual TraversalCode PreFunction(const Func*) { return TC_CONTINUE; }
	virtual TraversalCode PostFunction(const Func*) { return TC_CONTINUE; }

	virtual TraversalCode PreStmt(const Stmt*) { return TC_CONTINUE; }
	virtual TraversalCode PostStmt(const Stmt*) { return TC_CONTINUE; }

	virtual TraversalCode PreExpr(const Expr*) { return TC_CONTINUE; }
	virtual TraversalCode PostExpr(const Expr*) { return TC_CONTINUE; }

	virtual TraversalCode PreID(const ID*) { return TC_CONTINUE; }
	virtual TraversalCode PostID(const ID*) { return TC_CONTINUE; }

	virtual TraversalCode PreTypedef(const ID*) { return TC_CONTINUE; }
	virtual TraversalCode PostTypedef(const ID*) { return TC_CONTINUE; }

	virtual TraversalCode PreDecl(const ID*) { return TC_CONTINUE; }
	virtual TraversalCode PostDecl(const ID*) { return TC_CONTINUE; }

	Scope* current_scope;
};

TraversalCode traverse_all(TraversalCallback* cb);

#endif
