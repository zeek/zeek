// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "TraverseTypes.h"

class Func;
class Scope;
class Stmt;
class Expr;
class ID;

class TraversalCallback {
public:
	TraversalCallback()	{ current_scope = 0; }
	virtual ~TraversalCallback() {}

	virtual TraversalCode PreFunction(const Func*) { return TC_CONTINUE; }
	virtual TraversalCode PostFunction(const Func*) { return TC_CONTINUE; }

	virtual TraversalCode PreStmt(const Stmt*) { return TC_CONTINUE; }
	virtual TraversalCode PostStmt(const Stmt*) { return TC_CONTINUE; }

	virtual TraversalCode PreExpr(const Expr*) { return TC_CONTINUE; }
	virtual TraversalCode PreExpr(const Expr* e1, const Expr* e2)
		{ return PreExpr(e1); }
	virtual TraversalCode PreExpr(const Expr* e1, const Expr* e2,
					const Expr* e3) { return PreExpr(e1); }
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
