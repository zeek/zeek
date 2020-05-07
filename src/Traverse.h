// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "TraverseTypes.h"

class Func;
class Scope;
class ID;

FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);

class TraversalCallback {
public:
	TraversalCallback()	{ current_scope = nullptr; }
	virtual ~TraversalCallback() {}

	virtual TraversalCode PreFunction(const Func*) { return TC_CONTINUE; }
	virtual TraversalCode PostFunction(const Func*) { return TC_CONTINUE; }

	virtual TraversalCode PreStmt(const zeek::detail::Stmt*) { return TC_CONTINUE; }
	virtual TraversalCode PostStmt(const zeek::detail::Stmt*) { return TC_CONTINUE; }

	virtual TraversalCode PreExpr(const zeek::detail::Expr*) { return TC_CONTINUE; }
	virtual TraversalCode PostExpr(const zeek::detail::Expr*) { return TC_CONTINUE; }

	virtual TraversalCode PreID(const ID*) { return TC_CONTINUE; }
	virtual TraversalCode PostID(const ID*) { return TC_CONTINUE; }

	virtual TraversalCode PreTypedef(const ID*) { return TC_CONTINUE; }
	virtual TraversalCode PostTypedef(const ID*) { return TC_CONTINUE; }

	virtual TraversalCode PreDecl(const ID*) { return TC_CONTINUE; }
	virtual TraversalCode PostDecl(const ID*) { return TC_CONTINUE; }

	Scope* current_scope;
};

TraversalCode traverse_all(TraversalCallback* cb);
