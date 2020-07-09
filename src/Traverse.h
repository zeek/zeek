// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "TraverseTypes.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Func, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Scope, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(ID, zeek::detail);

class TraversalCallback {
public:
	TraversalCallback()	{ current_scope = nullptr; }
	virtual ~TraversalCallback() {}

	virtual TraversalCode PreFunction(const zeek::Func*) { return TC_CONTINUE; }
	virtual TraversalCode PostFunction(const zeek::Func*) { return TC_CONTINUE; }

	virtual TraversalCode PreStmt(const zeek::detail::Stmt*) { return TC_CONTINUE; }
	virtual TraversalCode PostStmt(const zeek::detail::Stmt*) { return TC_CONTINUE; }

	virtual TraversalCode PreExpr(const zeek::detail::Expr*) { return TC_CONTINUE; }
	virtual TraversalCode PostExpr(const zeek::detail::Expr*) { return TC_CONTINUE; }

	virtual TraversalCode PreID(const zeek::detail::ID*) { return TC_CONTINUE; }
	virtual TraversalCode PostID(const zeek::detail::ID*) { return TC_CONTINUE; }

	virtual TraversalCode PreTypedef(const zeek::detail::ID*) { return TC_CONTINUE; }
	virtual TraversalCode PostTypedef(const zeek::detail::ID*) { return TC_CONTINUE; }

	virtual TraversalCode PreDecl(const zeek::detail::ID*) { return TC_CONTINUE; }
	virtual TraversalCode PostDecl(const zeek::detail::ID*) { return TC_CONTINUE; }

	zeek::detail::Scope* current_scope;
};

TraversalCode traverse_all(TraversalCallback* cb);
