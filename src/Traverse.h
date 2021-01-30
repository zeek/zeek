// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/TraverseTypes.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Func, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Scope, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(ID, zeek::detail);

namespace zeek::detail {

class TraversalCallback {
public:
	TraversalCallback()	{ current_scope = nullptr; }
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

} // namespace zeek::detail
