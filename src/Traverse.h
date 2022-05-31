// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Scope.h"
#include "zeek/TraverseTypes.h"

namespace zeek
	{

class Func;
class Type;

namespace detail
	{

class Stmt;
class Expr;
class ID;
class Attributes;
class Attr;

class TraversalCallback
	{
public:
	TraversalCallback() { current_scope = nullptr; }
	virtual ~TraversalCallback() { }

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

	// A caution regarding using the next two: when traversing types,
	// there's a possibility of encountering a (directly or indirectly)
	// recursive record.  So you'll need some way of avoiding that,
	// such as remembering which types have already been traversed
	// and skipping via TC_ABORTSTMT when seen again.
	virtual TraversalCode PreType(const Type*) { return TC_CONTINUE; }
	virtual TraversalCode PostType(const Type*) { return TC_CONTINUE; }

	virtual TraversalCode PreAttrs(const Attributes*) { return TC_CONTINUE; }
	virtual TraversalCode PostAttrs(const Attributes*) { return TC_CONTINUE; }

	virtual TraversalCode PreAttr(const Attr*) { return TC_CONTINUE; }
	virtual TraversalCode PostAttr(const Attr*) { return TC_CONTINUE; }

	ScopePtr current_scope;
	};

TraversalCode traverse_all(TraversalCallback* cb);

	} // namespace detail
	} // namespace zeek
