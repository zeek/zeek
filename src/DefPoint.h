// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Expr.h"
#include "Func.h"
#include "Stmt.h"

// A DefinitionPoint is a location where a variable, or possibly a record
// field, is defined (i.e., assigned to).  The class tracks the type of
// definition (a statement, inside an expression, an aggregate passed to
// a function or hook, or at the start of a function).

typedef enum {
	// Used to capture the notion "the variable may have no definition
	// at this point" (or "has no definition", depending on whether we're
	// concerned with minimal or maximal RDs).
	NO_DEF,

	// Assigned at the given statement.
	STMT_DEF,

	// The following includes assignments, +=, vec+=, $, ?$ ...
	// ... plus names (for implicit creation of records upon
	// seeing use) and calls (for aggregates).
	//
	// Note that ?$ does not in fact create a definition.  We include
	// it as a heuristic meaning "code after this point can assume
	// that the given record field is defined".
	EXPR_DEF,

	// Any time an aggregate is passed to a call to a function, there's
	// the possibility that the function might modify the aggregate's
	// value.  In principle we could track this more exactly, to determine
	// whether in fact any modification occurs; but to date, the
	// conservative assumption that the aggregate will be modified has
	// not lead to any significant instances of lost optimization
	// opportunities.
	CALL_EXPR_DEF,	// for aggregates

	// The variable is assigned when the function begins executing,
	// either through an explicit initialization for a local, or because
	// it's a function parameter.
	FUNC_DEF,

} def_point_type;

class DefinitionPoint {
public:
	DefinitionPoint()
		{
		o = nullptr;
		t = NO_DEF;
		}

	DefinitionPoint(const Stmt* s)
		{
		o = s;
		t = STMT_DEF;
		}

	DefinitionPoint(const Expr* e)
		{
		o = e;
		t = EXPR_DEF;
		}

	DefinitionPoint(const Func* f)
		{
		o = f;
		t = FUNC_DEF;
		}

	def_point_type Tag() const	{ return t; }

	const BroObj* OpaqueVal() const	{ return o; }

	// The following put the responsbility on the caller to ensure
	// that the correct method flavor is used.
	const Stmt* StmtVal() const	{ return (const Stmt*) o; }
	const Expr* ExprVal() const	{ return (const Expr*) o; }
	const Func* FuncVal() const	{ return (const Func*) o; }

	bool SameAs(const DefinitionPoint& dp) const
		{
		return dp.Tag() == Tag() && dp.OpaqueVal() == OpaqueVal();
		}

protected:
	def_point_type t;
	const BroObj* o;
};
