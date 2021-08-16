// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/Stmt.h"

namespace zeek::detail {

// A DefinitionPoint is a location where a variable, or possibly a record
// field, is defined (i.e., assigned to).  The class tracks the type of
// definition (a statement, inside an expression, an aggregate passed to
// a function or hook, or at the start of a function).

enum DefPointType {
	// Used to capture the notion "the variable may have no definition
	// at this point" (or "has no definition", depending on whether we're
	// concerned with minimal or maximal RDs).
	NO_DEF_POINT,

	// Assigned at the given statement.
	STMT_DEF,

	// The following includes assignments, +=, vec+=, $, ?$ ...
	// ... plus names (for implicit creation of records upon
	// seeing use) and calls (for aggregates).
	//
	// Note that ?$ does not in fact create a definition.  We include
	// it as a heuristic meaning "code after this point can assume
	// that the given record field is defined".  The heuristic can
	// fail if the ?$ predicate is ultimately negated, something that
	// we don't try to identify.  Basically, the idea is that if the
	// script writer is cognizant of needing to check for the existence
	// of a field, most likely they got the check correct.  Any errors
	// we make in this regard only lead to mistakes in identify usage
	// problems, not in actual run-time execution.
	EXPR_DEF,

	// The variable is assigned when the function begins executing,
	// either through an explicit initialization for a local, or because
	// it's a function parameter.
	FUNC_DEF,

};

class DefinitionPoint {
public:
	DefinitionPoint()
		{
		o = nullptr;
		t = NO_DEF_POINT;
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

	DefPointType Tag() const	{ return t; }

	const Obj* OpaqueVal() const	{ return o; }

	const Stmt* StmtVal() const
		{ 
		ASSERT(t == STMT_DEF);
		return (const Stmt*) o;
		}

	const Expr* ExprVal() const
		{
		ASSERT(t == EXPR_DEF);
		return (const Expr*) o;
		}

	const Func* FuncVal() const
		{
		ASSERT(t == FUNC_DEF);
		return (const Func*) o;
		}

	bool SameAs(const DefinitionPoint& dp) const
		{
		return dp.Tag() == Tag() && dp.OpaqueVal() == OpaqueVal();
		}

protected:
	DefPointType t;
	const Obj* o;
};

} // zeek::detail
