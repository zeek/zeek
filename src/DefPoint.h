// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Expr.h"
#include "Func.h"
#include "Stmt.h"


typedef enum {
	NO_DEF,
	STMT_DEF,
	// The following includes assignments, +=, vec+=, $, $? ...
	// ... plus names (for implicit creation of records upon
	// seeing use) and calls (for aggregates).
	EXPR_DEF,
	CALL_EXPR_DEF,	// for aggregates
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
