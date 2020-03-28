// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Expr.h"
#include "Stmt.h"


typedef enum {
	NO_DEF,
	STMT_DEF,
	NAME_EXPR_DEF,	// implicit creation of records upon seeing use
	ASSIGN_EXPR_DEF,
	ADDTO_EXPR_DEF,
	FIELD_EXPR_DEF,
	HAS_FIELD_EXPR_DEF,
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

	DefinitionPoint(const NameExpr* n)
		{
		o = n;
		t = NAME_EXPR_DEF;
		}

	DefinitionPoint(const AssignExpr* a)
		{
		o = a;
		t = ASSIGN_EXPR_DEF;
		}

	DefinitionPoint(const AddToExpr* a)
		{
		o = a;
		t = ADDTO_EXPR_DEF;
		}

	DefinitionPoint(const FieldExpr* f)
		{
		o = f;
		t = FIELD_EXPR_DEF;
		}

	DefinitionPoint(const HasFieldExpr* f)
		{
		o = f;
		t = HAS_FIELD_EXPR_DEF;
		}

	DefinitionPoint(const CallExpr* c)
		{
		o = c;
		t = CALL_EXPR_DEF;
		}

	DefinitionPoint(const Func* f)
		{
		o = f;
		t = FUNC_DEF;
		}

	def_point_type Tag() const	{ return t; }

	const BroObj* OpaqueVal() const	{ return o; }

	const Stmt* StmtVal() const	{ return (const Stmt*) o; }
	const AssignExpr* AssignVal() const	
		{ return (const AssignExpr*) o; }
	const AddToExpr* AddToVal() const	
		{ return (const AddToExpr*) o; }
	const Func* FuncVal() const	{ return (const Func*) o; }

	bool SameAs(const DefinitionPoint& dp) const
		{
		return dp.Tag() == Tag() && dp.OpaqueVal() == OpaqueVal();
		}

protected:
	def_point_type t;
	const BroObj* o;
};
