// See the file "COPYING" in the main distribution directory for copyright.

#include "ProfileFunc.h"


TraversalCode ProfileFunc::PreStmt(const Stmt* s)
	{
	++num_stmts;

	if ( s->Tag() == STMT_WHEN )
		++num_when_stmts;

	return TC_CONTINUE;
	}

TraversalCode ProfileFunc::PreExpr(const Expr* e)
	{
	if ( e->Tag() == EXPR_NAME )
		{
		auto n = e->AsNameExpr();
		auto id = n->Id();
		if ( id->IsGlobal() )
			globals.insert(id);
		}

	else if ( e->Tag() == EXPR_LAMBDA )
		++num_lambdas;

	++num_exprs;

	return TC_CONTINUE;
	}
