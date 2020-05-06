// See the file "COPYING" in the main distribution directory for copyright.

#include "ProfileFunc.h"
#include "Stmt.h"


TraversalCode ProfileFunc::PreStmt(const Stmt* s)
	{
	++num_stmts;

	if ( s->Tag() == STMT_WHEN )
		++num_when_stmts;

	else if ( s->Tag() == STMT_FOR )
		{
		auto sf = s->AsForStmt();
		auto loop_vars = sf->LoopVars();
		auto value_var = sf->ValueVar();

		for ( auto id : *loop_vars )
			locals.insert(id);

		if ( value_var )
			locals.insert(value_var);
		}

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
		else
			locals.insert(id);
		}

	else if ( e->Tag() == EXPR_LAMBDA )
		++num_lambdas;

	++num_exprs;

	return TC_CONTINUE;
	}
