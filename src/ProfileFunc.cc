// See the file "COPYING" in the main distribution directory for copyright.

#include "ProfileFunc.h"
#include "Desc.h"
#include "Stmt.h"


TraversalCode ProfileFunc::PreStmt(const Stmt* s)
	{
	++num_stmts;

	if ( s->Tag() == STMT_INIT )
		{
		// Don't recurse into these, as we don't want to
		// consider a local that only appears in one of these
		// as a relevant local.
		for ( auto id : *s->AsInitStmt()->Inits() )
			inits.insert(id);

		return TC_ABORTSTMT;
		}

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
	++num_exprs;

	if ( e->Tag() == EXPR_NAME )
		{
		auto n = e->AsNameExpr();
		auto id = n->Id();
		if ( id->IsGlobal() )
			globals.insert(id);
		else
			locals.insert(id);
		}

	else if ( e->Tag() == EXPR_CALL )
		{
		auto c = e->AsCallExpr();
		auto f = c->Func();

		if ( f->Tag() == EXPR_NAME &&
		     f->AsNameExpr()->Id()->IsGlobal() )
			{
			// Only recurse into the arguments.
			auto args = c->Args();
			args->Traverse(this);
			return TC_ABORTSTMT;
			}
		}

	else if ( e->Tag() == EXPR_LAMBDA )
		++num_lambdas;

	return TC_CONTINUE;
	}
