// See the file "COPYING" in the main distribution directory for copyright.

#include "ProfileFunc.h"
#include "Desc.h"
#include "Stmt.h"
#include "Func.h"


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
	if ( e->Tag() == EXPR_CONST )
		// These are the only expressions that we allow to be reused,
		// since we never need information about them to be distinct
		// to their position in the program.
		;
	else
		ASSERT(expr_order.count(e) == 0);

	expr_order[e] = num_exprs;
	ordered_exprs.push_back(e);

	++num_exprs;

	switch ( e->Tag() ) {
	case EXPR_NAME:
		{
		auto n = e->AsNameExpr();
		auto id = n->Id();
		if ( id->IsGlobal() )
			globals.insert(id);
		else
			locals.insert(id);
		break;
		}

	case EXPR_CALL:
		{
		auto c = e->AsCallExpr();
		auto f = c->Func();

		if ( f->Tag() != EXPR_NAME )
			{
			does_indirect_calls = true;
			return TC_CONTINUE;
			}

		auto n = f->AsNameExpr();
		auto func = n->Id();

		if ( ! func->IsGlobal() )
			{
			does_indirect_calls = true;
			return TC_CONTINUE;
			}

		auto func_v = func->ID_Val();
		if ( func_v )
			{
			auto func_vf = func_v->AsFunc();

			if ( func_vf->AsBroFunc() )
				script_calls.insert(func_vf);
			else
				BiF_calls.insert(func_vf);
			}
		else
			{
			// We could complain, but for now we don't because
			// if we're invoked prior to full Zeek initialization,
			// the value might indeed not there.
			// printf("no function value for global %s\n", func->Name());
			}

		// Only recurse into the arguments.
		auto args = c->Args();
		args->Traverse(this);
		return TC_ABORTSTMT;
		}

	case EXPR_EVENT:
		events.insert(e->AsEventExpr()->Name());
		break;

	case EXPR_LAMBDA:
		++num_lambdas;
		break;

	default:
		break;
	}

	return TC_CONTINUE;
	}
