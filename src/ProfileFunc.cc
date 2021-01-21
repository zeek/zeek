// See the file "COPYING" in the main distribution directory for copyright.

#include "ProfileFunc.h"
#include "Desc.h"
#include "Stmt.h"
#include "Func.h"


TraversalCode ProfileFunc::PreStmt(const Stmt* s)
	{
	++num_stmts;

	auto tag = s->Tag();

	if ( compute_hash )
		UpdateHash(int(tag));

	if ( tag == STMT_INIT )
		{
		// Don't recurse into these, as we don't want to
		// consider a local that only appears in one of these
		// as a relevant local.
		for ( auto id : *s->AsInitStmt()->Inits() )
			inits.insert(id);

		return TC_ABORTSTMT;
		}

	switch ( tag ) {
	case STMT_WHEN:
		++num_when_stmts;

		in_when = true;
		s->AsWhenStmt()->Cond()->Traverse(this);
		in_when = false;

		// It doesn't do any harm for us to re-traverse the
		// conditional in our normal operating mode, so we don't
		// bother hand-traversing the rest of the when but just
		// let the usual processing do it.
		break;

	case STMT_FOR:
		{
		auto sf = s->AsForStmt();
		auto loop_vars = sf->LoopVars();
		auto value_var = sf->ValueVar();

		for ( auto id : *loop_vars )
			locals.insert(id);

		if ( value_var )
			locals.insert(value_var);
		}
		break;

	case STMT_SWITCH:
		{
		// If this is a type-case switch statement, then
		// find the identifiers created so we can add them
		// to our list of locals.  Ideally this wouldn't be
		// necessary since *surely* if one bothers to define
		// such an identifier then it'll be subsequently used,
		// and we'll pick up the local that way ... but if
		// for some reason it's not, then we'll have an incomplete
		// list of locals that need to be tracked.
		auto sw = s->AsSwitchStmt();
		for ( auto& c : *sw->Cases() )
			{
			auto idl = c->TypeCases();
			if ( idl ) 
				{
				for ( auto id : *idl )
					locals.insert(id);
				}
			}
		}
		break;

	default:
		break;
	}

	return TC_CONTINUE;
	}

TraversalCode ProfileFunc::PreExpr(const Expr* e)
	{
	++num_exprs;

	auto tag = e->Tag();

	if ( compute_hash )
		UpdateHash(int(tag));

	switch ( tag ) {
	case EXPR_CONST:
		if ( compute_hash )
			{
			CheckType(e->Type().release());
			UpdateHash(e->AsConstExpr()->Value());
			}
		break;

	case EXPR_NAME:
		{
		auto n = e->AsNameExpr();
		auto id = n->Id();
		if ( id->IsGlobal() )
			globals.insert(id);
		else
			locals.insert(id);

		if ( compute_hash )
			{
			UpdateHash(id);
			CheckType(e->Type().release());
			}

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
			auto bf = func_vf->AsBroFunc();

			if ( bf )
				{
				script_calls.insert(bf);

				if ( in_when )
					when_calls.insert(bf);
				}
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

	default:
		break;
	}

	return TC_CONTINUE;
	}

void ProfileFunc::CheckType(const BroType* t)
	{
	auto& tn = t->GetName();
	if ( tn.size() > 0 && seen_types.count(tn) > 0 )
		return;

	if ( seen_type_ptrs.count(t) > 0 )
		return;

	seen_types.insert(tn);
	seen_type_ptrs.insert(t);

	UpdateHash(t);
	}

void ProfileFunc::UpdateHash(const BroObj* o)
	{
	ODesc d;
	o->Describe(&d);
	std::string desc(d.Description());
	auto h = std::hash<std::string>{}(desc);
	MergeInHash(h);
	}
