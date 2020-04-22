// See the file "COPYING" in the main distribution directory for copyright.

#include "UseDefs.h"
#include "Expr.h"
#include "Stmt.h"
#include "Reporter.h"


UseDefs::~UseDefs()
	{
	for ( auto& s : use_defs_map )
		if ( UDs_are_copies.find(s.first) == UDs_are_copies.end() )
			delete s.second;
	}

void UseDefs::Analyze(const Stmt* s)
	{
	(void) PropagateUDs(s, nullptr);
	}

use_defs* UseDefs::PropagateUDs(const Stmt* s, use_defs* succ_UDs)
	{
	switch ( s->Tag() ) {
	case STMT_LIST:
		{
		auto sl = s->AsStmtList();
		auto stmts = sl->Stmts();

		for ( int i = stmts.length(); --i >= 0; )
			{
			auto s = stmts[i];
			succ_UDs = PropagateUDs(s, succ_UDs);
			}

		return CopyUDs(s, succ_UDs);
		}

	case STMT_EVENT_BODY_LIST:	// ###
		break;

	case STMT_PRINT:
	case STMT_NEXT:
	case STMT_BREAK:
	case STMT_FALLTHROUGH:
		return CopyUDs(s, succ_UDs);

	case STMT_EVENT:
	case STMT_CHECK_ANY_LEN:
	case STMT_ADD:
	case STMT_DELETE:
	case STMT_RETURN:
		{
		auto e = ((const ExprStmt*) s)->StmtExpr();
		return CreateUDs(s, ExprUDs(e));
		}

	case STMT_EXPR:
		break;

	case STMT_IF:
		{
		auto i = s->AsIfStmt();
		auto cond = i->StmtExpr();

		auto cond_UDs = ExprUDs(cond);
		auto true_UDs = PropagateUDs(i->TrueBranch(), succ_UDs);
		auto false_UDs = PropagateUDs(i->FalseBranch(), succ_UDs);

		auto UDs = CreateUDs(s, UD_Union(cond_UDs, true_UDs, false_UDs));
		delete cond_UDs;

		return UDs;
		}

	case STMT_WHEN:
		// ###
		break;

	case STMT_SWITCH:
		{
		use_defs* sw_UDs = nullptr;

		auto sw = s->AsSwitchStmt();
		auto cases = sw->Cases();

		for ( const auto& c : *cases )
			{
			auto body = c->Body();
			auto UDs = PropagateUDs(body, succ_UDs);

			auto exprs = c->ExprCases();
			if ( exprs )
				{
				auto e_UDs = ExprUDs(exprs);
				UDs = UD_Union(UDs, e_UDs);
				delete e_UDs;
				}

			auto type_ids = c->TypeCases();
			if ( type_ids )
				for ( const auto& id : *type_ids )
					UDs = RemoveID(id, UDs);

			FoldInUDs(sw_UDs, UDs);
			// sw_UDs = UD_Union(sw_UDs, UDs); delete old

			// We either created UDs afresh via UD_Union
			// or via RemoveID.
			delete UDs;

			return sw_UDs;
			}

		auto e_UDs = ExprUDs(sw->StmtExpr());

		if ( sw->HasDefault() )
			FoldInUDs(sw_UDs, e_UDs);
		else
			// keep successor definitions in the mix
			FoldInUDs(sw_UDs, succ_UDs, e_UDs);

		delete e_UDs;

		return CreateUDs(s, sw_UDs);
		}

	case STMT_FOR:
		{
		auto f = s->AsForStmt();

		auto body = f->LoopBody();
		auto body_UDs = PropagateUDs(body, succ_UDs);

		auto e = f->LoopExpr();
		auto f_UDs = ExprUDs(e);
		FoldInUDs(f_UDs, body_UDs);

		// Confluence: loop the top FDs back around to the bottom.
		UpdateUDs(body, f_UDs);

		auto ids = f->LoopVar();
		for ( auto& id : *ids )
			RemoveUDFrom(f_UDs, id);

		auto val_var = f->ValueVar();
		if ( val_var )
			RemoveUDFrom(f_UDs, val_var);

		// The loop might not execute at all.
		FoldInUDs(f_UDs, succ_UDs);

		return CreateUDs(s, f_UDs);
		}

	case STMT_WHILE:
		{
		auto w = s->AsWhileStmt();
		auto body = w->Body();

		auto body_UDs = PropagateUDs(body, succ_UDs);

		auto cond = w->Condition();
		auto w_UDs = ExprUDs(cond);
		FoldInUDs(w_UDs, body_UDs);

		auto cond_stmt = w->CondStmt();
		if ( cond_stmt )
			{
			auto new_UDs = PropagateUDs(cond_stmt, w_UDs);

			// That propagate definitely created a new
			// set of UDs since the whole point of cond_stmt
			// is that it has assignments in it.  So
			// don't leak the old one.
			delete w_UDs;
			w_UDs = new_UDs;
			}

		// Confluence: loop the top FDs back around to the bottom.
		UpdateUDs(body, w_UDs);

		// The loop might not execute at all.
		FoldInUDs(w_UDs, succ_UDs);

		return CreateUDs(s, w_UDs);
		}

	default:
		reporter->InternalError("non-reduced statement in use-def analysis");
	}
	}

use_defs* UseDefs::FindUsage(const Stmt* s)
	{
	auto s_map = use_defs_map.find(s);

	if ( s_map == use_defs_map.end() )
		reporter->InternalError("missing use-defs");

	return s_map->second;
	}

use_defs* UseDefs::CopyUDs(const Stmt* s, use_defs* UDs)
	{
	use_defs_map[s] = UDs;
	UDs_are_copies.insert(s);
	return UDs;
	}

use_defs* UseDefs::CreateUDs(const Stmt* s, use_defs* UDs)
	{
	use_defs_map[s] = UDs;
	UDs_are_copies.erase(s);
	return UDs;
	}
