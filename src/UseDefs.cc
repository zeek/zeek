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
	case STMT_EVENT_BODY_LIST:	// ###
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

	case STMT_NULL:
	case STMT_NEXT:
	case STMT_BREAK:
	case STMT_FALLTHROUGH:
		// ### For most of these this isn't right, but Oh Well,
		// doesn't actually do any harm.
		return CopyUDs(s, succ_UDs);

	case STMT_PRINT:
		return CreateExprUDs(s, s->AsPrintStmt()->ExprList(), succ_UDs);

	case STMT_EVENT:
	case STMT_CHECK_ANY_LEN:
	case STMT_ADD:
	case STMT_DELETE:
	case STMT_RETURN:
		{
		auto e = ((const ExprStmt*) s)->StmtExpr();

		if ( e )
			return CreateExprUDs(s, e, succ_UDs);
		else
			return CopyUDs(s, succ_UDs);
		}

	case STMT_EXPR:
		{
		auto e = s->AsExprStmt()->StmtExpr();

		if ( e->Tag() != EXPR_ASSIGN )
			return CreateExprUDs(s, e, succ_UDs);

		auto a = e->AsAssignExpr();
		auto lhs_ref = a->GetOp1();

		if ( lhs_ref->Tag() != EXPR_REF )
			reporter->InternalError("lhs inconsistency in UseDefs::ExprUDs");

		auto lhs_var = lhs_ref->GetOp1();
		auto lhs_id = lhs_var->AsNameExpr()->Id();
		auto lhs_UDs = RemoveID(lhs_id, succ_UDs);
		auto rhs_UDs = ExprUDs(a->GetOp2().get());
		auto UDs = UD_Union(lhs_UDs, rhs_UDs);

		delete lhs_UDs;
		delete rhs_UDs;

		return CreateUDs(s, UDs);
		}

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
		return CopyUDs(s, succ_UDs);

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

use_defs* UseDefs::ExprUDs(const Expr* e)
	{
	auto uds = new use_defs;
	switch ( e->Tag() ) {
	case EXPR_NAME:
		AddInExprUDs(uds, e);
		break;

	case EXPR_CONST:
		break;

	case EXPR_CALL:
		{
		auto c = e->AsCallExpr();
		AddInExprUDs(uds, c->Func());
		AddInExprUDs(uds, c->Args());
		break;
		}

	case EXPR_LIST:
		{
		auto l = e->AsListExpr();
		for ( const auto& l_e : l->Exprs() )
			AddInExprUDs(uds, l_e);

		break;
		}

	default:
		auto op1 = e->GetOp1();
		auto op2 = e->GetOp2();
		auto op3 = e->GetOp3();

		if ( ! op1 )
			reporter->InternalError("expression inconsistency in UseDefs::ExprUDs");

		AddInExprUDs(uds, op1.get());
		if ( op2 ) AddInExprUDs(uds, op2.get());
		if ( op3 ) AddInExprUDs(uds, op3.get());

		break;
	}

	return uds;
	}

void UseDefs::AddInExprUDs(use_defs* uds, const Expr* e)
	{
	if ( e->Tag() == EXPR_NAME )
		AddID(uds, e->AsNameExpr()->Id());

	else if ( e->Tag() == EXPR_LIST )
		{
		auto l = e->AsListExpr();
		for ( const auto& l_e : l->Exprs() )
			AddInExprUDs(uds, l_e);
		}

	else if ( e->Tag() == EXPR_EVENT )
		AddInExprUDs(uds, e->GetOp1().get());

	else if ( e->Tag() == EXPR_FIELD_ASSIGN )
		{
		auto f = e->AsFieldAssignExpr();
		AddInExprUDs(uds, f->Op());
		}

	else if ( e->Tag() != EXPR_CONST )
		reporter->InternalError("list expression not reduced");
	}

void UseDefs::AddID(use_defs* uds, const ID* id)
	{
	uds->insert(id);
	}

use_defs* UseDefs::RemoveID(const ID* id, const use_defs* UDs)
	{
	if ( ! UDs )
		return nullptr;

	use_defs* new_uds = new use_defs;

	*new_uds = *UDs;
	new_uds->erase(id);

	return new_uds;
	}

void UseDefs::RemoveUDFrom(use_defs* UDs, const ID* id)
	{
	if ( UDs )
		UDs->erase(id);
	}

void UseDefs::FoldInUDs(use_defs*& main_UDs, const use_defs* u1,
			const use_defs* u2)
	{
	auto old_main = main_UDs;
	main_UDs = new use_defs;

	if ( old_main )
		{
		*main_UDs = *old_main;
		delete old_main;
		}

	if ( u1 )
		for ( auto ud : *u1 )
			main_UDs->insert(ud);

	if ( u2 )
		for ( auto ud : *u2 )
			main_UDs->insert(ud);
	}

void UseDefs::UpdateUDs(const Stmt* s, const use_defs* UDs)
	{
	auto curr_uds = FindUsage(s);

	if ( ! curr_uds || UDs_are_copies.find(s) != UDs_are_copies.end() )
		{
		// Copy-on-write.
		auto new_uds = new use_defs;

		if ( curr_uds )
			*new_uds = *curr_uds;

		CreateUDs(s, new_uds);

		curr_uds = new_uds;
		}

	if ( UDs )
		{
		for ( auto u : *UDs )
			curr_uds->insert(u);
		}
	}

use_defs* UseDefs::UD_Union(const use_defs* u1, const use_defs* u2,
				const use_defs* u3)
	{
	auto new_uds = new use_defs;

	if ( u1 )
		*new_uds = *u1;

	if ( u2 )
		for ( auto& u : *u2 )
			AddID(new_uds, u);

	if ( u3 )
		for ( auto& u : *u3 )
			AddID(new_uds, u);

	return new_uds;
	}

use_defs* UseDefs::CopyUDs(const Stmt* s, use_defs* UDs)
	{
	use_defs_map[s] = UDs;
	UDs_are_copies.insert(s);
	return UDs;
	}

use_defs* UseDefs::CreateExprUDs(const Stmt* s, const Expr* e,
					const use_defs* UDs)
	{
	auto e_UDs = ExprUDs(e);
	auto new_UDs = UD_Union(UDs, e_UDs);
	delete e_UDs;

	return CreateUDs(s, new_UDs);
	}

use_defs* UseDefs::CreateUDs(const Stmt* s, use_defs* UDs)
	{
	use_defs_map[s] = UDs;
	UDs_are_copies.erase(s);
	return UDs;
	}
