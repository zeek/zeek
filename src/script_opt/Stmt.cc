// See the file "COPYING" in the main distribution directory for copyright.

// Optimization-related methods for Stmt classes.

#include "zeek/Stmt.h"
#include "zeek/Expr.h"


namespace zeek::detail {


void ExprListStmt::Inline(Inliner* inl)
	{
	auto& e = l->Exprs();
	for ( auto i = 0; i < e.length(); ++i )
		e.replace(i, e[i]->Inline(inl).release());
	}


StmtPtr PrintStmt::Duplicate()
	{
	return SetSucc(new PrintStmt(l->Duplicate()->AsListExprPtr()));
	}


StmtPtr ExprStmt::Duplicate()
	{
	return SetSucc(new ExprStmt(e ? e->Duplicate() : nullptr));
	}

void ExprStmt::Inline(Inliner* inl)
	{
	if ( e )
		e = e->Inline(inl);
	}


StmtPtr IfStmt::Duplicate()
	{
	return SetSucc(new IfStmt(e->Duplicate(), s1->Duplicate(),
					s2->Duplicate()));
	}

void IfStmt::Inline(Inliner* inl)
	{
	ExprStmt::Inline(inl);

	if ( s1 )
		s1->Inline(inl);
	if ( s2 )
		s2->Inline(inl);
	}


IntrusivePtr<Case> Case::Duplicate()
	{
	if ( expr_cases )
		{
		auto new_exprs = expr_cases->Duplicate()->AsListExprPtr();
		return make_intrusive<Case>(new_exprs, type_cases, s->Duplicate());
		}

	else
		return make_intrusive<Case>(nullptr, type_cases, s->Duplicate());
	}


StmtPtr SwitchStmt::Duplicate()
	{
	auto new_cases = new case_list;

	loop_over_list(*cases, i)
		new_cases->append((*cases)[i]->Duplicate().release());

	return SetSucc(new SwitchStmt(e->Duplicate(), new_cases));
	}

void SwitchStmt::Inline(Inliner* inl)
	{
	ExprStmt::Inline(inl);

	for ( auto c : *cases )
		// In principle this can do the operation multiple times
		// for a given body, but that's no big deal as repeated
		// calls won't do anything.
		c->Body()->Inline(inl);
	}


StmtPtr AddStmt::Duplicate()
	{
	return SetSucc(new AddStmt(e->Duplicate()));
	}


StmtPtr DelStmt::Duplicate()
	{
	return SetSucc(new DelStmt(e->Duplicate()));
	}


StmtPtr EventStmt::Duplicate()
	{
	return SetSucc(new EventStmt(e->Duplicate()->AsEventExprPtr()));
	}


StmtPtr WhileStmt::Duplicate()
	{
	return SetSucc(new WhileStmt(loop_condition->Duplicate(),
					body->Duplicate()));
	}

void WhileStmt::Inline(Inliner* inl)
	{
	loop_condition = loop_condition->Inline(inl);

	if ( loop_cond_stmt )
		loop_cond_stmt->Inline(inl);
	if ( body )
		body->Inline(inl);
	}


StmtPtr ForStmt::Duplicate()
	{
	auto expr_copy = e->Duplicate();

	auto new_loop_vars = new zeek::IDPList;
	loop_over_list(*loop_vars, i)
		{
		auto id = (*loop_vars)[i];
		zeek::Ref(id);
		new_loop_vars->append(id);
		}

	ForStmt* f;
	if ( value_var )
		f = new ForStmt(new_loop_vars, expr_copy, value_var);
	else
		f = new ForStmt(new_loop_vars, expr_copy);

	f->AddBody(body->Duplicate());

	return SetSucc(f);
	}

void ForStmt::Inline(Inliner* inl)
	{
	ExprStmt::Inline(inl);
	body->Inline(inl);
	}


StmtPtr ReturnStmt::Duplicate()
	{
	return SetSucc(new ReturnStmt(e ? e->Duplicate() : nullptr, true));
	}

ReturnStmt::ReturnStmt(ExprPtr arg_e, bool ignored)
	: ExprStmt(STMT_RETURN, std::move(arg_e))
	{
	}


StmtPtr StmtList::Duplicate()
	{
	auto new_sl = new StmtList();

	for ( auto& stmt : Stmts() )
		new_sl->Stmts().push_back(stmt->Duplicate().release());

	return SetSucc(new_sl);
	}

void StmtList::Inline(Inliner* inl)
	{
	for ( const auto& stmt : Stmts() )
		stmt->Inline(inl);
	}


StmtPtr InitStmt::Duplicate()
	{
	// Need to duplicate the initializer list since later reductions
	// can modify it in place.
	std::vector<IDPtr> new_inits;
	for ( auto id : inits )
		new_inits.push_back(id);

	return SetSucc(new InitStmt(new_inits));
	}


StmtPtr WhenStmt::Duplicate()
	{
	auto cond_d = cond->Duplicate();
	auto s1_d = s1->Duplicate();
	auto s2_d = s2 ? s2->Duplicate() : nullptr;
	auto timeout_d = timeout ? timeout->Duplicate() : nullptr;

	return SetSucc(new WhenStmt(cond_d, s1_d, s2_d, timeout_d, is_return));
	}

void WhenStmt::Inline(Inliner* inl)
	{
	// Don't inline, since we currently don't correctly capture
	// the frames of closures.
	}


} // namespace zeek::detail
