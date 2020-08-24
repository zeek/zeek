// See the file "COPYING" in the main distribution directory for copyright.

#include "GenRDs.h"
#include "Scope.h"
#include "ScriptAnaly.h"
#include "Reporter.h"
#include "Desc.h"


// Helper class that tracks definitions gathered in a block that either
// need to be propagated to the beginning of the block or to the end.
// Used for RD propagation due to altered control flow (next/break/fallthrough).
// Managed as a stack (vector) to deal with nested loops, switches, etc.
// Only applies to gathering maximum RDs.
struct BlockDefs {
	BlockDefs(bool _is_case)
		{ is_case = _is_case; }

	void AddPreRDs(RD_ptr RDs)	{ pre_RDs.push_back(RDs); }
	void AddPostRDs(RD_ptr RDs)	{ post_RDs.push_back(RDs); }
	void AddFutureRDs(RD_ptr RDs)	{ future_RDs.push_back(RDs); }

	void Clear()
		{ pre_RDs.clear(); post_RDs.clear(); future_RDs.clear(); }

	vector<RD_ptr> pre_RDs;
	vector<RD_ptr> post_RDs;
	vector<RD_ptr> future_RDs;	// RDs for next case block

	// Whether this block is for a switch case.  If not,
	// it's for a loop body.
	bool is_case;
};


RD_Decorate::RD_Decorate(const ProfileFunc* _pf) : pf(_pf)
	{
	}

void RD_Decorate::TraverseFunction(const Func* f, Scope* scope,
					IntrusivePtr<Stmt> body)
	{
	func_flavor = f->Flavor();

	auto args = scope->OrderedVars();
        auto nparam = f->FType()->Args()->NumFields();

	mgr.SetEmptyPre(f);

	for ( auto a : args )
		{
		if ( --nparam < 0 )
			break;

		CreateInitPostDef(a.get(), DefinitionPoint(f), true, nullptr);
		}

	for ( const auto& g : pf->globals )
		CreateInitPostDef(g, DefinitionPoint(f), true, nullptr);

	if ( ! mgr.HasPostMinRDs(f) )
		// This happens if we have no arguments or globals.  Use the
		// empty ones we set up.
		mgr.SetPostFromPre(f);

	if ( analysis_options.min_rd_trace )
		{
		printf("traversing function %s, post min RDs:\n", f->Name());
		mgr.GetPostMinRDs(f)->Dump();
		}

	if ( analysis_options.max_rd_trace )
		{
		printf("traversing function %s, post max RDs:\n", f->Name());
		mgr.GetPostMaxRDs(f)->Dump();
		}

	mgr.SetPreFromPost(body.get(), f);
	body->Traverse(this);
	}

TraversalCode RD_Decorate::PreStmt(const Stmt* s)
	{
	ASSERT(mgr.HasPreMinRDs(s));
	ASSERT(mgr.HasPreMaxRDs(s));

	if ( analysis_options.min_rd_trace )
		{
		printf("pre min RDs for stmt %s:\n", obj_desc(s));
		mgr.GetPreMinRDs(s)->Dump();
		printf("\n");
		}

	if ( analysis_options.max_rd_trace )
		{
		printf("pre max RDs for stmt %s:\n", obj_desc(s));
		mgr.GetPreMaxRDs(s)->Dump();
		printf("\n");
		}

	switch ( s->Tag() ) {
        case STMT_EXPR:
        case STMT_EVENT:
        case STMT_ADD:
        case STMT_DELETE:
        case STMT_RETURN:
        case STMT_CHECK_ANY_LEN:
		{
		// Can't use AsExprStmt() since it doesn't know about
		// the tags of its subclasses.
		auto e = ((const ExprStmt*) s)->StmtExpr();
		mgr.SetPreFromPre(e, s);
		break;
		}

        case STMT_PRINT:
		{
		auto l = s->AsPrintStmt()->ExprList();
		mgr.SetPreFromPre(l, s);
		break;
		}

        case STMT_CATCH_RETURN:
		{
		auto cr = s->AsCatchReturnStmt();
		auto block = cr->Block().get();
		auto ret_var = cr->RetVar();

		mgr.SetPreFromPre(block, s);
		block->Traverse(this);

		// Treat the block as a no-op for analyzing RDs,
		// since it shouldn't affect the definition status of
		// any of the RDs outside of it.  (The one exception is
		// for globals, which we address by doing a SyncGlobals()
		// for inlined returns.)  The only question is how to
		// propagate RDs relating to the return value.
		mgr.SetPostFromPre(s);

		if ( ret_var )
			{
			// Ideally for the return variable (if any) we'd track
			// whether all of the paths out of the block go through
			// a "return <expr>".  One way we could do that would
			// be to literally assign it for internal returns.
			// The trick with that is it could entail some subtle
			// debugging of how RDs are propagated across internal
			// returns.  For now, we punt and just mark it as
			// defined.
			CreateInitPostDef(ret_var->Id(), DefinitionPoint(s),
						true, nullptr);
			}

		return TC_ABORTSTMT;
		}

	case STMT_LIST:
		{
		auto sl = s->AsStmtList();
		auto stmts = sl->Stmts();
		const Stmt* pred_stmt = s;

		for ( const auto& stmt : stmts )
			{
			if ( pred_stmt == s )
				mgr.SetPreFromPre(stmt, pred_stmt);
			else
				mgr.SetPreFromPost(stmt, pred_stmt);

			stmt->Traverse(this);

			if ( analysis_options.min_rd_trace )
				{
				printf("post min RDs for stmt %s:\n", obj_desc(stmt));
				mgr.GetPostMinRDs(stmt)->Dump();
				printf("\n");
				}

			if ( analysis_options.max_rd_trace )
				{
				printf("post max RDs for stmt %s:\n", obj_desc(stmt));
				mgr.GetPostMaxRDs(stmt)->Dump();
				printf("\n");
				}

			pred_stmt = stmt;
			}

		if ( pred_stmt == s )
			mgr.SetPostFromPre(sl, pred_stmt);
		else
			mgr.SetPostFromPost(sl, pred_stmt);

		return TC_ABORTSTMT;
		}

	case STMT_IF:
		{
		// While we'd like to think no assignment definitions
		// will occur inside conditions (though they could for
		// non-reduced code), in any case a ?$ operator can
		// create definitions, so we have to accommodate that
		// possibility.
		auto i = s->AsIfStmt();
		auto cond = i->StmtExpr();

		mgr.SetPreFromPre(cond, s);
		cond->Traverse(this);

		mgr.SetPreFromPost(i->TrueBranch(), cond);
		i->TrueBranch()->Traverse(this);

		mgr.SetPreFromPost(i->FalseBranch(), cond);
		i->FalseBranch()->Traverse(this);

		auto true_reached = ! i->TrueBranch()->NoFlowAfter(false);
		auto false_reached = ! i->FalseBranch()->NoFlowAfter(false);

		if ( true_reached && false_reached )
			DoIfStmtConfluence(i);

		else
			{
			if ( true_reached )
				mgr.CreatePostRDsFromPost(s, i->TrueBranch());

			else if ( false_reached )
				mgr.CreatePostRDsFromPost(s, i->FalseBranch());

			else
				CreateEmptyPostRDs(s);
			}

		return TC_ABORTSTMT;
		}

	case STMT_SWITCH:
		TraverseSwitch(s->AsSwitchStmt());
		return TC_ABORTSTMT;

	case STMT_FOR:
		{
		auto f = s->AsForStmt();

		auto ids = f->LoopVars();
		auto e = f->LoopExpr();
		auto body = f->LoopBody();
		auto val_var = f->ValueVar();

		mgr.SetPreFromPre(e, s);
		e->Traverse(this);
		mgr.SetPreFromPost(body, e);

		for ( const auto& id : *ids )
			CreateInitPreDef(id, DefinitionPoint(body));

		if ( val_var )
			CreateInitPreDef(val_var, DefinitionPoint(body));

		// If the loop expression's value is uninitialized, that's
		// okay, it will just result in an empty loop.  In principle,
		// for a non-reduced statement it's possible that *getting*
		// to the value will touch on something uninitialized.
		// For reduced form, however, that will already have been
		// hoisted out, so not a concern.
		//
		// To keep from traversing the loop expression, we just do
		// the body manually here.

		block_defs.push_back(new BlockDefs(false));

		body->Traverse(this);

		DoLoopConfluence(s, body, body);

		return TC_ABORTSTMT;
		}

	case STMT_WHILE:
		{
		auto w = s->AsWhileStmt();

		auto cond = w->Condition();

		// This is the *predecessor* statement.
		auto cond_stmt = w->CondStmt();

		// This is the *conditional itself*, but as a statement.
		auto cond_s = w->ConditionAsStmt();

		if ( cond_stmt )
			{
			mgr.SetPreFromPre(cond_stmt, w);
			cond_stmt->Traverse(this);
			mgr.SetPreFromPost(cond, cond_stmt);
			}
		else
			mgr.SetPreFromPre(cond, w);

		cond->Traverse(this);
		mgr.SetPreFromPre(cond_s, cond);
		mgr.SetPostFromPost(cond_s, cond);

		auto body = w->Body();
		mgr.SetPreFromPre(body, cond);

		block_defs.push_back(new BlockDefs(false));

		body->Traverse(this);
		auto loop_top = cond_stmt ? cond_stmt : cond_s;
		DoLoopConfluence(s, loop_top, body);

		// Make sure the conditional gets its RDs updated.

		if ( cond_stmt )
			{
			cond_stmt->Traverse(this);
			mgr.SetPreFromPost(cond, cond_stmt);
			}
		else
			mgr.SetPreFromPost(cond, cond_s);

		cond->Traverse(this);

		return TC_ABORTSTMT;
		}

	case STMT_WHEN:
		{
		// ### punt on these for now, need to reflect on bindings.
		return TC_ABORTSTMT;
		}

	default:
		break;
	}

	return TC_CONTINUE;
	}

void RD_Decorate::TraverseSwitch(const SwitchStmt* sw)
	{
	DefinitionPoint ds(sw);

	auto e = sw->StmtExpr();
	auto cases = sw->Cases();

	mgr.SetPreFromPre(e, sw);
	auto sw_min_pre = mgr.GetPreMinRDs(sw);
	auto sw_max_pre = mgr.GetPreMaxRDs(sw);

	auto bd = new BlockDefs(true);
	block_defs.push_back(bd);

	RD_ptr sw_post_min_rds = nullptr;
	RD_ptr sw_post_max_rds = nullptr;

	if ( sw->HasDefault() )
		// Guaranteed that we'll execute one of the switch blocks.
		// Start with an empty set of RDs for the post-max and
		// build them up via union.
		sw_post_max_rds = make_new_RD_ptr();

	else
		{
		// Entire set of cases is optional, so merge in entering RDs.
		mgr.CreatePostRDsFromPre(sw);

		sw_post_min_rds = mgr.GetPostMinRDs(sw);
		sw_post_max_rds = mgr.GetPostMaxRDs(sw);
		}

	// Used to track fall-through.
	RD_ptr prev_RDs;

	for ( const auto& c : *cases )
		{
		auto body = c->Body();

		mgr.SetPreMinRDs(body, sw_min_pre);
		mgr.SetPreMaxRDs(body, sw_max_pre);

		if ( prev_RDs )
			{
			mgr.MergeIntoPre(body, prev_RDs);
			prev_RDs = nullptr;
			}

		auto exprs = c->ExprCases();
		if ( exprs )
			{
			mgr.SetPreFromPre(exprs, body);
			exprs->Traverse(this);

			// It's perverse to modify a variable in a
			// case expression ... and won't happen for
			// reduced code, so we just ignore the
			// possibility that it occurred.
			}

		auto type_ids = c->TypeCases();
		if ( type_ids )
			{
			for ( const auto& id : *type_ids )
				CreateInitPreDef(id, DefinitionPoint(body));
			}

		auto body_min_pre = mgr.GetPreMinRDs(body);
		auto body_max_pre = mgr.GetPreMaxRDs(body);

		// Don't inherit body-def analysis developed for previous case.
		bd->Clear();
		body->Traverse(this);

		if ( bd->pre_RDs.size() > 0 )
			reporter->InternalError("mispropagation of switch body defs");

		if ( body->NoFlowAfter(true) )
			// Post RDs for this block are irrelevant.
			continue;

		// Propagate what comes out of the block.
		auto case_min_rd = mgr.GetPostMinRDs(body);
		auto case_max_rd = mgr.GetPostMaxRDs(body);

		// Look for any definitions reflecting break or fallthrough
		// short-circuiting.  These only matter for max RDs.
		for ( const auto& post : bd->post_RDs )
			case_max_rd = case_max_rd->Union(post);

		// Scoop up definitions from fallthrough's and remember
		// them for the next block.
		for ( const auto& future : bd->future_RDs )
			{
			if ( ! prev_RDs )
				prev_RDs = future;
			else
				prev_RDs = prev_RDs->Union(future);
			}

		// It's possible we haven't set sw_post_min_rds (if the
		// switch has a default and thus is guaranteed to execute
		// one of the blocks).  OTOH, sw_post_max_rds is always set.
		sw_post_min_rds = sw_post_min_rds ?
			sw_post_min_rds->IntersectWithConsolidation(case_min_rd, ds) :
			make_new_RD_ptr(case_min_rd);

		sw_post_max_rds = sw_post_max_rds->Union(case_max_rd);
		}

	if ( ! sw_post_min_rds )
		// This happens when all of the cases return, including
		// a default.  In that case, sw_post_max_rds is already
		// an empty RD.
		sw_post_min_rds = make_new_RD_ptr();

	mgr.SetPostRDs(sw, sw_post_min_rds, sw_post_max_rds);
	sw_post_min_rds.release();
	sw_post_max_rds.release();

	block_defs.pop_back();
	delete bd;
	}

void RD_Decorate::DoIfStmtConfluence(const IfStmt* i)
	{
	auto min_if_branch_rd = mgr.GetPostMinRDs(i->TrueBranch());
	auto min_else_branch_rd = mgr.GetPostMinRDs(i->FalseBranch());
	auto min_post_rds = min_if_branch_rd->Intersect(min_else_branch_rd);

	auto max_if_branch_rd = mgr.GetPostMaxRDs(i->TrueBranch());
	auto max_else_branch_rd = mgr.GetPostMaxRDs(i->FalseBranch());
	auto max_post_rds = max_if_branch_rd->Union(max_else_branch_rd);

	mgr.CreatePostRDs(i, min_post_rds, max_post_rds);
	min_post_rds.release();
	max_post_rds.release();
	}

void RD_Decorate::DoLoopConfluence(const Stmt* s, const Stmt* top,
					const Stmt* body)
	{
	auto bd = block_defs.back();
	block_defs.pop_back();

	auto loop_pre = mgr.GetPreMaxRDs(top);
	auto loop_post = mgr.GetPostMaxRDs(body);

	for ( const auto& pre : bd->pre_RDs )
		{
		mgr.MergeIntoPre(top, pre);

		// Factor in that these definitions also
		// essentially make it to the beginning of
		// the entire loop.
		mgr.MergeIntoPre(s, pre);
		}

	for ( const auto& post : bd->post_RDs )
		{
		mgr.MergeIntoPost(body, post);
		mgr.MergeIntoPre(s, post);
		}

	// Freshen due to mergers.
	loop_pre = mgr.GetPreMaxRDs(top);
	auto loop_min_post = mgr.GetPostMinRDs(body);
	auto loop_max_post = mgr.GetPostMaxRDs(body);

	if ( loop_pre != loop_max_post )
		{
		// Some body assignments reached the end.  Propagate them
		// around the loop.
		mgr.MergeIntoPre(top, loop_max_post);

		if ( top != body )
			{
			// Don't have to worry about block-defs as it's
			// simply an expression evaluation, no next/break's.
			top->Traverse(this);
			mgr.MergeIntoPre(body, mgr.GetPostMaxRDs(top));
			}

		auto bd2 = new BlockDefs(false);
		block_defs.push_back(bd2);
		body->Traverse(this);
		block_defs.pop_back();

		// Ideally we'd check for consistency with the previous
		// definitions in bd.  This is tricky because the body
		// itself might not have RDs if it ends in a "break" or
		// such.
		delete bd2;
		}

	DefinitionPoint ds(s);

	// Factor in that the loop might not execute at all.
	auto s_min_pre = mgr.GetPreMinRDs(s);
	auto s_max_pre = mgr.GetPreMaxRDs(s);

	// For min RDs, we want to compute them directly regardless
	// of whether the loop body has flow reach the end of it,
	// since an internal "next" can still cause definitions to
	// propagate to the beginning.
	auto min_post_rds = s_min_pre->IntersectWithConsolidation(loop_min_post,
									ds);
	mgr.SetPostMinRDs(s, min_post_rds);
	min_post_rds.release();

	// Note, we use ignore_break=true because what we care about is not
	// whether flow goes just beyond the last statement of the body,
	// but rather whether flow can start at the next statement *after*
	// the body, and a "break" will do that.
	if ( body->NoFlowAfter(true) )
		mgr.SetPostMaxRDs(s, s_max_pre);
	else
		{
		auto max_post_rds = s_max_pre->Union(loop_max_post);
		mgr.SetPostMaxRDs(s, max_post_rds);
		max_post_rds.release();
		}

	delete bd;
	}

TraversalCode RD_Decorate::PostStmt(const Stmt* s)
	{
	DefinitionPoint ds(s);

	switch ( s->Tag() ) {
        case STMT_EXPR:
		{
		auto e = s->AsExprStmt()->StmtExpr();
		mgr.CreatePostRDsFromPost(s, e);
		break;
		}

	case STMT_INIT:
		{
		mgr.CreatePostRDsFromPre(s);

		auto init = s->AsInitStmt();
		auto& inits = *init->Inits();

		for ( int i = 0; i < inits.length(); ++i )
			{
			auto id = inits[i];
			auto id_t = id->Type();

			// Only aggregates get initialized.
			auto tag = id_t->Tag();
			if ( ! ::IsAggr(tag) )
				continue;

			CreateInitPostDef(id, DefinitionPoint(s), false, 0);
			}

		break;
		}

	case STMT_RETURN:
		// No RDs make it past a return.  It's tempting to alter
		// this for inlined "caught" returns, since changes to
		// globals *do* make it past them.  However, doing so
		// is inconsistent with NoFlowAfter() treating such returns
		// as not having control flow go beyond them; and changing
		// NoFlowAfter() would be incorrect since it's about
		// *immediate* control flow, not broader control flow.
		CreateEmptyPostRDs(s);
		break;

	case STMT_NEXT:
		AddBlockDefs(s, true, false, false);
		CreateEmptyPostRDs(s);
		break;

	case STMT_BREAK:
		if ( block_defs.size() == 0 )
			{
			if ( func_flavor == FUNC_FLAVOR_HOOK )
				// Treat as a return.
				CreateEmptyPostRDs(s);
			else
				s->Error("\"break\" in a non-break context");
			break;
			}

		AddBlockDefs(s, false, false, block_defs.back()->is_case);

		if ( block_defs.back()->is_case )
			// The following propagates min RDs so they can
			// be intersected across switch cases.
			mgr.CreatePostRDsFromPre(s);
		else
			CreateEmptyPostRDs(s);

		break;

	case STMT_FALLTHROUGH:
		AddBlockDefs(s, false, true, true);
		mgr.CreatePostRDsFromPre(s);
		break;

	default:
		mgr.CreatePostRDsFromPre(s);
		break;
	}

	if ( analysis_options.min_rd_trace )
		{
		printf("post min RDs for stmt %s:\n", obj_desc(s));
		mgr.GetPostMinRDs(s)->Dump();
		printf("\n");
		}

	if ( analysis_options.max_rd_trace )
		{
		printf("post max RDs for stmt %s:\n", obj_desc(s));
		mgr.GetPostMaxRDs(s)->Dump();
		printf("\n");
		}

	return TC_CONTINUE;
	}

void RD_Decorate::CreateEmptyPostRDs(const Stmt* s)
	{
	auto empty_rds = make_new_RD_ptr();
	mgr.SetPostRDs(s, empty_rds, empty_rds);
	}

void RD_Decorate::AddBlockDefs(const Stmt* s,
				bool is_pre, bool is_future, bool is_case)
	{
	auto rds = mgr.GetPreMaxRDs(s);

	// Walk backward through the block defs finding the appropriate
	// match to this one.
	for ( int i = block_defs.size() - 1; i >= 0; --i )
		{
		auto bd = block_defs[i];

		if ( bd->is_case == is_case )
			{ // This one matches what we're looking for.
			if ( is_pre )
				bd->AddPreRDs(rds);
			else
				{
				bd->AddPostRDs(rds);
				if ( is_future )
					bd->AddFutureRDs(rds);
				}
			return;
			}
		}

	reporter->InternalError("didn't find matching block defs");
	}

bool RD_Decorate::CheckLHS(const Expr* lhs, const Expr* e)
	{
	// e can be an EXPR_ASSIGN or an EXPR_APPEND_TO.
	auto rhs = e->GetOp2();

	switch ( lhs->Tag() ) {
	case EXPR_REF:
		{
		auto r = lhs->AsRefExpr();
		mgr.SetPreFromPre(r->Op(), lhs);
		return CheckLHS(r->Op(), e);
		}

	case EXPR_NAME:
		{
		auto n = lhs->AsNameExpr();
		auto id = n->Id();

		CreateInitPostDef(id, DefinitionPoint(e), false, rhs.get());

		return true;
		}

	case EXPR_LIST:
		{
		auto l = lhs->AsListExpr();
		for ( const auto& expr : l->Exprs() )
			{
			if ( expr->Tag() != EXPR_NAME )
				// This will happen for table initialiers,
				// for example.
				return false;

			auto n = expr->AsNameExpr();
			auto id = n->Id();

			// Since the typing on the RHS may be dynamic,
			// we don't try to do any inference of possible
			// missing fields, hence "true" in the following.
			CreateInitPostDef(id, DefinitionPoint(e), true, 0);
			}

		return true;
		}

        case EXPR_FIELD:
		{
		auto f = lhs->AsFieldExpr();
		auto r = f->Op();

		if ( r->Tag() != EXPR_NAME && r->Tag() != EXPR_FIELD )
			// This is a more complicated expression that we're
			// not able to concretely track.
			return false;

		// Recurse to traverse LHS so as to install its definitions.
		mgr.SetPreFromPre(r, lhs);
		r->Traverse(this);

		auto r_def = mgr.GetExprDI(r);

		if ( ! r_def )
			// This should have already generated a complaint.
			// Avoid cascade.
			return true;

		auto fn = f->FieldName();

		auto field_rd = r_def->FindField(fn);
		auto ft = f->Type();
		if ( ! field_rd )
			field_rd = r_def->CreateField(fn, ft.get());

		CreateInitPostDef(field_rd, DefinitionPoint(e), false, rhs.get());

		return true;
		}

        case EXPR_INDEX:
		{
		auto i_e = lhs->AsIndexExpr();
		auto aggr = i_e->Op1();
		auto index = i_e->Op2();

		if ( aggr->Tag() == EXPR_NAME )
			{
			// Count this as an initialization of the aggregate.
			auto id = aggr->AsNameExpr()->Id();
			mgr.CreatePostDef(id, DefinitionPoint(e), false);

			// Don't recurse into assessing the aggregate,
			// since it's okay in this context.  However,
			// we do need to recurse into the index, which
			// could have problems.
			mgr.SetPreFromPre(index, lhs);
			index->Traverse(this);
			return true;
			}

		return false;
		}

	default:
		reporter->InternalError("bad tag in RD_Decorate::CheckLHS");
	}
	}

bool RD_Decorate::IsAggr(const Expr* e) const
	{
	if ( e->Tag() != EXPR_NAME )
		return false;

	auto n = e->AsNameExpr();
	auto id = n->Id();
	auto tag = id->Type()->Tag();

	return ::IsAggr(tag);
	}

TraversalCode RD_Decorate::PreExpr(const Expr* e)
	{
	ASSERT(mgr.HasPreMinRDs(e));
	ASSERT(mgr.HasPreMaxRDs(e));

	// Since there are no control flow or confluence issues (the latter
	// holds when working on reduced expressions; perverse assignments
	// inside &&/|| introduce confluence issues, but that won't lead
	// to optimization issues, just imprecision in tracking uninitialized
	// values).
	mgr.SetPostFromPre(e);

	switch ( e->Tag() ) {
        case EXPR_NAME:
		{
		auto n = e->AsNameExpr();
		auto id = n->Id();

		if ( id->IsGlobal() )
			break;

		if ( analysis_options.usage_issues > 0 &&
		     ! mgr.HasPreMinRD(e, id) && ! id->FindAttr(ATTR_IS_SET) )
			e->Error("used without definition");

		if ( id->Type()->Tag() == TYPE_RECORD )
			{
			auto di = mgr.GetID_DI(id);
			auto e_pre = mgr.GetPreMinRDs(e);
			CheckRecordRDs(di, DefinitionPoint(n), e_pre, e);
			}
		break;
		}

	case EXPR_LIST:
		{
		auto l = e->AsListExpr();
		for ( const auto& expr : l->Exprs() )
			mgr.SetPreFromPre(expr, e);

		break;
		}

        case EXPR_INCR:
        case EXPR_DECR:
		{
		auto lval = e->GetOp1();
		auto lhs = lval->AsRefExpr()->Op();

		mgr.SetPreFromPre(lval.get(), e);

		if ( lhs->Tag() == EXPR_NAME )
			(void) CheckLHS(lhs, e);
		break;
		}

        case EXPR_ADD_TO:
		{
		auto a_t = e->AsAddToExpr();
		auto lhs = a_t->Op1();
		auto rhs = a_t->Op2();

		mgr.SetPreFromPre(lhs, e);
		mgr.SetPreFromPre(rhs, e);

		if ( IsAggr(lhs) )
			{
			auto lhs_n = lhs->AsNameExpr();
			auto lhs_id = lhs_n->Id();

			// Treat this as an initalization of the set.
			mgr.CreatePostDef(lhs_id, DefinitionPoint(a_t), false);

			mgr.SetPreFromPre(rhs, e);
			rhs->Traverse(this);

			return TC_ABORTSTMT;
			}

		break;
		}

        case EXPR_ASSIGN:
		{
		auto a = e->AsAssignExpr();
		auto lhs = a->Op1();
		auto rhs = a->Op2();

		bool rhs_aggr = IsAggr(rhs);

		mgr.SetPreFromPre(lhs, a);
		mgr.SetPreFromPre(rhs, a);

		if ( CheckLHS(lhs, a) )
			{
			if ( ! rhs_aggr )
				rhs->Traverse(this);

			return TC_ABORTSTMT;
			}

		if ( rhs_aggr )
			{
			// No need to analyze the RHS.
			lhs->Traverse(this);
			return TC_ABORTSTMT;
			}

		// Too hard to figure out what's going on with the assignment.
		// Just analyze it in terms of values it accesses.
		break;
		}

        case EXPR_INDEX_ASSIGN:
		{
		auto a = e->AsIndexAssignExpr();
		auto aggr = a->Op1();
		auto index = a->Op2();
		auto rhs = a->GetOp3().get();

		bool rhs_aggr = IsAggr(rhs);

		mgr.SetPreFromPre(aggr, a);
		mgr.SetPreFromPre(index, a);
		mgr.SetPreFromPre(rhs, a);

		if ( aggr->Tag() == EXPR_NAME )
			{
			// Don't treat this as an initialization of the
			// aggregate, since what's changing is instead
			// an element of it.
			}
		else
			aggr->Traverse(this);

		index->Traverse(this);
		rhs->Traverse(this);

		return TC_ABORTSTMT;
		}

        case EXPR_FIELD_LHS_ASSIGN:
		{
		auto f = e->AsFieldLHSAssignExpr();
		auto aggr = f->Op1();
		auto r = f->Op2();

		mgr.SetPreFromPre(aggr, e);
		mgr.SetPreFromPre(r, e);

		if ( aggr->Tag() == EXPR_NAME )
			{
			// Don't treat as an initialization of the aggregate.
			}
		else
			aggr->Traverse(this);

		r->Traverse(this);

		auto r_def = mgr.GetExprDI(aggr);
		if ( ! r_def )
			// This should have already generated a complaint.
			// Avoid cascade.
			break;

		auto offset = f->Field();
		auto field_rd = r_def->FindField(offset);

		auto ft = f->Type();
		if ( ! field_rd )
			field_rd = r_def->CreateField(offset, ft.get());

		CreateInitPostDef(field_rd, DefinitionPoint(e), false, r);

		return TC_ABORTSTMT;
		}

	case EXPR_FIELD:
		{
		auto f = e->AsFieldExpr();
		auto r = f->Op();

		mgr.SetPreFromPre(r, e);

		if ( r->Tag() != EXPR_NAME && r->Tag() != EXPR_FIELD )
			break;

		r->Traverse(this);

		if ( r->Tag() == EXPR_NAME )
			{
			auto r_n = r->AsNameExpr();
			if ( r_n->Id()->IsGlobal() )
				// Don't worry about record fields in globals.
				return TC_ABORTSTMT;
			}

		if ( analysis_options.usage_issues > 1 )
			{
			auto r_def = mgr.GetExprDI(r);

			if ( r_def )
				{
				auto fn = f->FieldName();
				auto field_rd = mgr.GetConstID_DI(r_def, fn);

				auto e_pre = mgr.GetPreMinRDs(e);
				if ( ! field_rd || ! e_pre->HasDI(field_rd) )
					printf("no reaching def for %s\n", obj_desc(e));
				}
			}

		return TC_ABORTSTMT;
		}

	case EXPR_HAS_FIELD:
		{
		auto hf = e->AsHasFieldExpr();
		auto r = hf->Op();

		mgr.SetPreFromPre(r, e);

		// Treat this as a definition of r$fn, since it's
		// assuring that that field exists.  That's not quite
		// right, since this expression's parent could be a
		// negation, but at least we know that the script
		// writer is thinking about whether it's defined.

		if ( r->Tag() == EXPR_NAME )
			{
			auto id_e = r->AsNameExpr();
			auto id = id_e->Id();
			auto id_rt = id_e->Type()->AsRecordType();
			auto id_di = mgr.GetID_DI(id);

			if ( ! id_di && ! analysis_options.inliner )
				{
				printf("no ID reaching def for %s\n", id->Name());
				break;
				}

			auto fn = hf->FieldName();
			auto field_rd = id_di->FindField(fn);
			if ( ! field_rd )
				{
				auto ft = id_rt->FieldType(fn);
				field_rd = id_di->CreateField(fn, ft);
				CreateInitPostDef(field_rd, DefinitionPoint(hf),
							false, 0);
				}
			}

		break;
		}

	case EXPR_CALL:
		{
		auto c = e->AsCallExpr();
		auto f = c->Func();
		auto args_l = c->Args();

		// If one of the arguments is an aggregate, then
		// it's actually passed by reference, and we shouldn't
		// ding it for not being initialized.  In addition,
		// we should treat this as a definition of the
		// aggregate, because while it can't be actually
		// reassigned, all of its dynamic properties can change
		// due to the call.  (In the future, we could consider
		// analyzing the call to see whether this is in fact
		// the case.
		//
		// We handle all of this by just doing the traversal
		// ourselves.
		mgr.SetPreFromPre(f, e);
		f->Traverse(this);

		mgr.SetPreFromPre(args_l, e);

		for ( const auto& expr : args_l->Exprs() )
			{
			mgr.SetPreFromPre(expr, e);

			if ( IsAggr(expr) )
				// Not only do we skip analyzing it, but
				// we consider it initialized post-return.
				mgr.CreatePostDef(expr->AsNameExpr()->Id(), 
						DefinitionPoint(c), false);
			else
				expr->Traverse(this);
			}

		// Kill definitions dependent on globals that might have
		// been modified by the call.  In the future, we can
		// aim to comprehensively understand which globals could
		// possibly be altered, but for now we just assume they
		// call could.
		for ( const auto& g : pf->globals )
			if ( ! g->IsConst() )
				mgr.CreatePostDef(g, DefinitionPoint(c), false);

		return TC_ABORTSTMT;
		}

	case EXPR_INLINE:
		{
		ASSERT(0);
		auto inl = e->AsInlineExpr();
		mgr.SetPreFromPre(inl->Args().get(), inl);
		mgr.SetPreFromPre(inl->Body().get(), inl);
		break;
		}

	case EXPR_COND:
		// Special hack.  We don't bother traversing the operands
		// of conditionals.  This is because we use them heavily
		// to deconstruct logical expressions for which the
		// actual operand access is safe (guaranteed not to
		// access a value that hasn't been undefined), but the
		// flow analysis has trouble determining that.  In principle
		// we could do a bit better here and only traverse operands
		// that aren't temporaries, but that's a bit of a pain
		// to discern.
		mgr.SetPreFromPre(e->GetOp1().get(), e);
		mgr.SetPreFromPre(e->GetOp2().get(), e);
		mgr.SetPreFromPre(e->GetOp3().get(), e);

		e->GetOp1()->Traverse(this);

		return TC_ABORTSTMT;

	case EXPR_LAMBDA:
		// ### Too tricky to get these right.
		return TC_ABORTSTMT;

	default:
		if ( e->GetOp1() )
			mgr.SetPreFromPre(e->GetOp1().get(), e);
		if ( e->GetOp2() )
			mgr.SetPreFromPre(e->GetOp2().get(), e);
		if ( e->GetOp3() )
			mgr.SetPreFromPre(e->GetOp3().get(), e);

		break;
	}

	return TC_CONTINUE;
	}

TraversalCode RD_Decorate::PostExpr(const Expr* e)
	{
	if ( e->Tag() == EXPR_APPEND_TO )
		{
		// We don't treat the expression as an initialization
		// in the PreExpr phase, because we want to catch a
		// possible uninitialized LHS.  But now we can since
		// it's definitely initialized after executing.
		auto lhs = e->GetOp1();

		(void) CheckLHS(lhs.get(), e);
		}

	return TC_CONTINUE;
	}

void RD_Decorate::TrackInits(const Func* f, const id_list* inits)
	{
	// This code is duplicated for STMT_INIT.  It's a pity that
	// that doesn't get used for aggregates that are initialized
	// just incidentally.
	for ( int i = 0; i < inits->length(); ++i )
		{
		auto id = (*inits)[i];
		auto id_t = id->Type();

		// Only aggregates get initialized.
		auto tag = id_t->Tag();
		if ( ::IsAggr(tag) )
			CreateInitPostDef(id, DefinitionPoint(f), false, 0);
		}
	}

void RD_Decorate::CreateInitPreDef(const ID* id, DefinitionPoint dp)
	{
	auto di = mgr.GetID_DI(id);
	if ( ! di )
		return;

	CreateInitDef(di, dp, true, true, nullptr);
	}

void RD_Decorate::CreateInitPostDef(const ID* id, DefinitionPoint dp,
				bool assume_full, const Expr* rhs)
	{
	auto di = mgr.GetID_DI(id);
	if ( ! di )
		return;

	CreateInitDef(di, dp, false, assume_full, rhs);
	}

void RD_Decorate::CreateInitPostDef(DefinitionItem* di, DefinitionPoint dp,
				bool assume_full, const Expr* rhs)
	{
	CreateInitDef(di, dp, false, assume_full, rhs);
	}

void RD_Decorate::CreateInitDef(DefinitionItem* di, DefinitionPoint dp,
				bool is_pre, bool assume_full,
				const Expr* rhs)
	{
	if ( is_pre )
		mgr.CreatePreDef(di, dp, false);
	else
		mgr.CreatePostDef(di, dp, false);

	if ( di->Type()->Tag() != TYPE_RECORD )
		return;

	const DefinitionItem* rhs_di = nullptr;

	if ( rhs )
		{
		if ( rhs->Type()->Tag() == TYPE_ANY )
			// All bets are off.
			assume_full = true;

		else
			{
			rhs_di = mgr.GetExprDI(rhs);

			if ( ! rhs_di )
				// This happens because the RHS is an
				// expression more complicated than just a
				// variable or a field reference.  Just assume
				// it's fully initialized.
				assume_full = true;
			}
		}

	CreateRecordRDs(di, dp, is_pre, assume_full, rhs_di);
	}

void RD_Decorate::CreateRecordRDs(DefinitionItem* di, DefinitionPoint dp,
				bool is_pre, bool assume_full,
				const DefinitionItem* rhs_di)
	{
	auto rt = di->Type()->AsRecordType();
	auto n = rt->NumFields();

	for ( auto i = 0; i < n; ++i )
		{
		auto n_i = rt->FieldName(i);
		auto t_i = rt->FieldType(i);
		auto rhs_di_i = rhs_di ? rhs_di->FindField(n_i) : nullptr;

		bool field_is_defined = false;

		if ( assume_full )
			field_is_defined = true;

		else if ( rhs_di_i )
			field_is_defined = true;

		else if ( rt->FieldHasAttr(i, ATTR_DEFAULT) )
			field_is_defined = true;

		else if ( ! rt->FieldHasAttr(i, ATTR_OPTIONAL) &&
			  ! is_atomic_type(t_i) )
			// Non-optional aggregates within records will be
			// initialized.
			field_is_defined = true;

		if ( ! field_is_defined )
			continue;

		auto di_i = di->CreateField(n_i, t_i);

		if ( is_pre )
			mgr.CreatePreDef(di_i, dp, true);
		else
			mgr.CreatePostDef(di_i, dp, true);

		if ( analysis_options.usage_issues > 1 )
			if ( t_i->Tag() == TYPE_RECORD )
				CreateRecordRDs(di_i, dp, is_pre,
						assume_full, rhs_di_i);
		}
	}

void RD_Decorate::CheckRecordRDs(DefinitionItem* di, DefinitionPoint dp,
					const RD_ptr& pre_rds, const BroObj* o)
	{
	auto rt = di->Type()->AsRecordType();
	auto num_fields = rt->NumFields();

	for ( auto i = 0; i < num_fields; ++i )
		{
		if ( rt->FieldHasAttr(i, ATTR_DEFAULT) ||
		     rt->FieldHasAttr(i, ATTR_OPTIONAL) )
			continue;

		auto n_i = rt->FieldName(i);
		auto field_di = di->FindField(n_i);

		if ( analysis_options.usage_issues <= 1 )
			continue;

		// The following works correctly, but finds a number
		// of places in the base scripts where indeed non-optional
		// record elements are not initialized.
		if ( ! field_di || ! pre_rds->HasDI(field_di) )
			{
			printf("%s$%s (%s) may be used without definition\n",
				di->Name(), n_i, obj_desc(o));
			}

		else
			{
			// The following allows us to comprehensively track
			// nested records to see if any uninitialized elements
			// might be used.  However, it is also computationally
			// very heavy if run on the full code base because
			// there are some massive records (in some places
			// nested 5 deep).
			auto t_i = rt->FieldType(i);
			if ( t_i->Tag() == TYPE_RECORD )
				CheckRecordRDs(field_di, dp, pre_rds, o);
			}
		}

	CreateRecordRDs(di, dp, false, nullptr);
	}
