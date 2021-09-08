// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/GenRDs.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/Scope.h"
#include "zeek/Reporter.h"
#include "zeek/Desc.h"


namespace zeek::detail {


RD_Decorate::RD_Decorate(std::shared_ptr<ProfileFunc> _pf, const Func* f,
                         ScopePtr scope, StmtPtr body)
: pf(std::move(_pf))
	{
	TraverseFunction(f, scope, body);
	}

void RD_Decorate::TraverseFunction(const Func* f, ScopePtr scope, StmtPtr body)
	{
	func_flavor = f->Flavor();

	const auto& args = scope->OrderedVars();
	int nparam = f->GetType()->Params()->NumFields();

	mgr.SetEmptyPre(f);

	for ( const auto& a : args )
		{
		if ( --nparam < 0 )
			break;

		CreateInitPostDef(a.get(), DefinitionPoint(f), true, nullptr);
		}

	for ( const auto& g : pf->Globals() )
		CreateInitPostDef(g, DefinitionPoint(f), true, nullptr);

	if ( ! mgr.HasPostMinRDs(f) )
		// This happens if we have no arguments or globals.  Use the
		// empty ones we set up.
		mgr.SetPostFromPre(f);

	mgr.SetPreFromPost(body.get(), f);
	body->Traverse(this);
	}

TraversalCode RD_Decorate::PreStmt(const Stmt* s)
	{
	ASSERT(mgr.HasPreMinRDs(s));
	ASSERT(mgr.HasPreMaxRDs(s));

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

		mgr.SetPreFromPre(block, s);
		block->Traverse(this);

		// Treat the block as a no-op for analyzing RDs,
		// since it shouldn't affect the definition status of
		// any of the RDs outside of it.  (The one exception is
		// for globals, which we can address by synchronizing
		// globals after inlined returns.)  The only question is
		// how to propagate RDs relating to the return value.
		mgr.SetPostFromPre(s);

		auto ret_var = cr->RetVar();
		if ( ret_var )
			{
			// Ideally for the return variable (if any) we'd track
			// whether all of the paths out of the block go through
			// a "return <expr>".  One way we could do that would
			// be to literally assign it for internal returns.
			// The trick with that is it could entail some subtle
			// debugging of how RDs are propagated across internal
			// returns.  For now, we punt and just mark it as
			// defined.  This doesn't lead to any incorrect
			// optimization decisions, it just misses out on
			// an opportunity to flag a potential return-without-
			// value ... but only in the case where we're using
			// inlining, too.
			CreateInitPostDef(ret_var->Id(), DefinitionPoint(s),
						true, nullptr);
			}

		return TC_ABORTSTMT;
		}

	case STMT_LIST:
		{
		auto sl = s->AsStmtList();
		const auto& stmts = sl->Stmts();
		const Stmt* pred_stmt = s;	// current Stmt's predecessor

		for ( const auto& stmt : stmts )
			{
			if ( pred_stmt == s )
				mgr.SetPreFromPre(stmt, pred_stmt);
			else
				mgr.SetPreFromPost(stmt, pred_stmt);

			stmt->Traverse(this);
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
		// non-reduced code) - but in any case a ?$ operator can
		// create pseudo-definitions, so we have to accommodate that
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
				mgr.SetPostFromPost(s, i->TrueBranch());

			else if ( false_reached )
				mgr.SetPostFromPost(s, i->FalseBranch());

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
			CreateInitPreDef(val_var.get(), DefinitionPoint(body));

		// If the loop expression's value is uninitialized, that's
		// okay, it will just result in an empty loop.  In principle,
		// for a non-reduced statement it's possible that *getting*
		// to the value will touch on something uninitialized.
		// For reduced form, however, that will already have been
		// hoisted out, so not a concern.
		//
		// To keep from traversing the loop expression, we just do
		// the body manually here.

		block_defs.emplace_back(std::make_unique<BlockDefs>(false));

		body->Traverse(this);

		DoLoopConfluence(s, body, body);

		return TC_ABORTSTMT;
		}

	case STMT_WHILE:
		{
		auto w = s->AsWhileStmt();
		auto cond = w->Condition().get();

		// This is the *predecessor* statement, i.e., what
		// gets executed (due to transformation-to-reduced-form)
		// prior to evaluating the conditional.
		auto cond_stmt = w->CondPredStmt().get();

		// This is the *conditional itself*, but as a statement.
		auto cond_s = w->ConditionAsStmt().get();

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

		auto body = w->Body().get();
		mgr.SetPreFromPre(body, cond);

		block_defs.emplace_back(std::make_unique<BlockDefs>(false));

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

	block_defs.emplace_back(std::make_unique<BlockDefs>(true));
	auto bd = block_defs.back().get();

	RDPtr sw_post_min_rds = nullptr;
	RDPtr sw_post_max_rds = nullptr;

	if ( sw->HasDefault() )
		// Guaranteed that we'll execute one of the switch blocks.
		// Start with an empty set of RDs for the post-max and
		// build them up via union.
		sw_post_max_rds = make_intrusive<ReachingDefs>();

	else
		{
		// Entire set of cases is optional, so merge in entering RDs.
		mgr.SetPostFromPre(sw);

		sw_post_min_rds = mgr.GetPostMinRDs(sw);
		sw_post_max_rds = mgr.GetPostMaxRDs(sw);
		}

	// Used to track fall-through.
	RDPtr prev_RDs;

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
				if ( id->Name() )
					CreateInitPreDef(id, DefinitionPoint(body));
			}

		auto body_min_pre = mgr.GetPreMinRDs(body);
		auto body_max_pre = mgr.GetPreMaxRDs(body);

		// Don't inherit body-def analysis developed for preceding
		// switch case.
		bd->Clear();
		body->Traverse(this);

		if ( ! bd->PreRDs().empty() )
			reporter->InternalError("mispropagation of switch body defs");

		if ( body->NoFlowAfter(true) )
			// Post RDs for this block are irrelevant.
			continue;

		// Propagate what comes out of the block.
		auto case_min_rd = mgr.GetPostMinRDs(body);
		auto case_max_rd = mgr.GetPostMaxRDs(body);

		// Look for any definitions reflecting break or fallthrough
		// short-circuiting.  These only matter for max RDs.
		for ( const auto& post : bd->PostRDs() )
			case_max_rd = case_max_rd->Union(post);

		// Scoop up definitions from fallthrough's and remember
		// them for the next block.
		for ( const auto& future : bd->FutureRDs() )
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
				make_intrusive<ReachingDefs>(case_min_rd);

		sw_post_max_rds = sw_post_max_rds->Union(case_max_rd);
		}

	if ( ! sw_post_min_rds )
		// This happens when all of the cases return, including
		// a default.  In that case, sw_post_max_rds is already
		// an empty RD.
		sw_post_min_rds = make_intrusive<ReachingDefs>();

	mgr.SetPostRDs(sw, std::move(sw_post_min_rds), std::move(sw_post_max_rds));

	block_defs.pop_back();
	}

void RD_Decorate::DoIfStmtConfluence(const IfStmt* i)
	{
	auto min_if_branch_rd = mgr.GetPostMinRDs(i->TrueBranch());
	auto min_else_branch_rd = mgr.GetPostMinRDs(i->FalseBranch());
	auto min_post_rds = min_if_branch_rd->Intersect(min_else_branch_rd);

	auto max_if_branch_rd = mgr.GetPostMaxRDs(i->TrueBranch());
	auto max_else_branch_rd = mgr.GetPostMaxRDs(i->FalseBranch());
	auto max_post_rds = max_if_branch_rd->Union(max_else_branch_rd);

	mgr.SetPostRDs(i, std::move(min_post_rds), std::move(max_post_rds));
	}

void RD_Decorate::DoLoopConfluence(const Stmt* s, const Stmt* top,
					const Stmt* body)
	{
	auto bd = std::move(block_defs.back());
	block_defs.pop_back();

	auto loop_pre = mgr.GetPreMaxRDs(top);
	auto loop_post = mgr.GetPostMaxRDs(body);

	for ( const auto& pre : bd->PreRDs() )
		{
		mgr.MergeIntoPre(top, pre);

		// Factor in that these definitions also
		// essentially make it to the beginning of
		// the entire loop.
		mgr.MergeIntoPre(s, pre);
		}

	for ( const auto& post : bd->PostRDs() )
		mgr.MergeIntoPost(body, post);

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

		block_defs.emplace_back(std::make_unique<BlockDefs>(false));
		body->Traverse(this);
		block_defs.pop_back();

		// Ideally we'd check for consistency with the previous
		// definitions in bd.  This is tricky because the body
		// itself might not have RDs if it ends in a "break" or
		// such.
		}

	DefinitionPoint ds(s);

	// Factor in that the loop might not execute at all.
	auto s_min_pre = mgr.GetPreMinRDs(s);
	auto s_max_pre = mgr.GetPreMaxRDs(s);

	// For min RDs, we want to compute them directly regardless
	// of whether the loop body has flow reaching the end of it,
	// since an internal "next" can still cause definitions to
	// propagate to the beginning.
	auto min_post_rds = s_min_pre->IntersectWithConsolidation(loop_min_post, ds);
	mgr.SetPostMinRDs(s, std::move(min_post_rds));

	// Note, we use ignore_break=true because what we care about is not
	// whether flow goes just beyond the last statement of the body,
	// but rather whether flow can start at the next statement *after*
	// the body, and a "break" will do that.
	if ( body->NoFlowAfter(true) )
		mgr.SetPostMaxRDs(s, s_max_pre);
	else
		{
		auto max_post_rds = s_max_pre->Union(loop_max_post);
		mgr.SetPostMaxRDs(s, std::move(max_post_rds));
		}
	}

TraversalCode RD_Decorate::PostStmt(const Stmt* s)
	{
	DefinitionPoint ds(s);

	switch ( s->Tag() ) {
	case STMT_EXPR:
		{
		auto e = s->AsExprStmt()->StmtExpr();
		mgr.SetPostFromPost(s, e);
		break;
		}

	case STMT_INIT:
		{
		mgr.SetPostFromPre(s);

		auto init = s->AsInitStmt();
		auto& inits = init->Inits();

		for ( const auto& id : inits )
			{
			auto id_t = id->GetType();

			// Only aggregates get initialized.
			if ( ! zeek::IsAggr(id_t->Tag()) )
				continue;

			CreateInitPostDef(id.get(), DefinitionPoint(s), false, 0);
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
		if ( block_defs.empty() )
			{
			if ( func_flavor == FUNC_FLAVOR_HOOK )
				// Treat as a return.
				CreateEmptyPostRDs(s);
			else
				s->Error("\"break\" in a non-break context");
			break;
			}

		AddBlockDefs(s, false, false, block_defs.back()->IsCase());

		if ( block_defs.back()->IsCase() )
			// The following propagates min RDs so they can
			// be intersected across switch cases.
			mgr.SetPostFromPre(s);
		else
			CreateEmptyPostRDs(s);

		break;

	case STMT_FALLTHROUGH:
		AddBlockDefs(s, false, true, true);
		mgr.SetPostFromPre(s);
		break;

	default:
		mgr.SetPostFromPre(s);
		break;
	}

	return TC_CONTINUE;
	}

void RD_Decorate::CreateEmptyPostRDs(const Stmt* s)
	{
	auto empty_rds = make_intrusive<ReachingDefs>();
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
		auto& bd = block_defs[i];

		if ( bd->IsCase() == is_case )
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
		{ // look for [a, b, c] = any_val
		auto l = lhs->AsListExpr();
		for ( const auto& expr : l->Exprs() )
			{
			if ( expr->Tag() != EXPR_NAME )
				// This will happen for table initializers,
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
		if ( ! field_rd )
			field_rd = r_def->CreateField(fn, f->GetType());

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

			// Don't recurse into assessing the aggregate itself,
			// since it's okay in this context.  However, we do
			// need to recurse into the index, which could have
			// problems (references to possibly uninitialized
			// values).
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
	auto tag = id->GetType()->Tag();

	return zeek::IsAggr(tag);
	}

void RD_Decorate::CheckVar(const Expr* e, const ID* id, bool check_fields)
	{
	if ( id->IsGlobal() )
		return;

	if ( analysis_options.usage_issues > 0 &&
	     ! mgr.HasPreMinRD(e, id) && ! id->GetAttr(ATTR_IS_ASSIGNED) )
		e->Warn("possibly used without definition");

	if ( check_fields && id->GetType()->Tag() == TYPE_RECORD )
		{
		auto di = mgr.GetID_DI(id);
		auto e_pre = mgr.GetPreMinRDs(e);
		CheckRecordRDs(di, DefinitionPoint(e), e_pre, e);
		}
	}

TraversalCode RD_Decorate::PreExpr(const Expr* e)
	{
	ASSERT(mgr.HasPreMinRDs(e));
	ASSERT(mgr.HasPreMaxRDs(e));

	// There are no control flow or confluence issues - the latter
	// holds when working on reduced expressions; perverse assignments
	// inside &&/|| introduce confluence issues, but that won't lead
	// to optimization issues, just imprecision in tracking uninitialized
	// values.
	mgr.SetPostFromPre(e);

	switch ( e->Tag() ) {
	case EXPR_NAME:
		CheckVar(e, e->AsNameExpr()->Id(), true);
		break;

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
		auto lhs = lval->AsRefExprPtr()->Op();

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

		if ( lhs->Tag() == EXPR_LIST &&
		     rhs->GetType()->Tag() != TYPE_ANY )
			{
			// This combination occurs only for assignments used
			// to initialize table entries.  Treat it as references
			// to both the lhs and the rhs, not as an assignment.
			mgr.SetPreFromPre(a->GetOp1().get(), a);
			mgr.SetPreFromPre(a->GetOp2().get(), a);
			return TC_CONTINUE;
			}

		bool rhs_aggr = IsAggr(rhs);

		mgr.SetPreFromPre(lhs, a);
		mgr.SetPreFromPre(rhs, a);

		if ( ! rhs_aggr )
			{
			rhs->Traverse(this);

			// The RHS could have established a pseudo-RD
			// due to a ?$ operation.
			mgr.SetPostFromPost(e, rhs);
			}

		if ( CheckLHS(lhs, a) )
			return TC_ABORTSTMT;

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

		if ( ! field_rd )
			field_rd = r_def->CreateField(offset, f->GetType());

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

		if ( analysis_options.usage_issues > 1 )
			{
			auto r_def = mgr.GetExprDI(r);

			if ( r_def && ! r_def->RootID()->GetAttr(ATTR_IS_ASSIGNED) )
				{
				auto fn = f->FieldName();
				auto field_rd = mgr.GetConstID_DI(r_def.get(), fn);

				auto e_pre = mgr.GetPreMinRDs(e);
				if ( ! field_rd || ! e_pre->HasDI(field_rd) )
					printf("record field possibly used without being set: %s\n", obj_desc(e).c_str());
				}
			}

		if ( r->Tag() == EXPR_NAME )
			{
			auto r_id = r->AsNameExpr()->Id();
			if ( r_id->IsGlobal() )
				// Don't worry about record fields in globals.
				return TC_ABORTSTMT;

			// For names, we care about checking the name
			// itself, but if it's a record we don't want to
			// complain about missing fields, as they're
			// irrelevant other than the one specifically
			// being referenced.  So we do the CheckVar here
			// and don't descend recursively.
			CheckVar(r, r_id, false);
			}

		else
			// Recursively check the subexpression.
			r->Traverse(this);

		return TC_ABORTSTMT;
		}

	case EXPR_HAS_FIELD:
		{
		auto hf = e->AsHasFieldExpr();
		auto r = hf->Op();

		mgr.SetPreFromPre(r, e);

		// Treat this as a definition of r$fn, since it's
		// ensuring that that field exists.  That's not quite
		// right, since this expression's parent could be a
		// negation, but at least we know that the script
		// writer is thinking about whether it's defined.

		if ( r->Tag() == EXPR_NAME )
			{
			auto id_e = r->AsNameExpr();
			auto id = id_e->Id();
			auto id_rt = id_e->GetType()->AsRecordType();
			auto id_di = mgr.GetID_DI(id);

			if ( ! id_di )
				{
				printf("%s possibly used without definition\n",
					id->Name());
				break;
				}

			auto fn = hf->FieldName();
			auto ft = id_rt->GetFieldType(fn);
			auto field_rd = id_di->CreateField(fn, std::move(ft));

			CreateInitPostDef(field_rd, DefinitionPoint(hf),
						true, 0);

			// Don't analyze r itself, since it's not expected
			// to be defined here.
			return TC_ABORTSTMT;
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
		// the case.)
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
		// all could.
		for ( const auto& g : pf->Globals() )
			if ( ! g->IsConst() )
				mgr.CreatePostDef(g, DefinitionPoint(c), false);

		return TC_ABORTSTMT;
		}

	case EXPR_INLINE:
		{
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

	case EXPR_RECORD_CONSTRUCTOR:
		{
		auto r = static_cast<const RecordConstructorExpr*>(e);
		auto l = r->Op();
		mgr.SetPreFromPre(l.get(), e);
		break;
		}

	case EXPR_LAMBDA:
		{
		auto l = static_cast<const LambdaExpr*>(e);
		const auto& ids = l->OuterIDs();

		for ( auto& id : ids )
			CheckVar(e, id, false);

		// Don't descend into the lambda body - we analyze and
		// optimize it separately, as its own function.
		return TC_ABORTSTMT;
		}

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

void RD_Decorate::CreateInitPostDef(std::shared_ptr<DefinitionItem> di,
					DefinitionPoint dp, bool assume_full,
					const Expr* rhs)
	{
	CreateInitDef(std::move(di), dp, false, assume_full, rhs);
	}

void RD_Decorate::CreateInitDef(std::shared_ptr<DefinitionItem> di,
				DefinitionPoint dp, bool is_pre,
				bool assume_full, const Expr* rhs)
	{
	if ( is_pre )
		mgr.CreatePreDef(di, dp, false);
	else
		mgr.CreatePostDef(di, dp, false);

	if ( di->GetType()->Tag() != TYPE_RECORD )
		return;

	std::shared_ptr<DefinitionItem> rhs_di;

	if ( rhs )
		{
		if ( rhs->GetType()->Tag() == TYPE_ANY )
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

	CreateRecordRDs(std::move(di), dp, is_pre, assume_full, rhs_di.get());
	}

void RD_Decorate::CreateRecordRDs(std::shared_ptr<DefinitionItem> di,
					DefinitionPoint dp,
					bool is_pre, bool assume_full,
					const DefinitionItem* rhs_di)
	{
	auto rt = di->GetType()->AsRecordType();
	auto n = rt->NumFields();

	for ( auto i = 0; i < n; ++i )
		{
		auto n_i = rt->FieldName(i);
		const auto& t_i = rt->GetFieldType(i);
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

		// Only track RDs associated with record fields if we're
		// looking to report associated usage issues, because
		// it's quite expensive to do so.
		if ( analysis_options.usage_issues > 1 )
			if ( t_i->Tag() == TYPE_RECORD )
				CreateRecordRDs(di_i, dp, is_pre,
						assume_full, rhs_di_i.get());
		}
	}

void RD_Decorate::CheckRecordRDs(std::shared_ptr<DefinitionItem> di,
					DefinitionPoint dp,
					const RDPtr& pre_rds, const Obj* o)
	{
	CreateRecordRDs(di, dp, false, nullptr);

	auto root_id = di->RootID();
	if ( root_id->GetAttr(ATTR_IS_ASSIGNED) )
		// No point checking for unset fields.
		return;

	auto rt = di->GetType()->AsRecordType();
	auto num_fields = rt->NumFields();

	for ( auto i = 0; i < num_fields; ++i )
		{
		if ( rt->FieldHasAttr(i, ATTR_DEFAULT) ||
		     rt->FieldHasAttr(i, ATTR_OPTIONAL) ||
		     rt->FieldHasAttr(i, ATTR_IS_ASSIGNED) )
			continue;

		auto n_i = rt->FieldName(i);
		auto field_di = di->FindField(n_i);

		if ( analysis_options.usage_issues <= 1 )
			continue;

		// The following works correctly, but finds a number
		// of places in the base scripts where indeed non-optional
		// record elements are not initialized.
		if ( ! field_di || ! pre_rds->HasDI(field_di.get()) )
			{
			printf("%s$%s (%s) possibly used without being set\n",
				di->Name(), n_i, obj_desc(o).c_str());
			}

		else
			{
			// The following allows us to comprehensively track
			// nested records to see if any uninitialized elements
			// might be used.  However, it is also computationally
			// very heavy if run on the full code base because
			// there are some massive records (in some places
			// nested 5 deep).
			const auto& t_i = rt->GetFieldType(i);
			if ( t_i->Tag() == TYPE_RECORD )
				CheckRecordRDs(field_di, dp, pre_rds, o);
			}
		}
	}


} // zeek::detail
