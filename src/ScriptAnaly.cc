// See the file "COPYING" in the main distribution directory for copyright.

#include "ScriptAnaly.h"
#include "DefSetsMgr.h"
#include "ProfileFunc.h"
#include "Reduce.h"
#include "Inline.h"
#include "ZAM.h"
#include "Desc.h"
#include "Expr.h"
#include "Stmt.h"
#include "Scope.h"
#include "EventRegistry.h"
#include "Traverse.h"
#include "Reporter.h"
#include "module_util.h"


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

class RD_Decorate : public TraversalCallback {
public:
	RD_Decorate(const ProfileFunc* pf);

	void TraverseFunction(const Func*, Scope* scope,
				IntrusivePtr<Stmt> body);

	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PostStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;
	TraversalCode PostExpr(const Expr*) override;

	void TrackInits(const Func* f, const id_list* inits);

	const DefSetsMgr* GetDefSetsMgr() const	{ return &mgr; }

protected:
	void TraverseSwitch(const SwitchStmt* sw);
	void DoIfStmtConfluence(const IfStmt* i);
	void DoLoopConfluence(const Stmt* s, const Stmt* top, const Stmt* body);
	bool CheckLHS(const Expr* lhs, const Expr* a);

	bool IsAggrTag(TypeTag tag) const;
	bool IsAggr(const Expr* e) const;

	bool ControlCouldReachEnd(const Stmt* s, bool ignore_break) const;

	void CreateInitPreDef(const ID* id, DefinitionPoint dp);

	void CreateInitPostDef(const ID* id, DefinitionPoint dp,
				bool assume_full, const Expr* rhs);

	void CreateInitPostDef(DefinitionItem* di, DefinitionPoint dp,
				bool assume_full, const Expr* rhs);

	void CreateInitDef(DefinitionItem* di, DefinitionPoint dp, bool is_pre,
				bool assume_full, const Expr* rhs);

	void CreateRecordRDs(DefinitionItem* di, DefinitionPoint dp,
				bool assume_full, const DefinitionItem* rhs_di)
		{ CreateRecordRDs(di, dp, false, assume_full, rhs_di); }
	void CreateRecordRDs(DefinitionItem* di, DefinitionPoint dp, bool is_pre,
				bool assume_full, const DefinitionItem* rhs_di);

	void CheckRecordRDs(DefinitionItem* di, DefinitionPoint dp,
					const RD_ptr& pre_rds, const BroObj* o);

	void CreateEmptyPostRDs(const Stmt* s);
	void AddBlockDefs(const Stmt* s,
				bool is_pre, bool is_future, bool is_case);

	const ProfileFunc* pf;
	DefSetsMgr mgr;
	vector<BlockDefs*> block_defs;
};


RD_Decorate::RD_Decorate(const ProfileFunc* _pf) : pf(_pf)
	{
	}


void RD_Decorate::TraverseFunction(const Func* f, Scope* scope,
					IntrusivePtr<Stmt> body)
	{
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

	if ( analysis_options.rd_trace )
		{
		printf("traversing function %s, post min RDs:\n", f->Name());
		mgr.GetPostMinRDs(f)->Dump();
		// mgr.GetPostMaxRDs(f)->Dump();
		}

	mgr.SetPreFromPost(body.get(), f);
	body->Traverse(this);
	}

TraversalCode RD_Decorate::PreStmt(const Stmt* s)
	{
	ASSERT(mgr.HasPreMinRDs(s));
	ASSERT(mgr.HasPreMaxRDs(s));

	if ( analysis_options.rd_trace )
		{
		printf("pre min RDs for stmt %s:\n", obj_desc(s));
		mgr.GetPreMinRDs(s)->Dump();
		// mgr.GetPreMaxRDs(s)->Dump();
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

			if ( analysis_options.rd_trace )
				{
				printf("post min RDs for stmt %s:\n", obj_desc(stmt));
				mgr.GetPostMinRDs(stmt)->Dump();
				// mgr.GetPostMaxRDs(stmt)->Dump();
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

		auto true_reached =
			ControlCouldReachEnd(i->TrueBranch(), false);
		auto false_reached =
			ControlCouldReachEnd(i->FalseBranch(), false);

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
			mgr.SetPreFromPost(cond, cond_stmt);
		else
			mgr.SetPreFromPost(cond, cond_s);

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

		if ( ! ControlCouldReachEnd(body, true) )
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
	DefinitionPoint di(i);
	auto min_if_branch_rd = mgr.GetPostMinRDs(i->TrueBranch());
	auto min_else_branch_rd = mgr.GetPostMinRDs(i->FalseBranch());
	auto min_post_rds =
		min_if_branch_rd->IntersectWithConsolidation(min_else_branch_rd,
								di);
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
		if ( pre != loop_pre )
			mgr.MergeIntoPre(top, pre);

	for ( const auto& post : bd->post_RDs )
		if ( post != loop_post )
			mgr.MergeIntoPost(body, post);

	// Freshen due to mergers.
	loop_pre = mgr.GetPreMaxRDs(top);
	loop_post = mgr.GetPostMaxRDs(body);

	if ( loop_pre != loop_post )
		{
		// Some body assignments reached the end.  Propagate them
		// around the loop.
		mgr.MergeIntoPre(top, loop_post);

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
		// definitions in bd.
		delete bd2;
		}

	DefinitionPoint ds(s);

	// Factor in that the loop might not execute at all.
	auto s_min_pre = mgr.GetPreMinRDs(s);
	auto s_max_pre = mgr.GetPreMaxRDs(s);

	if ( ControlCouldReachEnd(body, false) )
		{
		auto body_min_post = mgr.GetPostMinRDs(body);
		auto body_max_post = mgr.GetPostMaxRDs(body);

		auto min_post_rds =
			s_min_pre->IntersectWithConsolidation(body_min_post, ds);
		auto max_post_rds = s_max_pre->Union(body_max_post);

		mgr.CreatePostRDs(s, min_post_rds, max_post_rds);
		min_post_rds.release();
		max_post_rds.release();
		}

	else
		mgr.CreatePostRDs(s, s_min_pre, s_max_pre);

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
			if ( ! IsAggrTag(tag) )
				continue;

			CreateInitPostDef(id, DefinitionPoint(s), false, 0);
			}

		break;
		}

	case STMT_RETURN:
		// No RDs make it past a return.  It's tempting to alter
		// this for inlined "caught" returns, since changes to
		// globals *do* make it past them.  However, doing so
		// is inconsistent with ControlCouldReachEnd() treating
		// such returns as not having control flow go beyond them;
		// and changing ControlCouldReachEnd() would be incorrect
		// since it's about *immediate* control flow, not broader
		// control flow.
		CreateEmptyPostRDs(s);
		break;

	case STMT_NEXT:
		AddBlockDefs(s, true, false, false);
		CreateEmptyPostRDs(s);
		break;

	case STMT_BREAK:
		if ( block_defs.size() == 0 )
			{
			// This is presumably a break inside a hook.
			// Treat as a return.
			CreateEmptyPostRDs(s);
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

	if ( analysis_options.rd_trace )
		{
		printf("post min RDs for stmt %s:\n", obj_desc(s));
		mgr.GetPostMinRDs(s)->Dump();
		// mgr.GetPostMaxRDs(s)->Dump();
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

bool RD_Decorate::IsAggrTag(TypeTag tag) const
	{
	return tag == TYPE_VECTOR || tag == TYPE_TABLE || tag == TYPE_RECORD;
	}

bool RD_Decorate::IsAggr(const Expr* e) const
	{
	if ( e->Tag() != EXPR_NAME )
		return false;

	auto n = e->AsNameExpr();
	auto id = n->Id();
	auto tag = id->Type()->Tag();

	return IsAggrTag(tag);
	}

bool RD_Decorate::ControlCouldReachEnd(const Stmt* s, bool ignore_break) const
	{
	switch ( s->Tag() ) {
	case STMT_RETURN:
	case STMT_NEXT:
		return false;

	case STMT_BREAK:
		return ignore_break;

	case STMT_FOR:
	case STMT_WHILE:
		// The loop body might not execute at all.
		return true;

	case STMT_IF:
		{
		auto i = s->AsIfStmt();

		if ( ControlCouldReachEnd(i->TrueBranch(), ignore_break) )
			return true;

		return ControlCouldReachEnd(i->FalseBranch(), ignore_break);
		}

	case STMT_SWITCH:
		{
		auto sw = s->AsSwitchStmt();
		auto cases = sw->Cases();

		bool control_reaches_end = false;
		bool default_seen = false;
		for ( const auto& c : *cases )
			{
			bool body_def = ControlCouldReachEnd(c->Body(), true);

			if ( body_def )
				control_reaches_end = true;

			if ( (! c->ExprCases() ||
			      c->ExprCases()->Exprs().length() == 0) &&
			     (! c->TypeCases() ||
			      c->TypeCases()->length() == 0) )
				default_seen = true;
			}

		if ( ! default_seen )
			return true;

		return control_reaches_end;
		}

	case STMT_LIST:
		{
		auto l = s->AsStmtList();

		bool reaches_so_far = true;

		for ( const auto& stmt : l->Stmts() )
			{
			if ( ! reaches_so_far )
				{
				// printf("dead code: %s\n", obj_desc(stmt));
				return false;
				}

			if ( ! ControlCouldReachEnd(stmt, ignore_break) )
				reaches_so_far = false;
			}

		return reaches_so_far;
		}

	default:
		return true;
	}
	}

TraversalCode RD_Decorate::PreExpr(const Expr* e)
	{
	ASSERT(mgr.HasPreMinRDs(e));
	ASSERT(mgr.HasPreMaxRDs(e));

	if ( analysis_options.rd_trace && 0 )
		{
		printf("---\npre RDs for expr %s:\n", obj_desc(e));
		mgr.GetPreMinRDs(e)->Dump();
		// mgr.GetPreMaxRDs(e)->Dump();
		}

	// Since there are no control flow or confluence issues (the latter
	// holds when working on reduced expressions; perverse assignments
	// inside &&/|| introduce confluence issues, but that won't lead
	// to optimization issues, just imprecision in tracking uninitialized
	// values).
	mgr.SetPostFromPre(e);

	if ( analysis_options.rd_trace && 0 )
		{
		printf("---\nnominal post RDs for expr %s:\n", obj_desc(e));
		mgr.GetPostMaxRDs(e)->Dump();
		printf("---\n\n");
		}

	switch ( e->Tag() ) {
        case EXPR_NAME:
		{
		auto n = e->AsNameExpr();
		auto id = n->Id();

		if ( id->IsGlobal() )
			break;

		if ( ! mgr.HasPreMinRD(e, id) )
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

		if ( analysis_options.find_deep_uninits )
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
		// ding it for not being initialized.
		//
		// We handle this by just doing the traversal ourselves.
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
		if ( IsAggrTag(tag) )
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

		if ( analysis_options.find_deep_uninits )
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

		if ( ! analysis_options.find_deep_uninits )
			continue;

		// The following works correctly, but finds a number
		// of places in the base scripts where indeed non-optional
		// record elements are not initialized.
		if ( ! field_di || ! pre_rds->HasDI(field_di) )
			{
			printf("no reaching def for %s$%s (%s)\n",
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


void optimize_func(BroFunc* f, IntrusivePtr<Scope> scope_ptr,
			IntrusivePtr<Stmt>& body)
	{
	if ( reporter->Errors() > 0 )
		return;

	if ( ! analysis_options.activate )
		return;

	if ( analysis_options.only_func &&
	     ! streq(f->Name(), analysis_options.only_func) )
		return;

	if ( analysis_options.only_func )
		printf("Original: %s\n", obj_desc(body));

	ProfileFunc pf_orig;
	body->Traverse(&pf_orig);

	if ( pf_orig.num_when_stmts > 0 || pf_orig.num_lambdas > 0 )
		{
		if ( analysis_options.only_func )
			printf("Skipping analysis due to \"when\" statement or use of lambdas\n");
		return;
		}

	auto scope = scope_ptr.get();

	::Ref(scope);
	push_existing_scope(scope);

	auto rc = new Reducer(scope);

	auto new_body = body->Reduce(rc);

	if ( reporter->Errors() > 0 )
		{
		pop_scope();
		delete rc;
		return;
		}

	non_reduced_perp = nullptr;
	checking_reduction = true;
	if ( ! new_body->IsReduced(rc) )
		printf("Reduction inconsistency for %s: %s\n", f->Name(),
			obj_desc(non_reduced_perp));
	checking_reduction = false;

	if ( analysis_options.only_func || analysis_options.dump_xform )
		printf("Transformed: %s\n", obj_desc(new_body));

	IntrusivePtr<Stmt> new_body_ptr = {AdoptRef{}, new_body};

	f->ReplaceBody(body, new_body_ptr);
	body = new_body_ptr;

	int new_frame_size =
		scope->Length() + rc->NumTemps() + rc->NumNewLocals();

	if ( new_frame_size > f->FrameSize() )
		f->SetFrameSize(new_frame_size);

	if ( analysis_options.optimize )
		{
		ProfileFunc pf_red;
		body->Traverse(&pf_red);

		auto cb = new RD_Decorate(&pf_red);
		cb->TraverseFunction(f, scope, new_body_ptr);

		rc->SetDefSetsMgr(cb->GetDefSetsMgr());

		new_body = new_body->Reduce(rc);
		new_body_ptr = {AdoptRef{}, new_body};

		if ( analysis_options.only_func || analysis_options.dump_xform )
			printf("Optimized: %s\n", obj_desc(new_body));

		f->ReplaceBody(body, new_body_ptr);
		body = new_body_ptr;

		// See comment below about leaking cb.
		// delete cb;
		}

	ProfileFunc* pf_red = new ProfileFunc;
	body->Traverse(pf_red);

	auto cb = new RD_Decorate(pf_red);
	cb->TraverseFunction(f, scope, new_body_ptr);

	rc->SetDefSetsMgr(cb->GetDefSetsMgr());

	auto ud = new UseDefs(new_body, rc);
	ud->Analyze();

	if ( analysis_options.ud_dump )
		ud->Dump();

	ud->RemoveUnused();

	if ( analysis_options.compile )
		{
		auto zam = new ZAM(f, scope, new_body, ud, rc, pf_red);
		new_body = zam->CompileBody();

		if ( analysis_options.only_func || analysis_options.dump_code )
			zam->Dump();

		new_body_ptr = {AdoptRef{}, new_body};
		f->ReplaceBody(body, new_body_ptr);
		body = new_body_ptr;
		}

	delete ud;
	delete rc;
	delete pf_red;

	// We can actually speed up our analysis by 10+% by skipping this.
	// Clearly we need to revisit the data structures, but for now we
	// opt for expediency.
	// delete cb;

	pop_scope();
	}


FuncInfo::~FuncInfo()
	{
	delete pf;
	}

std::vector<FuncInfo*> funcs;

void analyze_func(BroFunc* f)
	{
	auto info = new FuncInfo(f, {NewRef{}, f->GetScope()}, f->CurrentBody());
	funcs.push_back(info);
	}

void analyze_orphan_functions()
	{
	std::unordered_set<Func*> called_functions;

	for ( auto& f : funcs )
		{
		for ( auto& c : f->pf->script_calls )
			called_functions.insert(c);

		// Functions can also be implicitly called, if they show
		// up in the globals of a function (which might be passing
		// the function to another function to call).

		for ( auto& g : f->pf->globals )
			if ( g->Type()->Tag() == TYPE_FUNC && g->ID_Val() &&
			     g->ID_Val()->AsFunc()->AsBroFunc() )
			called_functions.insert(g->ID_Val()->AsFunc());
		}

	for ( auto& f : funcs )
		{
		auto func = f->func;

		if ( func->Flavor() == FUNC_FLAVOR_FUNCTION )
			// Too many of these are unused to be worth reporting.
			continue;

		bool is_called =
			called_functions.find(func) != called_functions.end();

#if 0
		if ( ! is_called && func->Flavor() == FUNC_FLAVOR_FUNCTION )
			printf("orphan function %s\n", func->Name());
#endif

		if ( ! is_called && func->Flavor() == FUNC_FLAVOR_HOOK )
			printf("orphan hook %s\n", func->Name());
		}
	}

void analyze_orphan_events()
	{
	std::unordered_set<const char*> globals;

	for ( auto& f : funcs )
		for ( auto& g : f->pf->events )
			globals.insert(g);

	for ( auto& f : funcs )
		{
		auto func = f->func;

		if ( func->Flavor() == FUNC_FLAVOR_EVENT )
			{
			auto fn = func->Name();
			auto h = event_registry->Lookup(fn);
			if ( (! h || ! h->Used()) &&
			     globals.find(fn) == globals.end() )
				printf("event %s cannot be generated\n", fn);
			}
		}
	}


struct AnalyOpt analysis_options;

void analyze_scripts()
	{
	static bool did_init = false;

	if ( ! did_init )
		{
		if ( getenv("ZEEK_ANALY") )
			analysis_options.activate = true;

		analysis_options.only_func = getenv("ZEEK_ONLY");
		analysis_options.report_profile = getenv("ZEEK_ZAM_PROFILE");
		analysis_options.find_deep_uninits = getenv("ZEEK_FIND_DEEP_UNINITS");
		analysis_options.rd_trace = getenv("ZEEK_OPT_TRACE");
		analysis_options.ud_dump = getenv("ZEEK_UD_DUMP");
		analysis_options.inliner = getenv("ZEEK_INLINE");
		analysis_options.optimize = getenv("ZEEK_OPTIMIZE");
		analysis_options.compile = getenv("ZEEK_COMPILE");
		analysis_options.no_ZAM_opt = getenv("ZEEK_NO_ZAM_OPT");
		analysis_options.dump_code = getenv("ZEEK_DUMP_CODE");
		analysis_options.dump_xform = getenv("ZEEK_DUMP_XFORM");

		if ( analysis_options.only_func )
			analysis_options.activate = true;

		did_init = true;
		}

	// Now that everything's parsed and BiF's have been initialized,
	// profile functions.
	for ( auto& f : funcs )
		{
		f->pf = new ProfileFunc();
		f->body->Traverse(f->pf);
		}

	// analyze_orphan_events();
	// analyze_orphan_functions();
	Inliner* inl = analysis_options.inliner ? new Inliner(funcs) : nullptr;

	for ( auto& f : funcs )
		{
		if ( inl && inl->WasInlined(f->func) )
			; // printf("skipping optimizing %s\n", f->func->Name());
		else
			{
#if 0
			auto loc = f->body->GetLocationInfo();
			printf("optimizing %s (%s line %d)\n", f->func->Name(),
				loc->filename ? loc->filename : "<none>",
				loc->first_line);
			// printf("body: %s\n", obj_desc(f->body));
#endif
			optimize_func(f->func, f->scope, f->body);
			}
		}

	finalize_functions(funcs);

	delete inl;
	}

void profile_script_execution()
	{
	printf("%d vals created, %d destructed\n", num_Vals, num_del_Vals);
	printf("%d string vals created, %d destructed\n", num_StringVals, num_del_StringVals);

	if ( analysis_options.report_profile )
		{
		report_ZOP_profile();

		for ( auto& f : funcs )
			{
			if ( f->body->Tag() == STMT_COMPILED )
				f->body->AsCompiler()->ProfileExecution();
			}
		}
	}

void finish_script_execution()
	{
	profile_script_execution();

	for ( auto& f : funcs )
		delete f;
	}
