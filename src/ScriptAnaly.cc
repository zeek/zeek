// See the file "COPYING" in the main distribution directory for copyright.

#include "ScriptAnaly.h"
#include "DefSetsMgr.h"
#include "Reduce.h"
#include "Desc.h"
#include "Expr.h"
#include "Stmt.h"
#include "Scope.h"
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

class ProfileFunc : public TraversalCallback {
public:
	TraversalCode PreExpr(const Expr*) override;

	// Globals seen in the function.
	std::unordered_set<const ID*> globals;
};

TraversalCode ProfileFunc::PreExpr(const Expr* e)
	{
	if ( e->Tag() == EXPR_NAME )
		{
		auto n = e->AsNameExpr();
		auto id = n->Id();
		if ( id->IsGlobal() )
			globals.insert(id);
		}

	return TC_CONTINUE;
	}

class RD_Decorate : public TraversalCallback {
public:
	RD_Decorate(const ProfileFunc& pf);

	TraversalCode PreFunction(const Func*) override;
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

	void CreateEmptyPostRDs(const Stmt* s);
	void AddBlockDefs(const Stmt* s,
				bool is_pre, bool is_future, bool is_case);

	const ProfileFunc& pf;
	DefSetsMgr mgr;
	vector<BlockDefs*> block_defs;
	bool trace;
};


RD_Decorate::RD_Decorate(const ProfileFunc& _pf) : pf(_pf)
	{
	trace = getenv("ZEEK_OPT_TRACE") != nullptr;
	}


TraversalCode RD_Decorate::PreFunction(const Func* f)
	{
	auto ft = f->FType();
	auto args = ft->Args();
	auto scope = f->GetScope();

	int n = args->NumFields();

	mgr.SetEmptyPre(f);

	for ( int i = 0; i < n; ++i )
		{
		auto arg_i = args->FieldName(i);
		auto arg_i_id = scope->Lookup(arg_i);

		if ( ! arg_i_id )
			arg_i_id = scope->Lookup(make_full_var_name(current_module.c_str(), arg_i).c_str());

		CreateInitPostDef(arg_i_id, DefinitionPoint(f), true, nullptr);
		}

	for ( const auto& g : pf.globals )
		CreateInitPostDef(g, DefinitionPoint(f), true, nullptr);

	if ( ! mgr.HasPostMinRDs(f) )
		// This happens if we have no arguments or globals.  Use the
		// empty ones we set up.
		mgr.SetPostFromPre(f);

	if ( trace )
		{
		printf("traversing function %s, post RDs:\n", f->Name());
		mgr.GetPostMaxRDs(f)->Dump();
		}

	auto bodies = f->GetBodies();
	for ( const auto& body : bodies )
		mgr.SetPreFromPost(body.stmts.get(), f);

	return TC_CONTINUE;
	}

TraversalCode RD_Decorate::PreStmt(const Stmt* s)
	{
	ASSERT(mgr.HasPreMinRDs(s));
	ASSERT(mgr.HasPreMaxRDs(s));

	if ( trace )
		{
		printf("pre RDs for stmt %s:\n", obj_desc(s));
		// mgr.GetPreMinRDs(s)->Dump();
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

	case STMT_LIST:
	case STMT_EVENT_BODY_LIST:
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

			if ( trace )
				{
				printf("post RDs for stmt %s:\n", obj_desc(stmt));
				// mgr.GetPostMinRDs(stmt)->Dump();
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

		auto ids = f->LoopVar();
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

		auto cond_stmt = w->CondStmt();
		auto cond = w->Condition();

		if ( cond_stmt )
			{
			mgr.SetPreFromPre(cond_stmt, w);
			cond_stmt->Traverse(this);
			mgr.SetPreFromPost(cond, cond_stmt);
			}
		else
			mgr.SetPreFromPre(cond, w);

		cond->Traverse(this);

		auto body = w->Body();
		mgr.SetPreFromPre(body, cond);

		block_defs.push_back(new BlockDefs(false));

		body->Traverse(this);
		DoLoopConfluence(s, cond_stmt, body);

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

	bool has_default = false;
	for ( const auto& c : *cases )
		{
		if ( (! c->ExprCases() ||
		      c->ExprCases()->Exprs().length() == 0) &&
		     (! c->TypeCases() ||
		      c->TypeCases()->length() == 0) )
			has_default = true;
		}

	RD_ptr sw_post_min_rds = nullptr;
	RD_ptr sw_post_max_rds = nullptr;

	if ( has_default )
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
		CreateEmptyPostRDs(s);
		break;

	case STMT_NEXT:
		AddBlockDefs(s, true, false, false);
		CreateEmptyPostRDs(s);
		break;

	case STMT_BREAK:
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
	for ( auto i = block_defs.size() - 1; i >= 0; --i )
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

		auto r_def = mgr.GetExprReachingDef(r);

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
	case STMT_EVENT_BODY_LIST:
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

	if ( trace && 0 )
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

	if ( trace && 0 )
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

		if ( ! mgr.HasPreMinRD(e, id) )
			{
			printf("%s has no pre at %s\n", id->Name(), obj_desc(e));
			exit(1);
			}

		if ( id->Type()->Tag() == TYPE_RECORD )
			CreateRecordRDs(mgr.GetIDReachingDef(id),
					DefinitionPoint(n), false, nullptr);

		break;
		}

	case EXPR_LIST:
		{
		auto l = e->AsListExpr();
		for ( const auto& expr : l->Exprs() )
			mgr.SetPreFromPre(expr, e);

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
			{ // Same as corresponding CheckLHS code.
			// Count this as an initialization of the aggregate.
			auto id = aggr->AsNameExpr()->Id();
			mgr.CreatePostDef(id, DefinitionPoint(e), false);

			// Don't recurse into assessing the aggregate,
			// since it's okay in this context.
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

		aggr->Traverse(this);
		r->Traverse(this);

		auto r_def = mgr.GetExprReachingDef(aggr);
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

		auto r_def = mgr.GetExprReachingDef(r);

		if ( r_def )
			{
			auto fn = f->FieldName();
			auto field_rd =
				mgr.GetConstIDReachingDef(r_def, fn);

			auto e_pre = mgr.GetPreMinRDs(e);
			if ( ! field_rd || ! e_pre->HasDI(field_rd) )
				printf("no reaching def for %s\n", obj_desc(e));
			}

		return TC_ABORTSTMT;
		}

	case EXPR_HAS_FIELD:
		{
		auto hf = e->AsHasFieldExpr();
		auto r = hf->Op();

		mgr.SetPreFromPre(r, e);

		// Treat this as a definition of lhs$fn, since it's
		// assuring that that field exists.  That's not quite
		// right, since this expression's parent could be a
		// negation, but at least we know that the script
		// writer is thinking about whether it's defined.

		if ( r->Tag() == EXPR_NAME )
			{
			auto id_e = r->AsNameExpr();
			auto id = id_e->Id();
			auto id_rt = id_e->Type()->AsRecordType();
			auto id_rd = mgr.GetIDReachingDef(id);

			if ( ! id_rd )
				{
				printf("no ID reaching def for %s\n", id->Name());
				break;
				}

			auto fn = hf->FieldName();
			auto field_rd = id_rd->FindField(fn);
			if ( ! field_rd )
				{
				auto ft = id_rt->FieldType(fn);
				field_rd = id_rd->CreateField(fn, ft);
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

		// ### Should kill definitions dependent on globals
		// that might have been modified by the call.

		return TC_ABORTSTMT;
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
	auto di = mgr.GetIDReachingDef(id);
	if ( ! di )
		return;

	CreateInitDef(di, dp, true, true, nullptr);
	}

void RD_Decorate::CreateInitPostDef(const ID* id, DefinitionPoint dp,
				bool assume_full, const Expr* rhs)
	{
	auto di = mgr.GetIDReachingDef(id);
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
			rhs_di = mgr.GetExprReachingDef(rhs);

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
	// (1) deal with LHS record creators
	// (2) populate globals
	auto rt = di->Type()->AsRecordType();
	auto n = rt->NumFields();

	for ( auto i = 0; i < n; ++i )
		{
		auto n_i = rt->FieldName(i);
		auto rhs_di_i = rhs_di ? rhs_di->FindField(n_i) : nullptr;

		bool field_is_defined = false;

		if ( assume_full )
			field_is_defined = true;

		else if ( rhs_di_i )
			field_is_defined = true;

		else if ( rt->FieldHasAttr(i, ATTR_DEFAULT) )
			field_is_defined = true;

		if ( ! field_is_defined )
			continue;

		auto t_i = rt->FieldType(i);
		auto di_i = di->CreateField(n_i, t_i);

		if ( is_pre )
			mgr.CreatePreDef(di_i, dp, true);
		else
			mgr.CreatePostDef(di_i, dp, true);

		if ( t_i->Tag() == TYPE_RECORD )
			CreateRecordRDs(di_i, dp, is_pre, assume_full, rhs_di_i);
		}
	}


class FolderFinder : public TraversalCallback {
public:
	// TraversalCode PreExpr(const Expr*) override;
	TraversalCode PreExpr(const Expr*, const Expr*) override;
	TraversalCode PreExpr(const Expr*, const Expr*, const Expr*) override;

protected:
	void ReportFoldable(const Expr* e, const char* type);
};

void FolderFinder::ReportFoldable(const Expr* e, const char* type)
	{
	printf("foldable %s: %s\n", type, obj_desc(e));
	}

TraversalCode FolderFinder::PreExpr(const Expr* expr, const Expr* op)
	{
	if ( op->IsConst() )
		ReportFoldable(expr, "unary");

	return TC_CONTINUE;
	}

TraversalCode FolderFinder::PreExpr(const Expr* expr, const Expr* op1, const Expr* op2)
	{
	if ( op1->IsConst() && op2->IsConst() )
		ReportFoldable(expr, "binary");

	return TC_CONTINUE;
	}


bool did_init = false;
bool activate = false;
bool optimize = false;
const char* only_func = 0;

void analyze_func(const IntrusivePtr<ID>& id, const id_list* inits, Stmt* body)
	{
	if ( reporter->Errors() > 0 )
		return;

	if ( ! did_init )
		{
		if ( getenv("ZEEK_ANALY") )
			activate = true;

		only_func = getenv("ZEEK_ONLY");

		optimize = getenv("ZEEK_OPTIMIZE");

		if ( only_func )
			activate = true;

		did_init = true;
		}

	if ( ! activate )
		return;

	auto f = id->ID_Val()->AsFunc()->AsBroFunc();

	if ( only_func && ! streq(f->Name(), only_func) )
		return;

	push_scope(id, nullptr);
	ReductionContext rc(f->GetScope());

	if ( only_func )
		printf("Original: %s\n", obj_desc(body));

	auto new_body = body->Reduce(&rc);

	non_reduced_perp = nullptr;
	checking_reduction = true;
	if ( ! new_body->IsReduced() )
		printf("Reduction inconsistency for %s: %s\n", id->Name(),
			obj_desc(non_reduced_perp));
	checking_reduction = false;

	if ( only_func )
		printf("Transformed: %s\n", obj_desc(new_body));

	IntrusivePtr<Stmt> body_ptr = {AdoptRef{}, body};
	IntrusivePtr<Stmt> new_body_ptr = {AdoptRef{}, new_body};

	f->ReplaceBody(body_ptr, new_body_ptr);
	f->GrowFrameSize(rc.NumTemps());

	if ( optimize )
		{
		ProfileFunc pf;
		f->Traverse(&pf);

		RD_Decorate cb(pf);
		f->Traverse(&cb);

		rc.SetDefSetsMgr(cb.GetDefSetsMgr());
		body_ptr = new_body_ptr;
		new_body = new_body->Reduce(&rc);
		new_body_ptr = {AdoptRef{}, new_body};

		if ( only_func )
			printf("Optimized: %s\n", obj_desc(new_body));

		f->ReplaceBody(body_ptr, new_body_ptr);
		}

	pop_scope();
	}
