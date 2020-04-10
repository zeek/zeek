// See the file "COPYING" in the main distribution directory for copyright.

#include "ScriptAnaly.h"
#include "DefItem.h"
#include "DefPoint.h"
#include "ReachingDefs.h"
#include "Reduce.h"
#include "Desc.h"
#include "Expr.h"
#include "Stmt.h"
#include "Scope.h"
#include "Traverse.h"
#include "module_util.h"


static char obj_desc_storage[8192];

static const char* obj_desc(const BroObj* o)
	{
	ODesc d;
	d.SetDoOrig(false);
	o->Describe(&d);
	d.SP();
	o->GetLocationInfo()->Describe(&d);

	strcpy(obj_desc_storage, d.Description());

	return obj_desc_storage;
	}


class RD_Decorate : public TraversalCallback {
public:
	RD_Decorate();

	TraversalCode PreFunction(const Func*) override;
	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PostStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;
	TraversalCode PostExpr(const Expr*) override;

	void TrackInits(const Func* f, const id_list* inits);

protected:
	bool CheckLHS(const Expr* lhs, const AssignExpr* a);

	bool IsAggrTag(TypeTag tag) const;
	bool IsAggr(const Expr* e) const;

	bool ControlReachesEnd(const Stmt* s, bool is_definite,
				bool ignore_break = false) const;

	const RD_ptr& GetPreMinRDs(const BroObj* o) const
		{ return GetRDs(pre_min_defs, o); }
	const RD_ptr& GetPostMinRDs(const BroObj* o) const
		{
		if ( HasPostMinRDs(o) )
			return GetRDs(post_min_defs, o);
		else
			return GetPreMinRDs(o);
		}

	const RD_ptr& GetRDs(const IntrusivePtr<ReachingDefSet> defs,
				const BroObj* o) const
		{
		return defs->FindRDs(o);
		}

	// ### If we want to go to sharing RD sets using copy-on-write,
	// then a starting point is altering the const RD_ptr&'s in
	// these APIs to instead be RD_ptr's.
	void SetPreMinRDs(const BroObj* o, const RD_ptr& rd)
		{ pre_min_defs->SetRDs(o, rd); }
	void SetPostMinRDs(const BroObj* o, const RD_ptr& rd)
		{ post_min_defs->SetRDs(o, rd); }

	bool HasPreMinRDs(const BroObj* o) const
		{
		return pre_min_defs->HasRDs(o);
		}

	bool HasPreMinRD(const BroObj* o, const ID* id) const
		{
		return pre_min_defs->HasRD(o, id);
		}

	bool HasPreMinRD(const BroObj* o, const DefinitionItem* di)
		{
		return pre_min_defs->HasRD(o, di);
		}

	bool HasPostMinRDs(const BroObj* o) const
		{
		return post_min_defs->HasRDs(o);
		}

	void CreatePreDef(const ID* id, DefinitionPoint dp);
	void CreatePreDef(DefinitionItem* di, DefinitionPoint dp);
	void CreatePostDef(const ID* id, DefinitionPoint dp);
	void CreatePostDef(DefinitionItem* di, DefinitionPoint dp);

	void CreateDef(DefinitionItem* di, DefinitionPoint dp, bool is_pre);

	void CreateInitPreDef(const ID* id, DefinitionPoint dp);

	void CreateInitPostDef(const ID* id, DefinitionPoint dp,
				bool assume_full, const AssignExpr* init);

	void CreateInitPostDef(DefinitionItem* di, DefinitionPoint dp,
				bool assume_full, const AssignExpr* init);

	void CreateInitDef(DefinitionItem* di, DefinitionPoint dp, bool is_pre,
				bool assume_full, const AssignExpr* init);

	void CreateRecordRDs(DefinitionItem* di, DefinitionPoint dp,
				bool assume_full, const DefinitionItem* rhs_di);
	void CreateRecordRDs(DefinitionItem* di, DefinitionPoint dp, bool is_pre,
				bool assume_full, const DefinitionItem* rhs_di);

	void CreateEmptyPostRDs(const Stmt* s);
	void CreatePostRDs(const Stmt* s, const RD_ptr& post_rds);

	// Mappings of reaching defs pre- and post- execution
	// of the given object.
	IntrusivePtr<ReachingDefSet> pre_min_defs;
	IntrusivePtr<ReachingDefSet> post_min_defs;

	// The object we most recently finished analyzing.
	const BroObj* last_obj;

	DefItemMap item_map;

	bool trace;
};


RD_Decorate::RD_Decorate()
	{
	pre_min_defs = make_intrusive<ReachingDefSet>(item_map);
	post_min_defs = make_intrusive<ReachingDefSet>(item_map);

	last_obj = nullptr;

	trace = getenv("ZEEK_OPT_TRACE") != nullptr;
	}


TraversalCode RD_Decorate::PreFunction(const Func* f)
	{
	auto ft = f->FType();
	auto args = ft->Args();
	auto scope = f->GetScope();

	int n = args->NumFields();

	auto empty_rds = make_new_RD_ptr();
	SetPreMinRDs(f, empty_rds);
	empty_rds.release();

	for ( int i = 0; i < n; ++i )
		{
		auto arg_i = args->FieldName(i);
		auto arg_i_id = scope->Lookup(arg_i);

		if ( ! arg_i_id )
			arg_i_id = scope->Lookup(make_full_var_name(current_module.c_str(), arg_i).c_str());

		CreateInitPostDef(arg_i_id, DefinitionPoint(f), true, 0);
		}

	if ( ! HasPostMinRDs(f) )
		// This happens if we have no arguments.  Use the
		// empty ones we set up.
		SetPostMinRDs(f, GetPreMinRDs(f));

	if ( trace )
		{
		printf("traversing function %s, post RDs:\n", f->Name());
		GetPostMinRDs(f)->Dump();
		}

	auto bodies = f->GetBodies();
	for ( const auto& body : bodies )
		SetPreMinRDs(body.stmts.get(), GetPostMinRDs(f));

	// This shouldn't be needed, since the body will have
	// explicit PreMinRDs set.
	last_obj = f;

	// Don't continue traversal here, as that will then loop over
	// older bodies.  Instead, we do it manually.
	return TC_ABORTALL;
	}

TraversalCode RD_Decorate::PreStmt(const Stmt* s)
	{
	if ( ! HasPreMinRDs(s) )
		SetPreMinRDs(s, GetPostMinRDs(last_obj));

	const auto my_rds = GetPreMinRDs(s);
	DefinitionPoint ds(s);

	if ( trace )
		{
		printf("pre RDs for stmt %s:\n", obj_desc(s));
		my_rds->Dump();
		}

	last_obj = s;

	switch ( s->Tag() ) {
        case STMT_EXPR:
		{
		auto e = s->AsExprStmt()->StmtExpr();
		SetPreMinRDs(e, my_rds);
		break;
		}

	case STMT_LIST:
	case STMT_EVENT_BODY_LIST:
		{
		auto sl = s->AsStmtList();
		auto stmts = sl->Stmts();
		auto curr_rds = my_rds;

		for ( const auto& stmt : stmts )
			{
			SetPreMinRDs(stmt, curr_rds);
			stmt->Traverse(this);
			last_obj = stmt;
			curr_rds = GetPostMinRDs(stmt);
			}

		SetPostMinRDs(sl, curr_rds);

		last_obj = s;

		return TC_ABORTSTMT;
		}

	case STMT_IF:
		{
		// For now we assume there no definitions occur
		// inside the conditional.  If one does, we'll
		// detect that & complain about it in the PostStmt.
		//
		// (Note: when working with reduced statements, this
		// is a non-issue.)
		auto i = s->AsIfStmt();

		// Need to manually control traversal since don't want
		// RDs coming out of the TrueBranch to propagate to the
		// FalseBranch.

		SetPreMinRDs(i->TrueBranch(), my_rds);
		i->TrueBranch()->Traverse(this);

		SetPreMinRDs(i->FalseBranch(), my_rds);
		i->FalseBranch()->Traverse(this);

		auto if_branch_rd = GetPostMinRDs(i->TrueBranch());
		auto else_branch_rd = GetPostMinRDs(i->FalseBranch());

		auto true_reached = ControlReachesEnd(i->TrueBranch(), false);
		auto false_reached = ControlReachesEnd(i->FalseBranch(), false);

		if ( true_reached && false_reached )
			{
			auto post_rds = if_branch_rd->IntersectWithConsolidation(else_branch_rd, ds);
			CreatePostRDs(s, post_rds);
			post_rds.release();
			}

		else
			{
			if ( true_reached )
				CreatePostRDs(s, if_branch_rd);

			else if ( false_reached )
				CreatePostRDs(s, else_branch_rd);

			else
				CreateEmptyPostRDs(s);
			}

		return TC_ABORTSTMT;
		}

	case STMT_SWITCH:
		{
		auto sw = s->AsSwitchStmt();
		auto cases = sw->Cases();

		for ( const auto& c : *cases )
			{
			auto body = c->Body();
			SetPreMinRDs(body, my_rds);

			auto type_ids = c->TypeCases();
			if ( type_ids )
				{
				for ( const auto& id : *type_ids )
					CreateInitPreDef(id,
						DefinitionPoint(body));
				}
			}

		break;
		}

	case STMT_FOR:
		{
		auto f = s->AsForStmt();

		auto ids = f->LoopVar();
		auto e = f->LoopExpr();
		auto body = f->LoopBody();
		auto val_var = f->ValueVar();

		SetPreMinRDs(e, my_rds);
		e->Traverse(this);
		SetPreMinRDs(body, GetPostMinRDs(e));

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
		// To keep from traversing, we just do the body manually here.

		body->Traverse(this);

		// ### If post differs from pre, propagate to
		// beginning and re-traverse.

		// Apply intersection since loop might not execute
		// at all.
		auto post_rds = GetPreMinRDs(s)->IntersectWithConsolidation(GetPostMinRDs(body), ds);

		CreatePostRDs(s, post_rds);
		post_rds.release();

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

TraversalCode RD_Decorate::PostStmt(const Stmt* s)
	{
	DefinitionPoint ds(s);

	switch ( s->Tag() ) {
        case STMT_EXPR:
		{
		auto e = s->AsExprStmt()->StmtExpr();
		CreatePostRDs(s, GetPostMinRDs(e));
		break;
		}

	case STMT_SWITCH:
		{
		auto sw = s->AsSwitchStmt();
		auto cases = sw->Cases();

		bool did_first = false;
		bool default_seen = false;

		RD_ptr sw_post_rds = nullptr;

		for ( const auto& c : *cases )
			{
			if ( ControlReachesEnd(c->Body(), false) )
				{
				auto case_rd = GetPostMinRDs(c->Body());

				if ( did_first )
					sw_post_rds =
						sw_post_rds->IntersectWithConsolidation(case_rd, ds);
				else
					{
					sw_post_rds =
						make_new_RD_ptr(case_rd.get());
					did_first = true;
					}
				}

			if ( (! c->ExprCases() ||
			      c->ExprCases()->Exprs().length() == 0) &&
			     (! c->TypeCases() ||
			      c->TypeCases()->length() == 0) )
				default_seen = true;
			}

		if ( ! default_seen )
			{
			if ( sw_post_rds )
				sw_post_rds = sw_post_rds->Union(GetPreMinRDs(s));
			else
				{
				// We can fall through, and if so the
				// only definitions are those that came
				// into this statement.
				CreatePostRDs(s, GetPreMinRDs(s));
				break;
				}
			}

		CreatePostRDs(s, sw_post_rds);
		sw_post_rds.release();

		break;
		}

	case STMT_WHILE:
		{
		auto w = s->AsWhileStmt();
		auto body = w->Body();

		// ### If post differs from pre, propagate to
		// beginning and re-traverse.

		// Apply intersection since loop might not execute
		// at all.
		auto while_post_rds =
			GetPreMinRDs(s)->IntersectWithConsolidation(GetPostMinRDs(body), ds);

		CreatePostRDs(s, while_post_rds);
		while_post_rds.release();

		break;
		}

	case STMT_INIT:
		{
		CreatePostRDs(s, GetPreMinRDs(s));

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

	case STMT_NEXT:
	case STMT_BREAK:
	case STMT_RETURN:
		CreateEmptyPostRDs(s);
		break;

	case STMT_FALLTHROUGH:
		// Yuck, really ought to propagate its RDs into
		// the next case, but that's quite ugly.  It
		// only matters if (1) there are meaningful
		// definitions crossing into the case *and*
		// (2) we start doing analyses that depend on
		// potential RDs and not just minimalist RDs.
		//
		// Anyhoo, punt for now. ###
		CreatePostRDs(s, GetPreMinRDs(s));
		break;

	default:
		CreatePostRDs(s, GetPreMinRDs(s));
		break;
	}

	return TC_CONTINUE;
	}

void RD_Decorate::CreateEmptyPostRDs(const Stmt* s)
	{
	CreatePostRDs(s, make_new_RD_ptr());
	}

void RD_Decorate::CreatePostRDs(const Stmt* s, const RD_ptr& post_rds)
	{
	SetPostMinRDs(s, post_rds);
	last_obj = s;

	if ( trace )
		{
		printf("post RDs for stmt %s:\n", obj_desc(s));
		GetPostMinRDs(s)->Dump();
		}
	}

bool RD_Decorate::CheckLHS(const Expr* lhs, const AssignExpr* a)
	{
	switch ( lhs->Tag() ) {
	case EXPR_REF:
		{
		auto r = lhs->AsRefExpr();
		return CheckLHS(r->Op(), a);
		}

	case EXPR_NAME:
		{
		auto n = lhs->AsNameExpr();
		auto id = n->Id();

		CreateInitPostDef(id, DefinitionPoint(a), false, a);

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
			CreateInitPostDef(id, DefinitionPoint(a), true, 0);
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
		r->Traverse(this);

		auto r_def = item_map.GetExprReachingDef(r);

		if ( ! r_def )
			// This should have already generated a complaint.
			// Avoid cascade.
			return true;

		auto fn = f->FieldName();

		auto field_rd = r_def->FindField(fn);
		auto ft = f->Type();
		if ( ! field_rd )
			field_rd = r_def->CreateField(fn, ft);

		CreateInitPostDef(field_rd, DefinitionPoint(a), false, a);

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
			CreatePostDef(id, DefinitionPoint(a));

			// Don't recurse into assessing the aggregate,
			// since it's okay in this context.  However,
			// we do need to recurse into the index, which
			// could have problems.
			index->Traverse(this);
			return true;
			}

		return false;
		}

	default:
		return false;
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

bool RD_Decorate::ControlReachesEnd(const Stmt* s, bool is_definite,
					bool ignore_break) const
	{
	switch ( s->Tag() ) {
	case STMT_NEXT:
	case STMT_RETURN:
		return false;

	case STMT_BREAK:
		return ignore_break;

	case STMT_IF:
		{
		auto i = s->AsIfStmt();

		auto true_reaches =
			ControlReachesEnd(i->TrueBranch(), is_definite);
		auto false_reaches =
			ControlReachesEnd(i->FalseBranch(), is_definite);

		if ( is_definite )
			return true_reaches && false_reaches;
		else
			return true_reaches || false_reaches;
		}

	case STMT_SWITCH:
		{
		auto sw = s->AsSwitchStmt();
		auto cases = sw->Cases();

		bool control_reaches_end = is_definite;
		bool default_seen = false;
		for ( const auto& c : *cases )
			{
			bool body_def = ControlReachesEnd(c->Body(),
								is_definite,
								true);

			if ( is_definite && ! body_def )
				control_reaches_end = false;

			if ( ! is_definite && body_def )
				control_reaches_end = true;

			if ( (! c->ExprCases() ||
			      c->ExprCases()->Exprs().length() == 0) &&
			     (! c->TypeCases() ||
			      c->TypeCases()->length() == 0) )
				default_seen = true;
			}

		if ( ! is_definite && ! default_seen )
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

			if ( ! ControlReachesEnd(stmt, is_definite,
							ignore_break) )
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
	if ( ! HasPreMinRDs(e) )
		SetPreMinRDs(e, GetPostMinRDs(last_obj));

	if ( trace )
		{
		printf("pre RDs for expr %s:\n", obj_desc(e));
		GetPreMinRDs(e)->Dump();
		}

	// Since there are no control flow or confluence issues (the latter
	// holds when working on reduced expressions; perverse assignments
	// inside &&/|| introduce confluence issues, but that won't lead
	// to optimization issues, just imprecision in tracking uninitialized
	// values).
	SetPostMinRDs(e, GetPreMinRDs(e));

	if ( trace )
		{
		printf("nominal post RDs for expr %s:\n", obj_desc(e));
		GetPostMinRDs(e)->Dump();
		}

	last_obj = e;

	switch ( e->Tag() ) {
        case EXPR_NAME:
		{
		auto n = e->AsNameExpr();
		auto id = n->Id();

		if ( id->IsGlobal() )
			{
			// Treat global as fully initialized. ### may need Pre here
			CreateInitPostDef(id, DefinitionPoint(n), true, nullptr);
			}

		else if ( ! HasPreMinRD(e, id) )
			printf("%s has no pre at %s\n", id->Name(), obj_desc(e));

		if ( id->Type()->Tag() == TYPE_RECORD )
			CreateRecordRDs(item_map.GetIDReachingDef(id),
					DefinitionPoint(n), false, nullptr);

		break;
		}

        case EXPR_ADD_TO:
		{
		auto a_t = e->AsAddToExpr();
		auto lhs = a_t->Op1();

		if ( IsAggr(lhs) )
			{
			auto lhs_n = lhs->AsNameExpr();
			auto lhs_id = lhs_n->Id();

			// Treat this as an initalization of the set.
			CreatePostDef(lhs_id, DefinitionPoint(a_t));

			a_t->Op2()->Traverse(this);
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

		if ( CheckLHS(lhs, a) )
			{
			if ( ! rhs_aggr )
				rhs->Traverse(this);

			last_obj = e;
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

	case EXPR_FIELD:
		{
		auto f = e->AsFieldExpr();
		auto r = f->Op();

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

		auto r_def = item_map.GetExprReachingDef(r);

		if ( r_def )
			{
			auto fn = f->FieldName();
			auto field_rd =
				item_map.GetConstIDReachingDef(r_def, fn);

			auto e_pre = GetPreMinRDs(e);
			if ( ! field_rd || ! e_pre->HasDI(field_rd) )
				printf("no reaching def for %s\n", obj_desc(e));
			}

		return TC_ABORTSTMT;
		}

	case EXPR_HAS_FIELD:
		{
		auto hf = e->AsHasFieldExpr();
		auto r = hf->Op();

		// Treat this as a definition of lhs$fn, since it's
		// assuring that that field exists.

		if ( r->Tag() == EXPR_NAME )
			{
			auto id_e = r->AsNameExpr();
			auto id = id_e->Id();
			auto id_rt = id_e->Type()->AsRecordType();
			auto id_rd = item_map.GetIDReachingDef(id);

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
		f->Traverse(this);

		for ( const auto& expr : args_l->Exprs() )
			{
			if ( IsAggr(expr) )
				// Not only do we skip analyzing it, but
				// we consider it initialized post-return.
				CreatePostDef(expr->AsNameExpr()->Id(), 
						DefinitionPoint(c));
			else
				expr->Traverse(this);
			}

		return TC_ABORTSTMT;
		}

	case EXPR_LAMBDA:
		// ### Too tricky to get these right.
		return TC_ABORTSTMT;

	default:
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

		(void) CheckLHS(lhs.get(), nullptr);
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

void RD_Decorate::CreatePreDef(const ID* id, DefinitionPoint dp)
	{
	auto di = item_map.GetIDReachingDef(id);
	CreatePreDef(di, dp);
	}

void RD_Decorate::CreatePreDef(DefinitionItem* di, DefinitionPoint dp)
	{
	CreateDef(di, dp, true);
	}

void RD_Decorate::CreatePostDef(const ID* id, DefinitionPoint dp)
	{
	auto di = item_map.GetIDReachingDef(id);
	CreatePostDef(di, dp);
	}

void RD_Decorate::CreatePostDef(DefinitionItem* di, DefinitionPoint dp)
	{
	auto where = dp.OpaqueVal();

	if ( ! post_min_defs->HasRDs(where) )
		{
		// We haven't yet started creating post RDs for this
		// statement/expression, so create them.
		auto pre = GetPreMinRDs(where);
		SetPostMinRDs(where, GetPreMinRDs(where));
		}

	CreateDef(di, dp, false);
	}

void RD_Decorate::CreateDef(DefinitionItem* di, DefinitionPoint dp, bool is_pre)
	{
	auto where = dp.OpaqueVal();

	IntrusivePtr<ReachingDefSet>& defs =
		is_pre ? pre_min_defs : post_min_defs;

	defs->AddOrReplace(where, di, dp);
	}

void RD_Decorate::CreateInitPreDef(const ID* id, DefinitionPoint dp)
	{
	auto di = item_map.GetIDReachingDef(id);
	if ( ! di )
		return;

	CreateInitDef(di, dp, true, true, nullptr);
	}

void RD_Decorate::CreateInitPostDef(const ID* id, DefinitionPoint dp,
				bool assume_full, const AssignExpr* init)
	{
	auto di = item_map.GetIDReachingDef(id);
	if ( ! di )
		return;

	CreateInitDef(di, dp, false, assume_full, init);
	}

void RD_Decorate::CreateInitPostDef(DefinitionItem* di, DefinitionPoint dp,
				bool assume_full, const AssignExpr* init)
	{
	CreateInitDef(di, dp, false, assume_full, init);
	}

void RD_Decorate::CreateInitDef(DefinitionItem* di, DefinitionPoint dp,
				bool is_pre, bool assume_full,
				const AssignExpr* init)
	{
	if ( is_pre )
		CreatePreDef(di, dp);
	else
		CreatePostDef(di, dp);

	if ( di->Type()->Tag() != TYPE_RECORD )
		return;

	const DefinitionItem* rhs_di = nullptr;

	if ( init )
		{
		auto rhs = init->Op2();

		if ( rhs->Type()->Tag() == TYPE_ANY )
			// All bets are off.
			assume_full = true;

		else
			{
			rhs_di = item_map.GetExprReachingDef(rhs);

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
				bool assume_full, const DefinitionItem* rhs_di)
	{
	CreateRecordRDs(di, dp, false, assume_full, rhs_di);
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
			CreatePreDef(di_i, dp);
		else
			CreatePostDef(di_i, dp);

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
const char* only_func = 0;

void analyze_func(const IntrusivePtr<ID>& id, const id_list* inits, Stmt* body)
	{
	if ( ! did_init )
		{
		if ( getenv("ZEEK_ANALY") )
			activate = true;

		only_func = getenv("ZEEK_ONLY");

		if ( only_func )
			activate = true;

		did_init = true;
		}

	if ( ! activate )
		return;

	auto f = id->ID_Val()->AsFunc()->AsBroFunc();

	if ( only_func && ! streq(f->Name(), only_func) )
		return;

	RD_Decorate cb;
	f->Traverse(&cb);
	cb.TrackInits(f, inits);
	body->Traverse(&cb);

	push_scope(id, nullptr);
	ReductionContext rc(f->GetScope());

return;
	if ( only_func )
		printf("Original: %s\n", obj_desc(body));

	auto new_body = body->Reduce(&rc);

	if ( only_func )
		printf("Transformed: %s\n", obj_desc(new_body));

	f->ReplaceBody({AdoptRef{}, body}, {AdoptRef{}, new_body});
	f->GrowFrameSize(rc.NumTemps());
	pop_scope();
	}
