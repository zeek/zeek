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
	bool CheckLHS(RD_ptr rd, const Expr* lhs, const AssignExpr* a);

	bool IsAggrTag(TypeTag tag) const;
	bool IsAggr(const Expr* e) const;

	bool ControlReachesEnd(const Stmt* s, bool is_definite,
				bool ignore_break = false) const;

	RD_ptr PredecessorRDs() const
		{
		auto rd = PostRDsIfAny(last_obj);
		if ( rd && rd->Size() > 0 )
			return rd;

		// PostRDs haven't been set yet.
		return GetPreRDs(last_obj);
		}

	RD_ptr PreRDsIfAny(const BroObj* o) const
		{ return pre_defs->RDsIfAny(o); }
	RD_ptr PostRDsIfAny(const BroObj* o) const
		{ return post_defs->RDsIfAny(o); }

	RD_ptr GetPreRDs(const BroObj* o) const
		{ return GetRDs(pre_defs, o); }
	RD_ptr GetPostRDs(const BroObj* o) const
		{ return GetRDs(post_defs, o); }

	RD_ptr GetRDs(ReachingDefSet* defs, const BroObj* o) const
		{
		auto rds = defs->FindRDs(o);
		ASSERT(rds != nullptr);
		return rds;
		}

	// ### If we want to go to sharing RD sets using copy-on-write,
	// then a starting point is altering the const RD_ptr&'s in
	// these APIs to instead be RD_ptr's.
	void AddPreRDs(const BroObj* o, const RD_ptr& rd)
		{ pre_defs->AddRDs(o, rd); }
	void AddPostRDs(const BroObj* o, const RD_ptr& rd)
		{ post_defs->AddRDs(o, rd); }

	bool HasPreRD(const BroObj* o, const ID* id) const
		{
		return pre_defs->HasRD(o, id);
		}

	void AddRD(RD_ptr rd, const ID* id, DefinitionPoint dp);

	void AddRDWithInit(RD_ptr rd, const ID* id, DefinitionPoint dp,
				bool assume_full,const AssignExpr* init);

	void AddRDWithInit(RD_ptr rd, DefinitionItem* di,
				DefinitionPoint dp, bool assume_full,
				const AssignExpr* init);

	void CreateRecordRDs(RD_ptr rd, DefinitionItem* di,
				bool assume_full, DefinitionPoint dp,
				const DefinitionItem* rhs_di);

	// Mappings of reaching defs pre- and post- execution
	// of the given object.
	ReachingDefSet* pre_defs;
	ReachingDefSet* post_defs;

	// The object we most recently finished analyzing.
	const BroObj* last_obj;

	DefItemMap item_map;

	bool trace;
};


RD_Decorate::RD_Decorate()
	{
	pre_defs = new ReachingDefSet(item_map);
	post_defs = new ReachingDefSet(item_map);
	last_obj = nullptr;

	trace = getenv("ZEEK_OPT_TRACE") != nullptr;
	}


TraversalCode RD_Decorate::PreFunction(const Func* f)
	{
	auto ft = f->FType();
	auto args = ft->Args();
	auto scope = f->GetScope();

	int n = args->NumFields();

	auto rd = make_new_RD_ptr();

	for ( int i = 0; i < n; ++i )
		{
		auto arg_i = args->FieldName(i);
		auto arg_i_id = scope->Lookup(arg_i);

		if ( ! arg_i_id )
			arg_i_id = scope->Lookup(make_full_var_name(current_module.c_str(), arg_i).c_str());

		AddRDWithInit(rd, arg_i_id, DefinitionPoint(f), true, 0);
		}

	AddPostRDs(f, rd);
	last_obj = f;

	if ( trace )
		{
		printf("traversing function %s, post RDs:\n", f->Name());
		GetPostRDs(f)->Dump();
		}

	// Don't continue traversal here, as that will then loop over
	// older bodies.  Instead, we do it manually.
	return TC_ABORTALL;
	}

TraversalCode RD_Decorate::PreStmt(const Stmt* s)
	{
	AddPreRDs(s, PredecessorRDs());

	auto rd = GetPreRDs(s);

	if ( trace )
		{
		printf("pre RDs for stmt %s:\n", stmt_name(s->Tag()));
		rd->Dump();
		}

	last_obj = s;

	switch ( s->Tag() ) {
	case STMT_IF:
		{
		// For now we assume there no definitions occur
		// inside the conditional.  If one does, we'll
		// detect that & complain about it in the PostStmt.
		auto i = s->AsIfStmt();

		// ### need to manually control traversal since
		// don't want RDs coming out of the TrueBranch
		// to propagate to the FalseBranch.
		auto my_rds = rd;
		AddPreRDs(i->TrueBranch(), my_rds);
		AddPreRDs(i->FalseBranch(), my_rds);

		break;
		}

	case STMT_SWITCH:
		{
		auto sw = s->AsSwitchStmt();
		auto cases = sw->Cases();

		for ( const auto& c : *cases )
			{
			auto type_ids = c->TypeCases();
			if ( type_ids )
				{
				for ( const auto& id : *type_ids )
					AddRDWithInit(rd, id,
						DefinitionPoint(s), true, 0);
				}

			AddPreRDs(c->Body(), rd);
			}

		break;
		}

	case STMT_FOR:
		{
		auto f = s->AsForStmt();

		auto ids = f->LoopVar();
		auto e = f->LoopExpr();
		auto body = f->LoopBody();

		for ( const auto& id : *ids )
			AddRDWithInit(rd, id, DefinitionPoint(s),
						true, 0);

		auto val_var = f->ValueVar();
		if ( val_var )
			AddRDWithInit(rd, val_var, DefinitionPoint(s), true, 0);

		AddPreRDs(e, rd);
		AddPreRDs(body, rd);

		if ( e->Tag() == EXPR_NAME )
			{
			// Don't traverse into the loop expression,
			// as it's okay if it's not initialized at this
			// point - that will just result in any empty loop.
			//
			// But then we do need to manually traverse the
			// body.
			body->Traverse(this);
			return TC_ABORTSTMT;

			// ### need to do PostStmt for For here
			}

		break;
		}

	case STMT_RETURN:
		{
		auto r = s->AsReturnStmt();
		auto e = r->StmtExpr();

		if ( e && IsAggr(e) )
			return TC_ABORTSTMT;

		break;
		}

	case STMT_ADD:
		{
		auto a = s->AsAddStmt();
		auto a_e = a->StmtExpr();

		if ( a_e->Tag() == EXPR_INDEX )
			{
			auto a_e_i = a_e->AsIndexExpr();
			auto a1 = a_e_i->Op1();
			auto a2 = a_e_i->Op2();

			if ( IsAggr(a1) )
				{
				a2->Traverse(this);

				auto i1 = a1->AsNameExpr()->Id();
				AddRD(rd, i1, DefinitionPoint(s));
				AddPostRDs(s, rd);

				return TC_ABORTSTMT;
				}
			}

		break;
		}

	default:
		break;
	}

	return TC_CONTINUE;
	}

TraversalCode RD_Decorate::PostStmt(const Stmt* s)
	{
	RD_ptr post_rds = nullptr;

	switch ( s->Tag() ) {
	case STMT_PRINT:
	case STMT_EVENT:
	case STMT_WHEN:
		post_rds = GetPreRDs(s);
		break;

        case STMT_EXPR:
		{
		auto e = s->AsExprStmt()->StmtExpr();
		post_rds = GetPostRDs(e);
		break;
		}

	case STMT_IF:
		{
		auto i = s->AsIfStmt();

		// ### traverse i and propagate

		auto if_branch_rd = GetPostRDs(i->TrueBranch());
		auto else_branch_rd = GetPostRDs(i->FalseBranch());

		auto true_reached = ControlReachesEnd(i->TrueBranch(), false);
		auto false_reached = ControlReachesEnd(i->FalseBranch(), false);

		if ( true_reached && false_reached )
			post_rds = if_branch_rd->Intersect(else_branch_rd);

		else if ( true_reached )
			post_rds = if_branch_rd;

		else if ( false_reached )
			post_rds = else_branch_rd;

		else
			; // leave empty

		break;
		}

	case STMT_SWITCH:
		{
		auto sw = s->AsSwitchStmt();
		auto cases = sw->Cases();

		bool did_first = false;
		bool default_seen = false;

		for ( const auto& c : *cases )
			{
			if ( ControlReachesEnd(c->Body(), false) )
				{
				auto case_rd = GetPostRDs(c->Body());
				if ( did_first )
					post_rds = post_rds->Intersect(case_rd);
				else
					{
					post_rds = case_rd;
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
			if ( post_rds )
				post_rds = post_rds->Union(GetPreRDs(s));
			else
				post_rds = GetPreRDs(s);
			}

		break;
		}

	case STMT_FOR:
		{
		auto f = s->AsForStmt();
		auto body = f->LoopBody();

		// ### If post differs from pre, propagate to
		// beginning and re-traverse.

		// Apply intersection since loop might not execute
		// at all.
		post_rds = GetPreRDs(s)->Intersect(GetPostRDs(body));

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
		post_rds = GetPreRDs(s)->Intersect(GetPostRDs(body));

		break;
		}

	case STMT_LIST:
	case STMT_EVENT_BODY_LIST:
		{
		auto l = s->AsStmtList();
		auto stmts = l->Stmts();

		if ( ControlReachesEnd(l, false ) )
			{
			if ( stmts.length() == 0 )
				post_rds = GetPreRDs(s);
			else
				post_rds = GetPostRDs(stmts[stmts.length() - 1]);
			}

		else
			;  // leave empty

		break;
		}

	case STMT_INIT:
		{
		auto init = s->AsInitStmt();
		auto& inits = *init->Inits();

		post_rds = GetPreRDs(s);

		for ( int i = 0; i < inits.length(); ++i )
			{
			auto id = inits[i];
			auto id_t = id->Type();

			// Only aggregates get initialized.
			auto tag = id_t->Tag();
			if ( ! IsAggrTag(tag) )
				continue;

			AddRDWithInit(post_rds, id, DefinitionPoint(s), false, 0);
			}

		break;
		}

	case STMT_NEXT:
	case STMT_BREAK:
	case STMT_RETURN:
		// No control flow past these statements, so no
		// post reaching defs.
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
		break;

	case STMT_ADD:
		// Tracking what's added to sets could have
		// some analysis utility but seems pretty rare,
		// so we punt for now. ###
		break;

	case STMT_DELETE:
		// Ideally we'd track these for removing optional
		// record elements, or (maybe) some inferences
		// about table/set elements. ###
		break;

	default:
		break;
	}

	if ( ! post_rds )
		post_rds = make_new_RD_ptr();

	AddPostRDs(s, post_rds);
	last_obj = s;

	if ( trace )
		{
		printf("post RDs for stmt %s:\n", stmt_name(s->Tag()));
		GetPostRDs(s)->Dump();
		}

	return TC_CONTINUE;
	}

bool RD_Decorate::CheckLHS(RD_ptr rd, const Expr* lhs, const AssignExpr* a)
	{
	switch ( lhs->Tag() ) {
	case EXPR_REF:
		{
		auto r = lhs->AsRefExpr();
		return CheckLHS(rd, r->Op(), a);
		}

	case EXPR_NAME:
		{
		auto n = lhs->AsNameExpr();
		auto id = n->Id();

		AddRDWithInit(rd, id, DefinitionPoint(a), false, a);

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
			AddRDWithInit(rd, id, DefinitionPoint(a), true, 0);
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

		AddRDWithInit(rd, field_rd, DefinitionPoint(a), false, a);

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
			AddRD(rd, id, DefinitionPoint(a));

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
				printf("dead code: %s\n", obj_desc(stmt));
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
	AddPreRDs(e, PredecessorRDs());

	auto rd = GetPreRDs(e);

	if ( trace )
		{
		printf("pre RDs for expr %s:\n", expr_name(e->Tag()));
		GetPreRDs(e)->Dump();
		}

	last_obj = e;

	switch ( e->Tag() ) {
        case EXPR_NAME:
		{
		auto n = e->AsNameExpr();
		auto id = n->Id();

		if ( id->IsGlobal() )
			{
			// Treat global as fully initialized.
			AddRDWithInit(rd, id, DefinitionPoint(n), true, nullptr);
			AddPreRDs(e, rd);
			}

		if ( ! HasPreRD(e, id) )
			printf("%s has no pre at %s\n", id->Name(), obj_desc(e));

		if ( id->Type()->Tag() == TYPE_RECORD )
			{
			CreateRecordRDs(rd, item_map.GetIDReachingDef(id),
					false, DefinitionPoint(n), nullptr);
			AddPostRDs(e, rd);
			}

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
			AddRD(rd, lhs_id, DefinitionPoint(a_t));
			AddPostRDs(e, GetPreRDs(e));
			AddPostRDs(e, rd);

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

		if ( CheckLHS(rd, lhs, a) )
			{
			AddPostRDs(e, GetPreRDs(e));
			AddPostRDs(e, rd);

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

	case EXPR_FIELD:
		{
		auto f = e->AsFieldExpr();
		auto r = f->Op();

		if ( r->Tag() != EXPR_NAME && r->Tag() != EXPR_FIELD )
			break;

		r->Traverse(this);
		auto r_def = item_map.GetExprReachingDef(r);

		if ( r_def )
			{
			auto fn = f->FieldName();
			auto field_rd =
				item_map.GetConstIDReachingDef(r_def, fn);

			if ( ! field_rd )
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
				printf("no ID reaching def for %s\n", id->Name());

			auto fn = hf->FieldName();
			auto field_rd = id_rd->FindField(fn);
			if ( ! field_rd )
				{
				auto ft = id_rt->FieldType(fn);
				field_rd = id_rd->CreateField(fn, ft);
				rd->AddRD(field_rd, DefinitionPoint(hf));
				AddPostRDs(e, rd);
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
				AddRD(rd, expr->AsNameExpr()->Id(), 
					DefinitionPoint(c));
			else
				expr->Traverse(this);
			}

		AddPostRDs(e, GetPreRDs(e));
		AddPostRDs(e, rd);

		return TC_ABORTSTMT;
		}

	case EXPR_LAMBDA:
		// ### Too tricky to get these right.
		AddPostRDs(e, GetPreRDs(e));
		return TC_ABORTSTMT;

	default:
		break;
	}

	AddPostRDs(e, GetPreRDs(e));

	return TC_CONTINUE;
	}

TraversalCode RD_Decorate::PostExpr(const Expr* e)
	{
	AddPostRDs(e, GetPreRDs(e));
	return TC_CONTINUE;
	}

void RD_Decorate::TrackInits(const Func* f, const id_list* inits)
	{
	// This code is duplicated for STMT_INIT.  It's a pity that
	// that doesn't get used for aggregates that are initialized
	// just incidentally.
	RD_ptr rd = make_new_RD_ptr();
	for ( int i = 0; i < inits->length(); ++i )
		{
		auto id = (*inits)[i];
		auto id_t = id->Type();

		// Only aggregates get initialized.
		auto tag = id_t->Tag();
		if ( IsAggrTag(tag) )
			AddRDWithInit(rd, id, DefinitionPoint(f), false, 0);
		}

	AddPostRDs(f, rd);
	}

void RD_Decorate::AddRD(RD_ptr rd, const ID* id, DefinitionPoint dp)
	{
	if ( id == 0 )
		printf("oops\n");

	auto di = item_map.GetIDReachingDef(id);

	if ( di )
		rd->AddRD(di, dp);
	}

void RD_Decorate::AddRDWithInit(RD_ptr rd, const ID* id,
				DefinitionPoint dp, bool assume_full,
				const AssignExpr* init)
	{
	auto di = item_map.GetIDReachingDef(id);
	if ( ! di )
		return;

	AddRDWithInit(rd, di, dp, assume_full, init);
	}

void RD_Decorate::AddRDWithInit(RD_ptr rd, DefinitionItem* di,
				DefinitionPoint dp, bool assume_full,
				const AssignExpr* init)
	{
	rd->AddRD(di, dp);

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

	CreateRecordRDs(rd, di, assume_full, dp, rhs_di);
	}

void RD_Decorate::CreateRecordRDs(RD_ptr rd, DefinitionItem* di,
					bool assume_full, DefinitionPoint dp,
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
		rd->AddRD(di_i, dp);

		if ( t_i->Tag() == TYPE_RECORD )
			CreateRecordRDs(rd, di_i, assume_full, dp, rhs_di_i);
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

	auto f = id->ID_Val()->AsFunc();

	if ( only_func && ! streq(f->Name(), only_func) )
		return;

	RD_Decorate cb;
	f->Traverse(&cb);
	cb.TrackInits(f, inits);
	body->Traverse(&cb);

	push_scope(id, nullptr);
	ReductionContext rc(f->GetScope());
	printf("Original: %s\n", obj_desc(body));
	auto new_body = body->Reduce(&rc);
	printf("Transformed: %s\n", obj_desc(new_body));
	f->ReplaceBody({AdoptRef{}, body}, {AdoptRef{}, new_body});
	pop_scope();
	}
