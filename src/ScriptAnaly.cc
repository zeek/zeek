// See the file "COPYING" in the main distribution directory for copyright.

#include "ScriptAnaly.h"
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


typedef enum {
	NO_DEF,
	STMT_DEF,
	ASSIGN_EXPR_DEF,
	ADDTO_EXPR_DEF,
	CALL_EXPR_DEF,	// for aggregates
	FUNC_DEF,
} def_point_type;

class DefinitionPoint {
public:
	DefinitionPoint()
		{
		o = nullptr;
		t = NO_DEF;
		}

	DefinitionPoint(const Stmt* s)
		{
		o = s;
		t = STMT_DEF;
		}

	DefinitionPoint(const AssignExpr* a)
		{
		o = a;
		t = ASSIGN_EXPR_DEF;
		}

	DefinitionPoint(const AddToExpr* a)
		{
		o = a;
		t = ADDTO_EXPR_DEF;
		}

	DefinitionPoint(const CallExpr* c)
		{
		o = c;
		t = CALL_EXPR_DEF;
		}

	DefinitionPoint(const Func* f)
		{
		o = f;
		t = FUNC_DEF;
		}

	def_point_type Tag() const	{ return t; }

	const BroObj* OpaqueVal() const	{ return o; }

	const Stmt* StmtVal() const	{ return (const Stmt*) o; }
	const AssignExpr* AssignVal() const	
		{ return (const AssignExpr*) o; }
	const AddToExpr* AddToVal() const	
		{ return (const AddToExpr*) o; }
	const Func* FuncVal() const	{ return (const Func*) o; }

	bool SameAs(const DefinitionPoint& dp) const
		{
		return dp.Tag() == Tag() && dp.OpaqueVal() == OpaqueVal();
		}

protected:
	def_point_type t;
	const BroObj* o;
};

static DefinitionPoint no_def;

typedef std::map<const ID*, DefinitionPoint> ReachingDefs;

static ReachingDefs null_RDs;

typedef std::map<const BroObj*, ReachingDefs> AnalyInfo;


class RD_Decorate : public TraversalCallback {
public:
	RD_Decorate()
		{
		pre_a_i = new AnalyInfo;
		post_a_i = new AnalyInfo;
		last_obj = nullptr;
		}

	~RD_Decorate() override
		{
		delete pre_a_i;
		delete post_a_i;
		}

	TraversalCode PreFunction(const Func*) override;
	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PostStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;
	TraversalCode PostExpr(const Expr*) override;

protected:
	bool CheckLHS(ReachingDefs& rd, const Expr* lhs, const AssignExpr* a);

	bool IsAggrTag(TypeTag tag) const;
	bool IsAggr(const Expr* e) const;

	bool ControlReachesEnd(const Stmt* s, bool is_definite,
				bool ignore_break = false) const;

	const ReachingDefs& PredecessorRDs() const
		{
		auto& rd = PostRDs(last_obj);
		if ( rd.size() > 0 )
			return rd;

		// PostRDs haven't been set yet.
		return PreRDs(last_obj);
		}

	const ReachingDefs& PreRDs(const BroObj* o) const
		{ return RDs(pre_a_i, o); }
	const ReachingDefs& PostRDs(const BroObj* o) const
		{ return RDs(post_a_i, o); }

	void AddPreRDs(const BroObj* o, const ReachingDefs& rd)
		{ AddRDs(pre_a_i, o, rd); }
	void AddPostRDs(const BroObj* o, const ReachingDefs& rd)
		{ AddRDs(post_a_i, o, rd); }

	void AddRDs(AnalyInfo* a_i, const BroObj* o, const ReachingDefs& rd)
		{
		if ( HasRDs(a_i, o) )
			MergeRDs(a_i, o, rd);
		else
			a_i->insert(AnalyInfo::value_type(o, rd));
		}

	void MergeRDs(AnalyInfo* a_i, const BroObj* o, const ReachingDefs& rd)
		{
		auto& curr_rds = a_i->find(o)->second;
		for ( auto& one_rd : rd )
			AddRD(curr_rds, one_rd.first, one_rd.second);
		}

	bool HasRDs(AnalyInfo* a_i, const BroObj* o) const
		{
		auto RDs = a_i->find(o);
		return RDs != a_i->end();
		}

	void AddRD(ReachingDefs& rd, const ID* id, DefinitionPoint dp) const
		{
		if ( id == 0 )
			printf("ooops\n");
		rd.insert(ReachingDefs::value_type(id, dp));
		}

	bool HasPreRD(const BroObj* o, const ID* id) const
		{
		return HasRD(pre_a_i, o, id);
		}

	bool HasRD(const AnalyInfo* a_i, const BroObj* o, const ID* id) const
		{
		auto RDs = a_i->find(o);
		if ( RDs == a_i->end() )
			return false;

		return RDs->second.find(id) != RDs->second.end();
		}

	const DefinitionPoint& FindRD(const AnalyInfo* a_i, const BroObj* o,
					const ID* id) const
		{
		auto RDs = a_i->find(o);
		if ( RDs == a_i->end() )
			return no_def;

		auto dp = RDs->second.find(id);
		if ( dp == RDs->second.end() )
			return no_def;

		return dp->second;
		}

	const ReachingDefs& RDs(const AnalyInfo* a_i, const BroObj* o) const
		{
		if ( o == nullptr )
			return null_RDs;

		auto rd = a_i->find(o);
		if ( rd != a_i->end() )
			return rd->second;
		else
			return null_RDs;
		}

	void DumpRDs(const ReachingDefs& rd) const;
	void PrintRD(const ID*, const DefinitionPoint& dp) const;

	bool RDsDiffer(const ReachingDefs& r1, const ReachingDefs& r2) const;

	ReachingDefs IntersectRDs(const ReachingDefs& r1,
					const ReachingDefs& r2) const;
	ReachingDefs UnionRDs(const ReachingDefs& r1,
					const ReachingDefs& r2) const;

	bool RDHasPair(const ReachingDefs& r,
			const ID* id, const DefinitionPoint& dp) const;

	// Mappings of reaching defs pre- and post- execution
	// of the given object.
	AnalyInfo* pre_a_i;
	AnalyInfo* post_a_i;

	// The object we most recently finished analyzing.
	const BroObj* last_obj;

	bool trace = false;
};


TraversalCode RD_Decorate::PreFunction(const Func* f)
	{
	auto ft = f->FType();
	auto args = ft->Args();
	auto scope = f->GetScope();

	int n = args->NumFields();

	ReachingDefs rd;

	for ( int i = 0; i < n; ++i )
		{
		auto arg_i = args->FieldName(i);
		auto arg_i_id = scope->Lookup(arg_i);

		if ( ! arg_i_id )
			arg_i_id = scope->Lookup(make_full_var_name(current_module.c_str(), arg_i).c_str());

#if 0
		if ( ! arg_i_id )
			printf("can't look up %s\n", args->FieldName(i));
		else
			printf("adding param %s (%s)\n", args->FieldName(i), arg_i_id->Name());
#endif

		AddRD(rd, arg_i_id, DefinitionPoint(f));
		}

	AddPostRDs(f, rd);
	last_obj = f;

	if ( trace )
		{
		printf("traversing function %s, post RDs:\n", f->Name());
		DumpRDs(PostRDs(f));
		}

	// Don't continue traversal here, as that will then loop over
	// older bodies.  Instead, we do it manually.
	return TC_ABORTALL;
	}

TraversalCode RD_Decorate::PreStmt(const Stmt* s)
	{
	auto rd = PredecessorRDs();
	AddPreRDs(s, rd);

	rd = PreRDs(s);

	if ( trace )
		{
		printf("pre RDs for stmt %s:\n", stmt_name(s->Tag()));
		DumpRDs(rd);
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
			AddPreRDs(c->Body(), rd);

		break;
		}

	case STMT_FOR:
		{
		auto f = s->AsForStmt();

		auto ids = f->LoopVar();
		auto e = f->LoopExpr();
		auto body = f->LoopBody();

		for ( const auto& id : *ids )
			AddRD(rd, id, DefinitionPoint(s));

		auto val_var = f->ValueVar();
		if ( val_var )
			AddRD(rd, val_var, DefinitionPoint(s));

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
	ReachingDefs post_rds;

	switch ( s->Tag() ) {
	case STMT_PRINT:
	case STMT_EVENT:
	case STMT_WHEN:
		post_rds = PreRDs(s);
		break;

        case STMT_EXPR:
		{
		auto e = s->AsExprStmt()->StmtExpr();
		post_rds = PostRDs(e);
		break;
		}

	case STMT_IF:
		{
		auto i = s->AsIfStmt();

		if ( RDsDiffer(PostRDs(i), PreRDs(s)) )
			; // Complain

		auto if_branch_rd = PostRDs(i->TrueBranch());
		auto else_branch_rd = PostRDs(i->FalseBranch());

		auto true_reached = ControlReachesEnd(i->TrueBranch(), false);
		auto false_reached = ControlReachesEnd(i->FalseBranch(), false);

		if ( true_reached && false_reached )
			post_rds = IntersectRDs(if_branch_rd, else_branch_rd);

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
				auto case_rd = PostRDs(c->Body());
				if ( did_first )
					post_rds = IntersectRDs(post_rds,
								case_rd);
				else
					post_rds = case_rd;
				}

			if ( (! c->ExprCases() ||
			      c->ExprCases()->Exprs().length() == 0) &&
			     (! c->TypeCases() ||
			      c->TypeCases()->length() == 0) )
				default_seen = true;
			}

		if ( ! default_seen )
			post_rds = UnionRDs(post_rds, PreRDs(s));

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
		post_rds = IntersectRDs(PreRDs(s), PostRDs(body));

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
		post_rds = IntersectRDs(PreRDs(s), PostRDs(body));

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
				post_rds = PreRDs(s);
			else
				post_rds = PostRDs(stmts[stmts.length() - 1]);
			}

		else
			;  // leave empty

		break;
		}

	case STMT_INIT:
		{
		auto init = s->AsInitStmt();
		auto& inits = *init->Inits();

		post_rds = PreRDs(s);

		for ( int i = 0; i < inits.length(); ++i )
			{
			auto id = inits[i];
			auto id_t = id->Type();

			// Only aggregates get initialized.
			auto tag = id_t->Tag();
			if ( IsAggrTag(tag) )
				AddRD(post_rds, id, DefinitionPoint(s));
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

	AddPostRDs(s, post_rds);
	last_obj = s;

	return TC_CONTINUE;
	}

bool RD_Decorate::CheckLHS(ReachingDefs& rd, const Expr* lhs,
				const AssignExpr* a)
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
		AddRD(rd, id, DefinitionPoint(a));
		return true;
		}

	case EXPR_LIST:
		{
		auto l = lhs->AsListExpr();
		for ( const auto& expr : l->Exprs() )
			{
			if ( expr->Tag() == EXPR_NAME )
				{
				auto n = expr->AsNameExpr();
				auto id = n->Id();
				AddRD(rd, id, DefinitionPoint(a));
				}

			else
				// This will happen for table initialiers,
				// for example.
				return false;
			}

		return true;
		}

        case EXPR_FIELD:
		{
		auto f = lhs->AsFieldExpr();
		auto r = f->Op();

		if ( r->Tag() == EXPR_NAME )
			{
			// ### should track field assignment here

			// Don't recurse into assessing the operand,
			// since it's not a reference to the name itself.

			// ### For now, though, mark it as initialized here.
			auto id = r->AsNameExpr()->Id();
			AddRD(rd, id, DefinitionPoint(a));
			return true;
			}

		return false;
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
	auto rd = PredecessorRDs();
	AddPreRDs(e, rd);

	if ( trace )
		{
		printf("pre RDs for expr %s:\n", expr_name(e->Tag()));
		DumpRDs(PreRDs(e));
		}

	last_obj = e;

	switch ( e->Tag() ) {
        case EXPR_NAME:
		{
		auto n = e->AsNameExpr();
		auto id = n->Id();
		if ( ! id->IsGlobal() && ! HasPreRD(e, id) )
			printf("%s has no pre at %s\n", id->Name(), obj_desc(e));

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
			AddPostRDs(e, PreRDs(e));
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
			AddPostRDs(e, PreRDs(e));
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

	case EXPR_HAS_FIELD:
		// ### in the future, use this to protect subsequent field
		// accesses.
		break;

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

		AddPostRDs(e, PreRDs(e));
		AddPostRDs(e, rd);

		return TC_ABORTSTMT;
		}

	case EXPR_LAMBDA:
		// ### Too tricky to get these right.
		AddPostRDs(e, PreRDs(e));
		return TC_ABORTSTMT;

	default:
		break;
	}

	AddPostRDs(e, PreRDs(e));

	return TC_CONTINUE;
	}

TraversalCode RD_Decorate::PostExpr(const Expr* e)
	{
	AddPostRDs(e, PreRDs(e));
	return TC_CONTINUE;
	}


bool RD_Decorate::RDHasPair(const ReachingDefs& r,
				const ID* id, const DefinitionPoint& dp) const
	{
	// ### update for multimap
	auto l = r.find(id);
	return l != r.end() && l->second.SameAs(dp);
	}

ReachingDefs RD_Decorate::IntersectRDs(const ReachingDefs& r1,
					const ReachingDefs& r2) const
	{
	ReachingDefs res;

	auto i = r1.begin();
	while ( i != r1.end() )
		{
		if ( RDHasPair(r2, i->first, i->second) )
			AddRD(res, i->first, i->second);

		++i;
		}

	return res;
	}

ReachingDefs RD_Decorate::UnionRDs(const ReachingDefs& r1,
					const ReachingDefs& r2) const
	{
	ReachingDefs res = r2;

	auto i = r1.begin();
	while ( i != r1.end() )
		{
		if ( ! RDHasPair(r2, i->first, i->second) )
			AddRD(res, i->first, i->second);

		++i;
		}

	return res;
	}

bool RD_Decorate::RDsDiffer(const ReachingDefs& r1, const ReachingDefs& r2) const
	{
	// This is just an optimization.
	if ( r1.size() != r2.size() )
		return false;

	auto r3 = IntersectRDs(r1, r2);

	return r3.size() == r1.size();
	}


void RD_Decorate::DumpRDs(const ReachingDefs& rd) const
	{
	if ( rd.size() == 0 )
		{
		printf("<none>\n");
		return;
		}

	auto r = rd.begin();

	for ( auto r = rd.begin(); r != rd.end(); ++r )
		PrintRD(r->first, r->second);
	}

void RD_Decorate::PrintRD(const ID* id, const DefinitionPoint& dp) const
	{
	printf("RD for %s\n", id->Name());
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


void analyze_func(const Func* f, const Stmt* body)
	{
	// if ( streq(f->Name(), "test_func") )
		{
		RD_Decorate cb;
		f->Traverse(&cb);
		body->Traverse(&cb);
		}
	}
