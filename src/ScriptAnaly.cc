// See the file "COPYING" in the main distribution directory for copyright.

#include "ScriptAnaly.h"
#include "Desc.h"
#include "Expr.h"
#include "Stmt.h"
#include "Scope.h"
#include "Traverse.h"


typedef enum {
	STMT_DEF,
	ASSIGNEXPR_DEF,
	FUNC_DEF,
} def_point_type;

class DefinitionPoint {
public:
	DefinitionPoint(const Stmt* s)
		{
		stmt = s;
		t = STMT_DEF;

		assign = nullptr;
		func = nullptr;
		}

	DefinitionPoint(const AssignExpr* a)
		{
		assign = a;
		t = ASSIGNEXPR_DEF;

		stmt = nullptr;
		func = nullptr;
		}

	DefinitionPoint(const Func* f)
		{
		func = f;
		t = FUNC_DEF;

		stmt = nullptr;
		assign = nullptr;
		}

protected:
	def_point_type t;

	const Stmt* stmt;
	const AssignExpr* assign;
	const Func* func;
};

typedef std::map<const ID*, const BroObj*> ReachingDefs;

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
		// ### think Union
		a_i->insert(AnalyInfo::value_type(o, rd));
		}

	void AddRD(ReachingDefs& rd, const ID* id, const BroObj* e) const
		{
		rd.insert(ReachingDefs::value_type(id, e));
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

	void PrintRD(const ID*, const BroObj*) const;

	bool RDsDiffer(const ReachingDefs& r1, const ReachingDefs& r2) const;

	ReachingDefs IntersectRDs(const ReachingDefs& r1,
					const ReachingDefs& r2) const;

	bool RDHasPair(const ReachingDefs& r,
			const ID* id, const BroObj* o) const;

	// Mappings of reaching defs pre- and post- execution
	// of the given object.
	AnalyInfo* pre_a_i;
	AnalyInfo* post_a_i;

	// The object we most recently finished analyzing.
	const BroObj* last_obj;
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
		AddRD(rd, arg_i_id, f);
		}

	AddPostRDs(f, rd);
	last_obj = f;

	printf("traversing function %s\n", f->Name());
	return TC_CONTINUE;
	}

TraversalCode RD_Decorate::PreStmt(const Stmt* s)
	{
	auto rd = PostRDs(last_obj);
	AddPreRDs(s, rd);

	last_obj = s;

	switch ( s->Tag() ) {
	case STMT_IF:
		{
		// For now we assume there no definitions occur
		// inside the conditional.  If one does, we'll
		// detect that & complain about it in the PostStmt.
		auto i = s->AsIfStmt();
		auto if_branch_rd = PostRDs(i->TrueBranch());
		auto else_branch_rd = PostRDs(i->FalseBranch());

		AddPreRDs(s, if_branch_rd);
		AddPreRDs(s, else_branch_rd);

		break;
		}

	case STMT_SWITCH:
		{
		auto sw = s->AsSwitchStmt();
		auto cases = sw->Cases();

		for ( const auto& c : *cases )
			AddPreRDs(c, rd);

		break;
		}

	case STMT_FOR:
		{
		auto f = s->AsForStmt();

		auto ids = f->LoopVar();
		auto e = f->LoopExpr();
		auto body = f->LoopBody();

		for ( const auto& id : *ids )
			AddRD(rd, id, s);

		AddPreRDs(body, rd);

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

		post_rds = IntersectRDs(if_branch_rd, else_branch_rd);

		break;
		}

	case STMT_SWITCH:
		{
		auto sw = s->AsSwitchStmt();
		auto cases = sw->Cases();

		bool did_first = false;

		for ( const auto& c : *cases )
			{
			auto case_rd = PostRDs(c);
			if ( did_first )
				post_rds = IntersectRDs(post_rds, case_rd);
			else
				post_rds = case_rd;
			}

		break;
		}

	case STMT_FOR:
		{
		auto f = s->AsForStmt();
		auto body = f->LoopBody();

		// Apply intersection since loop might not execute
		// at all.
		post_rds = IntersectRDs(PreRDs(s), PostRDs(body));

		break;
		}

	case STMT_WHILE:
		{
		auto w = s->AsWhileStmt();
		auto body = w->Body();

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

		if ( stmts.length() == 0 )
			post_rds = PreRDs(s);
		else
			post_rds = PostRDs(stmts[stmts.length() - 1]);

		break;
		}

	case STMT_INIT:
		{
		auto init = s->AsInitStmt();
		auto& inits = *init->Inits();

		post_rds = PreRDs(s);

		for ( int i = 0; i < inits.length(); ++i )
			AddRD(post_rds, inits[i], s);

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

#if 0
        STMT_INIT,
#endif

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
	case EXPR_NAME:
		{
		auto n = lhs->AsNameExpr();
		auto id = n->Id();
		AddRD(rd, id, a);
		return true;
		}

	// ### in the future, we should handle EXPR_FIELD here
	// for record assignments.

	default:
		return false;
	}
	}

TraversalCode RD_Decorate::PreExpr(const Expr* e)
	{
	auto rd = PostRDs(last_obj);
	AddPreRDs(e, rd);

	last_obj = e;

	switch ( e->Tag() ) {
        case EXPR_NAME:
		{
		auto n = e->AsNameExpr();
		auto id = n->Id();
		if ( ! HasPreRD(e, id) )
			printf("got one\n");

		break;
		}

        case EXPR_ASSIGN:
		{
		auto a = e->AsAssignExpr();
		auto lhs = a->Op1();
		auto rhs = a->Op2();

		if ( CheckLHS(rd, lhs, a) )
			{
			AddPostRDs(a, rd);
			rhs->Traverse(this);
			return TC_ABORTSTMT;
			}

		// Too hard to figure out what's going on with the assignment.
		// Just analyze it in terms of values it accesses.
		break;
		}

        case EXPR_FIELD_ASSIGN:
		// ### in the future, track specific field.

        case EXPR_FIELD:
		// ### in the future, analyze access to specific fields.
		break;

	case EXPR_HAS_FIELD:
		// ### in the future, use this to protect subsequent field
		// accesses.
		break;

	default:
		break;
	}

	AddPostRDs(e, PreRDs(e));

	return TC_CONTINUE;
	}

TraversalCode RD_Decorate::PostExpr(const Expr* e)
	{
	switch ( e->Tag() ) {
        case EXPR_NAME:
		{
		auto n = e->AsNameExpr();
		auto id = n->Id();
		if ( ! HasPreRD(e, id) )
			printf("got one\n");

		break;
		}

        case EXPR_ASSIGN:
		{
		auto a = e->AsAssignExpr();
		auto lhs = a->Op1();
		}

        case EXPR_INDEX:
        case EXPR_FIELD:
	case EXPR_HAS_FIELD:
        case EXPR_FIELD_ASSIGN:
        case EXPR_INDEX_SLICE_ASSIGN:
		break;

	default:
		AddPostRDs(e, PreRDs(e));
		break;
	}

	return TC_CONTINUE;
	}


bool RD_Decorate::RDHasPair(const ReachingDefs& r,
				const ID* id, const BroObj* o) const
	{
	// ### update for multimap
	auto l = r.find(id);
	return l != r.end() && l->second == o;
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

bool RD_Decorate::RDsDiffer(const ReachingDefs& r1, const ReachingDefs& r2) const
	{
	// This is just an optimization.
	if ( r1.size() != r2.size() )
		return false;

	auto r3 = IntersectRDs(r1, r2);

	return r3.size() == r1.size();
	}


void RD_Decorate::PrintRD(const ID*, const BroObj*) const
	{
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
	ODesc d;

	e->Describe(&d);
	d.SP();

	auto l = e->GetLocationInfo();
	if ( l )
		l->Describe(&d);
	else
		d.Add(" no location info");

	printf("foldable %s: %s\n", type, d.Description());
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


void analyze_func(const Func* f)
	{
	RD_Decorate cb;
	f->Traverse(&cb);
	}
