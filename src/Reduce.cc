// See the file "COPYING" in the main distribution directory for copyright.

#include "ID.h"
#include "Var.h"
#include "Scope.h"
#include "Expr.h"
#include "Stmt.h"
#include "Desc.h"
#include "Reporter.h"
#include "Reduce.h"


class TempVar {
public:
	TempVar(int num, const IntrusivePtr<BroType>& t, IntrusivePtr<Expr> rhs);
	~TempVar()	{ delete name; }

	const char* Name() const	{ return name; }
	const BroType* Type() const	{ return type.get(); }
	const Expr* RHS() const		{ return rhs.get(); }

	IntrusivePtr<ID> Id() const		{ return id; }
	void SetID(IntrusivePtr<ID> _id)	{ id = _id; }

	void Deactivate()	{ active = false; }
	bool IsActive() const	{ return active; }

	const ConstExpr* Const() const	{ return const_expr; }
	// Surely the most use of "const" in any single line in
	// the Zeek codebase :-P.
	void SetConst(const ConstExpr* _const) { const_expr = _const; }

	IntrusivePtr<ID> Alias() const		{ return alias; }
	const DefPoints* DPs() const		{ return dps; }
	void SetAlias(IntrusivePtr<ID> id, const DefPoints* dps);
	void SetDPs(const DefPoints* _dps);

	const RD_ptr& MaxRDs() const	{ return max_rds; }
	void SetMaxRDs(RD_ptr rds)	{ max_rds = rds; }

protected:
	char* name;
	IntrusivePtr<ID> id;
	const IntrusivePtr<BroType>& type;
	IntrusivePtr<Expr> rhs;
	bool active = true;
	const ConstExpr* const_expr;
	IntrusivePtr<ID> alias;
	const DefPoints* dps;
	RD_ptr max_rds;
};

TempVar::TempVar(int num, const IntrusivePtr<BroType>& t,
			IntrusivePtr<Expr> _rhs) : type(t), dps(nullptr)
	{
	char buf[8192];
	snprintf(buf, sizeof buf, "#%d", num);
	name = copy_string(buf);
	id = nullptr;
	rhs = _rhs;
	const_expr = nullptr;
	alias = nullptr;
	dps = nullptr;
	max_rds = nullptr;
	}

void TempVar::SetAlias(IntrusivePtr<ID> _alias, const DefPoints* _dps)
	{
	if ( alias )
		reporter->InternalError("Re-aliasing a temporary");

	if ( ! _dps )
		{
		printf("trying to alias %s to %s\n", name, _alias->Name());
		reporter->InternalError("Empty dps for alias");
		}

	if ( alias == id )
		reporter->InternalError("Creating alias loop");

	alias = _alias;
	dps = _dps;
	}

void TempVar::SetDPs(const DefPoints* _dps)
	{
	ASSERT(_dps->length() == 1);
	dps = _dps;
	}


Reducer::Reducer(Scope* s)
	{
	scope = s;
	mgr = nullptr;
	}

Reducer::~Reducer()
	{
	for ( int i = 0; i < temps.length(); ++i )
		delete temps[i];
	}

IntrusivePtr<Expr> Reducer::GenTemporaryExpr(const IntrusivePtr<BroType>& t,
						IntrusivePtr<Expr> rhs)
	{
	return {AdoptRef{}, new NameExpr(GenTemporary(t, rhs))};
	}

bool Reducer::SameDPs(const DefPoints* dp1, const DefPoints* dp2) const
	{
	if ( dp1 == dp2 )
		return true;

	if ( ! dp1 || ! dp2 )
		return false;

	// Given how we construct DPs, they should be element-by-element
	// equivalent; we don't have to worry about reordering.
	if ( dp1->length() != dp2->length() )
		return false;

	for ( auto i = 0; i < dp1->length(); ++i )
		if ( ! (*dp1)[i].SameAs((*dp2)[i]) )
			return false;

	return true;
	}

bool Reducer::SameVal(const Val* v1, const Val* v2) const
	{
	if ( is_atomic_val(v1) )
		return same_atomic_val(v1, v2);
	else
		return v1 == v2;
	}

IntrusivePtr<Expr> Reducer::NewVarUsage(IntrusivePtr<ID> var,
						const DefPoints* dps,
						const Expr* orig)
	{
	if ( ! dps )
		reporter->InternalError("null defpoints in NewVarUsage");

	auto var_usage = make_intrusive<NameExpr>(var);
	SetDefPoints(var_usage.get(), dps);
	TrackExprReplacement(orig, var_usage.get());

	return var_usage;
	}

const DefPoints* Reducer::GetDefPoints(const NameExpr* var)
	{
	auto dps = FindDefPoints(var);

	if ( ! dps )
		{
		auto id = var->Id();
		auto di = mgr->GetConstID_DI(id);
		auto rds = mgr->GetPreMaxRDs(GetRDLookupObj(var));

		dps = rds->GetDefPoints(di);

		SetDefPoints(var, dps);
		}

	return dps;
	}

const DefPoints* Reducer::FindDefPoints(const NameExpr* var) const
	{
	auto dps = var_usage_to_DPs.find(var);
	if ( dps == var_usage_to_DPs.end() )
		return nullptr;
	else
		return dps->second;
	}

void Reducer::SetDefPoints(const NameExpr* var, const DefPoints* dps)
	{
	var_usage_to_DPs[var] = dps;
	}

bool Reducer::SameOp(const Expr* op1, const Expr* op2)
	{
	if ( op1 == op2 )
		return true;

	if ( op1->Tag() != op2->Tag() )
		return false;

	if ( op1->Tag() == EXPR_NAME )
		{
		auto op1_n = op1->AsNameExpr();
		auto op2_n = op2->AsNameExpr();

		auto op1_id = op1_n->Id();
		auto op2_id = op2_n->Id();

		if ( op1_id != op2_id )
			return false;

		auto op1_dps = GetDefPoints(op1_n);
		auto op2_dps = GetDefPoints(op2_n);

		return SameDPs(op1_dps, op2_dps);
		}

	else if ( op1->Tag() == EXPR_CONST )
		{
		auto op1_c = op1->AsConstExpr();
		auto op2_c = op2->AsConstExpr();

		auto op1_v = op1_c->Value();
		auto op2_v = op2_c->Value();

		return SameVal(op1_v, op2_v);
		}

	else if ( op1->Tag() == EXPR_LIST )
		{
		auto op1_l = op1->AsListExpr()->Exprs();
		auto op2_l = op2->AsListExpr()->Exprs();

		if ( op1_l.length() != op2_l.length() )
			return false;

		for ( auto i = 0; i < op1_l.length(); ++i )
			if ( ! SameExpr(op1_l[i], op2_l[i]) )
				return false;

		return true;
		}

	else
		reporter->InternalError("bad singleton tag");
	}

// Returns true if the RHS associated with the expression "tmp" is
// equivalent to orig_rhs, given the reaching definitions associated
// with lhs.
bool Reducer::SameExpr(const Expr* e1, const Expr* e2)
	{
	if ( e1 == e2 )
		return true;

	if ( e1->Tag() != e2->Tag() )
		return false;

	if ( ! same_type(e1->Type().get(), e2->Type().get()) )
		return false;

	switch ( e1->Tag() ) {
	case EXPR_NAME:
	case EXPR_CONST:
		return SameOp(e1, e2);

	case EXPR_CLONE:
	case EXPR_RECORD_CONSTRUCTOR:
	case EXPR_TABLE_CONSTRUCTOR:
	case EXPR_SET_CONSTRUCTOR:
	case EXPR_VECTOR_CONSTRUCTOR:
	case EXPR_EVENT:
	case EXPR_SCHEDULE:
		// These always generate a new value.
		return false;

	case EXPR_INCR:
	case EXPR_DECR:
	case EXPR_AND_AND:
	case EXPR_OR_OR:
	case EXPR_ASSIGN:
	case EXPR_FIELD_ASSIGN:
	case EXPR_INDEX_SLICE_ASSIGN:
		// All of these should have been translated into something
		// else.
		reporter->InternalError("Unexpected tag in Reducer::SameExpr");

	case EXPR_ANY_INDEX:
		{
		auto a1 = e1->AsAnyIndexExpr();
		auto a2 = e2->AsAnyIndexExpr();

		if ( a1->Index() != a2->Index() )
			return false;

		return SameOp(a1->GetOp1(), a2->GetOp1());
		}

	case EXPR_FIELD:
		{
		auto f1 = e1->AsFieldExpr();
		auto f2 = e2->AsFieldExpr();

		if ( f1->Field() != f2->Field() )
			return false;

		return SameOp(f1->GetOp1(), f2->GetOp1());
		}

	case EXPR_HAS_FIELD:
		{
		auto f1 = e1->AsHasFieldExpr();
		auto f2 = e2->AsHasFieldExpr();

		if ( f1->Field() != f2->Field() )
			return false;

		return SameOp(f1->GetOp1(), f2->GetOp1());
		}

	case EXPR_LIST:
		{
		auto l1 = e1->AsListExpr()->Exprs();
		auto l2 = e2->AsListExpr()->Exprs();

		ASSERT(l1.length() == l2.length());

		for ( int i = 0; i < l1.length(); ++i )
			if ( ! SameExpr(l1[i], l2[i]) )
				return false;

		return true;
		}

	case EXPR_CALL:
		{
		auto c1 = e1->AsCallExpr();
		auto c2 = e2->AsCallExpr();
		auto f1 = c1->Func();
		auto f2 = c2->Func();

		if ( f1 != f2 )
			return false;

		if ( ! f1->IsPure() )
			return false;

		return SameExpr(c1->Args(), c2->Args());
		}

	case EXPR_LAMBDA:
		return false;

	case EXPR_IS:
		{
		if ( ! SameOp(e1->GetOp1(), e2->GetOp1()) )
			return false;

		auto i1 = e1->AsIsExpr();
		auto i2 = e2->AsIsExpr();

		return same_type(i1->TestType().get(), i2->TestType().get());
		}

	default:
		if ( ! e1->GetOp1() )
			reporter->InternalError("Bad default in Reducer::SameExpr");

		if ( ! SameOp(e1->GetOp1(), e2->GetOp1()) )
			return false;

		if ( e1->GetOp2() && ! SameOp(e1->GetOp2(), e2->GetOp2()) )
			return false;

		if ( e1->GetOp3() && ! SameOp(e1->GetOp3(), e2->GetOp3()) )
			return false;

		return true;
	}
	}

// Find a temporary, if any, whose RHS matches the given "rhs", using
// the reaching defs associated with "lhs".
IntrusivePtr<ID> Reducer::FindExprTmp(const Expr* rhs,
						const Expr* lhs,
						const TempVar* lhs_tmp)
	{
	for ( int i = 0; i < expr_temps.length(); ++i )
		{
		auto et_i = expr_temps[i];
		if ( et_i->Alias() || ! et_i->IsActive() || et_i == lhs_tmp )
			// This can happen due to re-reduction while
			// optimizing.
			continue;

		if ( SameExpr(rhs, et_i->RHS()) )
			{
			// Make sure its value always makes it here.
			auto id = et_i->Id();

			// We use lhs in the following rather than rhs
			// because the RHS can get rewritten (for example,
			// due to folding) after we generate RDs, and
			// thus might not have any.
			if ( ! mgr->HasPreMinRD(lhs, id.get()) )
				// Value isn't guaranteed to make it here.
				continue;

			return et_i->Id();
			}
		}

	return nullptr;
	}

bool Reducer::IsCSE(const AssignExpr* a,
				const NameExpr* lhs, const Expr* rhs)
	{
	auto a_max_rds = mgr->GetPostMaxRDs(GetRDLookupObj(a));

	auto lhs_id = lhs->Id();
	auto lhs_tmp = FindTemporary(lhs_id);
	auto rhs_tmp = FindExprTmp(rhs, lhs, lhs_tmp);

	IntrusivePtr<Expr> new_rhs;
	if ( rhs_tmp )
		{
		auto tmp_di = mgr->GetConstID_DI(rhs_tmp.get());
		auto dps = a_max_rds->GetDefPoints(tmp_di);
		new_rhs = NewVarUsage(rhs_tmp, dps, rhs);
		rhs = new_rhs.get();
		}

	if ( lhs_tmp )
		{
		if ( rhs->Tag() == EXPR_CONST )
			{ // mark temporary as just being a constant
			lhs_tmp->SetConst(rhs->AsConstExpr());
			return true;
			}

		if ( rhs->Tag() == EXPR_NAME )
			{
			auto rhs_id = rhs->AsNameExpr()->Id();
			auto rhs_tmp_var = FindTemporary(rhs_id);

			if ( rhs_tmp_var && rhs_tmp_var->Const() )
				{
				lhs_tmp->SetConst(rhs_tmp_var->Const());
				return true;
				}

			IntrusivePtr<ID> rhs_id_ptr = {NewRef{}, rhs_id};
			auto rhs_di = mgr->GetConstID_DI(rhs_id);
			auto dps = a_max_rds->GetDefPoints(rhs_di);

			auto rhs_const = CheckForConst(rhs_id_ptr, dps);
			if ( rhs_const )
				lhs_tmp->SetConst(rhs_const);
			else
				lhs_tmp->SetAlias(rhs_id_ptr, dps);

			return true;
			}

		// Track where we define the temporary.
		auto lhs_di = mgr->GetConstID_DI(lhs_id);
		auto dps = a_max_rds->GetDefPoints(lhs_di);
		if ( lhs_tmp->DPs() && ! SameDPs(lhs_tmp->DPs(), dps) )
			reporter->InternalError("double DPs for temporary");

		lhs_tmp->SetDPs(dps);
		SetDefPoints(lhs, dps);

		expr_temps.append(lhs_tmp);
		}

	return false;
	}

const ConstExpr* Reducer::CheckForConst(const IntrusivePtr<ID>& id,
						const DefPoints* dps) const
	{
	ASSERT(dps && dps->length() > 0);
	if ( dps->length() != 1 )
		// Multiple definitions of the variable reach to this
		// location.  In theory we could check whether they *all*
		// provide the same constant, but that seems hardly likely.
		return nullptr;

	auto dp = (*dps)[0];
	const Expr* e = nullptr;

	if ( dp.Tag() == STMT_DEF )
		{
		auto s = dp.StmtVal();
		if ( s->Tag() != STMT_EXPR )
			// Defined in a statement other than an assignment.
			return nullptr;

		auto s_e = s->AsExprStmt();
		e = s_e->StmtExpr();
		}

	else if ( dp.Tag() == EXPR_DEF )
		e = dp.ExprVal();

	else
		return nullptr;

	if ( e->Tag() != EXPR_ASSIGN )
		// Not sure why this would happen, other than EXPR_APPEND_TO,
		// but in any case not an expression we can mine for a
		// constant.
		return nullptr;

	auto a_e = e->AsAssignExpr();
	auto rhs = a_e->Op2();

	if ( rhs->Tag() != EXPR_CONST )
		return nullptr;

	return rhs->AsConstExpr();
	}

void Reducer::TrackExprReplacement(const Expr* orig, const Expr* e)
	{
	new_expr_to_orig[e] = orig;
	}

const BroObj* Reducer::GetRDLookupObj(const Expr* e) const
	{
	auto orig_e = new_expr_to_orig.find(e);
	if ( orig_e == new_expr_to_orig.end() )
		return e;
	else
		return orig_e->second;
	}

Expr* Reducer::OptExpr(Expr* e)
	{
	IntrusivePtr<Stmt> opt_stmts;
	auto opt_e = e->Reduce(this, opt_stmts);

	if ( opt_stmts )
		reporter->InternalError("Generating new statements while optimizing");

	if ( opt_e->Tag() == EXPR_NAME )
		return UpdateExpr({AdoptRef{}, opt_e}).release();

	// ### If this is an IndexAssignExpr or a FieldLHSAssignExpr,
	// make sure any temporaries associated with the aggregate
	// don't propagate across this statement for CSE.
	return opt_e;
	}

IntrusivePtr<Expr> Reducer::OptExpr(IntrusivePtr<Expr> e_ptr)
	{
	auto e = e_ptr.get();
	auto new_e = OptExpr(e);
	if ( new_e == e )
		{
		// Undo the Ref() that occurred.
		Unref(e);
		return e_ptr;
		}

	return {AdoptRef{}, new_e};
	}

IntrusivePtr<Expr> Reducer::UpdateExpr(IntrusivePtr<Expr> e)
	{
	if ( e->Tag() != EXPR_NAME )
		return OptExpr(e);

	auto n = e->AsNameExpr();
	auto id = n->Id();

	auto tmp_var = FindTemporary(id);
	if ( ! tmp_var )
		{
		auto max_rds = mgr->GetPreMaxRDs(GetRDLookupObj(n));

		IntrusivePtr<ID> id_ptr = {NewRef{}, id};
		auto di = mgr->GetConstID_DI(id);
		auto dps = max_rds->GetDefPoints(di);

		auto is_const = CheckForConst(id_ptr, dps);
		if ( is_const )
			{
			// Remember this variable as one whose value
			// we used for constrant propagation.  That
			// ensures we can subsequently not complain
			// about it being assigned but not used (though
			// we can still omit the assignment).
			constant_vars.insert(id);
			return make_intrusive<ConstExpr>(is_const->ValuePtr());
			}

		return e;
		}

	if ( tmp_var->Const() )
		return make_intrusive<ConstExpr>(tmp_var->Const()->ValuePtr());

	auto alias = tmp_var->Alias();
	if ( alias )
		{
		// Make sure that the definition points for the
		// alias here are the same as when the alias
		// was created.
		auto alias_tmp = FindTemporary(alias.get());

		if ( alias_tmp )
			{
			while ( alias_tmp->Alias() )
				{
				// Alias chains can occur due to
				// re-reduction while optimizing.
				auto a_id = alias_tmp->Id();
				if ( a_id == id )
					return e;

				alias_tmp = FindTemporary(alias_tmp->Id().get());
				}

			// Temporaries always have only one definition point,
			// so no need to check for consistency.
			auto new_usage = NewVarUsage(alias, alias_tmp->DPs(), e.get());
			return new_usage;
			}

		auto e_max_rds = mgr->GetPreMaxRDs(GetRDLookupObj(e.get()));
		auto alias_di = mgr->GetConstID_DI(alias.get());
		auto alias_dps = e_max_rds->GetDefPoints(alias_di);

		if ( SameDPs(alias_dps, tmp_var->DPs()) )
			return NewVarUsage(alias, alias_dps, e.get());
		else
			{
			printf("DPs differ: %s\n", obj_desc(e));
			return e;
			}
		}

	auto rhs = tmp_var->RHS();
	if ( rhs->Tag() != EXPR_CONST )
		return e;

	auto c = rhs->AsConstExpr();
	return make_intrusive<ConstExpr>(c->ValuePtr());
	}

Stmt* Reducer::MergeStmts(const NameExpr* lhs, IntrusivePtr<Expr> rhs,
					Stmt* succ_stmt)
	{
	// First check for tmp=rhs.
	auto lhs_id = lhs->Id();
	auto lhs_tmp = FindTemporary(lhs_id);

	if ( ! lhs_tmp )
		return nullptr;

	// We have tmp=rhs.  Now look for var=tmp.
	if ( succ_stmt->Tag() != STMT_EXPR )
		return nullptr;

	auto s_e = succ_stmt->AsExprStmt()->StmtExpr();
	if ( s_e->Tag() != EXPR_ASSIGN )
		return nullptr;

	auto a = s_e->AsAssignExpr();
	auto a_lhs = a->GetOp1();
	auto a_rhs = a->GetOp2();

	if ( a_lhs->Tag() != EXPR_REF || a_rhs->Tag() != EXPR_NAME )
		// Complex 2nd-statement assignment, or RHS not a candidate.
		return nullptr;

	auto a_lhs_deref = a_lhs->AsRefExpr()->GetOp1();
	if ( a_lhs_deref->Tag() != EXPR_NAME )
		// Complex 2nd-statement assignment.
		return nullptr;

	auto a_lhs_var = a_lhs_deref->AsNameExpr()->Id();
	auto a_rhs_var = a_rhs->AsNameExpr()->Id();

	if ( a_rhs_var != lhs_id )
		// 2nd statement is var=something else.
		return nullptr;

	if ( FindTemporary(a_lhs_var) )
		{
		// "var" is itself a temporary.  Don't complain, as
		// complex reductions can generate these.  We'll wind
		// up folding the chain once it hits a regular variable.
		return nullptr;
		}

	// Got it.  Mark the original temporary as no longer relevant.
	lhs_tmp->Deactivate();
	auto merge_e = make_intrusive<AssignExpr>(a_lhs_deref, rhs, false,
							nullptr, nullptr, false);
	TrackExprReplacement(rhs.get(), merge_e.get());

	return new ExprStmt(merge_e);
	}

IntrusivePtr<ID> Reducer::GenTemporary(const IntrusivePtr<BroType>& t,
						IntrusivePtr<Expr> rhs)
	{
	if ( Optimizing() )
		reporter->InternalError("Generating a new temporary while optimizing");

	if ( omitted_stmts.size() > 0 )
		reporter->InternalError("Generating a new temporary while pruning statements");

	auto temp = new TempVar(temps.length(), t, rhs);
	IntrusivePtr<ID> temp_id =
		install_ID(temp->Name(), "<internal>", false, false);

	temp_id->SetOffset(temp_id->Offset() + scope->Length());

	temp->SetID(temp_id);
	temp_id->SetType(t);

	temps.append(temp);
	ids_to_temps[temp_id.get()] = temp;

	return temp_id;
	}

TempVar* Reducer::FindTemporary(const ID* id) const
	{
	auto tmp = ids_to_temps.find(id);
	if ( tmp == ids_to_temps.end() )
		return nullptr;
	else
		return tmp->second;
	}


const Expr* non_reduced_perp;
bool checking_reduction;

bool NonReduced(const Expr* perp)
	{
	if ( checking_reduction )
		non_reduced_perp = perp;

	return false;
	}
