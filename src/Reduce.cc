// See the file "COPYING" in the main distribution directory for copyright.

#include "ID.h"
#include "Var.h"
#include "Scope.h"
#include "Expr.h"
#include "Stmt.h"
#include "Desc.h"
#include "ProfileFunc.h"
#include "Reporter.h"
#include "Reduce.h"
#include "TempVar.h"


class CSE_ValidityChecker : public TraversalCallback {
public:
	CSE_ValidityChecker(const std::vector<const ID*>& ids,
			const Expr* start_e, const Expr* end_e);

	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PostStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;

	bool IsValid() const
		{
		if ( ! is_valid )
			return false;

		if ( ! have_end_e )
			reporter->InternalError("CSE_ValidityChecker: saw start but not end");
		return true;
		}

protected:
	// Returns true if an assigment involving the given identifier on
	// the LHS is in conflict with the given list of identifiers.
	bool CheckID(const std::vector<const ID*>& ids, const ID* id) const;

	// Returns true if the assignment given by 'e' modifies an aggregate
	// with the same type as that of one of the identifiers.
	bool CheckAggrMod(const std::vector<const ID*>& ids,
				const Expr* e) const;

	const std::vector<const ID*>& ids;
	const Expr* start_e;
	const Expr* end_e;

	int field;
	IntrusivePtr<BroType> field_type;

	bool is_valid = true;
	bool have_start_e = false;
	bool have_end_e = false;

	// Whether analyzed expressions occur in the context of
	// a statement that modifies an aggregate ("add" or "delete").
	bool in_aggr_mod_stmt = false;
};

CSE_ValidityChecker::CSE_ValidityChecker(const std::vector<const ID*>& _ids,
				const Expr* _start_e, const Expr* _end_e)
: ids(_ids)
	{
	start_e = _start_e;
	end_e = _end_e;

	// Track whether this is a record assignment, in which case
	// we're attuned to assignments to the same field for the
	// same type of record.
	if ( start_e->Tag() == EXPR_FIELD )
		{
		field = start_e->AsFieldExpr()->Field();

		// Track the type of the record, too, so we don't confuse
		// field references to different records that happen to
		// have the same offset as potential aliases.
		field_type = start_e->GetOp1()->Type();
		}

	else
		field = -1;	// flags that there's no relevant field
	}

TraversalCode CSE_ValidityChecker::PreStmt(const Stmt* s)
	{
	if ( s->Tag() == STMT_ADD || s->Tag() == STMT_DELETE )
		in_aggr_mod_stmt = true;

	return TC_CONTINUE;
	}

TraversalCode CSE_ValidityChecker::PostStmt(const Stmt* s)
	{
	if ( s->Tag() == STMT_ADD || s->Tag() == STMT_DELETE )
		in_aggr_mod_stmt = false;

	return TC_CONTINUE;
	}

TraversalCode CSE_ValidityChecker::PreExpr(const Expr* e)
	{
	if ( e == start_e )
		{
		ASSERT(! have_start_e);
		have_start_e = true;

		// Don't analyze the expression, as it's our starting
		// point and we don't want to conflate its properties
		// with those of any intervening expression.
		return TC_CONTINUE;
		}

	if ( e == end_e )
		{
		if ( ! have_start_e )
			reporter->InternalError("CSE_ValidityChecker: saw end but not start");

		ASSERT(! have_end_e);
		have_end_e = true;

		// ... and we're now done.
		return TC_ABORTALL;
		}

	if ( ! have_start_e )
		// We don't yet have a starting point.
		return TC_CONTINUE;

	// We have a starting point, and not yet an ending point.
	auto t = e->Tag();

	switch ( t ) {
	case EXPR_ASSIGN:
		{
		auto lhs_ref = e->GetOp1()->AsRefExpr();
		auto lhs = lhs_ref->GetOp1()->AsNameExpr();

		if ( CheckID(ids, lhs->Id()) )
			{
			is_valid = false;
			return TC_ABORTALL;
			}

		// Note, we don't use CheckAggrMod() because this
		// is a plain assignment.  It might be changing a variable's
		// binding to an aggregate, but it's not changing the
		// aggregate itself.
		}
		break;

	case EXPR_INDEX_ASSIGN:
		{
		auto lhs_aggr = e->GetOp1();
		auto lhs_aggr_id = lhs_aggr->AsNameExpr()->Id();

		if ( CheckID(ids, lhs_aggr_id) || CheckAggrMod(ids, e) )
			{
			is_valid = false;
			return TC_ABORTALL;
			}
		}
		break;

	case EXPR_FIELD_LHS_ASSIGN:
		{
		auto lhs = e->GetOp1();
		auto lhs_aggr_id = lhs->AsNameExpr()->Id();
		auto lhs_field = e->AsFieldLHSAssignExpr()->Field();

		if ( lhs_field == field &&
		     same_type(lhs_aggr_id->TypePtr(), field_type) )
			{
			// Potential assignment to the same field as for
			// our expression of interest.  Even if the
			// identifier involved is not one we have our eye
			// on, due to aggregate aliasing this could be
			// altering the value of our expression, so bail.
			is_valid = false;
			return TC_ABORTALL;
			}

		if ( CheckAggrMod(ids, e) )
			{
			is_valid = false;
			return TC_ABORTALL;
			}
		}
		break;

	case EXPR_CALL:
		{
		for ( auto i : ids )
			if ( i->IsGlobal() || IsAggr(i->Type()) )
				{
				is_valid = false;
				return TC_ABORTALL;
				}
		}
		break;

	default:
		if ( in_aggr_mod_stmt && (t == EXPR_INDEX || t == EXPR_FIELD) )
			{
			auto aggr = e->GetOp1();
			auto aggr_id = aggr->AsNameExpr()->Id();

			if ( CheckID(ids, aggr_id) )
				{
				is_valid = false;
				return TC_ABORTALL;
				}
			}

		break;
	}

	return TC_CONTINUE;
	}

bool CSE_ValidityChecker::CheckID(const std::vector<const ID*>& ids,
					const ID* id) const
	{
	// Only check type info for aggregates.
	auto id_t = IsAggr(id->Type()) ? id->Type() : nullptr;

	for ( auto i : ids )
		{
		if ( id == i )
			return true;	// reassignment

		if ( id_t && same_type(id_t, i->Type()) )
			// Same-type aggregate.
			return true;
		}

	return false;
	}

bool CSE_ValidityChecker::CheckAggrMod(const std::vector<const ID*>& ids,
					const Expr* e) const
	{
	auto e_i_t = e->Type();
	if ( IsAggr(e_i_t) )
		{
		// This assignment sets an aggregate value.
		// Look for type matches.
		for ( auto i : ids )
			if ( same_type(e_i_t, i->TypePtr()) )
				return true;
		}

	return false;
	}


Reducer::Reducer(Scope* s)
	{
	scope = s;
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

NameExpr* Reducer::UpdateName(NameExpr* n)
	{
	if ( NameIsReduced(n) )
		{
		Ref(n);
		return n;
		}

	return new NameExpr(FindNewLocal(n));
	}

bool Reducer::NameIsReduced(const NameExpr* n) const
	{
	auto id = n->Id();
	return inline_block_level == 0 || id->IsGlobal() || IsTemporary(id) ||
		IsNewLocal(n);
	}

id_list* Reducer::UpdateIDs(id_list* ids)
	{
	loop_over_list(*ids, i)
		{
		IntrusivePtr<ID> id = {NewRef{}, (*ids)[i]};

		if ( ! ID_IsReduced(id) )
			(*ids)[i] = UpdateID(id).release();
		}

	return ids;
	}

bool Reducer::IDsAreReduced(const id_list* ids) const
	{
	for ( auto& id : *ids )
		if ( ! ID_IsReduced(id) )
			return false;

	return true;
	}

IntrusivePtr<ID> Reducer::UpdateID(IntrusivePtr<ID> id)
	{
	if ( ID_IsReduced(id) )
		return id;

	return GenLocal(id.get());
	}

bool Reducer::ID_IsReduced(const ID* id) const
	{
	return inline_block_level == 0 || id->IsGlobal() || IsTemporary(id) ||
		IsNewLocal(id);
	}

IntrusivePtr<NameExpr> Reducer::GenInlineBlockName(ID* id)
	{
	return make_intrusive<NameExpr>(GenLocal(id));
	}

IntrusivePtr<NameExpr> Reducer::PushInlineBlock(IntrusivePtr<BroType> type)
	{
	++inline_block_level;

	if ( ! type || type->Tag() == TYPE_VOID )
		return nullptr;

	char buf[8192];
	int n = new_locals.size();
	snprintf(buf, sizeof buf, "@retvar");

	IntrusivePtr<ID> ret_id = install_ID(buf, "<internal>", false, false);
	ret_id->SetType(type);

	// Track this as a new local *if* we're in the outermost inlining
	// block.  If we're recursively deeper into inlining, then this
	// variable will get mapped to a local anyway, so no need.
	if ( inline_block_level == 1 )
		new_locals.insert(ret_id.get());

	return GenInlineBlockName(ret_id.release());
	}

void Reducer::PopInlineBlock()
	{
	--inline_block_level;
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

		return same_DPs(op1_dps, op2_dps);
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

	if ( ! same_type(e1->Type(), e2->Type()) )
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

		return same_type(i1->TestType(), i2->TestType());
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
// the reaching defs associated with the assignment "a".
IntrusivePtr<ID> Reducer::FindExprTmp(const Expr* rhs, const Expr* a,
					const TempVar* lhs_tmp)
	{
	for ( int i = 0; i < expr_temps.length(); ++i )
		{
		auto et_i = expr_temps[i];
		if ( et_i->Alias() || ! et_i->IsActive() || et_i == lhs_tmp )
			// This can happen due to re-reduction while
			// optimizing.
			continue;

		auto et_i_expr = et_i->RHS();

		if ( SameExpr(rhs, et_i_expr) )
			{
			// Make sure its value always makes it here.
			auto id = et_i->Id().get();

			// We use 'a' in the following rather than rhs
			// because the RHS can get rewritten (for example,
			// due to folding) after we generate RDs, and
			// thus might not have any.
			if ( ! mgr->HasSinglePreMinRD(a, id) )
				// Value isn't guaranteed to make it here.
				continue;

			// Make sure there aren't ambiguities due to
			// possible modifications to aggregates.
			if ( ! ExprValid(id, et_i_expr, a) )
				continue;

			return et_i->Id();
			}
		}

	return nullptr;
	}

bool Reducer::ExprValid(const ID* id, const Expr* e1, const Expr* e2) const
	{
	// Here are the considerations for expression validity.
	//
	// * None of the operands used in the given expression can
	//   have been assigned.
	//
	// * If the expression yields an aggregate, or one of the
	//   operands in the expression is an aggregate, then there
	//   must not be any assignments to aggregates of the same
	//   type(s).  This is to deal with possible aliases.
	//
	// * Same goes to modifications of aggregates via "add" or "delete".
	//
	// * No propagation of expressions based on aggregates across
	//   function calls.
	//
	// * No propagation of expressions based on globals across calls.

	// Tracks which ID's are germane for our analysis.
	std::vector<const ID*> ids;

	ids.push_back(id);

	// Compute variables involved in the expression.
	auto op1 = e1->GetOp1();
	auto op2 = e1->GetOp2();
	auto op3 = e1->GetOp3();

	if ( op1 && op1->Tag() == EXPR_NAME )
		ids.push_back(op1->AsNameExpr()->Id());
	if ( op2 && op2->Tag() == EXPR_NAME )
		ids.push_back(op2->AsNameExpr()->Id());
	if ( op3 && op3->Tag() == EXPR_NAME )
		ids.push_back(op3->AsNameExpr()->Id());

	if ( e1->Tag() == EXPR_NAME )
		ids.push_back(e1->AsNameExpr()->Id());

	CSE_ValidityChecker vc(ids, e1, e2);
	reduction_root->Traverse(&vc);

	return vc.IsValid();
	}

bool Reducer::IsCSE(const AssignExpr* a, const NameExpr* lhs, const Expr* rhs)
	{
	auto a_max_rds = mgr->GetPostMaxRDs(GetRDLookupObj(a));

	auto lhs_id = lhs->Id();
	auto lhs_tmp = FindTemporary(lhs_id);
	auto rhs_tmp = FindExprTmp(rhs, a, lhs_tmp);

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
		if ( lhs_tmp->DPs() && ! same_DPs(lhs_tmp->DPs(), dps) )
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

		if ( s->Tag() == STMT_CATCH_RETURN )
			{
			// Check to see if this got optimized to an assignment.
			auto cr = s->AsCatchReturnStmt();
			s = cr->AssignStmt().get();

			if ( ! s )
				return nullptr;
			}

		if ( s->Tag() != STMT_EXPR )
			{
			// Defined in a statement other than an assignment.
			return nullptr;
			}

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

	if ( id->IsGlobal() )
		return e;

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
			// we used for constant propagation.  That
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

		if ( same_DPs(alias_dps, tmp_var->DPs()) )
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

	if ( a_lhs_var->Type()->Tag() != a_rhs_var->Type()->Tag() )
		// This can happen when we generate an assignment
		// specifically to convert to/from an "any" type.
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

	temp->SetID(temp_id);
	temp_id->SetType(t);

	temps.append(temp);
	ids_to_temps[temp_id.get()] = temp;

	return temp_id;
	}

IntrusivePtr<ID> Reducer::FindNewLocal(const NameExpr* n)
	{
	auto id = n->Id();
	auto mapping = orig_to_new_locals.find(id);

	if ( mapping != orig_to_new_locals.end() )
		return mapping->second;

	return GenLocal(id);
	}

IntrusivePtr<ID> Reducer::GenLocal(ID* orig)
	{
	if ( Optimizing() )
		reporter->InternalError("Generating a new local while optimizing");

	if ( omitted_stmts.size() > 0 )
		reporter->InternalError("Generating a new local while pruning statements");

	char buf[8192];
	int n = new_locals.size();
	snprintf(buf, sizeof buf, "%s.%d", orig->Name(), n);

	IntrusivePtr<ID> local_id = install_ID(buf, "<internal>", false, false);
	IntrusivePtr<BroType> t = {NewRef{}, orig->Type()};
	local_id->SetType(t);

	new_locals.insert(local_id.get());
	orig_to_new_locals[orig] = local_id;

	return local_id;
	}

bool Reducer::IsNewLocal(const ID* id) const
	{
	ID* non_const_ID = (ID*) id;	// I don't get why C++ requires this
	return new_locals.count(non_const_ID) != 0;
	}

TempVar* Reducer::FindTemporary(const ID* id) const
	{
	auto tmp = ids_to_temps.find(id);
	if ( tmp == ids_to_temps.end() )
		return nullptr;
	else
		return tmp->second;
	}


bool same_DPs(const DefPoints* dp1, const DefPoints* dp2)
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


const Expr* non_reduced_perp;
bool checking_reduction;

bool NonReduced(const Expr* perp)
	{
	if ( checking_reduction )
		non_reduced_perp = perp;

	return false;
	}
