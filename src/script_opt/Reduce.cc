// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ID.h"
#include "zeek/Var.h"
#include "zeek/Scope.h"
#include "zeek/Expr.h"
#include "zeek/Stmt.h"
#include "zeek/Desc.h"
#include "zeek/Reporter.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/Reduce.h"
#include "zeek/script_opt/TempVar.h"


namespace zeek::detail {


ExprPtr Reducer::GenTemporaryExpr(const TypePtr& t, ExprPtr rhs)
	{
	auto e = make_intrusive<NameExpr>(GenTemporary(t, rhs));
	e->SetLocationInfo(rhs->GetLocationInfo());
	return e;
	}

NameExprPtr Reducer::UpdateName(NameExprPtr n)
	{
	if ( NameIsReduced(n.get()) )
		return n;

	return make_intrusive<NameExpr>(FindNewLocal(n));
	}

bool Reducer::NameIsReduced(const NameExpr* n) const
	{
	auto id = n->Id();
	return inline_block_level == 0 || id->IsGlobal() || IsTemporary(id) ||
		IsNewLocal(n);
	}

void Reducer::UpdateIDs(IDPList* ids)
	{
	loop_over_list(*ids, i)
		{
		IDPtr id = {NewRef{}, (*ids)[i]};

		if ( ! ID_IsReduced(id) )
			{
			Unref((*ids)[i]);
			(*ids)[i] = UpdateID(id).release();
			}
		}
	}

void Reducer::UpdateIDs(std::vector<IDPtr>& ids)
	{
	for ( auto& id : ids )
		if ( ! ID_IsReduced(id) )
			id = UpdateID(id);
	}

bool Reducer::IDsAreReduced(const IDPList* ids) const
	{
	for ( auto& id : *ids )
		if ( ! ID_IsReduced(id) )
			return false;

	return true;
	}

bool Reducer::IDsAreReduced(const std::vector<IDPtr>& ids) const
	{
	for ( const auto& id : ids )
		if ( ! ID_IsReduced(id) )
			return false;

	return true;
	}

IDPtr Reducer::UpdateID(IDPtr id)
	{
	if ( ID_IsReduced(id) )
		return id;

	return FindNewLocal(id);
	}

bool Reducer::ID_IsReduced(const ID* id) const
	{
	return inline_block_level == 0 || id->IsGlobal() || IsTemporary(id) ||
		IsNewLocal(id);
	}

NameExprPtr Reducer::GenInlineBlockName(IDPtr id)
	{
	return make_intrusive<NameExpr>(GenLocal(id));
	}

NameExprPtr Reducer::PushInlineBlock(TypePtr type)
	{
	++inline_block_level;

	if ( ! type || type->Tag() == TYPE_VOID )
		return nullptr;

	IDPtr ret_id = install_ID("@retvar", "<internal>", false, false);
	ret_id->SetType(type);

	// Track this as a new local *if* we're in the outermost inlining
	// block.  If we're recursively deeper into inlining, then this
	// variable will get mapped to a local anyway, so no need.
	if ( inline_block_level == 1 )
		new_locals.insert(ret_id.get());

	return GenInlineBlockName(ret_id);
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

IDPtr Reducer::GenTemporary(const TypePtr& t, ExprPtr rhs)
	{
	if ( Optimizing() )
		reporter->InternalError("Generating a new temporary while optimizing");

	auto temp = new TempVar(temps.length(), t, rhs);
	IDPtr temp_id = install_ID(temp->Name(), "<internal>", false, false);

	temp->SetID(temp_id);
	temp_id->SetType(t);

	temps.append(temp);
	ids_to_temps[temp_id.get()] = temp;

	return temp_id;
	}

IDPtr Reducer::FindNewLocal(const IDPtr& id)
	{
	auto mapping = orig_to_new_locals.find(id.get());

	if ( mapping != orig_to_new_locals.end() )
		return mapping->second;

	return GenLocal(id);
	}

IDPtr Reducer::GenLocal(const IDPtr& orig)
	{
	if ( Optimizing() )
		reporter->InternalError("Generating a new local while optimizing");

	char buf[8192];
	int n = new_locals.size();
	snprintf(buf, sizeof buf, "%s.%d", orig->Name(), n);

	IDPtr local_id = install_ID(buf, "<internal>", false, false);
	local_id->SetType(orig->GetType());
	local_id->SetAttrs(orig->GetAttrs());

	new_locals.insert(local_id.get());
	orig_to_new_locals[orig.get()] = local_id;

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

StmtPtr Reducer::MergeStmts(const NameExpr* lhs, ExprPtr rhs, Stmt* succ_stmt)
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

	auto a_lhs_deref = a_lhs->AsRefExprPtr()->GetOp1();
	if ( a_lhs_deref->Tag() != EXPR_NAME )
		// Complex 2nd-statement assignment.
		return nullptr;

	auto a_lhs_var = a_lhs_deref->AsNameExpr()->Id();
	auto a_rhs_var = a_rhs->AsNameExpr()->Id();

	if ( a_rhs_var != lhs_id )
		// 2nd statement is var=something else.
		return nullptr;

	if ( a_lhs_var->GetType()->Tag() != a_rhs_var->GetType()->Tag() )
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

	return make_intrusive<ExprStmt>(merge_e);
	}

void Reducer::TrackExprReplacement(const Expr* orig, const Expr* e)
	{
	new_expr_to_orig[e] = orig;
	}


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
		field_type = start_e->GetOp1()->GetType();
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
		auto lhs_ref = e->GetOp1()->AsRefExprPtr();
		auto lhs = lhs_ref->GetOp1()->AsNameExpr();

		if ( CheckID(ids, lhs->Id(), false) )
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

		if ( CheckID(ids, lhs_aggr_id, true) || CheckAggrMod(ids, e) )
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
		     same_type(lhs_aggr_id->GetType(), field_type) )
			{
			// Potential assignment to the same field as for
			// our expression of interest.  Even if the
			// identifier involved is not one we have our eye
			// on, due to aggregate aliasing this could be
			// altering the value of our expression, so bail.
			is_valid = false;
			return TC_ABORTALL;
			}

		if ( CheckID(ids, lhs_aggr_id, true) || CheckAggrMod(ids, e) )
			{
			is_valid = false;
			return TC_ABORTALL;
			}
		}
		break;

	case EXPR_CALL:
		{
		for ( auto i : ids )
			if ( i->IsGlobal() || IsAggr(i->GetType()) )
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

			if ( CheckID(ids, aggr_id, true) )
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
					const ID* id, bool ignore_orig) const
	{
	// Only check type info for aggregates.
	auto id_t = IsAggr(id->GetType()) ? id->GetType() : nullptr;

	for ( auto i : ids )
		{
		if ( ignore_orig && i == ids.front() )
			continue;

		if ( id == i )
			return true;	// reassignment

		if ( id_t && same_type(id_t, i->GetType()) )
			// Same-type aggregate.
			return true;
		}

	return false;
	}

bool CSE_ValidityChecker::CheckAggrMod(const std::vector<const ID*>& ids,
					const Expr* e) const
	{
	auto e_i_t = e->GetType();
	if ( IsAggr(e_i_t) )
		{
		// This assignment sets an aggregate value.
		// Look for type matches.
		for ( auto i : ids )
			if ( same_type(e_i_t, i->GetType()) )
				return true;
		}

	return false;
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


} // zeek::detail
