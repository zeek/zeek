// See the file "COPYING" in the main distribution directory for copyright.

#include "ID.h"
#include "Var.h"
#include "Scope.h"
#include "Expr.h"
#include "Stmt.h"
#include "Desc.h"
#include "ProfileFunc.h"
#include "Reporter.h"
#include "zeek/script_opt/Reduce.h"
#include "zeek/script_opt/TempVar.h"


namespace zeek::detail {


Reducer::Reducer(Scope* s)
	{
	scope = s;
	}

Reducer::~Reducer()
	{
	for ( int i = 0; i < temps.length(); ++i )
		delete temps[i];
	}

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

	return make_intrusive<NameExpr>(FindNewLocal(n.get()));
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
	for ( auto& id : ids )
		if ( ! ID_IsReduced(id) )
			return false;

	return true;
	}

IDPtr Reducer::UpdateID(IDPtr id)
	{
	if ( ID_IsReduced(id) )
		return id;

	return FindNewLocal(id.get());
	}

bool Reducer::ID_IsReduced(const ID* id) const
	{
	return inline_block_level == 0 || id->IsGlobal() || IsTemporary(id) ||
		IsNewLocal(id);
	}

NameExprPtr Reducer::GenInlineBlockName(IDPtr id)
	{
	return make_intrusive<NameExpr>(GenLocal(id.get()));
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

IDPtr Reducer::FindNewLocal(ID* id)
	{
	auto mapping = orig_to_new_locals.find(id);

	if ( mapping != orig_to_new_locals.end() )
		return mapping->second;

	return GenLocal(id);
	}

IDPtr Reducer::GenLocal(ID* orig)
	{
	if ( Optimizing() )
		reporter->InternalError("Generating a new local while optimizing");

	char buf[8192];
	int n = new_locals.size();
	snprintf(buf, sizeof buf, "%s.%d", orig->Name(), n);

	IDPtr local_id = install_ID(buf, "<internal>", false, false);
	local_id->SetType(orig->GetType());

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


const Expr* non_reduced_perp;
bool checking_reduction;

bool NonReduced(const Expr* perp)
	{
	if ( checking_reduction )
		non_reduced_perp = perp;

	return false;
	}


} // zeek::detail
