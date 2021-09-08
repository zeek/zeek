// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ID.h"
#include "zeek/Var.h"
#include "zeek/Scope.h"
#include "zeek/Expr.h"
#include "zeek/Stmt.h"
#include "zeek/Desc.h"
#include "zeek/Reporter.h"
#include "zeek/script_opt/ExprOptInfo.h"
#include "zeek/script_opt/StmtOptInfo.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/Reduce.h"
#include "zeek/script_opt/TempVar.h"


namespace zeek::detail {

StmtPtr Reducer::Reduce(StmtPtr s)
	{
	reduction_root = std::move(s);

	try
		{
		return reduction_root->Reduce(this);
		}
	catch ( InterpreterException& e )
		{
		/* Already reported. */
		return reduction_root;
		}
	}

ExprPtr Reducer::GenTemporaryExpr(const TypePtr& t, ExprPtr rhs)
	{
	auto e = make_intrusive<NameExpr>(GenTemporary(t, rhs));
	e->SetLocationInfo(rhs->GetLocationInfo());

	// No need to associate with current statement, since these
	// are not generated during optimization.

	return e;
	}

NameExprPtr Reducer::UpdateName(NameExprPtr n)
	{
	if ( NameIsReduced(n.get()) )
		return n;

	auto ne = make_intrusive<NameExpr>(FindNewLocal(n));

	// This name can be used by follow-on optimization analysis,
	// so need to associate it with its statement.
	BindExprToCurrStmt(ne);

	return ne;
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

NameExprPtr Reducer::GenInlineBlockName(const IDPtr& id)
	{
	// We do this during reduction, not optimization, so no need
	// to associate with curr_stmt.
	return make_intrusive<NameExpr>(GenLocal(id));
	}

NameExprPtr Reducer::PushInlineBlock(TypePtr type)
	{
	++inline_block_level;

	if ( ! type || type->Tag() == TYPE_VOID )
		return nullptr;

	IDPtr ret_id = install_ID("@retvar", "<internal>", false, false);
	ret_id->SetType(type);
	ret_id->GetOptInfo()->SetTemp();

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

ExprPtr Reducer::NewVarUsage(IDPtr var, const Expr* orig)
	{
	auto var_usage = make_intrusive<NameExpr>(var);
	BindExprToCurrStmt(var_usage);

	return var_usage;
	}

void Reducer::BindExprToCurrStmt(const ExprPtr& e)
	{
	e->GetOptInfo()->stmt_num = curr_stmt->GetOptInfo()->stmt_num;
	}

void Reducer::BindStmtToCurrStmt(const StmtPtr& s)
	{
	s->GetOptInfo()->stmt_num = curr_stmt->GetOptInfo()->stmt_num;
	}

bool Reducer::SameOp(const Expr* op1, const Expr* op2)
	{
	if ( op1 == op2 )
		return true;

	if ( op1->Tag() != op2->Tag() )
		return false;

	if ( op1->Tag() == EXPR_NAME )
		{
		// Needs to be both the same identifier and in contexts
		// where the identifier has the same definitions.
		auto op1_n = op1->AsNameExpr();
		auto op2_n = op2->AsNameExpr();

		auto op1_id = op1_n->Id();
		auto op2_id = op2_n->Id();

		if ( op1_id != op2_id )
			return false;

		auto e_stmt_1 = op1->GetOptInfo()->stmt_num;
		auto e_stmt_2 = op2->GetOptInfo()->stmt_num;

		auto def_1 = op1_id->GetOptInfo()->DefinitionBefore(e_stmt_1);
		auto def_2 = op2_id->GetOptInfo()->DefinitionBefore(e_stmt_2);

		return def_1 == def_2 && def_1 != NO_DEF;
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

	reporter->InternalError("bad singleton tag");
	return false;
	}

bool Reducer::SameExpr(const Expr* e1, const Expr* e2)
	{
	if ( e1 == e2 )
		return true;

	if ( e1->Tag() != e2->Tag() )
		return false;

	if ( ! same_type(e1->GetType(), e2->GetType()) )
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

IDPtr Reducer::FindExprTmp(const Expr* rhs, const Expr* a,
				const std::shared_ptr<const TempVar>& lhs_tmp)
	{
	for ( const auto& et_i : expr_temps )
		{
		if ( et_i->Alias() || ! et_i->IsActive() || et_i == lhs_tmp )
			// This can happen due to re-reduction while
			// optimizing.
			continue;

		auto et_i_expr = et_i->RHS();

		if ( SameExpr(rhs, et_i_expr) )
			{
			// We have an apt candidate.  Make sure its value
			// always makes it here.
			auto id = et_i->Id().get();

			auto stmt_num = a->GetOptInfo()->stmt_num;
			auto def = id->GetOptInfo()->DefinitionBefore(stmt_num);

			if ( def == NO_DEF )
				// The temporary's value isn't guaranteed
				// to make it here.
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
	// * Same goes to modifications of aggregates via "add" or "delete"
	//   or "+=" append.
	//
	// * No propagation of expressions that are based on aggregates
	//   across function calls.
	//
	// * No propagation of expressions that are based on globals
	//   across calls.

	// Tracks which ID's are germane for our analysis.
	std::vector<const ID*> ids;

	ids.push_back(id);

	// Identify variables involved in the expression.
	CheckIDs(e1->GetOp1().get(), ids);
	CheckIDs(e1->GetOp2().get(), ids);
	CheckIDs(e1->GetOp3().get(), ids);

	if ( e1->Tag() == EXPR_NAME )
		ids.push_back(e1->AsNameExpr()->Id());

	CSE_ValidityChecker vc(ids, e1, e2);
	reduction_root->Traverse(&vc);

	return vc.IsValid();
	}

void Reducer::CheckIDs(const Expr* e, std::vector<const ID*>& ids) const
	{
	if ( ! e )
		return;

	if ( e->Tag() == EXPR_LIST )
		{
		const auto& e_l = e->AsListExpr()->Exprs();
		for ( auto i = 0; i < e_l.length(); ++i )
			CheckIDs(e_l[i], ids);
		}

	else if ( e->Tag() == EXPR_NAME )
		ids.push_back(e->AsNameExpr()->Id());
	}

bool Reducer::IsCSE(const AssignExpr* a, const NameExpr* lhs, const Expr* rhs)
	{
	auto lhs_id = lhs->Id();
	auto lhs_tmp = FindTemporary(lhs_id);	// nil if LHS not a temporary
	auto rhs_tmp = FindExprTmp(rhs, a, lhs_tmp);

	ExprPtr new_rhs;
	if ( rhs_tmp )
		{ // We already have a temporary
		new_rhs = NewVarUsage(rhs_tmp, rhs);
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
			auto rhs_id = rhs->AsNameExpr()->IdPtr();
			auto rhs_tmp_var = FindTemporary(rhs_id.get());

			if ( rhs_tmp_var && rhs_tmp_var->Const() )
				{ // temporary can be replaced with constant
				lhs_tmp->SetConst(rhs_tmp_var->Const());
				return true;
				}

			// Treat the LHS as either an alias for the RHS,
			// or as a constant if the RHS is a constant in
			// this context.
			auto stmt_num = a->GetOptInfo()->stmt_num;
			auto rhs_const = CheckForConst(rhs_id, stmt_num);

			if ( rhs_const )
				lhs_tmp->SetConst(rhs_const);
			else
				lhs_tmp->SetAlias(rhs_id);

			return true;
			}

		expr_temps.emplace_back(lhs_tmp);
		}

	return false;
	}

const ConstExpr* Reducer::CheckForConst(const IDPtr& id, int stmt_num) const
	{
	if ( id->GetType()->Tag() == TYPE_ANY )
		// Don't propagate identifiers of type "any" as constants.
		// This is because the identifier might be used in some
		// context that's dynamically unreachable due to the type
		// of its value (such as via a type-switch), but for which
		// constant propagation of the constant value to that
		// context can result in compile-time errors when folding
		// expressions in which the identifier appears (and is
		// in that context presumed to have a different type).
		return nullptr;

	auto oi = id->GetOptInfo();
	auto c = oi->Const();

	if ( c )
		return c;

	auto e = id->GetOptInfo()->DefExprBefore(stmt_num);
	if ( e )
		{
		auto ce = constant_exprs.find(e.get());
		if ( ce != constant_exprs.end() )
			e = ce->second;

		if ( e->Tag() == EXPR_CONST )
			return e->AsConstExpr();

		// Follow aliases.
		if ( e->Tag() != EXPR_NAME )
			return nullptr;

		return CheckForConst(e->AsNameExpr()->IdPtr(), stmt_num);
		}

	return nullptr;
	}

ConstExprPtr Reducer::Fold(ExprPtr e)
	{
	auto c = make_intrusive<ConstExpr>(e->Eval(nullptr));
	FoldedTo(e, c);
	return c;
	}

void Reducer::FoldedTo(ExprPtr e, ConstExprPtr c)
	{
	constant_exprs[e.get()] = std::move(c);
	folded_exprs.push_back(std::move(e));
	}

ExprPtr Reducer::OptExpr(Expr* e)
	{
	StmtPtr opt_stmts;
	auto opt_e = e->Reduce(this, opt_stmts);

	if ( opt_stmts )
		reporter->InternalError("Generating new statements while optimizing");

	if ( opt_e->Tag() == EXPR_NAME )
		return UpdateExpr(opt_e);

	return opt_e;
	}

ExprPtr Reducer::UpdateExpr(ExprPtr e)
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
		IDPtr id_ptr = {NewRef{}, id};
		auto stmt_num = e->GetOptInfo()->stmt_num;
		auto is_const = CheckForConst(id_ptr, stmt_num);

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
		// Make sure that the definitions for the alias here are
		// the same as when the alias was created.
		auto alias_tmp = FindTemporary(alias.get());

		// Resolve any alias chains.
		while ( alias_tmp && alias_tmp->Alias() )
			{
			alias = alias_tmp->Alias();
			alias_tmp = FindTemporary(alias.get());
			}

		if ( alias->GetOptInfo()->IsTemp() )
			{
			// Temporaries always have only one definition,
			// so no need to check for consistency.
			auto new_usage = NewVarUsage(alias, e.get());
			return new_usage;
			}

		auto e_stmt_1 = e->GetOptInfo()->stmt_num;
		auto e_stmt_2 = tmp_var->RHS()->GetOptInfo()->stmt_num;

		auto def_1 = alias->GetOptInfo()->DefinitionBefore(e_stmt_1);
		auto def_2 = tmp_var->Id()->GetOptInfo()->DefinitionBefore(e_stmt_2);

		if ( def_1 == def_2 && def_1 != NO_DEF )
			return NewVarUsage(alias, e.get());
		else
			return e;
		}

	auto rhs = tmp_var->RHS();
	if ( rhs->Tag() != EXPR_CONST )
		return e;

	auto c = rhs->AsConstExpr();
	return make_intrusive<ConstExpr>(c->ValuePtr());
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
	auto merge_e_stmt = make_intrusive<ExprStmt>(merge_e);

	// Update the associated stmt_num's.  For strict correctness, we
	// want both of these bound to the earlier of the two statements
	// we're merging (though in practice, either will work, since
	// we're eliding the only difference between the two).  Our
	// caller ensures this.
	BindExprToCurrStmt(merge_e);
	BindStmtToCurrStmt(merge_e_stmt);

	return merge_e_stmt;
	}

IDPtr Reducer::GenTemporary(const TypePtr& t, ExprPtr rhs)
	{
	if ( Optimizing() )
		reporter->InternalError("Generating a new temporary while optimizing");

	if ( omitted_stmts.size() > 0 )
		reporter->InternalError("Generating a new temporary while pruning statements");

	auto temp = std::make_shared<TempVar>(temps.size(), t, rhs);
	IDPtr temp_id = install_ID(temp->Name(), "<internal>", false, false);

	temp->SetID(temp_id);
	temp_id->SetType(t);

	temps.push_back(temp);
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

	if ( omitted_stmts.size() > 0 )
		reporter->InternalError("Generating a new local while pruning statements");

	char buf[8192];
	int n = new_locals.size();
	snprintf(buf, sizeof buf, "%s.%d", orig->Name(), n);

	IDPtr local_id = install_ID(buf, "<internal>", false, false);
	local_id->SetType(orig->GetType());
	local_id->SetAttrs(orig->GetAttrs());

	if ( orig->GetOptInfo()->IsTemp() )
		local_id->GetOptInfo()->SetTemp();

	new_locals.insert(local_id.get());
	orig_to_new_locals[orig.get()] = local_id;

	return local_id;
	}

bool Reducer::IsNewLocal(const ID* id) const
	{
	ID* non_const_ID = (ID*) id;	// I don't get why C++ requires this
	return new_locals.count(non_const_ID) != 0;
	}

std::shared_ptr<TempVar> Reducer::FindTemporary(const ID* id) const
	{
	auto tmp = ids_to_temps.find(id);
	if ( tmp == ids_to_temps.end() )
		return nullptr;
	else
		return tmp->second;
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

	case EXPR_APPEND_TO:
		// This doesn't directly change any identifiers, but does
		// alter an aggregate.
		if ( CheckAggrMod(ids, e) )
			{
			is_valid = false;
			return TC_ABORTALL;
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
	const auto& e_i_t = e->GetType();
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


const Expr* non_reduced_perp;
bool checking_reduction;

bool NonReduced(const Expr* perp)
	{
	if ( checking_reduction )
		non_reduced_perp = perp;

	return false;
	}


} // zeek::detail
