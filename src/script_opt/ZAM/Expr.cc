// See the file "COPYING" in the main distribution directory for copyright.

// Methods for traversing Expr AST nodes to generate ZAM code.

#include "zeek/script_opt/ZAM/Compile.h"
#include "zeek/Reporter.h"
#include "zeek/Desc.h"

namespace zeek::detail {

const ZAMStmt ZAMCompiler::CompileExpr(const Expr* e)
	{
	switch ( e->Tag() ) {
	case EXPR_INCR:
	case EXPR_DECR:
		return CompileIncrExpr(static_cast<const IncrExpr*>(e));

	case EXPR_APPEND_TO:
		return CompileAppendToExpr(static_cast<const AppendToExpr*>(e));

	case EXPR_ASSIGN:
		return CompileAssignExpr(static_cast<const AssignExpr*>(e));

	case EXPR_INDEX_ASSIGN:
		{
		auto iae = static_cast<const IndexAssignExpr*>(e);
		auto t = iae->GetOp1()->GetType()->Tag();
		if ( t == TYPE_VECTOR )
			return AssignVecElems(iae);

		ASSERT(t == TYPE_TABLE);
		return AssignTableElem(iae);
		}

	case EXPR_FIELD_LHS_ASSIGN:
		return CompileFieldLHSAssignExpr(static_cast<const FieldLHSAssignExpr*>(e));

	case EXPR_SCHEDULE:
		return CompileScheduleExpr(static_cast<const ScheduleExpr*>(e));

	case EXPR_EVENT:
		{
		auto ee = static_cast<const EventExpr*>(e);
		auto h = ee->Handler().Ptr();
		auto args = ee->Args();
		return EventHL(h, args);
		}

	default:
		reporter->InternalError("bad statement type in ZAMCompile::CompileExpr");
	}
	}

const ZAMStmt ZAMCompiler::CompileIncrExpr(const IncrExpr* e)
	{
	auto target = e->Op()->AsRefExpr()->GetOp1()->AsNameExpr();

	auto s = EmptyStmt();

	if ( target->GetType()->Tag() == TYPE_INT )
		{
		if ( e->Tag() == EXPR_INCR )
			return IncrIV(target);
		else
			return DecrIV(target);
		}

	if ( e->Tag() == EXPR_INCR )
		return IncrUV(target);
	else
		return DecrUV(target);
	}

const ZAMStmt ZAMCompiler::CompileAppendToExpr(const AppendToExpr* e)
	{
	auto op1 = e->GetOp1();
	auto op2 = e->GetOp2();

	auto n2 = op2->Tag() == EXPR_NAME ? op2->AsNameExpr() : nullptr;
	auto cc = op2->Tag() != EXPR_NAME ? op2->AsConstExpr() : nullptr;

	if ( op1->Tag() == EXPR_FIELD )
		{
		auto f = op1->AsFieldExpr()->Field();
		auto n1 = op1->GetOp1()->AsNameExpr();
		return AppendToField(n1, n2, cc, f);
		}

	auto n1 = op1->AsNameExpr();

	return n2 ? AppendToVV(n1, n2) : AppendToVC(n1, cc);
	}

const ZAMStmt ZAMCompiler::CompileAssignExpr(const AssignExpr* e)
	{
	auto op1 = e->GetOp1();
	auto op2 = e->GetOp2();

	auto lhs = op1->AsRefExpr()->GetOp1()->AsNameExpr();
	auto lt = lhs->GetType().get();
	auto rhs = op2.get();
	auto r1 = rhs->GetOp1();

	if ( rhs->Tag() == EXPR_INDEX &&
	     (r1->Tag() == EXPR_NAME || r1->Tag() == EXPR_CONST) )
		return CompileAssignToIndex(lhs, rhs->AsIndexExpr());

	switch ( rhs->Tag() ) {
#include "ZAM-GenDirectDefs.h"

	default:
		break;
	}

	auto rt = rhs->GetType();

	auto r2 = rhs->GetOp2();
	auto r3 = rhs->GetOp3();

	if ( rhs->Tag() == EXPR_LAMBDA )
		{
		// ###
		// reporter->Error("lambda expressions not supported for compiling");
		return ErrorStmt();
		}

	if ( rhs->Tag() == EXPR_NAME )
		return AssignVV(lhs, rhs->AsNameExpr());

	if ( rhs->Tag() == EXPR_CONST )
		return AssignVC(lhs, rhs->AsConstExpr());

	if ( rhs->Tag() == EXPR_IN && r1->Tag() == EXPR_LIST )
		{
		// r2 can be a constant due to propagating "const"
		// globals, for example.
		if ( r2->Tag() == EXPR_NAME )
			{
			auto r2n = r2->AsNameExpr();

			if ( r2->GetType()->Tag() == TYPE_TABLE )
				return L_In_TVLV(lhs, r1->AsListExpr(), r2n);

			return L_In_VecVLV(lhs, r1->AsListExpr(), r2n);
			}

		auto r2c = r2->AsConstExpr();

		if ( r2->GetType()->Tag() == TYPE_TABLE )
			return L_In_TVLC(lhs, r1->AsListExpr(), r2c);

		return L_In_VecVLC(lhs, r1->AsListExpr(), r2c);
		}

	if ( rhs->Tag() == EXPR_ANY_INDEX )
		return AnyIndexVVi(lhs, r1->AsNameExpr(),
		                   rhs->AsAnyIndexExpr()->Index());

	if ( rhs->Tag() == EXPR_COND && r2->IsConst() && r3->IsConst() )
		{
		// Split into two statement, given we don't support
		// two constants in a single statement.
		auto n1 = r1->AsNameExpr();
		auto c2 = r2->AsConstExpr();
		auto c3 = r3->AsConstExpr();
		(void) CondC1VVC(lhs, n1, c2);
		return CondC2VVC(lhs, n1, c3);
		}

	if ( r1 && r2 )
		{
		auto v1 = IsVector(r1->GetType()->Tag());
		auto v2 = IsVector(r2->GetType()->Tag());

		if ( v1 != v2 && rhs->Tag() != EXPR_IN )
			{
			reporter->Error("deprecated mixed vector/scalar operation not supported for ZAM compiling");
			return ErrorStmt();
			}
		}

	if ( r1 && r1->IsConst() )
#include "ZAM-GenExprsDefsC1.h"

	else if ( r2 && r2->IsConst() )
#include "ZAM-GenExprsDefsC2.h"

	else if ( r3 && r3->IsConst() )
#include "ZAM-GenExprsDefsC3.h"

	else
#include "ZAM-GenExprsDefsV.h"
	}

const ZAMStmt ZAMCompiler::CompileAssignToIndex(const NameExpr* lhs,
                                                const IndexExpr* rhs)
	{
	auto aggr = rhs->GetOp1();
	auto const_aggr = aggr->Tag() == EXPR_CONST;

	auto indexes_expr = rhs->GetOp2()->AsListExpr();
	auto indexes = indexes_expr->Exprs();

	auto n = const_aggr ? nullptr : aggr->AsNameExpr();
	auto con = const_aggr ? aggr->AsConstExpr() : nullptr;

	if ( indexes.length() == 1 &&
	     indexes[0]->GetType()->Tag() == TYPE_VECTOR )
		{
		auto index1 = indexes[0];
		if ( index1->Tag() == EXPR_CONST )
			{
			reporter->Error("constant vector indexes not supported for ZAM compiling");
			return ErrorStmt();
			}

		auto index = index1->AsNameExpr();
		auto ind_t = index->GetType()->AsVectorType();

		if ( IsBool(ind_t->Yield()->Tag()) )
			return const_aggr ?
			       IndexVecBoolSelectVCV(lhs, con, index) :
			       IndexVecBoolSelectVVV(lhs, n, index);

		return const_aggr ? IndexVecIntSelectVCV(lhs, con, index) :
		                    IndexVecIntSelectVVV(lhs, n, index);
		}

	return const_aggr ? IndexVCL(lhs, con, indexes_expr) :
	                    IndexVVL(lhs, n, indexes_expr);
	}

const ZAMStmt ZAMCompiler::CompileFieldLHSAssignExpr(const FieldLHSAssignExpr* e)
	{
	auto lhs = e->Op1()->AsNameExpr();
	auto rhs = e->Op2();
	auto field = e->Field();

	if ( rhs->Tag() == EXPR_NAME )
		return Field_LHS_AssignFV(e, rhs->AsNameExpr());

	if ( rhs->Tag() == EXPR_CONST )
		return Field_LHS_AssignFC(e, rhs->AsConstExpr());

	auto r1 = rhs->GetOp1();
	auto r2 = rhs->GetOp2();

	if ( rhs->Tag() == EXPR_FIELD )
		{
		auto rhs_f = rhs->AsFieldExpr();
		if ( r1->Tag() == EXPR_NAME )
			return Field_LHS_AssignFVi(e, r1->AsNameExpr(),
			                           rhs_f->Field());

		return Field_LHS_AssignFCi(e, r1->AsConstExpr(),
		                           rhs_f->Field());
		}

	if ( r1 && r1->IsConst() )
#include "ZAM-GenFieldsDefsC1.h"

	else if ( r2 && r2->IsConst() )
#include "ZAM-GenFieldsDefsC2.h"

	else
#include "ZAM-GenFieldsDefsV.h"
	}

const ZAMStmt ZAMCompiler::CompileScheduleExpr(const ScheduleExpr* e)
	{
	auto event = e->Event();
	auto when = e->When();

	auto event_args = event->Args();
        auto handler = event->Handler();

        bool is_interval = when->GetType()->Tag() == TYPE_INTERVAL;

        if ( when->Tag() == EXPR_NAME )
                return ScheduleViHL(when->AsNameExpr(), is_interval,
		                    handler.Ptr(), event_args);
        else
                return ScheduleCiHL(when->AsConstExpr(), is_interval,
		                    handler.Ptr(), event_args);
	}

} // zeek::detail
