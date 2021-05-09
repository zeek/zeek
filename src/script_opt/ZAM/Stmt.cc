// See the file "COPYING" in the main distribution directory for copyright.

// Methods for traversing Stmt AST nodes to generate ZAM code.

#include "zeek/script_opt/ZAM/Compile.h"
#include "zeek/Reporter.h"

namespace zeek::detail {

const ZAMStmt ZAMCompiler::CompileStmt(const Stmt* body)
	{
	SetCurrStmt(body);

	switch ( body->Tag() ) {
	case STMT_PRINT:
		return CompilePrintStmt(static_cast<const PrintStmt*>(body));

	case STMT_EXPR:
		return CompileExprStmt(static_cast<const ExprStmt*>(body));

	case STMT_IF:
		return CompileIfStmt(static_cast<const IfStmt*>(body));

	case STMT_SWITCH:
		return Switch(static_cast<const SwitchStmt*>(body));

	case STMT_ADD:
		return CompileAddStmt(static_cast<const AddStmt*>(body));

	case STMT_DELETE:
		return CompileDelStmt(static_cast<const DelStmt*>(body));

	case STMT_EVENT:
		{
		auto es = static_cast<const EventStmt*>(body);
		auto e = static_cast<const EventExpr*>(es->StmtExpr());
		return CompileExpr(e);
		}

	case STMT_WHILE:
		return CompileWhileStmt(static_cast<const WhileStmt*>(body));

	case STMT_FOR:
		return For(static_cast<const ForStmt*>(body));

	case STMT_NEXT:
		return Next();

	case STMT_BREAK:
		return Break();

	case STMT_FALLTHROUGH:
		return FallThrough();

	case STMT_RETURN:
		return Return(static_cast<const ReturnStmt*>(body));

	case STMT_CATCH_RETURN:
		return CatchReturn(static_cast<const CatchReturnStmt*>(body));

	case STMT_LIST:
		return CompileStmtList(static_cast<const StmtList*>(body));

	case STMT_INIT:
		return CompileInitStmt(static_cast<const InitStmt*>(body));

	case STMT_NULL:
		return EmptyStmt();

	case STMT_WHEN:
		return When(static_cast<const WhenStmt*>(body));

	case STMT_CHECK_ANY_LEN:
		{
		auto cs = static_cast<const CheckAnyLenStmt*>(body);
		auto n = cs->StmtExpr()->AsNameExpr();
		auto expected_len = cs->ExpectedLen();
		return CheckAnyLenVi(n, expected_len);
		}

	default:
		reporter->InternalError("bad statement type in ZAMCompile::CompileStmt");
	}
	}

const ZAMStmt ZAMCompiler::CompilePrintStmt(const PrintStmt* ps)
	{
	auto& l = ps->ExprListPtr();

	if ( l->Exprs().length() == 1 )
		{
		auto e0 = l->Exprs()[0];
		if ( e0->Tag() == EXPR_NAME )
			return Print1V(e0->AsNameExpr());
		else
			return Print1C(e0->AsConstExpr());
		}

	return PrintO(BuildVals(l));
	}

const ZAMStmt ZAMCompiler::CompileExprStmt(const ExprStmt* es)
	{
	auto e = es->StmtExprPtr();

	if ( e->Tag() == EXPR_CALL )
		return Call(es);

	if ( e->Tag() == EXPR_ASSIGN && e->GetOp2()->Tag() == EXPR_CALL )
		return AssignToCall(es);

	return CompileExpr(e);
	}

const ZAMStmt ZAMCompiler::CompileIfStmt(const IfStmt* is)
	{
	auto e = is->StmtExprPtr();
	auto block1 = is->TrueBranch();
	auto block2 = is->FalseBranch();

	if ( block1->Tag() == STMT_NULL )
		block1 = nullptr;

	if ( block2->Tag() == STMT_NULL )
		block2 = nullptr;

	if ( ! block1 && ! block2 )
		// No need to evaluate conditional as it ought to be
		// side-effect free in reduced form.
		return EmptyStmt();

	if ( ! block1 )
		{
		// See if we're able to invert the conditional.  If not,
		// then IfElse() will need to deal with inverting the test.
		// But we try here first, since some conditionals blow
		// up into zillions of different operators depending
		// on the type of their operands, so it's much simpler to
		// deal with them now.

		bool do_swap = false;
		BroExprTag t = e->Tag();

		switch ( t ) {
		case EXPR_EQ:
		case EXPR_NE:
		case EXPR_LT:
		case EXPR_LE:
		case EXPR_GE:
		case EXPR_GT:
			do_swap = true;

		default: break;
		}

		if ( do_swap )
			{
			e->InvertSense();
			block1 = block2;
			block2 = nullptr;
			}
		}

	return IfElse(e.get(), block1, block2);
	}

const ZAMStmt ZAMCompiler::CompileAddStmt(const AddStmt* as)
	{
	auto e = as->StmtExprPtr();
	auto aggr = e->GetOp1()->AsNameExpr();
	auto index_list = e->GetOp2();

	if ( index_list->Tag() != EXPR_LIST )
		reporter->InternalError("non-list in \"add\"");

	auto indices = index_list->AsListExprPtr();
	auto& exprs = indices->Exprs();

	if ( exprs.length() == 1 )
		{
		auto e1 = exprs[0];
		if ( e1->Tag() == EXPR_NAME )
			return AddStmt1VV(aggr, e1->AsNameExpr());
		else
			return AddStmt1VC(aggr, e1->AsConstExpr());
		}

	return AddStmtVO(aggr, BuildVals(indices));
	}

const ZAMStmt ZAMCompiler::CompileDelStmt(const DelStmt* ds)
	{
	auto e = ds->StmtExprPtr();
	auto aggr = e->GetOp1()->AsNameExpr();

	if ( e->Tag() == EXPR_FIELD )
		{
		int field = e->AsFieldExpr()->Field();
		return DelFieldVi(aggr, field);
		}

	auto index_list = e->GetOp2();

	if ( index_list->Tag() != EXPR_LIST )
		reporter->InternalError("non-list in \"delete\"");

	auto internal_ind = BuildVals(index_list->AsListExprPtr());

	return DelTableVO(aggr, internal_ind);
	}

const ZAMStmt ZAMCompiler::CompileWhileStmt(const WhileStmt* ws)
	{
	auto loop_condition = ws->Condition();

	if ( loop_condition->Tag() == EXPR_CONST )
		{
		if ( loop_condition->IsZero() )
			return EmptyStmt();
		else
			return Loop(ws->Body().get());
		}

	auto cond_pred = ws->CondPredStmt();
	return While(cond_pred.get(), loop_condition.get(), ws->Body().get());
	}

const ZAMStmt ZAMCompiler::CompileStmtList(const StmtList* ws)
	{
	auto start = StartingBlock();

	for ( const auto& stmt : ws->Stmts() )
		CompileStmt(stmt);

	return FinishBlock(start);
	}

const ZAMStmt ZAMCompiler::CompileInitStmt(const InitStmt* is)
	{
	auto last = EmptyStmt();

	for ( const auto& aggr : is->Inits() )
		{
		if ( IsUnused(aggr, is) )
			continue;

		auto& t = aggr->GetType();

		switch ( t->Tag() ) {
		case TYPE_RECORD:
			last = InitRecord(aggr, t->AsRecordType());
			break;

		case TYPE_VECTOR:
			last = InitVector(aggr, t->AsVectorType());
			break;

		case TYPE_TABLE:
			last = InitTable(aggr, t->AsTableType(),
			                 aggr->GetAttrs().get());
			break;

		default:
			break;
		}
		}

	return last;
	}

} // zeek::detail
