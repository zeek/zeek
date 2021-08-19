// See the file "COPYING" in the main distribution directory for copyright.

// Methods for traversing Stmt AST nodes to generate ZAM code.

#include "zeek/IPAddr.h"
#include "zeek/Reporter.h"
#include "zeek/ZeekString.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {

const ZAMStmt ZAMCompiler::CompileStmt(const Stmt* s)
	{
	SetCurrStmt(s);

	switch ( s->Tag() ) {
	case STMT_PRINT:
		return CompilePrint(static_cast<const PrintStmt*>(s));

	case STMT_EXPR:
		return CompileExpr(static_cast<const ExprStmt*>(s));

	case STMT_IF:
		return CompileIf(static_cast<const IfStmt*>(s));

	case STMT_SWITCH:
		return CompileSwitch(static_cast<const SwitchStmt*>(s));

	case STMT_ADD:
		return CompileAdd(static_cast<const AddStmt*>(s));

	case STMT_DELETE:
		return CompileDel(static_cast<const DelStmt*>(s));

	case STMT_EVENT:
		{
		auto es = static_cast<const EventStmt*>(s);
		auto e = static_cast<const EventExpr*>(es->StmtExpr());
		return CompileExpr(e);
		}

	case STMT_WHILE:
		return CompileWhile(static_cast<const WhileStmt*>(s));

	case STMT_FOR:
		return CompileFor(static_cast<const ForStmt*>(s));

	case STMT_RETURN:
		return CompileReturn(static_cast<const ReturnStmt*>(s));

	case STMT_CATCH_RETURN:
		return CompileCatchReturn(static_cast<const CatchReturnStmt*>(s));

	case STMT_LIST:
		return CompileStmts(static_cast<const StmtList*>(s));

	case STMT_INIT:
		return CompileInit(static_cast<const InitStmt*>(s));

	case STMT_NULL:
		return EmptyStmt();

	case STMT_WHEN:
		return CompileWhen(static_cast<const WhenStmt*>(s));

	case STMT_CHECK_ANY_LEN:
		{
		auto cs = static_cast<const CheckAnyLenStmt*>(s);
		auto n = cs->StmtExpr()->AsNameExpr();
		auto expected_len = cs->ExpectedLen();
		return CheckAnyLenVi(n, expected_len);
		}

	case STMT_NEXT:
		return CompileNext();

	case STMT_BREAK:
		return CompileBreak();

	case STMT_FALLTHROUGH:
		return CompileFallThrough();

	default:
		reporter->InternalError("bad statement type in ZAMCompile::CompileStmt");
	}
	}

const ZAMStmt ZAMCompiler::CompilePrint(const PrintStmt* ps)
	{
	auto& l = ps->ExprListPtr();

	if ( l->Exprs().length() == 1 )
		{ // special-case the common situation of printing just 1 item
		auto e0 = l->Exprs()[0];
		if ( e0->Tag() == EXPR_NAME )
			return Print1V(e0->AsNameExpr());
		else
			return Print1C(e0->AsConstExpr());
		}

	return PrintO(BuildVals(l));
	}

const ZAMStmt ZAMCompiler::CompileExpr(const ExprStmt* es)
	{
	auto e = es->StmtExprPtr();

	if ( e->Tag() == EXPR_CALL )
		return Call(es);

	if ( e->Tag() == EXPR_ASSIGN && e->GetOp2()->Tag() == EXPR_CALL )
		return AssignToCall(es);

	return CompileExpr(e);
	}

const ZAMStmt ZAMCompiler::CompileIf(const IfStmt* is)
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
		if ( e->InvertSense() )
			{
			block1 = block2;
			block2 = nullptr;
			}
		}

	return IfElse(e.get(), block1, block2);
	}

const ZAMStmt ZAMCompiler::IfElse(const Expr* e, const Stmt* s1, const Stmt* s2)
	{
	ZAMStmt cond_stmt = EmptyStmt();
	int branch_v;

	if ( e->Tag() == EXPR_NAME )
		{
		auto n = e->AsNameExpr();

		ZOp op = (s1 && s2) ? OP_IF_ELSE_VV :
		                      (s1 ? OP_IF_VV : OP_IF_NOT_VV);

		ZInstI cond(op, FrameSlot(n), 0);
		cond_stmt = AddInst(cond);
		branch_v = 2;
		}
	else
		cond_stmt = GenCond(e, branch_v);

	if ( s1 )
		{
		auto s1_end = CompileStmt(s1);
		if ( s2 )
			{
			auto branch_after_s1 = GoToStub();
			auto s2_end = CompileStmt(s2);
			SetV(cond_stmt, GoToTargetBeyond(branch_after_s1),
			     branch_v);
			SetGoTo(branch_after_s1, GoToTargetBeyond(s2_end));

			return s2_end;
			}

		else
			{
			SetV(cond_stmt, GoToTargetBeyond(s1_end), branch_v);
			return s1_end;
			}
		}

	// Only the else clause is non-empty.
	auto s2_end = CompileStmt(s2);

	// For complex conditionals, we need to invert their sense since
	// we're switching to "if ( ! cond ) s2".
	auto z = insts1[cond_stmt.stmt_num];

	switch ( z->op ) {
	case OP_IF_ELSE_VV:
	case OP_IF_VV:
	case OP_IF_NOT_VV:
		// These are generated correctly above, no need
		// to fix up.
		break;

	case OP_HAS_FIELD_COND_VVV:
		z->op = OP_NOT_HAS_FIELD_COND_VVV;
		break;
	case OP_NOT_HAS_FIELD_COND_VVV:
		z->op = OP_HAS_FIELD_COND_VVV;
		break;

	case OP_VAL_IS_IN_TABLE_COND_VVV:
		z->op = OP_VAL_IS_NOT_IN_TABLE_COND_VVV;
		break;
	case OP_VAL_IS_NOT_IN_TABLE_COND_VVV:
		z->op = OP_VAL_IS_IN_TABLE_COND_VVV;
		break;

	case OP_CONST_IS_IN_TABLE_COND_VVC:
		z->op = OP_CONST_IS_NOT_IN_TABLE_COND_VVC;
		break;
	case OP_CONST_IS_NOT_IN_TABLE_COND_VVC:
		z->op = OP_CONST_IS_IN_TABLE_COND_VVC;
		break;

	case OP_VAL2_IS_IN_TABLE_COND_VVVV:
		z->op = OP_VAL2_IS_NOT_IN_TABLE_COND_VVVV;
		break;
	case OP_VAL2_IS_NOT_IN_TABLE_COND_VVVV:
		z->op = OP_VAL2_IS_IN_TABLE_COND_VVVV;
		break;

	case OP_VAL2_IS_IN_TABLE_COND_VVVC:
		z->op = OP_VAL2_IS_NOT_IN_TABLE_COND_VVVC;
		break;
	case OP_VAL2_IS_NOT_IN_TABLE_COND_VVVC:
		z->op = OP_VAL2_IS_IN_TABLE_COND_VVVC;
		break;

	case OP_VAL2_IS_IN_TABLE_COND_VVCV:
		z->op = OP_VAL2_IS_NOT_IN_TABLE_COND_VVCV;
		break;
	case OP_VAL2_IS_NOT_IN_TABLE_COND_VVCV:
		z->op = OP_VAL2_IS_IN_TABLE_COND_VVCV;
		break;

	default:
		reporter->InternalError("inconsistency in ZAMCompiler::IfElse");
	}

	SetV(cond_stmt, GoToTargetBeyond(s2_end), branch_v);
	return s2_end;
	}

const ZAMStmt ZAMCompiler::GenCond(const Expr* e, int& branch_v)
	{
	auto op1 = e->GetOp1();
	auto op2 = e->GetOp2();

	NameExpr* n1 = nullptr;
	NameExpr* n2 = nullptr;
	ConstExpr* c = nullptr;

	if ( e->Tag() == EXPR_HAS_FIELD )
		{
		auto hf = e->AsHasFieldExpr();
		auto z = GenInst(OP_HAS_FIELD_COND_VVV, op1->AsNameExpr(),
		                 hf->Field());
		z.op_type = OP_VVV_I2_I3;
		branch_v = 3;
		return AddInst(z);
		}

	if ( e->Tag() == EXPR_IN )
		{
		auto op1 = e->GetOp1();
		auto op2 = e->GetOp2()->AsNameExpr();

		// First, deal with the easy cases: it's a single index.
		if ( op1->Tag() == EXPR_LIST )
			{
			auto& ind = op1->AsListExpr()->Exprs();
			if ( ind.length() == 1 )
				op1 = {NewRef{}, ind[0]};
			}

		if ( op1->Tag() == EXPR_NAME )
			{
			auto z = GenInst(OP_VAL_IS_IN_TABLE_COND_VVV,
			                 op1->AsNameExpr(), op2, 0);
			z.t = op1->GetType();
			branch_v = 3;
			return AddInst(z);
			}

		if ( op1->Tag() == EXPR_CONST )
			{
			auto z = GenInst(OP_CONST_IS_IN_TABLE_COND_VVC,
			                 op2, op1->AsConstExpr(), 0);
			z.t = op1->GetType();
			branch_v = 2;
			return AddInst(z);
			}

		// Now the harder case: 2 indexes.  (Any number here other
		// than two should have been disallowed due to how we reduce
		// conditional expressions.)

		auto& ind = op1->AsListExpr()->Exprs();
		ASSERT(ind.length() == 2);

		auto ind0 = ind[0];
		auto ind1 = ind[1];

		auto name0 = ind0->Tag() == EXPR_NAME;
		auto name1 = ind1->Tag() == EXPR_NAME;

		auto n0 = name0 ? ind0->AsNameExpr() : nullptr;
		auto n1 = name1 ? ind1->AsNameExpr() : nullptr;

		auto c0 = name0 ? nullptr : ind0->AsConstExpr();
		auto c1 = name1 ? nullptr : ind1->AsConstExpr();

		ZInstI z;

		if ( name0 && name1 )
			{
			z = GenInst(OP_VAL2_IS_IN_TABLE_COND_VVVV,
			            n0, n1, op2, 0);
			branch_v = 4;
			z.t2 = n0->GetType();
			}

		else if ( name0 )
			{
			z = GenInst(OP_VAL2_IS_IN_TABLE_COND_VVVC,
			            n0, op2, c1, 0);
			branch_v = 3;
			z.t2 = n0->GetType();
			}

		else if ( name1 )
			{
			z = GenInst(OP_VAL2_IS_IN_TABLE_COND_VVCV,
			            n1, op2, c0, 0);
			branch_v = 3;
			z.t2 = n1->GetType();
			}

		else
			{ // Both are constants, assign first to temporary.
			auto slot = TempForConst(c0);

			z = ZInstI(OP_VAL2_IS_IN_TABLE_COND_VVVC,
			           slot, FrameSlot(op2), 0, c1);
			z.op_type = OP_VVVC_I3;
			branch_v = 3;
			z.t2 = c0->GetType();
			}

		return AddInst(z);
		}

	if ( op1->Tag() == EXPR_NAME )
		{
		n1 = op1->AsNameExpr();

		if ( op2->Tag() == EXPR_NAME )
			n2 = op2->AsNameExpr();
		else
			c = op2->AsConstExpr();
		}

	else
		{
		c = op1->AsConstExpr();
		n2 = op2->AsNameExpr();
		}

	if ( n1 && n2 )
		branch_v = 3;
	else
		branch_v = 2;

	switch ( e->Tag() ) {
#include "ZAM-Conds.h"

	default:
		reporter->InternalError("bad expression type in ZAMCompiler::GenCond");
	}

	// Not reached.
	}

const ZAMStmt ZAMCompiler::CompileSwitch(const SwitchStmt* sw)
	{
	auto e = sw->StmtExpr();

	auto n = e->Tag() == EXPR_NAME ? e->AsNameExpr() : nullptr;
	auto c = e->Tag() == EXPR_CONST ? e->AsConstExpr() : nullptr;

	auto t = e->GetType()->Tag();

	// Need to track a new set of contexts for "break" statements.
	PushBreaks();

	auto& cases = *sw->Cases();

	if ( cases.length() > 0 && cases[0]->TypeCases() )
		return TypeSwitch(sw, n, c);
	else
		return ValueSwitch(sw, n, c);
	}

const ZAMStmt ZAMCompiler::ValueSwitch(const SwitchStmt* sw, const NameExpr* v,
                                       const ConstExpr* c)
	{
	int slot = v ? FrameSlot(v) : -1;

	if ( c )
		// Weird to have a constant switch expression, enough
		// so that it doesn't seem worth optimizing.
		slot = TempForConst(c);

	ASSERT(slot >= 0);

	// Figure out which jump table we're using.
	auto t = v ? v->GetType() : c->GetType();
	int tbl = 0;
	ZOp op;

	switch ( t->InternalType() ) {
	case TYPE_INTERNAL_INT:
		op = OP_SWITCHI_VVV;
		tbl = int_casesI.size();
		break;

	case TYPE_INTERNAL_UNSIGNED:
		op = OP_SWITCHU_VVV;
		tbl = uint_casesI.size();
		break;

	case TYPE_INTERNAL_DOUBLE:
		op = OP_SWITCHD_VVV;
		tbl = double_casesI.size();
		break;

	case TYPE_INTERNAL_STRING:
		op = OP_SWITCHS_VVV;
		tbl = str_casesI.size();
		break;

	case TYPE_INTERNAL_ADDR:
		op = OP_SWITCHA_VVV;
		tbl = str_casesI.size();
		break;

	case TYPE_INTERNAL_SUBNET:
		op = OP_SWITCHN_VVV;
		tbl = str_casesI.size();
		break;

	default:
		reporter->InternalError("bad switch type");
	}

	// Add the "head", i.e., the execution of the jump table.
	auto sw_head_op = ZInstI(op, slot, tbl, 0);
	sw_head_op.op_type = OP_VVV_I2_I3;

	auto sw_head = AddInst(sw_head_op);
	auto body_end = sw_head;

	// Generate each of the cases.
	auto cases = sw->Cases();
	std::vector<InstLabel> case_start;

	PushFallThroughs();
	for ( auto c : *cases )
		{
		auto start = GoToTargetBeyond(body_end);
		ResolveFallThroughs(start);
		case_start.push_back(start);
		PushFallThroughs();
		body_end = CompileStmt(c->Body());
		}

	auto sw_end = GoToTargetBeyond(body_end);
	ResolveFallThroughs(sw_end);
	ResolveBreaks(sw_end);

	int def_ind = sw->DefaultCaseIndex();
	if ( def_ind >= 0 )
		SetV3(sw_head, case_start[def_ind]);
	else
		SetV3(sw_head, sw_end);

	// Now fill out the corresponding jump table.
	//
	// We will only use one of these.
	CaseMapI<bro_int_t> new_int_cases;
	CaseMapI<bro_uint_t> new_uint_cases;
	CaseMapI<double> new_double_cases;
	CaseMapI<std::string> new_str_cases;

	for ( auto [cv, index] : sw->ValueMap() )
		{
		auto case_body_start = case_start[index];

		switch ( cv->GetType()->InternalType() ) {
		case TYPE_INTERNAL_INT:
			new_int_cases[cv->InternalInt()] = case_body_start;
			break;

		case TYPE_INTERNAL_UNSIGNED:
			new_uint_cases[cv->InternalUnsigned()] = case_body_start;
			break;

		case TYPE_INTERNAL_DOUBLE:
			new_double_cases[cv->InternalDouble()] = case_body_start;
			break;

		case TYPE_INTERNAL_STRING:
			{
			// This leaks, but only statically so not worth
			// tracking the value for ultimate deletion.
			auto sv = cv->AsString()->Render();
			std::string s(sv);
			new_str_cases[s] = case_body_start;
			break;
			}

		case TYPE_INTERNAL_ADDR:
			{
			auto a = cv->AsAddr().AsString();
			new_str_cases[a] = case_body_start;
			break;
			}

		case TYPE_INTERNAL_SUBNET:
			{
			auto n = cv->AsSubNet().AsString();
			new_str_cases[n] = case_body_start;
			break;
			}

		default:
			reporter->InternalError("bad recovered type when compiling switch");
		}
		}

	// Now add the jump table to the set we're keeping for the
	// corresponding type.

	switch ( t->InternalType() ) {
	case TYPE_INTERNAL_INT:
		int_casesI.push_back(new_int_cases);
		break;

	case TYPE_INTERNAL_UNSIGNED:
		uint_casesI.push_back(new_uint_cases);
		break;

	case TYPE_INTERNAL_DOUBLE:
		double_casesI.push_back(new_double_cases);
		break;

	case TYPE_INTERNAL_STRING:
	case TYPE_INTERNAL_ADDR:
	case TYPE_INTERNAL_SUBNET:
		str_casesI.push_back(new_str_cases);
		break;

	default:
		reporter->InternalError("bad switch type");
	}

	return body_end;
	}

const ZAMStmt ZAMCompiler::TypeSwitch(const SwitchStmt* sw, const NameExpr* v,
                                      const ConstExpr* c)
	{
	auto cases = sw->Cases();
	auto type_map = sw->TypeMap();

	auto body_end = EmptyStmt();

	auto tmp = NewSlot(true);	// true since we know "any" is managed

	int slot = v ? FrameSlot(v) : 0;

	if ( v && v->GetType()->Tag() != TYPE_ANY )
		{
		auto z = ZInstI(OP_ASSIGN_ANY_VV, tmp, slot);
		body_end = AddInst(z);
		slot = tmp;
		}

	if ( c )
		{
		auto z = ZInstI(OP_ASSIGN_ANY_VC, tmp, c);
		body_end = AddInst(z);
		slot = tmp;
		}

	int def_ind = sw->DefaultCaseIndex();
	ZAMStmt def_succ(0);	// successor to default, if any
	bool saw_def_succ = false;	// whether def_succ is meaningful

	PushFallThroughs();
	for ( auto& i : *type_map )
		{
		auto id = i.first;
		auto type = id->GetType();

		ZInstI z;

		z = ZInstI(OP_BRANCH_IF_NOT_TYPE_VV, slot, 0);
		z.SetType(type);
		auto case_test = AddInst(z);

		// Type cases that don't use "as" create a placeholder
		// ID with a null name.
		if ( id->Name() )
			{
			int id_slot = Frame1Slot(id, OP_CAST_ANY_VV);
			z = ZInstI(OP_CAST_ANY_VV, id_slot, slot);
			z.SetType(type);
			body_end = AddInst(z);
			}
		else
			body_end = case_test;

		ResolveFallThroughs(GoToTargetBeyond(body_end));
		body_end = CompileStmt((*cases)[i.second]->Body());
		SetV2(case_test, GoToTargetBeyond(body_end));

		if ( def_ind >= 0 && i.second == def_ind + 1 )
			{
			def_succ = case_test;
			saw_def_succ = true;
			}

		PushFallThroughs();
		}

	ResolveFallThroughs(GoToTargetBeyond(body_end));

	if ( def_ind >= 0 )
		{
		PushFallThroughs();

		body_end = CompileStmt((*sw->Cases())[def_ind]->Body());

		// Now resolve any fallthrough's in the default.
		if ( saw_def_succ )
			ResolveFallThroughs(GoToTargetBeyond(def_succ));
		else
			ResolveFallThroughs(GoToTargetBeyond(body_end));
		}

	ResolveBreaks(GoToTargetBeyond(body_end));

	return body_end;
	}

const ZAMStmt ZAMCompiler::CompileAdd(const AddStmt* as)
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

const ZAMStmt ZAMCompiler::CompileDel(const DelStmt* ds)
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

const ZAMStmt ZAMCompiler::CompileWhile(const WhileStmt* ws)
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

const ZAMStmt ZAMCompiler::While(const Stmt* cond_stmt, const Expr* cond,
                                 const Stmt* body)
	{
	auto head = StartingBlock();

	if ( cond_stmt )
		(void) CompileStmt(cond_stmt);

	ZAMStmt cond_IF = EmptyStmt();
	int branch_v;

	if ( cond->Tag() == EXPR_NAME )
		{
		auto n = cond->AsNameExpr();
		cond_IF = AddInst(ZInstI(OP_IF_VV, FrameSlot(n), 0));
		branch_v = 2;
		}
	else
		cond_IF = GenCond(cond, branch_v);

	PushNexts();
	PushBreaks();

	if ( body && body->Tag() != STMT_NULL )
		(void) CompileStmt(body);

	auto tail = GoTo(GoToTarget(head));

	auto beyond_tail = GoToTargetBeyond(tail);
	SetV(cond_IF, beyond_tail, branch_v);

	ResolveNexts(GoToTarget(head));
	ResolveBreaks(beyond_tail);

	return tail;
	}

const ZAMStmt ZAMCompiler::CompileFor(const ForStmt* f)
	{
	auto e = f->LoopExpr();
	auto val = e->Tag() == EXPR_NAME ? e->AsNameExpr() : nullptr;
	auto et = e->GetType()->Tag();

	PushNexts();
	PushBreaks();

	if ( et == TYPE_TABLE )
		return LoopOverTable(f, val);

	else if ( et == TYPE_VECTOR )
		return LoopOverVector(f, val);

	else if ( et == TYPE_STRING )
		return LoopOverString(f, e);

	else
		reporter->InternalError("bad \"for\" loop-over value when compiling");
	}

const ZAMStmt ZAMCompiler::LoopOverTable(const ForStmt* f, const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto value_var = f->ValueVar();
	auto body = f->LoopBody();

	// Check whether the loop variables are actually used in the body.
	// This is motivated by an idiom where there's both loop_vars and
	// a value_var, but the script only actually needs the value_var;
	// and also some weird cases where the script is managing a
	// separate iteration process manually.
	ProfileFunc body_pf(body);

	int num_unused = 0;

	auto aux = new ZInstAux(0);

	for ( int i = 0; i < loop_vars->length(); ++i )
		{
		auto id = (*loop_vars)[i];

		if ( body_pf.Locals().count(id) == 0 )
			++num_unused;

		aux->loop_vars.push_back(FrameSlot(id));
		aux->loop_var_types.push_back(id->GetType());
		}

	bool no_loop_vars = (num_unused == loop_vars->length());

	if ( value_var && body_pf.Locals().count(value_var.get()) == 0 )
		// This is more clearly a coding botch - someone left in
		// an unnecessary value_var variable.  But might as
		// well not do the work.
		value_var = nullptr;

	if ( value_var )
		aux->value_var_type = value_var->GetType();

	auto iter_slot = table_iters.size();
	table_iters.emplace_back(TableIterInfo());

	auto z = ZInstI(OP_INIT_TABLE_LOOP_VV, FrameSlot(val), iter_slot);
	z.op_type = OP_VV_I2;
	z.SetType(value_var ? value_var->GetType() : nullptr);
	z.aux = aux;

	auto init_end = AddInst(z);
	auto iter_head = StartingBlock();

	if ( value_var )
		{
		ZOp op = no_loop_vars ? OP_NEXT_TABLE_ITER_VAL_VAR_NO_VARS_VVV :
		                        OP_NEXT_TABLE_ITER_VAL_VAR_VVV;
		z = ZInstI(op, FrameSlot(value_var), iter_slot, 0);
		z.CheckIfManaged(value_var->GetType());
		z.op_type = OP_VVV_I2_I3;
		}
	else
		{
		ZOp op = no_loop_vars ? OP_NEXT_TABLE_ITER_NO_VARS_VV :
		                        OP_NEXT_TABLE_ITER_VV;
		z = ZInstI(op, iter_slot, 0);
		z.op_type = OP_VV_I1_I2;
		}

	z.aux = aux;	// so ZOpt.cc can get to it

	return FinishLoop(iter_head, z, body, iter_slot, true);
	}

const ZAMStmt ZAMCompiler::LoopOverVector(const ForStmt* f, const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto loop_var = (*loop_vars)[0];

	int iter_slot = num_step_iters++;

	auto z = ZInstI(OP_INIT_VECTOR_LOOP_VV, FrameSlot(val), iter_slot);
	z.op_type = OP_VV_I2;

	auto init_end = AddInst(z);
	auto iter_head = StartingBlock();

	z = ZInstI(OP_NEXT_VECTOR_ITER_VVV, FrameSlot(loop_var), iter_slot, 0);
	z.op_type = OP_VVV_I2_I3;

	return FinishLoop(iter_head, z, f->LoopBody(), iter_slot, false);
	}

const ZAMStmt ZAMCompiler::LoopOverString(const ForStmt* f, const Expr* e)
	{
	auto n = e->Tag() == EXPR_NAME ? e->AsNameExpr() : nullptr;
	auto c = e->Tag() == EXPR_CONST ? e->AsConstExpr() : nullptr;
	auto loop_vars = f->LoopVars();
	auto loop_var = (*loop_vars)[0];

	int iter_slot = num_step_iters++;

	ZInstI z;

	if ( n )
		{
		z = ZInstI(OP_INIT_STRING_LOOP_VV, FrameSlot(n), iter_slot);
		z.op_type = OP_VV_I2;
		}
	else
		{
		z = ZInstI(OP_INIT_STRING_LOOP_VC, iter_slot, c);
		z.op_type = OP_VC_I1;
		}

	auto init_end = AddInst(z);
	auto iter_head = StartingBlock();

	z = ZInstI(OP_NEXT_STRING_ITER_VVV, FrameSlot(loop_var), iter_slot, 0);
	z.is_managed = true;
	z.op_type = OP_VVV_I2_I3;

	return FinishLoop(iter_head, z, f->LoopBody(), iter_slot, false);
	}

const ZAMStmt ZAMCompiler::Loop(const Stmt* body)
	{
	PushNexts();
	PushBreaks();

	auto head = StartingBlock();
	(void) CompileStmt(body);
	auto tail = GoTo(GoToTarget(head));

	ResolveNexts(GoToTarget(head));
	ResolveBreaks(GoToTargetBeyond(tail));

	return tail;
	}

const ZAMStmt ZAMCompiler::FinishLoop(const ZAMStmt iter_head, ZInstI iter_stmt,
                                      const Stmt* body, int iter_slot,
                                      bool is_table)
	{
	auto loop_iter = AddInst(iter_stmt);
	auto body_end = CompileStmt(body);

	// We only need cleanup for looping over tables, but for now we
	// need some sort of placeholder instruction (until the optimizer
	// can elide it) to resolve loop exits.
	ZOp op = is_table ? OP_END_TABLE_LOOP_V : OP_NOP;

	auto loop_end = GoTo(GoToTarget(iter_head));
	auto z = ZInstI(op, iter_slot);
	z.op_type = is_table ? OP_V_I1 : OP_X;
	auto final_stmt = AddInst(z);

	auto ot = iter_stmt.op_type;
	if ( ot == OP_VVV_I3 || ot == OP_VVV_I2_I3)
		SetV3(loop_iter, GoToTarget(final_stmt));
	else
		SetV2(loop_iter, GoToTarget(final_stmt));

	ResolveNexts(GoToTarget(iter_head));
	ResolveBreaks(GoToTarget(final_stmt));

	return final_stmt;
	}

const ZAMStmt ZAMCompiler::CompileReturn(const ReturnStmt* r)
	{
	auto e = r->StmtExpr();

	if ( retvars.empty() )
		{ // a "true" return
		if ( e )
			{
			if ( e->Tag() == EXPR_NAME )
				return ReturnV(e->AsNameExpr());
			else
				return ReturnC(e->AsConstExpr());
			}

		else
			return ReturnX();
		}

	auto rv = retvars.back();
	if ( e && ! rv )
		reporter->InternalError("unexpected returned value inside inlined block");
	if ( ! e && rv )
		reporter->InternalError("expected returned value inside inlined block but none provider");

	if ( e )
		{
		if ( e->Tag() == EXPR_NAME )
			(void) AssignVV(rv, e->AsNameExpr());
		else
			(void) AssignVC(rv, e->AsConstExpr());
		}

	return CompileCatchReturn();
	}

const ZAMStmt ZAMCompiler::CompileCatchReturn(const CatchReturnStmt* cr)
	{
	retvars.push_back(cr->RetVar());

	PushCatchReturns();

	auto block = cr->Block();
	auto block_end = CompileStmt(block);
	retvars.pop_back();

	ResolveCatchReturns(GoToTargetBeyond(block_end));

	// If control flow runs off the end of the block, then we need
	// to consider sync'ing globals at that point.
	auto block_last = LastStmt(block.get());

	if ( block_last->Tag() == STMT_RETURN )
		return block_end;

	return top_main_inst;
	}

const ZAMStmt ZAMCompiler::CompileStmts(const StmtList* ws)
	{
	auto start = StartingBlock();

	for ( const auto& stmt : ws->Stmts() )
		CompileStmt(stmt);

	return FinishBlock(start);
	}

const ZAMStmt ZAMCompiler::CompileInit(const InitStmt* is)
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

const ZAMStmt ZAMCompiler::InitRecord(IDPtr id, RecordType* rt)
	{
	auto z = ZInstI(OP_INIT_RECORD_V, FrameSlot(id));
	z.SetType({NewRef{}, rt});
	return AddInst(z);
	}

const ZAMStmt ZAMCompiler::InitVector(IDPtr id, VectorType* vt)
	{
	auto z = ZInstI(OP_INIT_VECTOR_V, FrameSlot(id));
	z.SetType({NewRef{}, vt});
	return AddInst(z);
	}

const ZAMStmt ZAMCompiler::InitTable(IDPtr id, TableType* tt, Attributes* attrs)
	{
	auto z = ZInstI(OP_INIT_TABLE_V, FrameSlot(id));
	z.SetType({NewRef{}, tt});
	z.attrs = {NewRef{}, attrs};
	return AddInst(z);
	}

const ZAMStmt ZAMCompiler::CompileWhen(const WhenStmt* ws)
	{
	auto cond = ws->Cond();
	auto body = ws->Body();
	auto timeout = ws->TimeoutExpr();
	auto timeout_body = ws->TimeoutBody();
	auto is_return = ws->IsReturn();

	ZInstI z;

	if ( timeout )
		{
		// Note, we fill in is_return by hand since it's already
		// an int_val, doesn't need translation.
		if ( timeout->Tag() == EXPR_CONST )
			{
			z = GenInst(OP_WHEN_VVVC, timeout->AsConstExpr());
			z.op_type = OP_VVVC_I1_I2_I3;
			z.v3 = is_return;
			}
		else
			{
			z = GenInst(OP_WHEN_VVVV, timeout->AsNameExpr());
			z.op_type = OP_VVVV_I2_I3_I4;
			z.v4 = is_return;
			}
		}

	else
		{
		z = GenInst(OP_WHEN_VV);
		z.op_type = OP_VV_I1_I2;
		z.v1 = is_return;
		}

	z.e = cond;

	auto when_eval = AddInst(z);

	auto branch_past_blocks = GoToStub();

	auto when_body = CompileStmt(body);
	auto when_done = ReturnX();

	if ( timeout )
		{
		auto t_body = CompileStmt(timeout_body);
		auto t_done = ReturnX();

		if ( timeout->Tag() == EXPR_CONST )
			{
			SetV1(when_eval, GoToTargetBeyond(branch_past_blocks));
			SetV2(when_eval, GoToTargetBeyond(when_done));
			}
		else
			{
			SetV2(when_eval, GoToTargetBeyond(branch_past_blocks));
			SetV3(when_eval, GoToTargetBeyond(when_done));
			}

		SetGoTo(branch_past_blocks, GoToTargetBeyond(t_done));

		return t_done;
		}

	else
		{
		SetV2(when_eval, GoToTargetBeyond(branch_past_blocks));
		SetGoTo(branch_past_blocks, GoToTargetBeyond(when_done));

		return when_done;
		}
	}

} // zeek::detail
