// See the file "COPYING" in the main distribution directory for copyright.

// Methods for traversing Stmt AST nodes to generate ZAM code.

#include "zeek/IPAddr.h"
#include "zeek/Reporter.h"
#include "zeek/ZeekString.h"
#include "zeek/script_opt/ZAM/BuiltIn.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {

const ZAMStmt ZAMCompiler::CompileStmt(const Stmt* s) {
    auto loc = s->GetLocationInfo();
    ASSERT(loc->FirstLine() != 0 || s->Tag() == STMT_NULL);
    auto loc_copy = std::make_shared<Location>(loc->FileName(), loc->FirstLine(), loc->LastLine());
    ASSERT(! AST_blocks || s->Tag() == STMT_NULL || AST_blocks->HaveExpDesc(loc_copy.get()));
    auto loc_parent = ZAM::curr_loc->Parent();
    ZAM::curr_loc = std::make_shared<ZAMLocInfo>(ZAM::curr_func, std::move(loc_copy), ZAM::curr_loc->Parent());

    switch ( s->Tag() ) {
        case STMT_PRINT: return CompilePrint(static_cast<const PrintStmt*>(s));

        case STMT_EXPR: return CompileExpr(static_cast<const ExprStmt*>(s));

        case STMT_IF: return CompileIf(static_cast<const IfStmt*>(s));

        case STMT_SWITCH: return CompileSwitch(static_cast<const SwitchStmt*>(s));

        case STMT_EVENT: {
            auto es = static_cast<const EventStmt*>(s);
            auto e = static_cast<const EventExpr*>(es->StmtExpr());
            return CompileExpr(e);
        }

        case STMT_WHILE: return CompileWhile(static_cast<const WhileStmt*>(s));

        case STMT_FOR: return CompileFor(static_cast<const ForStmt*>(s));

        case STMT_RETURN: return CompileReturn(static_cast<const ReturnStmt*>(s));

        case STMT_CATCH_RETURN: return CompileCatchReturn(static_cast<const CatchReturnStmt*>(s));

        case STMT_LIST: return CompileStmts(static_cast<const StmtList*>(s));

        case STMT_INIT: return CompileInit(static_cast<const InitStmt*>(s));

        case STMT_WHEN: return CompileWhen(static_cast<const WhenStmt*>(s));

        case STMT_ASSERT: return CompileAssert(static_cast<const AssertStmt*>(s));

        case STMT_NULL: return EmptyStmt();

        case STMT_CHECK_ANY_LEN: {
            auto cs = static_cast<const CheckAnyLenStmt*>(s);
            auto n = cs->StmtExpr()->AsNameExpr();
            auto expected_len = cs->ExpectedLen();
            return CheckAnyLenVi(n, expected_len);
        }

        case STMT_NEXT: return CompileNext();

        case STMT_BREAK: return CompileBreak();

        case STMT_FALLTHROUGH: return CompileFallThrough();

        default: reporter->InternalError("bad statement type in ZAMCompile::CompileStmt");
    }
}

const ZAMStmt ZAMCompiler::CompilePrint(const PrintStmt* ps) {
    auto& l = ps->ExprListPtr();

    if ( l->Exprs().length() == 1 ) { // special-case the common situation of printing just 1 item
        auto e0 = l->Exprs()[0];
        if ( e0->Tag() == EXPR_NAME )
            return Print1V(e0->AsNameExpr());
        else
            return Print1C(e0->AsConstExpr());
    }

    return PrintO(BuildVals(l).get());
}

const ZAMStmt ZAMCompiler::CompileExpr(const ExprStmt* es) {
    auto e = es->StmtExprPtr();

    if ( e->Tag() == EXPR_CALL )
        return Call(es);

    if ( e->Tag() == EXPR_ASSIGN && e->GetOp2()->Tag() == EXPR_CALL )
        return AssignToCall(es);

    return CompileExpr(e);
}

const ZAMStmt ZAMCompiler::CompileIf(const IfStmt* is) {
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

    if ( ! block1 ) {
        // See if we're able to invert the conditional.  If not,
        // then IfElse() will need to deal with inverting the test.
        // But we try here first, since some conditionals blow
        // up into zillions of different operators depending
        // on the type of their operands, so it's much simpler to
        // deal with them now.
        if ( e->InvertSense() ) {
            block1 = block2;
            block2 = nullptr;
        }
    }

    return IfElse(e.get(), block1, block2);
}

const ZAMStmt ZAMCompiler::IfElse(const Expr* e, const Stmt* s1, const Stmt* s2) {
    ZAMStmt cond_stmt = EmptyStmt();
    int branch_v;

    if ( e->Tag() == EXPR_NAME ) {
        auto n = e->AsNameExpr();

        ZOp op = (s1 && s2) ? OP_IF_ELSE_Vb : (s1 ? OP_IF_Vb : OP_IF_NOT_Vb);

        ZInstI cond(op, FrameSlot(n), 0);
        cond_stmt = AddInst(cond);
        branch_v = 2;
    }
    else
        cond_stmt = GenCond(e, branch_v);

    AddCFT(insts1.back(), CFT_IF);

    if ( s1 ) {
        auto s1_end = CompileStmt(s1);
        AddCFT(insts1.back(), CFT_BLOCK_END);

        if ( s2 ) {
            auto branch_after_s1 = GoToStub();
            auto else_start = insts1.size();
            auto s2_end = CompileStmt(s2);

            SetV(cond_stmt, GoToTargetBeyond(branch_after_s1), branch_v);
            SetGoTo(branch_after_s1, GoToTargetBeyond(s2_end));

            if ( else_start < insts1.size() )
                // There was a non-empty else branch.
                AddCFT(insts1[else_start], CFT_ELSE);

            AddCFT(insts1.back(), CFT_BLOCK_END);

            return s2_end;
        }

        else {
            SetV(cond_stmt, GoToTargetBeyond(s1_end), branch_v);
            return s1_end;
        }
    }

    // Only the else clause is non-empty.
    auto s2_end = CompileStmt(s2);
    AddCFT(insts1.back(), CFT_BLOCK_END);

    // For complex conditionals, we need to invert their sense since
    // we're switching to "if ( ! cond ) s2".
    auto z = insts1[cond_stmt.stmt_num];

    switch ( z->op ) {
        case OP_IF_ELSE_Vb:
        case OP_IF_Vb:
        case OP_IF_NOT_Vb:
            // These are generated correctly above, no need
            // to fix up.
            break;

        case OP_HAS_FIELD_COND_Vib: z->op = OP_NOT_HAS_FIELD_COND_Vib; break;
        case OP_NOT_HAS_FIELD_COND_Vib: z->op = OP_HAS_FIELD_COND_Vib; break;

        case OP_CONN_EXISTS_COND_Vb: z->op = OP_NOT_CONN_EXISTS_COND_Vb; break;
        case OP_NOT_CONN_EXISTS_COND_Vb: z->op = OP_CONN_EXISTS_COND_Vb; break;

        case OP_IS_ICMP_PORT_COND_Vb: z->op = OP_NOT_IS_ICMP_PORT_COND_Vb; break;
        case OP_NOT_IS_ICMP_PORT_COND_Vb: z->op = OP_IS_ICMP_PORT_COND_Vb; break;

        case OP_IS_TCP_PORT_COND_Vb: z->op = OP_NOT_IS_TCP_PORT_COND_Vb; break;
        case OP_NOT_IS_TCP_PORT_COND_Vb: z->op = OP_IS_TCP_PORT_COND_Vb; break;

        case OP_IS_UDP_PORT_COND_Vb: z->op = OP_NOT_IS_UDP_PORT_COND_Vb; break;
        case OP_NOT_IS_UDP_PORT_COND_Vb: z->op = OP_IS_UDP_PORT_COND_Vb; break;

        case OP_IS_V4_ADDR_COND_Vb: z->op = OP_NOT_IS_V4_ADDR_COND_Vb; break;
        case OP_NOT_IS_V4_ADDR_COND_Vb: z->op = OP_IS_V4_ADDR_COND_Vb; break;

        case OP_IS_V6_ADDR_COND_Vb: z->op = OP_NOT_IS_V6_ADDR_COND_Vb; break;
        case OP_NOT_IS_V6_ADDR_COND_Vb: z->op = OP_IS_V6_ADDR_COND_Vb; break;

        case OP_READING_LIVE_TRAFFIC_COND_b: z->op = OP_NOT_READING_LIVE_TRAFFIC_COND_b; break;
        case OP_NOT_READING_LIVE_TRAFFIC_COND_b: z->op = OP_READING_LIVE_TRAFFIC_COND_b; break;

        case OP_READING_TRACES_COND_b: z->op = OP_NOT_READING_TRACES_COND_b; break;
        case OP_NOT_READING_TRACES_COND_b: z->op = OP_READING_TRACES_COND_b; break;

        case OP_TABLE_HAS_ELEMENTS_COND_Vb: z->op = OP_NOT_TABLE_HAS_ELEMENTS_COND_Vb; break;
        case OP_NOT_TABLE_HAS_ELEMENTS_COND_Vb: z->op = OP_TABLE_HAS_ELEMENTS_COND_Vb; break;

        case OP_VECTOR_HAS_ELEMENTS_COND_Vb: z->op = OP_NOT_VECTOR_HAS_ELEMENTS_COND_Vb; break;
        case OP_NOT_VECTOR_HAS_ELEMENTS_COND_Vb: z->op = OP_VECTOR_HAS_ELEMENTS_COND_Vb; break;

        case OP_VAL_IS_IN_TABLE_COND_VVb: z->op = OP_NOT_VAL_IS_IN_TABLE_COND_VVb; break;
        case OP_NOT_VAL_IS_IN_TABLE_COND_VVb: z->op = OP_VAL_IS_IN_TABLE_COND_VVb; break;

        case OP_CONST_IS_IN_TABLE_COND_VCb: z->op = OP_NOT_CONST_IS_IN_TABLE_COND_VCb; break;
        case OP_NOT_CONST_IS_IN_TABLE_COND_VCb: z->op = OP_CONST_IS_IN_TABLE_COND_VCb; break;

        case OP_VAL2_IS_IN_TABLE_COND_VVVb: z->op = OP_VAL2_IS_NOT_IN_TABLE_COND_VVVb; break;
        case OP_VAL2_IS_NOT_IN_TABLE_COND_VVVb: z->op = OP_VAL2_IS_IN_TABLE_COND_VVVb; break;

        case OP_VAL2_IS_IN_TABLE_COND_VVbC: z->op = OP_VAL2_IS_NOT_IN_TABLE_COND_VVbC; break;
        case OP_VAL2_IS_NOT_IN_TABLE_COND_VVbC: z->op = OP_VAL2_IS_IN_TABLE_COND_VVbC; break;

        case OP_VAL2_IS_IN_TABLE_COND_VVCb: z->op = OP_VAL2_IS_NOT_IN_TABLE_COND_VVCb; break;
        case OP_VAL2_IS_NOT_IN_TABLE_COND_VVCb: z->op = OP_VAL2_IS_IN_TABLE_COND_VVCb; break;

        default: reporter->InternalError("inconsistency in ZAMCompiler::IfElse");
    }

    SetV(cond_stmt, GoToTargetBeyond(s2_end), branch_v);
    return s2_end;
}

const ZAMStmt ZAMCompiler::GenCond(const Expr* e, int& branch_v) {
    auto op1 = e->GetOp1();
    auto op2 = e->GetOp2();

    if ( e->Tag() == EXPR_HAS_FIELD ) {
        auto hf = e->AsHasFieldExpr();
        auto f = hf->Field();
        auto z = GenInst(OP_HAS_FIELD_COND_Vib, op1->AsNameExpr(), f);
        z.op_type = OP_VVV_I2_I3;
        z.TrackRecordTypeForField(cast_intrusive<RecordType>(op1->GetType()), f);
        branch_v = 3;
        return AddInst(z);
    }

    if ( e->Tag() == EXPR_IN ) {
        auto op2 = e->GetOp2()->AsNameExpr();

        // First, deal with the easy cases: it's a single index.
        if ( op1->Tag() == EXPR_LIST ) {
            auto& ind = op1->AsListExpr()->Exprs();
            if ( ind.length() == 1 )
                op1 = {NewRef{}, ind[0]};
        }

        if ( op1->Tag() == EXPR_NAME ) {
            auto z = GenInst(OP_VAL_IS_IN_TABLE_COND_VVb, op1->AsNameExpr(), op2, 0);
            z.SetType(op1->GetType());
            branch_v = 3;
            return AddInst(z);
        }

        if ( op1->Tag() == EXPR_CONST ) {
            auto z = GenInst(OP_CONST_IS_IN_TABLE_COND_VCb, op2, op1->AsConstExpr(), 0);
            z.SetType(op1->GetType());
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

        if ( name0 && name1 ) {
            z = GenInst(OP_VAL2_IS_IN_TABLE_COND_VVVb, n0, n1, op2, 0);
            branch_v = 4;
            z.SetType2(n0->GetType());
        }

        else if ( name0 ) {
            z = GenInst(OP_VAL2_IS_IN_TABLE_COND_VVbC, n0, op2, c1, 0);
            branch_v = 3;
            z.SetType2(n0->GetType());
        }

        else if ( name1 ) {
            z = GenInst(OP_VAL2_IS_IN_TABLE_COND_VVCb, n1, op2, c0, 0);
            branch_v = 3;
            z.SetType2(n1->GetType());
        }

        else { // Both are constants, assign first to temporary.
            auto slot = TempForConst(c0);

            z = ZInstI(OP_VAL2_IS_IN_TABLE_COND_VVbC, slot, FrameSlot(op2), 0, c1);
            z.op_type = OP_VVVC_I3;
            branch_v = 3;
            z.SetType2(c0->GetType());
        }

        return AddInst(z);
    }

    if ( e->Tag() == EXPR_CALL ) {
        auto c = static_cast<const CallExpr*>(e);
        if ( IsZAM_BuiltInCond(this, c, branch_v) )
            return LastInst();
    }

    if ( e->Tag() == EXPR_SCRIPT_OPT_BUILTIN ) {
        auto bi = static_cast<const ScriptOptBuiltinExpr*>(e);
        ASSERT(bi->Tag() == ScriptOptBuiltinExpr::HAS_ELEMENTS);
        auto aggr = bi->GetOp1()->AsNameExpr();

        ZOp op;
        if ( aggr->GetType()->Tag() == TYPE_TABLE )
            op = OP_TABLE_HAS_ELEMENTS_COND_Vb;
        else
            op = OP_VECTOR_HAS_ELEMENTS_COND_Vb;

        branch_v = 2;
        return AddInst(GenInst(op, aggr, +0));
    }

    NameExpr* n1 = nullptr;
    NameExpr* n2 = nullptr;
    ConstExpr* c = nullptr;

    if ( op1->Tag() == EXPR_NAME ) {
        n1 = op1->AsNameExpr();

        if ( op2->Tag() == EXPR_NAME )
            n2 = op2->AsNameExpr();
        else
            c = op2->AsConstExpr();
    }

    else {
        c = op1->AsConstExpr();
        n2 = op2->AsNameExpr();
    }

    if ( n1 && n2 )
        branch_v = 3;
    else
        branch_v = 2;

// clang 10 gets perturbed that the indentation of the "default" in the
// following switch block doesn't match that of the cases that we include
// from "ZAM-Conds.h".  It really shouldn't worry about indentation mismatches
// across included files since those are not indicative of possible
// logic errors, but Oh Well.
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmisleading-indentation"
#endif
    switch ( e->Tag() ) {
#include "ZAM-Conds.h"

        default: reporter->InternalError("bad expression type in ZAMCompiler::GenCond");
    }
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

    // Not reached.
}

const ZAMStmt ZAMCompiler::CompileSwitch(const SwitchStmt* sw) {
    auto e = sw->StmtExpr();

    auto n = e->Tag() == EXPR_NAME ? e->AsNameExpr() : nullptr;
    auto c = e->Tag() == EXPR_CONST ? e->AsConstExpr() : nullptr;

    auto t = e->GetType()->Tag();

    // Need to track a new set of contexts for "break" statements.
    PushBreaks();

    if ( sw->TypeMap()->empty() )
        return ValueSwitch(sw, n, c);
    else
        return TypeSwitch(sw, n, c);
}

const ZAMStmt ZAMCompiler::ValueSwitch(const SwitchStmt* sw, const NameExpr* v, const ConstExpr* c) {
    int slot = v ? FrameSlot(v) : -1;

    if ( c )
        // Weird to have a constant switch expression, enough
        // so that it doesn't seem worth optimizing.
        slot = TempForConst(c);

    ASSERT(slot >= 0);

    // Figure out which jump table we're using.
    auto t = v ? v->GetType() : c->GetType();

    return GenSwitch(sw, slot, t->InternalType());
}

const ZAMStmt ZAMCompiler::GenSwitch(const SwitchStmt* sw, int slot, InternalTypeTag it) {
    ZOp op;

    switch ( it ) {
        case TYPE_INTERNAL_INT: op = OP_SWITCHI_Vii; break;

        case TYPE_INTERNAL_UNSIGNED: op = OP_SWITCHU_Vii; break;

        case TYPE_INTERNAL_DOUBLE: op = OP_SWITCHD_Vii; break;

        case TYPE_INTERNAL_STRING: op = OP_SWITCHS_Vii; break;

        case TYPE_INTERNAL_ADDR: op = OP_SWITCHA_Vii; break;

        case TYPE_INTERNAL_SUBNET: op = OP_SWITCHN_Vii; break;

        default: reporter->InternalError("bad switch type");
    }

    // Add the "head", i.e., the execution of the jump table. At this point,
    // we leave the table (v2) and default (v3) TBD.
    auto sw_head_op = ZInstI(op, slot, 0, 0);
    sw_head_op.op_type = OP_VVV_I2_I3;

    auto sw_head = AddInst(sw_head_op);
    auto body_end = sw_head;

    // Generate each of the cases.
    auto cases = sw->Cases();
    std::vector<InstLabel> case_start;
    int case_index = 0;

    PushFallThroughs();
    for ( auto sw_case : *cases ) {
        auto start = GoToTargetBeyond(body_end);
        ResolveFallThroughs(start);
        case_start.push_back(start);
        PushFallThroughs();
        body_end = CompileStmt(sw_case->Body());
    }

    auto sw_end = GoToTargetBeyond(body_end);
    ResolveFallThroughs(sw_end);
    ResolveBreaks(sw_end);

    int def_ind = sw->DefaultCaseIndex();
    if ( def_ind >= 0 ) {
        auto def = case_start[def_ind];
        SetV3(sw_head, def);
        AddCFT(def, CFT_DEFAULT);
    }
    else
        SetV3(sw_head, sw_end);

    // Now fill out the corresponding jump table.
    //
    // We will only use one of these.
    CaseMapI<zeek_int_t> new_int_cases;
    CaseMapI<zeek_uint_t> new_uint_cases;
    CaseMapI<double> new_double_cases;
    CaseMapI<std::string> new_str_cases;

    for ( auto [cv, index] : sw->ValueMap() ) {
        auto case_body_start = case_start[index];

        switch ( cv->GetType()->InternalType() ) {
            case TYPE_INTERNAL_INT: new_int_cases[cv->InternalInt()] = case_body_start; break;

            case TYPE_INTERNAL_UNSIGNED: new_uint_cases[cv->InternalUnsigned()] = case_body_start; break;

            case TYPE_INTERNAL_DOUBLE: new_double_cases[cv->InternalDouble()] = case_body_start; break;

            case TYPE_INTERNAL_STRING: {
                // This leaks, but only statically so not worth
                // tracking the value for ultimate deletion.
                auto sv = cv->AsString()->Render();
                std::string s(sv);
                new_str_cases[s] = case_body_start;
                delete[] sv;
                break;
            }

            case TYPE_INTERNAL_ADDR: {
                auto a = cv->AsAddr().AsString();
                new_str_cases[a] = case_body_start;
                break;
            }

            case TYPE_INTERNAL_SUBNET: {
                auto n = cv->AsSubNet().AsString();
                new_str_cases[n] = case_body_start;
                break;
            }

            default: reporter->InternalError("bad recovered type when compiling switch");
        }
    }

    // For type switches, we map them to consecutive numbers, and then use
    // a integer-valued switch on those.
    int tm_ctr = 0;
    for ( const auto& [_, index] : *sw->TypeMap() ) {
        auto case_body_start = case_start[index];
        new_int_cases[tm_ctr++] = case_body_start;
    }

    // Now add the jump table to the set we're keeping for the
    // corresponding type.

    size_t tbl;

    switch ( it ) {
        case TYPE_INTERNAL_INT:
            tbl = int_casesI.size();
            int_casesI.push_back(std::move(new_int_cases));
            break;

        case TYPE_INTERNAL_UNSIGNED:
            tbl = uint_casesI.size();
            uint_casesI.push_back(std::move(new_uint_cases));
            break;

        case TYPE_INTERNAL_DOUBLE:
            tbl = double_casesI.size();
            double_casesI.push_back(std::move(new_double_cases));
            break;

        case TYPE_INTERNAL_STRING:
        case TYPE_INTERNAL_ADDR:
        case TYPE_INTERNAL_SUBNET:
            tbl = str_casesI.size();
            str_casesI.push_back(std::move(new_str_cases));
            break;

        default: reporter->InternalError("bad switch type");
    }

    insts1[sw_head.stmt_num]->v2 = int(tbl);

    AddCFT(insts1[body_end.stmt_num], CFT_BLOCK_END);

    return body_end;
}

const ZAMStmt ZAMCompiler::TypeSwitch(const SwitchStmt* sw, const NameExpr* v, const ConstExpr* c) {
    auto cases = sw->Cases();
    auto type_map = sw->TypeMap();
    auto tmp = NewSlot(true); // true since we know "any" is managed

    int slot = v ? FrameSlot(v) : 0;

    if ( v ) {
        if ( v->GetType()->Tag() != TYPE_ANY ) {
            auto z = ZInstI(OP_ASSIGN_ANY_VV, tmp, slot);
            AddInst(z);
            slot = tmp;
        }
    }

    else {
        ASSERT(c);
        auto z = ZInstI(OP_ASSIGN_ANY_VC, tmp, c);
        AddInst(z);
        slot = tmp;
    }

    int ntypes = type_map->size();
    auto aux = new ZInstAux(ntypes);

    for ( size_t i = 0; i < type_map->size(); ++i ) {
        auto& tm = (*type_map)[i];
        auto id_i = tm.first;
        auto id_case = tm.second;

        auto slot = id_i->Name() ? FrameSlot(id_i) : -1;
        aux->Add(i, slot, id_i->GetType());
    }

    auto match_tmp = NewSlot(false);
    auto z = ZInstI(OP_DETERMINE_TYPE_MATCH_VV, match_tmp, slot);
    z.op_type = OP_VV;
    z.aux = aux;
    AddInst(z);

    return GenSwitch(sw, match_tmp, TYPE_INTERNAL_INT);
}

const ZAMStmt ZAMCompiler::CompileWhile(const WhileStmt* ws) {
    const auto& loop_condition = ws->Condition();

    if ( loop_condition->Tag() == EXPR_CONST ) {
        if ( loop_condition->IsZero() )
            return EmptyStmt();
        else
            return Loop(ws->Body().get());
    }

    auto cond_pred = ws->CondPredStmt();

    return While(cond_pred.get(), loop_condition.get(), ws->Body().get());
}

const ZAMStmt ZAMCompiler::While(const Stmt* cond_stmt, const Expr* cond, const Stmt* body) {
    auto head = StartingBlock();

    if ( cond_stmt )
        (void)CompileStmt(cond_stmt);

    ZAMStmt cond_IF = EmptyStmt();
    int branch_v;

    if ( cond->Tag() == EXPR_NAME ) {
        auto n = cond->AsNameExpr();
        cond_IF = AddInst(ZInstI(OP_IF_Vb, FrameSlot(n), 0));
        branch_v = 2;
    }
    else
        cond_IF = GenCond(cond, branch_v);

    AddCFT(insts1[head.stmt_num], CFT_LOOP);
    AddCFT(insts1[cond_IF.stmt_num], CFT_LOOP_COND);

    PushNexts();
    PushBreaks();

    if ( body && body->Tag() != STMT_NULL )
        (void)CompileStmt(body);

    AddCFT(insts1.back(), CFT_LOOP_END);

    auto tail = GoTo(GoToTarget(head));

    auto beyond_tail = GoToTargetBeyond(tail);
    SetV(cond_IF, beyond_tail, branch_v);

    ResolveNexts(GoToTarget(head));
    ResolveBreaks(beyond_tail);

    return tail;
}

const ZAMStmt ZAMCompiler::CompileFor(const ForStmt* f) {
    auto e = f->LoopExpr();
    auto val = e->Tag() == EXPR_NAME ? e->AsNameExpr() : nullptr;
    auto et = e->GetType()->Tag();

    PushNexts();
    PushBreaks();

    ZAMStmt z;

    if ( et == TYPE_TABLE )
        z = LoopOverTable(f, val);

    else if ( et == TYPE_VECTOR )
        z = LoopOverVector(f, val);

    else if ( et == TYPE_STRING )
        z = LoopOverString(f, e);

    else
        reporter->InternalError("bad \"for\" loop-over value when compiling");

    return z;
}

const ZAMStmt ZAMCompiler::LoopOverTable(const ForStmt* f, const NameExpr* val) {
    auto loop_vars = f->LoopVars();
    auto value_var = f->ValueVar();
    auto body = f->LoopBody();

    // We used to have more involved logic here to check whether the loop
    // variables are actually used in the body. Now that we have '_'
    // loop placeholder variables, this is no longer worth trying to
    // optimize for, though we still optimize for those placeholders.
    size_t num_unused = 0;

    auto aux = new ZInstAux(0);

    for ( const auto& id : *loop_vars ) {
        if ( id->IsBlank() )
            ++num_unused;

        int slot = id->IsBlank() ? -1 : FrameSlot(id);
        aux->loop_vars.push_back(slot);
        auto& t = id->GetType();
        aux->types.push_back(t);
        aux->is_managed.push_back(ZVal::IsManagedType(t));
    }

    bool no_loop_vars = (num_unused == loop_vars->size());

    if ( value_var )
        aux->value_var_type = value_var->GetType();

    auto iter_slot = table_iters.size();
    table_iters.emplace_back();

    auto zi = ZInstI(OP_INIT_TABLE_LOOP_Vf, FrameSlot(val), iter_slot);
    zi.op_type = OP_VV_I2;
    if ( value_var )
        zi.SetType(value_var->GetType());
    zi.aux = aux;

    (void)AddInst(zi);

    ZInstI zn;
    auto iter_head = StartingBlock();

    if ( value_var ) {
        ZOp op = no_loop_vars ? OP_NEXT_TABLE_ITER_VAL_VAR_NO_VARS_Vfb : OP_NEXT_TABLE_ITER_VAL_VAR_Vfb;
        zn = ZInstI(op, FrameSlot(value_var), iter_slot, 0);
        zn.CheckIfManaged(value_var->GetType());
        zn.op_type = OP_VVV_I2_I3;
    }
    else {
        ZOp op = no_loop_vars ? OP_NEXT_TABLE_ITER_NO_VARS_fb : OP_NEXT_TABLE_ITER_fb;
        zn = ZInstI(op, iter_slot, 0);
        zn.op_type = OP_VV_I1_I2;
    }

    // Need a separate instance of aux so the CFT info doesn't get shared with
    // the loop init. We populate it with the loop_vars (only) because the
    // optimizer needs access to those for (1) tracking their lifetime, and
    // (2) remapping them (not strictly needed, see the comment in ReMapFrame()).
    zn.aux = new ZInstAux(0);
    zn.aux->loop_vars = aux->loop_vars;
    AddCFT(&zn, CFT_LOOP);
    AddCFT(&zn, CFT_LOOP_COND);

    return FinishLoop(iter_head, zn, body, iter_slot, true);
}

const ZAMStmt ZAMCompiler::LoopOverVector(const ForStmt* f, const NameExpr* val) {
    auto loop_vars = f->LoopVars();
    auto loop_var = (*loop_vars)[0];
    auto value_var = f->ValueVar();

    int iter_slot = num_step_iters++;

    auto z = ZInstI(OP_INIT_VECTOR_LOOP_Vs, FrameSlot(val), iter_slot);
    z.op_type = OP_VV_I2;

    auto init_end = AddInst(z);
    auto iter_head = StartingBlock();

    int slot = loop_var->IsBlank() ? -1 : FrameSlot(loop_var);

    if ( value_var ) {
        if ( slot >= 0 ) {
            z = ZInstI(OP_NEXT_VECTOR_ITER_VAL_VAR_VVsb, slot, FrameSlot(value_var), iter_slot, 0);
            z.op_type = OP_VVVV_I3_I4;
        }
        else {
            z = ZInstI(OP_NEXT_VECTOR_BLANK_ITER_VAL_VAR_Vsb, FrameSlot(value_var), iter_slot, 0);
            z.op_type = OP_VVV_I2_I3;
        }

        z.SetType(value_var->GetType());
    }

    else {
        if ( slot >= 0 ) {
            z = ZInstI(OP_NEXT_VECTOR_ITER_Vsb, slot, iter_slot, 0);
            z.op_type = OP_VVV_I2_I3;
        }
        else {
            z = ZInstI(OP_NEXT_VECTOR_BLANK_ITER_sb, iter_slot, 0);
            z.op_type = OP_VV_I1_I2;
        }
    }

    AddCFT(&z, CFT_LOOP);
    AddCFT(&z, CFT_LOOP_COND);

    return FinishLoop(iter_head, z, f->LoopBody(), iter_slot, false);
}

const ZAMStmt ZAMCompiler::LoopOverString(const ForStmt* f, const Expr* e) {
    auto n = e->Tag() == EXPR_NAME ? e->AsNameExpr() : nullptr;
    auto c = e->Tag() == EXPR_CONST ? e->AsConstExpr() : nullptr;
    auto loop_vars = f->LoopVars();
    auto loop_var = (*loop_vars)[0];

    int iter_slot = num_step_iters++;

    ZInstI z;

    if ( n ) {
        z = ZInstI(OP_INIT_STRING_LOOP_Vs, FrameSlot(n), iter_slot);
        z.op_type = OP_VV_I2;
    }
    else {
        ASSERT(c);
        z = ZInstI(OP_INIT_STRING_LOOP_Cs, iter_slot, c);
        z.op_type = OP_VC_I1;
    }

    auto init_end = AddInst(z);
    auto iter_head = StartingBlock();

    if ( loop_var->IsBlank() ) {
        z = ZInstI(OP_NEXT_STRING_BLANK_ITER_sb, iter_slot, 0);
        z.op_type = OP_VV_I1_I2;
    }
    else {
        z = ZInstI(OP_NEXT_STRING_ITER_Vsb, FrameSlot(loop_var), iter_slot, 0);
        z.op_type = OP_VVV_I2_I3;
        z.is_managed = true;
    }

    AddCFT(&z, CFT_LOOP);
    AddCFT(&z, CFT_LOOP_COND);

    return FinishLoop(iter_head, z, f->LoopBody(), iter_slot, false);
}

const ZAMStmt ZAMCompiler::Loop(const Stmt* body) {
    PushNexts();
    PushBreaks();

    auto head = StartingBlock();
    auto b = CompileStmt(body);

    if ( head.stmt_num == static_cast<int>(insts1.size()) ) {
        reporter->Error("infinite empty loop: %s", obj_desc(body).c_str());
        return head;
    }

    AddCFT(insts1[head.stmt_num], CFT_LOOP);
    AddCFT(insts1[b.stmt_num], CFT_LOOP_END);

    auto tail = GoTo(GoToTarget(head));

    ResolveNexts(GoToTarget(head));
    ResolveBreaks(GoToTargetBeyond(tail));

    return tail;
}

const ZAMStmt ZAMCompiler::FinishLoop(const ZAMStmt iter_head, ZInstI& iter_stmt, const Stmt* body, int iter_slot,
                                      bool is_table) {
    auto loop_iter = AddInst(iter_stmt);
    auto body_end = CompileStmt(body);

    auto loop_end = GoTo(GoToTarget(iter_head));
    AddCFT(insts1[loop_end.stmt_num], CFT_LOOP_END);

    // We only need cleanup for looping over tables, but for now we
    // need some sort of placeholder instruction (until the optimizer
    // can elide it) to resolve loop exits.
    ZOp op = is_table ? OP_END_TABLE_LOOP_f : OP_NOP;

    auto z = ZInstI(op, iter_slot);
    z.op_type = is_table ? OP_V_I1 : OP_X;
    auto final_stmt = AddInst(z);

    auto ot = iter_stmt.op_type;
    if ( ot == OP_VVVV_I3_I4 )
        SetV4(loop_iter, GoToTarget(final_stmt));
    else if ( ot == OP_VVV_I3 || ot == OP_VVV_I2_I3 )
        SetV3(loop_iter, GoToTarget(final_stmt));
    else
        SetV2(loop_iter, GoToTarget(final_stmt));

    ResolveNexts(GoToTarget(iter_head));
    ResolveBreaks(GoToTarget(final_stmt));

    return final_stmt;
}

const ZAMStmt ZAMCompiler::CompileReturn(const ReturnStmt* r) {
    auto e = r->StmtExpr();

    if ( retvars.empty() ) { // a "true" return
        if ( e ) {
            if ( pf->ProfiledFunc()->Flavor() == FUNC_FLAVOR_HOOK ) {
                ASSERT(e->GetType()->Tag() == TYPE_BOOL);
                auto true_c = make_intrusive<ConstExpr>(val_mgr->True());
                return ReturnC(true_c.get());
            }

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

    if ( e ) {
        if ( e->Tag() == EXPR_NAME )
            (void)AssignVV(rv, e->AsNameExpr());
        else
            (void)AssignVC(rv, e->AsConstExpr());
    }

    return CompileCatchReturn();
}

const ZAMStmt ZAMCompiler::CompileCatchReturn(const CatchReturnStmt* cr) {
    retvars.push_back(cr->RetVar());

    const auto& hold_func = ZAM::curr_func;
    const auto& hold_loc = ZAM::curr_loc;

    ZAM::curr_func = cr->Func()->GetName();

    bool is_event_inline = (hold_func == ZAM::curr_func);

    if ( ! is_event_inline )
        ZAM::curr_loc = std::make_shared<ZAMLocInfo>(ZAM::curr_func, ZAM::curr_loc->LocPtr(), hold_loc);

    PushCatchReturns();

    auto block = cr->Block();
    auto block_end = CompileStmt(block);
    retvars.pop_back();

    ResolveCatchReturns(GoToTargetBeyond(block_end));

    if ( ! is_event_inline ) {
        // Strictly speaking, we could do this even if is_event_inline
        // is true, because the values won't have changed. However, that
        // just looks weird, so we condition this to match the above.
        ZAM::curr_func = hold_func;
        ZAM::curr_loc = hold_loc;
    }

    return block_end;
}

const ZAMStmt ZAMCompiler::CompileStmts(const StmtList* ws) {
    auto start = StartingBlock();

    for ( const auto& stmt : ws->Stmts() )
        CompileStmt(stmt);

    return FinishBlock(start);
}

const ZAMStmt ZAMCompiler::CompileInit(const InitStmt* is) {
    auto last = EmptyStmt();

    for ( const auto& aggr : is->Inits() ) {
        if ( IsUnused(aggr, is) )
            continue;

        auto& t = aggr->GetType();

        switch ( t->Tag() ) {
            case TYPE_RECORD: last = InitRecord(aggr, t->AsRecordType()); break;

            case TYPE_VECTOR: last = InitVector(aggr, t->AsVectorType()); break;

            case TYPE_TABLE: last = InitTable(aggr, t->AsTableType(), aggr->GetAttrs().get()); break;

            default: break;
        }
    }

    return last;
}

const ZAMStmt ZAMCompiler::CompileWhen(const WhenStmt* ws) {
    auto wi = ws->Info();
    auto timeout = wi->TimeoutExpr();

    auto lambda = NewSlot(true);
    (void)BuildLambda(lambda, wi->Lambda());

    std::vector<IDPtr> local_aggr_slots;
    for ( auto& l : wi->WhenExprLocals() )
        if ( IsAggr(l->GetType()->Tag()) )
            local_aggr_slots.push_back(l);

    int n = local_aggr_slots.size();
    auto aux = new ZInstAux(n);
    aux->wi = wi;

    for ( auto i = 0; i < n; ++i ) {
        const auto& la = local_aggr_slots[i];
        aux->Add(i, FrameSlot(la), la->GetType());
    }

    ZInstI z;

    if ( timeout ) {
        if ( timeout->Tag() == EXPR_NAME ) {
            auto ns = FrameSlot(timeout->AsNameExpr());
            z = ZInstI(OP_WHEN_TIMEOUT_VV, lambda, ns);
        }
        else {
            ASSERT(timeout->Tag() == EXPR_CONST);
            z = ZInstI(OP_WHEN_TIMEOUT_VC, lambda, timeout->AsConstExpr());
        }
    }

    else
        z = ZInstI(OP_WHEN_V, lambda);

    z.aux = aux;

    if ( ws->IsReturn() ) {
        (void)AddInst(z);
        z = ZInstI(OP_WHEN_RETURN_X);
    }

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::CompileAssert(const AssertStmt* as) {
    auto cond = as->StmtExpr();

    int cond_slot;
    if ( cond->Tag() == EXPR_CONST )
        cond_slot = TempForConst(cond->AsConstExpr());
    else
        cond_slot = FrameSlot(cond->AsNameExpr());

    auto decision_slot = NewSlot(false);

    (void)AddInst(ZInstI(OP_SHOULD_REPORT_ASSERT_VV, decision_slot, cond_slot));

    auto cond_stmt = AddInst(ZInstI(OP_IF_Vb, decision_slot, 0));
    AddCFT(insts1.back(), CFT_IF);

    ZInstI z;

    // We don't have a convenient way of directly introducing a std::string
    // constant, so we build one to hold it.
    auto cond_desc = make_intrusive<StringVal>(new String(as->CondDesc()));
    auto cond_desc_e = make_intrusive<ConstExpr>(cond_desc);

    if ( const auto& msg = as->Msg() ) {
        auto& msg_setup_stmt = as->MsgSetupStmt();
        if ( msg_setup_stmt )
            (void)CompileStmt(msg_setup_stmt);

        int msg_slot;
        if ( msg->Tag() == EXPR_CONST )
            msg_slot = TempForConst(msg->AsConstExpr());
        else
            msg_slot = FrameSlot(msg->AsNameExpr());

        z = ZInstI(OP_REPORT_ASSERT_WITH_MESSAGE_VVC, cond_slot, msg_slot, cond_desc_e.get());
    }
    else
        z = ZInstI(OP_REPORT_ASSERT_VC, cond_slot, cond_desc_e.get());

    auto end_inst = AddInst(z);
    AddCFT(insts1.back(), CFT_BLOCK_END);
    SetV(cond_stmt, GoToTargetBeyond(end_inst), 2);

    return end_inst;
}

const ZAMStmt ZAMCompiler::InitRecord(IDPtr id, RecordType* rt) {
    auto z = ZInstI(OP_INIT_RECORD_V, FrameSlot(id));
    z.SetType({NewRef{}, rt});
    return AddInst(z);
}

const ZAMStmt ZAMCompiler::InitVector(IDPtr id, VectorType* vt) {
    auto z = ZInstI(OP_INIT_VECTOR_V, FrameSlot(id));
    z.SetType({NewRef{}, vt});
    return AddInst(z);
}

const ZAMStmt ZAMCompiler::InitTable(IDPtr id, TableType* tt, Attributes* attrs) {
    auto z = ZInstI(OP_INIT_TABLE_V, FrameSlot(id));
    z.SetType({NewRef{}, tt});
    z.aux = new ZInstAux(0);
    z.aux->attrs = {NewRef{}, attrs};
    return AddInst(z);
}

} // namespace zeek::detail
