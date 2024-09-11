// See the file "COPYING" in the main distribution directory for copyright.

// Methods for traversing Expr AST nodes to generate ZAM code.

#include "zeek/Desc.h"
#include "zeek/Reporter.h"
#include "zeek/script_opt/ZAM/BuiltIn.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {

const ZAMStmt ZAMCompiler::CompileExpr(const Expr* e) {
    switch ( e->Tag() ) {
        case EXPR_INCR:
        case EXPR_DECR: return CompileIncrExpr(static_cast<const IncrExpr*>(e));

        case EXPR_APPEND_TO: return CompileAppendToExpr(static_cast<const AppendToExpr*>(e));

        case EXPR_AGGR_ADD: return CompileAdd(static_cast<const AggrAddExpr*>(e));

        case EXPR_AGGR_DEL: return CompileDel(static_cast<const AggrDelExpr*>(e));

        case EXPR_ADD_TO: return CompileAddToExpr(static_cast<const AddToExpr*>(e));

        case EXPR_REMOVE_FROM: return CompileRemoveFromExpr(static_cast<const RemoveFromExpr*>(e));

        case EXPR_ASSIGN: return CompileAssignExpr(static_cast<const AssignExpr*>(e));

        case EXPR_REC_ASSIGN_FIELDS:
        case EXPR_REC_ADD_FIELDS: return CompileRecFieldUpdates(static_cast<const RecordFieldUpdatesExpr*>(e));

        case EXPR_INDEX_ASSIGN: {
            auto iae = static_cast<const IndexAssignExpr*>(e);
            auto t = iae->GetOp1()->GetType()->Tag();
            if ( t == TYPE_VECTOR )
                return AssignVecElems(iae);

            ASSERT(t == TYPE_TABLE);
            return AssignTableElem(iae);
        }

        case EXPR_FIELD_LHS_ASSIGN: {
            auto flhs = static_cast<const FieldLHSAssignExpr*>(e);
            return CompileFieldLHSAssignExpr(flhs);
        }

        case EXPR_SCHEDULE: return CompileScheduleExpr(static_cast<const ScheduleExpr*>(e));

        case EXPR_EVENT: {
            auto ee = static_cast<const EventExpr*>(e);
            auto h = ee->Handler().Ptr();
            auto args = ee->Args();
            return EventHL(h, args);
        }

        default: reporter->InternalError("bad statement type in ZAMCompile::CompileExpr");
    }
}

const ZAMStmt ZAMCompiler::CompileIncrExpr(const IncrExpr* e) {
    auto target = e->Op()->AsRefExpr()->GetOp1()->AsNameExpr();

    if ( target->GetType()->Tag() == TYPE_INT ) {
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

const ZAMStmt ZAMCompiler::CompileAppendToExpr(const AppendToExpr* e) {
    auto n1 = e->GetOp1()->AsNameExpr();
    auto op2 = e->GetOp2();
    auto n2 = op2->Tag() == EXPR_NAME ? op2->AsNameExpr() : nullptr;
    auto cc = op2->Tag() != EXPR_NAME ? op2->AsConstExpr() : nullptr;

    if ( n1->GetType()->Yield()->Tag() == TYPE_ANY )
        return n2 ? AppendToAnyVecVV(n1, n2) : AppendToAnyVecVC(n1, cc);

    return n2 ? AppendToVV(n1, n2) : AppendToVC(n1, cc);
}

const ZAMStmt ZAMCompiler::CompileAdd(const AggrAddExpr* e) {
    auto op = e->GetOp1();
    auto aggr = op->GetOp1()->AsNameExpr();
    auto index_list = op->GetOp2();

    if ( index_list->Tag() != EXPR_LIST )
        reporter->InternalError("non-list in \"add\"");

    auto indices = index_list->AsListExprPtr();
    auto& exprs = indices->Exprs();

    if ( exprs.length() == 1 ) {
        auto e1 = exprs[0];
        if ( e1->Tag() == EXPR_NAME )
            return AddStmt1VV(aggr, e1->AsNameExpr());
        else
            return AddStmt1VC(aggr, e1->AsConstExpr());
    }

    return AddStmtVO(aggr, BuildVals(indices).get());
}

const ZAMStmt ZAMCompiler::CompileDel(const AggrDelExpr* e) {
    auto op = e->GetOp1();

    if ( op->Tag() == EXPR_NAME ) {
        auto n = op->AsNameExpr();

        if ( n->GetType()->Tag() == TYPE_TABLE )
            return ClearTableV(n);
        else
            return ClearVectorV(n);
    }

    auto aggr = op->GetOp1()->AsNameExpr();

    if ( op->Tag() == EXPR_FIELD ) {
        int field = op->AsFieldExpr()->Field();
        return DelFieldVi(aggr, field);
    }

    auto index_list = op->GetOp2();

    if ( index_list->Tag() != EXPR_LIST )
        reporter->InternalError("non-list in \"delete\"");

    auto internal_ind = BuildVals(index_list->AsListExprPtr());
    return DelTableVO(aggr, internal_ind.get());
}

const ZAMStmt ZAMCompiler::CompileAddToExpr(const AddToExpr* e) {
    auto op1 = e->GetOp1();
    auto t1 = op1->GetType()->Tag();

    auto op2 = e->GetOp2();
    auto n2 = op2->Tag() == EXPR_NAME ? op2->AsNameExpr() : nullptr;
    auto cc = op2->Tag() != EXPR_NAME ? op2->AsConstExpr() : nullptr;

    if ( op1->Tag() == EXPR_FIELD ) {
        assert(t1 == TYPE_PATTERN);
        auto f = op1->AsFieldExpr()->Field();
        auto n1 = op1->GetOp1()->AsNameExpr();

        ZInstI z;

        if ( n2 ) {
            z = ZInstI(OP_ADDPATTERNTOFIELD_VVi, FrameSlot(n1), FrameSlot(n2), f);
            z.op_type = OP_VVV_I3;
        }
        else {
            z = ZInstI(OP_ADDPATTERNTOFIELD_VCi, FrameSlot(n1), f, cc);
            z.op_type = OP_VVC_I2;
        }

        z.SetType(n2 ? n2->GetType() : cc->GetType());

        return AddInst(z);
    }

    auto n1 = op1->AsNameExpr();

    if ( t1 == TYPE_PATTERN )
        return n2 ? ExtendPatternVV(n1, n2) : ExtendPatternVC(n1, cc);

    if ( t1 == TYPE_VECTOR )
        return n2 ? AddVecToVecVV(n1, n2) : AddVecToVecVC(n1, cc);

    assert(t1 == TYPE_TABLE);

    return n2 ? AddTableToTableVV(n1, n2) : AddTableToTableVC(n1, cc);
}

const ZAMStmt ZAMCompiler::CompileRemoveFromExpr(const RemoveFromExpr* e) {
    auto n1 = e->GetOp1()->AsNameExpr();
    auto op2 = e->GetOp2();

    auto n2 = op2->Tag() == EXPR_NAME ? op2->AsNameExpr() : nullptr;
    auto cc = op2->Tag() != EXPR_NAME ? op2->AsConstExpr() : nullptr;

    return n2 ? RemoveTableFromTableVV(n1, n2) : RemoveTableFromTableVC(n1, cc);
}

const ZAMStmt ZAMCompiler::CompileAssignExpr(const AssignExpr* e) {
    auto op1 = e->GetOp1();
    auto op2 = e->GetOp2();

    auto lhs = op1->AsRefExpr()->GetOp1()->AsNameExpr();
    auto rhs = op2.get();

    if ( rhs->Tag() == EXPR_SCRIPT_OPT_BUILTIN )
        return CompileZAMBuiltin(lhs, static_cast<const ScriptOptBuiltinExpr*>(rhs));

    auto lt = lhs->GetType().get();
    auto r1 = rhs->GetOp1();

    if ( rhs->Tag() == EXPR_INDEX && (r1->Tag() == EXPR_NAME || r1->Tag() == EXPR_CONST) )
        return CompileAssignToIndex(lhs, rhs->AsIndexExpr());

    switch ( rhs->Tag() ) {
#include "ZAM-DirectDefs.h"

        default: break;
    }

    auto rt = rhs->GetType();

    auto r2 = rhs->GetOp2();
    auto r3 = rhs->GetOp3();

    if ( rhs->Tag() == EXPR_NAME )
        return AssignVV(lhs, rhs->AsNameExpr());

    if ( rhs->Tag() == EXPR_CONST )
        return AssignVC(lhs, rhs->AsConstExpr());

    if ( rhs->Tag() == EXPR_IN && r1->Tag() == EXPR_LIST ) {
        // r2 can be a constant due to propagating "const"
        // globals, for example.
        if ( r2->Tag() == EXPR_NAME ) {
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

    if ( rhs->Tag() == EXPR_ANY_INDEX ) {
        auto rhs_as_any = static_cast<const AnyIndexExpr*>(rhs);
        return AnyIndexVVi(lhs, r1->AsNameExpr(), rhs_as_any->Index());
    }

    if ( rhs->Tag() == EXPR_LAMBDA )
        return BuildLambda(lhs, op2);

    if ( rhs->Tag() == EXPR_COND && r1->GetType()->Tag() == TYPE_VECTOR )
        return Bool_Vec_CondVVVV(lhs, r1->AsNameExpr(), r2->AsNameExpr(), r3->AsNameExpr());

    if ( rhs->Tag() == EXPR_COND && r2->IsConst() && r3->IsConst() ) {
        // Split into two statement, given we don't support
        // two constants in a single statement.
        auto n1 = r1->AsNameExpr();
        auto c2 = r2->AsConstExpr();
        auto c3 = r3->AsConstExpr();
        (void)CondC1VVC(lhs, n1, c2);
        return CondC2VVC(lhs, n1, c3);
    }

    if ( r1 && r2 && ! r3 ) {
        auto v1 = IsVector(r1->GetType()->Tag());
        auto v2 = IsVector(r2->GetType()->Tag());

        if ( v1 != v2 && rhs->Tag() != EXPR_IN ) {
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

const ZAMStmt ZAMCompiler::CompileRecFieldUpdates(const RecordFieldUpdatesExpr* e) {
    auto rhs = e->GetOp2()->AsNameExpr();

    auto& rhs_map = e->RHSMap();

    auto aux = new ZInstAux(0);
    aux->map = e->LHSMap();
    aux->rhs_map = rhs_map;

    // Used to track the different types present, so we can see whether
    // we can use a homogeneous operator or need a mixed one. Won't be
    // needed if we're doing assignments, but handy if we're doing adds.
    std::set<TypeTag> field_tags;

    size_t num_managed = 0;

    for ( auto i : rhs_map ) {
        auto rt = rhs->GetType()->AsRecordType();
        auto rt_ft_i = rt->GetFieldType(i);
        field_tags.insert(rt_ft_i->Tag());

        if ( ZVal::IsManagedType(rt_ft_i) ) {
            aux->is_managed.push_back(true);
            ++num_managed;
        }
        else
            // This will only be needed if is_managed winds up being true,
            // but it's harmless to build it up in any case.
            aux->is_managed.push_back(false);

        // The following is only needed for non-homogeneous "add"s, but
        // likewise it's harmless to build it anyway.
        aux->types.push_back(rt_ft_i);
    }

    bool homogeneous = field_tags.size() == 1;
    // Here we leverage the fact that C++ "+=" works identically for
    // signed and unsigned int's.
    if ( ! homogeneous && field_tags.size() == 2 && field_tags.count(TYPE_INT) > 0 && field_tags.count(TYPE_COUNT) > 0 )
        homogeneous = true;

    ZOp op;

    if ( e->Tag() == EXPR_REC_ASSIGN_FIELDS ) {
        if ( num_managed == rhs_map.size() )
            // This operand allows for a simpler implementation.
            op = OP_REC_ASSIGN_FIELDS_ALL_MANAGED_VV;
        else if ( num_managed > 0 )
            op = OP_REC_ASSIGN_FIELDS_MANAGED_VV;
        else
            op = OP_REC_ASSIGN_FIELDS_VV;
    }

    else if ( homogeneous ) {
        if ( field_tags.count(TYPE_DOUBLE) > 0 )
            op = OP_REC_ADD_DOUBLE_FIELDS_VV;
        else
            // Here we leverage that += will work for both signed/unsigned.
            op = OP_REC_ADD_INT_FIELDS_VV;
    }

    else
        op = OP_REC_ADD_FIELDS_VV;

    auto lhs = e->GetOp1()->AsNameExpr();
    auto z = GenInst(op, lhs, rhs);
    z.aux = aux;

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::CompileZAMBuiltin(const NameExpr* lhs, const ScriptOptBuiltinExpr* zbi) {
    auto op1 = zbi->GetOp1();
    auto op2 = zbi->GetOp2();

    switch ( zbi->Tag() ) {
        case ScriptOptBuiltinExpr::MINIMUM:
        case ScriptOptBuiltinExpr::MAXIMUM: {
            auto t1 = op1->GetType()->InternalType();
            ASSERT(t1 == op2->GetType()->InternalType());

            bool is_min = zbi->Tag() == ScriptOptBuiltinExpr::MINIMUM;
            // Canonicalize to have constant as second op.
            if ( op1->Tag() == EXPR_CONST ) {
                ASSERT(op2->Tag() != EXPR_CONST);
                std::swap(op1, op2);
            }

            ZOp op;

            auto n1 = op1->AsNameExpr();
            auto n2 = op2->Tag() == EXPR_NAME ? op2->AsNameExpr() : nullptr;
            auto c = op2->Tag() == EXPR_CONST ? op2->AsConstExpr() : nullptr;

            if ( c ) {
                if ( t1 == TYPE_INTERNAL_UNSIGNED )
                    op = is_min ? OP_MINU_VVC : OP_MAXU_VVC;
                else if ( t1 == TYPE_INTERNAL_INT )
                    op = is_min ? OP_MINI_VVC : OP_MAXI_VVC;
                else {
                    ASSERT(t1 == TYPE_INTERNAL_DOUBLE);
                    op = is_min ? OP_MIND_VVC : OP_MAXD_VVC;
                }
            }
            else {
                if ( t1 == TYPE_INTERNAL_UNSIGNED )
                    op = is_min ? OP_MINU_VVV : OP_MAXU_VVV;
                else if ( t1 == TYPE_INTERNAL_INT )
                    op = is_min ? OP_MINI_VVV : OP_MAXI_VVV;
                else {
                    ASSERT(t1 == TYPE_INTERNAL_DOUBLE);
                    op = is_min ? OP_MIND_VVV : OP_MAXD_VVV;
                }
            }

            if ( c )
                return AddInst(GenInst(op, lhs, n1, c));
            else
                return AddInst(GenInst(op, lhs, n1, n2));
        }

        case ScriptOptBuiltinExpr::HAS_ELEMENTS: {
            auto n = op1->AsNameExpr();
            auto op = op1->GetType()->Tag() == TYPE_TABLE ? OP_TABLE_HAS_ELEMENTS_VV : OP_VECTOR_HAS_ELEMENTS_VV;
            return AddInst(GenInst(op, lhs, n));
        }

        case ScriptOptBuiltinExpr::FUNC_ID_STRING: {
            auto n = op1->AsNameExpr();
            return AddInst(GenInst(OP_FUNC_ID_STRING_VV, lhs, n));
        }

        default: reporter->InternalError("bad built-in tag in ZAMCompiler::CompileZAMBuiltin");
    }
}

const ZAMStmt ZAMCompiler::CompileAssignToIndex(const NameExpr* lhs, const IndexExpr* rhs) {
    auto aggr = rhs->GetOp1();
    auto const_aggr = aggr->Tag() == EXPR_CONST;

    auto indexes_expr = rhs->GetOp2()->AsListExpr();
    auto indexes = indexes_expr->Exprs();

    auto n = const_aggr ? nullptr : aggr->AsNameExpr();
    auto con = const_aggr ? aggr->AsConstExpr() : nullptr;

    if ( indexes.length() == 1 && indexes[0]->GetType()->Tag() == TYPE_VECTOR &&
         aggr->GetType()->Tag() != TYPE_TABLE ) {
        auto index1 = indexes[0];
        if ( index1->Tag() == EXPR_CONST ) {
            reporter->Error("constant vector indexes not supported for ZAM compiling");
            return ErrorStmt();
        }

        auto index = index1->AsNameExpr();
        auto ind_t = index->GetType()->AsVectorType();

        if ( IsBool(ind_t->Yield()->Tag()) )
            return const_aggr ? IndexVecBoolSelectVCV(lhs, con, index) : IndexVecBoolSelectVVV(lhs, n, index);

        return const_aggr ? IndexVecIntSelectVCV(lhs, con, index) : IndexVecIntSelectVVV(lhs, n, index);
    }

    if ( rhs->IsInsideWhen() ) {
        if ( const_aggr )
            return WhenIndexVCL(lhs, con, indexes_expr);
        else
            return WhenIndexVVL(lhs, n, indexes_expr);
    }

    if ( const_aggr )
        return IndexVCL(lhs, con, indexes_expr);
    else
        return IndexVVL(lhs, n, indexes_expr);
}

const ZAMStmt ZAMCompiler::CompileFieldLHSAssignExpr(const FieldLHSAssignExpr* e) {
    auto lhs = e->Op1()->AsNameExpr();
    auto rhs = e->Op2();
    auto field = e->Field();

    if ( rhs->Tag() == EXPR_NAME )
        return Field_LHS_AssignFVi(e, rhs->AsNameExpr(), field);

    if ( rhs->Tag() == EXPR_CONST )
        return Field_LHS_AssignFCi(e, rhs->AsConstExpr(), field);

    auto r1 = rhs->GetOp1();
    auto r2 = rhs->GetOp2();

    if ( rhs->Tag() == EXPR_FIELD ) {
        auto rhs_f = rhs->AsFieldExpr();

        // Note, the LHS field comes after the RHS field rather than before,
        // to maintain layout symmetry close to that for non-field RHS's.
        if ( r1->Tag() == EXPR_NAME )
            return Field_LHS_AssignFVii(e, r1->AsNameExpr(), rhs_f->Field(), field);

        return Field_LHS_AssignFCii(e, r1->AsConstExpr(), rhs_f->Field(), field);
    }

    if ( r1 && r1->IsConst() )
#include "ZAM-GenFieldsDefsC1.h"

        else if ( r2 && r2->IsConst() )
#include "ZAM-GenFieldsDefsC2.h"

            else
#include "ZAM-GenFieldsDefsV.h"
}

const ZAMStmt ZAMCompiler::CompileScheduleExpr(const ScheduleExpr* e) {
    auto event = e->Event();
    auto when = e->When();

    auto event_args = event->Args();
    auto handler = event->Handler();

    bool is_interval = when->GetType()->Tag() == TYPE_INTERVAL;

    if ( when->Tag() == EXPR_NAME )
        return ScheduleViHL(when->AsNameExpr(), is_interval, handler.Ptr(), event_args);
    else
        return ScheduleCiHL(when->AsConstExpr(), is_interval, handler.Ptr(), event_args);
}

const ZAMStmt ZAMCompiler::CompileSchedule(const NameExpr* n, const ConstExpr* c, int is_interval, EventHandler* h,
                                           const ListExpr* l) {
    int len = l->Exprs().length();
    ZInstI z;

    if ( len == 0 ) {
        z = n ? ZInstI(OP_SCHEDULE0_ViH, FrameSlot(n), is_interval) : ZInstI(OP_SCHEDULE0_CiH, is_interval, c);
        z.op_type = n ? OP_VV_I2 : OP_VC_I1;
        z.aux = new ZInstAux(0);
    }

    else {
        if ( n ) {
            z = ZInstI(OP_SCHEDULE_ViHL, FrameSlot(n), is_interval);
            z.op_type = OP_VV_I2;
        }
        else {
            z = ZInstI(OP_SCHEDULE_CiHL, is_interval, c);
            z.op_type = OP_VC_I1;
        }

        z.aux = InternalBuildVals(l);
    }

    z.aux->event_handler = h;

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::CompileEvent(EventHandler* h, const ListExpr* l) {
    auto exprs = l->Exprs();
    unsigned int n = exprs.length();

    bool all_vars = true;
    for ( auto i = 0U; i < n; ++i )
        if ( exprs[i]->Tag() == EXPR_CONST ) {
            all_vars = false;
            break;
        }

    if ( n > 4 || ! all_vars ) { // do generic form
        ZInstI z(OP_EVENT_HL);
        z.aux = InternalBuildVals(l);
        z.aux->event_handler = h;
        return AddInst(z);
    }

    ZInstI z;

    if ( n == 0 ) {
        z.op = OP_EVENT0_X;
        z.op_type = OP_X;
    }

    else {
        auto n0 = exprs[0]->AsNameExpr();
        z.v1 = FrameSlot(n0);
        z.SetType(n0->GetType());

        if ( n == 1 ) {
            z.op = OP_EVENT1_V;
            z.op_type = OP_V;
        }

        else {
            auto n1 = exprs[1]->AsNameExpr();
            z.v2 = FrameSlot(n1);
            z.SetType2(n1->GetType());

            if ( n == 2 ) {
                z.op = OP_EVENT2_VV;
                z.op_type = OP_VV;
            }

            else {
                z.aux = InternalBuildVals(l);

                auto n2 = exprs[2]->AsNameExpr();
                z.v3 = FrameSlot(n2);

                if ( n == 3 ) {
                    z.op = OP_EVENT3_VVV;
                    z.op_type = OP_VVV;
                }

                else {
                    z.op = OP_EVENT4_VVVV;
                    z.op_type = OP_VVVV;

                    auto n3 = exprs[3]->AsNameExpr();
                    z.v4 = FrameSlot(n3);
                }
            }
        }
    }

    if ( ! z.aux )
        z.aux = new ZInstAux(0);

    z.aux->event_handler = h;

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::CompileInExpr(const NameExpr* n1, const NameExpr* n2, const ConstExpr* c2,
                                         const NameExpr* n3, const ConstExpr* c3) {
    const Expr* op2 = n2;
    const Expr* op3 = n3;

    if ( ! op2 )
        op2 = c2;
    if ( ! op3 )
        op3 = c3;

    ZOp a;

    auto& op2_t = op2->GetType();
    auto& op3_t = op3->GetType();

    if ( op3_t->Tag() == TYPE_TABLE ) {
        if ( op3_t->AsTableType()->IsPatternIndex() && op2_t->Tag() == TYPE_STRING )
            a = n2 ? OP_STR_IN_PAT_TBL_VVV : OP_STR_IN_PAT_TBL_VCV;
        else
            a = n2 ? OP_VAL_IS_IN_TABLE_VVV : OP_CONST_IS_IN_TABLE_VVC;
    }
    else if ( op2->GetType()->Tag() == TYPE_PATTERN )
        a = n2 ? (n3 ? OP_P_IN_S_VVV : OP_P_IN_S_VVC) : OP_P_IN_S_VCV;

    else if ( op2->GetType()->Tag() == TYPE_STRING )
        a = n2 ? (n3 ? OP_S_IN_S_VVV : OP_S_IN_S_VVC) : OP_S_IN_S_VCV;

    else if ( op2->GetType()->Tag() == TYPE_ADDR && op3->GetType()->Tag() == TYPE_SUBNET )
        a = n2 ? (n3 ? OP_A_IN_S_VVV : OP_A_IN_S_VVC) : OP_A_IN_S_VCV;

    else
        reporter->InternalError("bad types when compiling \"in\"");

    auto s2 = n2 ? FrameSlot(n2) : 0;
    auto s3 = n3 ? FrameSlot(n3) : 0;
    auto s1 = Frame1Slot(n1, a);

    ZInstI z;

    if ( n2 ) {
        if ( n3 )
            z = ZInstI(a, s1, s2, s3);
        else
            z = ZInstI(a, s1, s2, c3);
    }
    else
        z = ZInstI(a, s1, s3, c2);

    TypePtr zt;

    if ( c2 )
        zt = c2->GetType();
    else if ( c3 )
        zt = c3->GetType();
    else
        zt = n2->GetType();

    z.SetType(zt);

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::CompileInExpr(const NameExpr* n1, const ListExpr* l, const NameExpr* n2,
                                         const ConstExpr* c) {
    auto& l_e = l->Exprs();
    int n = l_e.length();

    // Look for a very common special case: l is a single-element list,
    // and n2 is present rather than c.
    if ( n == 1 && n2 ) {
        ZInstI z;
        bool is_vec = n2->GetType()->Tag() == TYPE_VECTOR;

        if ( l_e[0]->Tag() == EXPR_NAME ) {
            auto l_e0_n = l_e[0]->AsNameExpr();
            ZOp op = is_vec ? OP_VAL_IS_IN_VECTOR_VVV : OP_VAL_IS_IN_TABLE_VVV;
            z = GenInst(op, n1, l_e0_n, n2);
        }

        else {
            auto l_e0_c = l_e[0]->AsConstExpr();
            ZOp op = is_vec ? OP_CONST_IS_IN_VECTOR_VCV : OP_CONST_IS_IN_TABLE_VVC;
            z = GenInst(op, n1, l_e0_c, n2);
        }

        z.SetType(l_e[0]->GetType());
        return AddInst(z);
    }

    // Also somewhat common is a 2-element index.  Here, one or both of
    // the elements might be a constant, which makes things messier.

    if ( n == 2 && n2 && (l_e[0]->Tag() == EXPR_NAME || l_e[1]->Tag() == EXPR_NAME) ) {
        auto is_name0 = l_e[0]->Tag() == EXPR_NAME;
        auto is_name1 = l_e[1]->Tag() == EXPR_NAME;

        auto l_e0_n = is_name0 ? l_e[0]->AsNameExpr() : nullptr;
        auto l_e1_n = is_name1 ? l_e[1]->AsNameExpr() : nullptr;

        auto l_e0_c = is_name0 ? nullptr : l_e[0]->AsConstExpr();
        auto l_e1_c = is_name1 ? nullptr : l_e[1]->AsConstExpr();

        ZInstI z;

        if ( l_e0_n && l_e1_n ) {
            z = GenInst(OP_VAL2_IS_IN_TABLE_VVVV, n1, l_e0_n, l_e1_n, n2);
            z.SetType2(l_e0_n->GetType());
        }

        else if ( l_e0_n ) {
            ASSERT(l_e1_c);

            z = GenInst(OP_VAL2_IS_IN_TABLE_VVVC, n1, l_e0_n, n2, l_e1_c);
            z.SetType2(l_e0_n->GetType());
        }

        else if ( l_e1_n ) {
            ASSERT(l_e0_c);

            z = GenInst(OP_VAL2_IS_IN_TABLE_VVCV, n1, l_e1_n, n2, l_e0_c);
            z.SetType2(l_e1_n->GetType());
        }

        else {
            // Ugh, both are constants.  Assign first to
            // a temporary.
            ASSERT(l_e0_c);
            ASSERT(l_e1_c);

            auto slot = TempForConst(l_e0_c);
            z = ZInstI(OP_VAL2_IS_IN_TABLE_VVVC, FrameSlot(n1), slot, FrameSlot(n2), l_e1_c);
            z.op_type = OP_VVVC;
            z.SetType2(l_e0_c->GetType());
        }

        return AddInst(z);
    }

    auto aggr = n2 ? (Expr*)n2 : (Expr*)c;

    ASSERT(aggr->GetType()->Tag() != TYPE_VECTOR);

    ZOp op = n2 ? OP_LIST_IS_IN_TABLE_VV : OP_LIST_IS_IN_TABLE_VC;

    ZInstI z;

    if ( n2 )
        z = ZInstI(op, Frame1Slot(n1, op), FrameSlot(n2));
    else
        z = ZInstI(op, Frame1Slot(n1, op), c);

    z.aux = InternalBuildVals(l);

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::CompileIndex(const NameExpr* n1, const NameExpr* n2, const ListExpr* l, bool in_when) {
    return CompileIndex(n1, FrameSlot(n2), n2->GetType(), l, in_when);
}

const ZAMStmt ZAMCompiler::CompileIndex(const NameExpr* n, const ConstExpr* c, const ListExpr* l, bool in_when) {
    auto tmp = TempForConst(c);
    return CompileIndex(n, tmp, c->GetType(), l, in_when);
}

const ZAMStmt ZAMCompiler::CompileIndex(const NameExpr* n1, int n2_slot, const TypePtr& n2t, const ListExpr* l,
                                        bool in_when) {
    ZInstI z;

    int n = l->Exprs().length();
    auto n2tag = n2t->Tag();

    // Whether this is an instance of indexing a table[pattern] of X
    // with a string.
    bool is_pat_str_ind = false;

    if ( n2tag == TYPE_TABLE && n == 1 ) {
        auto& ind_types = n2t->AsTableType()->GetIndices();
        auto& ind_type0 = ind_types->GetTypes()[0];
        auto ind = l->Exprs()[0];

        if ( ind_type0->Tag() == TYPE_PATTERN && ind->GetType()->Tag() == TYPE_STRING )
            is_pat_str_ind = true;
    }

    if ( n == 1 && ! in_when ) {
        auto ind = l->Exprs()[0];
        auto var_ind = ind->Tag() == EXPR_NAME;
        auto n3 = var_ind ? ind->AsNameExpr() : nullptr;
        auto c3 = var_ind ? nullptr : ind->AsConstExpr();
        zeek_uint_t c = 0;

        if ( ! var_ind ) {
            if ( ind->GetType()->Tag() == TYPE_COUNT )
                c = c3->Value()->AsCount();
            else if ( ind->GetType()->Tag() == TYPE_INT )
                c = c3->Value()->AsInt();
        }

        if ( n2tag == TYPE_STRING ) {
            if ( n3 ) {
                int n3_slot = FrameSlot(n3);
                auto zop = OP_INDEX_STRING_VVV;
                z = ZInstI(zop, Frame1Slot(n1, zop), n2_slot, n3_slot);
            }
            else {
                auto zop = OP_INDEX_STRINGC_VVi;
                z = ZInstI(zop, Frame1Slot(n1, zop), n2_slot, c);
                z.op_type = OP_VVV_I3;
            }

            return AddInst(z);
        }

        if ( n2tag == TYPE_VECTOR ) {
            auto n2_yt = n2t->AsVectorType()->Yield();
            bool is_any = n2_yt->Tag() == TYPE_ANY;

            if ( n3 ) {
                int n3_slot = FrameSlot(n3);

                ZOp zop;
                if ( in_when )
                    zop = OP_WHEN_INDEX_VEC_VVV;
                else if ( is_any )
                    zop = OP_INDEX_ANY_VEC_VVV;
                else
                    zop = OP_INDEX_VEC_VVV;

                z = ZInstI(zop, Frame1Slot(n1, zop), n2_slot, n3_slot);
            }
            else {
                ZOp zop;

                if ( in_when )
                    zop = OP_WHEN_INDEX_VECC_VVi;
                else if ( is_any )
                    zop = OP_INDEX_ANY_VECC_VVi;
                else
                    zop = OP_INDEX_VECC_VVi;

                z = ZInstI(zop, Frame1Slot(n1, zop), n2_slot, c);
                z.op_type = OP_VVV_I3;
            }

            z.SetType(n1->GetType());
            return AddInst(z);
        }

        if ( n2tag == TYPE_TABLE ) {
            if ( is_pat_str_ind ) {
                auto n1_slot = Frame1Slot(n1, OP1_WRITE);
                if ( n3 ) {
                    int n3_slot = FrameSlot(n3);
                    z = ZInstI(OP_TABLE_PATSTR_INDEX_VVV, n1_slot, n2_slot, n3_slot);
                }
                else
                    z = ZInstI(OP_TABLE_PATSTR_INDEX_VVC, n1_slot, n2_slot, c3);
            }
            else if ( n3 ) {
                int n3_slot = FrameSlot(n3);
                auto zop = AssignmentFlavor(OP_TABLE_INDEX1_VVV, n1->GetType()->Tag());
                z = ZInstI(zop, Frame1Slot(n1, zop), n2_slot, n3_slot);
                z.SetType(n3->GetType());
            }

            else {
                ASSERT(c3);
                auto zop = AssignmentFlavor(OP_TABLE_INDEX1_VVC, n1->GetType()->Tag());
                z = ZInstI(zop, Frame1Slot(n1, zop), n2_slot, c3);
            }

            if ( pfs->HasSideEffects(SideEffectsOp::READ, n2t) ) {
                z.aux = new ZInstAux(0);
                z.aux->can_change_non_locals = true;
            }

            return AddInst(z);
        }
    }

    auto indexes = l->Exprs();

    ZOp op;

    switch ( n2tag ) {
        case TYPE_VECTOR:
            op = in_when ? OP_WHEN_INDEX_VEC_SLICE_VV : OP_INDEX_VEC_SLICE_VV;
            z = ZInstI(op, Frame1Slot(n1, op), n2_slot);
            z.SetType(n2t);
            break;

        case TYPE_TABLE:
            if ( in_when ) {
                if ( is_pat_str_ind )
                    op = OP_WHEN_PATSTR_INDEX_VV;
                else
                    op = OP_WHEN_TABLE_INDEX_VV;
            }
            else
                op = OP_TABLE_INDEX_VV;

            z = ZInstI(op, Frame1Slot(n1, op), n2_slot);
            z.SetType(n1->GetType());
            break;

        case TYPE_STRING:
            op = OP_INDEX_STRING_SLICE_VV;
            z = ZInstI(op, Frame1Slot(n1, op), n2_slot);
            z.SetType(n1->GetType());
            break;

        default: reporter->InternalError("bad aggregate type when compiling index");
    }

    z.aux = InternalBuildVals(l);
    z.CheckIfManaged(n1->GetType());

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::BuildLambda(const NameExpr* n, ExprPtr e) {
    return BuildLambda(Frame1Slot(n, OP1_WRITE), std::move(e));
}

const ZAMStmt ZAMCompiler::BuildLambda(int n_slot, ExprPtr e) {
    auto lambda = cast_intrusive<LambdaExpr>(e);
    auto& captures = lambda->GetCaptures();
    int ncaptures = captures ? captures->size() : 0;

    auto aux = new ZInstAux(ncaptures);
    aux->lambda = cast_intrusive<LambdaExpr>(std::move(e));
    aux->id_val = lambda->Ingredients()->GetID();

    for ( int i = 0; i < ncaptures; ++i ) {
        auto& id_i = (*captures)[i].Id();

        if ( pf->WhenLocals().count(id_i.get()) > 0 )
            aux->Add(i, nullptr);
        else
            aux->Add(i, FrameSlot(id_i), id_i->GetType());
    }

    auto z = ZInstI(OP_LAMBDA_Vi, n_slot, lambda->PrimaryFunc()->FrameSize());
    z.op_type = OP_VV_I2;
    z.aux = aux;

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::AssignVecElems(const Expr* e) {
    ASSERT(e->Tag() == EXPR_INDEX_ASSIGN);
    auto index_assign = static_cast<const IndexAssignExpr*>(e);

    auto op1 = index_assign->GetOp1();
    const auto& t1 = op1->GetType();

    auto op3 = index_assign->GetOp3();
    const auto& t3 = op3->GetType();

    auto lhs = op1->AsNameExpr();
    auto lt = lhs->GetType();

    auto indexes_expr = index_assign->GetOp2()->AsListExpr();
    auto indexes = indexes_expr->Exprs();

    if ( indexes.length() > 1 ) { // Vector slice assignment.
        ASSERT(op1->Tag() == EXPR_NAME);
        ASSERT(op3->Tag() == EXPR_NAME);
        ASSERT(t1->Tag() == TYPE_VECTOR);
        ASSERT(t3->Tag() == TYPE_VECTOR);

        auto z = GenInst(OP_VECTOR_SLICE_ASSIGN_VV, lhs, op3->AsNameExpr());

        z.aux = InternalBuildVals(indexes_expr);

        return AddInst(z);
    }

    const auto& yt1 = t1->Yield();
    auto any_vec = yt1->Tag() == TYPE_VOID || yt1->Tag() == TYPE_ANY;
    auto any_val = IsAny(t3);

    auto op2 = indexes[0];

    if ( op2->Tag() == EXPR_CONST && op3->Tag() == EXPR_CONST ) {
        // Turn into a VVC assignment by assigning the index to
        // a temporary.
        auto c = op2->AsConstExpr();
        auto tmp = TempForConst(c);

        auto zop = any_vec ? OP_ANY_VECTOR_ELEM_ASSIGN_VVC : OP_VECTOR_ELEM_ASSIGN_VVC;

        return AddInst(ZInstI(zop, Frame1Slot(lhs, zop), tmp, op3->AsConstExpr()));
    }

    if ( op2->Tag() == EXPR_NAME ) {
        auto n2 = op2->AsNameExpr();
        ZAMStmt inst(0);

        if ( op3->Tag() == EXPR_NAME ) {
            auto n3 = op3->AsNameExpr();

            if ( any_vec )
                inst = Any_Vector_Elem_AssignVVV(lhs, n2, n3);
            else if ( any_val )
                inst = Vector_Elem_Assign_AnyVVV(lhs, n2, n3);
            else
                inst = Vector_Elem_AssignVVV(lhs, n2, n3);
        }

        else {
            auto c3 = op3->AsConstExpr();

            if ( any_vec )
                inst = Any_Vector_Elem_AssignVVC(lhs, n2, c3);
            else
                inst = Vector_Elem_AssignVVC(lhs, n2, c3);
        }

        TopMainInst()->SetType(t3);
        return inst;
    }

    auto c2 = op2->AsConstExpr();
    auto n3 = op3->AsNameExpr();
    auto index = c2->Value()->AsCount();

    ZAMStmt inst;

    if ( any_vec )
        inst = Any_Vector_Elem_AssignVVi(lhs, n3, index);
    else if ( any_val )
        inst = Vector_Elem_Assign_AnyVVi(lhs, n3, index);
    else
        inst = Vector_Elem_AssignVVi(lhs, n3, index);

    TopMainInst()->SetType(t3);
    return inst;
}

const ZAMStmt ZAMCompiler::AssignTableElem(const Expr* e) {
    ASSERT(e->Tag() == EXPR_INDEX_ASSIGN);
    auto index_assign = static_cast<const IndexAssignExpr*>(e);

    auto op1 = index_assign->GetOp1()->AsNameExpr();
    auto op2 = index_assign->GetOp2()->AsListExpr();
    auto op3 = index_assign->GetOp3();

    ZInstI z;

    if ( op3->Tag() == EXPR_NAME )
        z = GenInst(OP_TABLE_ELEM_ASSIGN_VV, op1, op3->AsNameExpr());
    else
        z = GenInst(OP_TABLE_ELEM_ASSIGN_VC, op1, op3->AsConstExpr());

    z.aux = InternalBuildVals(op2);
    z.SetType(op3->GetType());

    if ( pfs->HasSideEffects(SideEffectsOp::WRITE, op1->GetType()) )
        z.aux->can_change_non_locals = true;

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::Call(const ExprStmt* e) {
    auto c = cast_intrusive<CallExpr>(e->StmtExprPtr());

    if ( CheckForBuiltIn(c, c) )
        return LastInst();

    return DoCall(e->StmtExpr()->AsCallExpr(), nullptr);
}

const ZAMStmt ZAMCompiler::AssignToCall(const ExprStmt* e) {
    auto assign = e->StmtExpr()->AsAssignExpr();
    auto call = cast_intrusive<CallExpr>(assign->GetOp2());

    if ( CheckForBuiltIn(e->StmtExprPtr(), call) )
        return LastInst();

    auto n = assign->GetOp1()->AsRefExpr()->GetOp1()->AsNameExpr();

    return DoCall(call.get(), n);
}

bool ZAMCompiler::CheckForBuiltIn(const ExprPtr& e, CallExprPtr c) {
    if ( ! IsZAM_BuiltIn(this, e.get()) )
        return false;

    auto ret = LastInst();
    auto& i = insts1.back();
    if ( ! i->aux )
        i->aux = new ZInstAux(0);
    i->aux->call_expr = c;

    return true;
}

const ZAMStmt ZAMCompiler::DoCall(const CallExpr* c, const NameExpr* n) {
    auto func = c->Func()->AsNameExpr();
    auto func_id = func->IdPtr();
    auto func_val = func_id->GetVal();
    auto& args = c->Args()->Exprs();

    int nargs = args.length();
    int call_case = nargs;

    bool indirect = ! func_id->IsGlobal() || ! func_val;
    bool in_when = c->IsInWhen();

    if ( indirect || in_when )
        call_case = -1; // force default of some flavor of CallN

    auto nt = n ? n->GetType()->Tag() : TYPE_VOID;
    auto n_slot = n ? Frame1Slot(n, OP1_WRITE) : -1;

    ZInstI z;

    if ( call_case == 0 ) {
        if ( n ) {
            z = ZInstI(AssignmentFlavor(OP_CALL0_V, nt), n_slot);
            z.SetType(n->GetType());
        }
        else
            z = ZInstI(OP_CALL0_X);
    }

    else if ( call_case == 1 ) {
        auto arg0 = args[0];
        auto n0 = arg0->Tag() == EXPR_NAME ? arg0->AsNameExpr() : nullptr;
        auto c0 = arg0->Tag() == EXPR_CONST ? arg0->AsConstExpr() : nullptr;

        if ( n ) {
            if ( n0 )
                z = ZInstI(AssignmentFlavor(OP_CALL1_VV, nt), n_slot, FrameSlot(n0));
            else {
                ASSERT(c0);
                z = ZInstI(AssignmentFlavor(OP_CALL1_VC, nt), n_slot, c0);
            }
        }
        else {
            if ( n0 )
                z = ZInstI(OP_CALL1_V, FrameSlot(n0));
            else {
                ASSERT(c0);
                z = ZInstI(OP_CALL1_C, c0);
            }
        }

        z.SetType(arg0->GetType());
    }

    else {
        auto aux = new ZInstAux(nargs);

        for ( int i = 0; i < nargs; ++i ) {
            auto ai = args[i];
            auto ai_t = ai->GetType();
            if ( ai->Tag() == EXPR_NAME )
                aux->Add(i, FrameSlot(ai->AsNameExpr()), ai_t);
            else
                aux->Add(i, ai->AsConstExpr()->ValuePtr());
        }

        ZOp op;

        switch ( call_case ) {
            case 2: op = n ? OP_CALL2_V : OP_CALL2_X; break;
            case 3: op = n ? OP_CALL3_V : OP_CALL3_X; break;
            case 4: op = n ? OP_CALL4_V : OP_CALL4_X; break;
            case 5: op = n ? OP_CALL5_V : OP_CALL5_X; break;

            default:
                if ( in_when ) {
                    if ( ! indirect )
                        op = OP_WHENCALLN_V;
                    else if ( func_id->IsGlobal() )
                        op = OP_WHEN_ID_INDCALLN_V;
                    else
                        op = OP_WHENINDCALLN_VV;
                }

                else if ( indirect ) {
                    if ( func_id->IsGlobal() )
                        op = n ? OP_INDCALLN_V : OP_INDCALLN_X;
                    else
                        op = n ? OP_LOCAL_INDCALLN_VV : OP_LOCAL_INDCALLN_V;
                }

                else
                    op = n ? OP_CALLN_V : OP_CALLN_X;
                break;
        }

        if ( n ) {
            if ( ! in_when )
                op = AssignmentFlavor(op, nt);

            auto n_slot = Frame1Slot(n, OP1_WRITE);

            if ( indirect ) {
                if ( func_id->IsGlobal() ) {
                    z = ZInstI(op, n_slot);
                    z.op_type = OP_V;
                }
                else {
                    z = ZInstI(op, n_slot, FrameSlot(func));
                    z.op_type = OP_VV;
                }
            }

            else {
                z = ZInstI(op, n_slot);
                z.op_type = OP_V;
            }

            z.SetType(n->GetType());
        }
        else {
            if ( indirect && ! func_id->IsGlobal() ) {
                z = ZInstI(op, FrameSlot(func));
                z.op_type = OP_V;
            }
            else {
                z = ZInstI(op);
                z.op_type = OP_X;
            }
        }

        z.aux = aux;
    }

    if ( ! z.aux )
        z.aux = new ZInstAux(0);

    if ( indirect )
        z.aux->can_change_non_locals = true;

    else {
        IDSet non_local_ids;
        TypeSet aggrs;
        bool is_unknown = false;

        auto resolved = pfs->GetCallSideEffects(func, non_local_ids, aggrs, is_unknown);
        ASSERT(resolved);

        if ( is_unknown || ! non_local_ids.empty() || ! aggrs.empty() )
            z.aux->can_change_non_locals = true;
    }

    z.aux->call_expr = {NewRef{}, const_cast<CallExpr*>(c)};

    if ( ! indirect || func_id->IsGlobal() ) {
        z.aux->id_val = func_id;

        if ( ! indirect ) {
            z.aux->func = func_id->GetVal()->AsFunc();
            if ( z.aux->func->GetKind() == Func::BUILTIN_FUNC )
                z.aux->is_BiF_call = true;
        }
    }

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::ConstructTable(const NameExpr* n, const Expr* e) {
    auto con = e->GetOp1()->AsListExpr();
    auto tt = cast_intrusive<TableType>(n->GetType());
    auto width = tt->GetIndices()->GetTypes().size();

    auto z = GenInst(OP_CONSTRUCT_TABLE_Vi, n, width);
    z.aux = InternalBuildVals(con, width + 1);
    z.SetType(tt);
    ASSERT(e->Tag() == EXPR_TABLE_CONSTRUCTOR);
    z.aux->attrs = static_cast<const TableConstructorExpr*>(e)->GetAttrs();

    auto zstmt = AddInst(z);

    auto def_attr = z.aux->attrs ? z.aux->attrs->Find(ATTR_DEFAULT) : nullptr;
    if ( ! def_attr || def_attr->GetExpr()->Tag() != EXPR_LAMBDA )
        return zstmt;

    auto def_lambda = cast_intrusive<LambdaExpr>(def_attr->GetExpr());
    auto dl_t = def_lambda->GetType()->AsFuncType();
    auto& captures = dl_t->GetCaptures();

    if ( ! captures )
        return zstmt;

    // What a pain.  The table's default value is a lambda that has
    // captures.  The semantics of this are that the captures are
    // evaluated at table-construction time.  We need to build the
    // lambda and assign it as the table's default.

    auto slot = NewSlot(true); // since func_val's are managed
    (void)BuildLambda(slot, def_lambda);

    z = GenInst(OP_SET_TABLE_DEFAULT_LAMBDA_VV, n, slot);
    z.op_type = OP_VV;
    z.SetType(def_lambda->GetType());

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::ConstructSet(const NameExpr* n, const Expr* e) {
    auto con = e->GetOp1()->AsListExpr();
    auto tt = n->GetType()->AsTableType();
    auto width = tt->GetIndices()->GetTypes().size();

    auto z = GenInst(OP_CONSTRUCT_SET_Vi, n, width);
    z.aux = InternalBuildVals(con, width);
    z.SetType(e->GetType());
    ASSERT(e->Tag() == EXPR_SET_CONSTRUCTOR);
    z.aux->attrs = static_cast<const SetConstructorExpr*>(e)->GetAttrs();

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::ConstructRecord(const NameExpr* n, const Expr* e, bool is_from_rec) {
    auto rec_e = is_from_rec ? e->GetOp1().get() : e;
    ASSERT(rec_e->Tag() == EXPR_RECORD_CONSTRUCTOR);
    auto rc = static_cast<const RecordConstructorExpr*>(rec_e);
    auto rt = rec_e->GetType()->AsRecordType();

    auto aux = InternalBuildVals(rc->Op().get());

    // Note that we set the vector to the full size of the record being
    // constructed, *not* the size of any map (which could be smaller).
    // This is because we want to provide the vector directly to the
    // constructor.
    aux->zvec.resize(rt->NumFields());

    if ( pfs->HasSideEffects(SideEffectsOp::CONSTRUCTION, rec_e->GetType()) )
        aux->can_change_non_locals = true;

    ZOp op;

    const auto& map = rc->Map();
    int network_time_index = -1; // -1 = "no network_time() initializer"

    if ( map ) {
        aux->map = *map;

        auto fi = std::make_unique<std::vector<std::pair<int, std::shared_ptr<detail::FieldInit>>>>();

        // Populate the field inits as needed.
        for ( auto& c : rt->CreationInits() ) {
            bool seen = false;
            for ( auto r : *map )
                if ( c.first == r ) {
                    // Superseded by a constructor element;
                    seen = true;
                    break;
                }

            if ( ! seen ) {
                // Look for very fine-grained optimization: a record
                // initialization expression of network_time(). This winds
                // up occurring a lot, and it's expensive since it means
                // every such record creation entails a script-level
                // function call.
                auto ie = c.second->InitExpr();
                if ( ie && ie->Tag() == EXPR_CALL ) {
                    auto call = ie->AsCallExpr();
                    auto func = call->Func();
                    if ( func->Tag() == EXPR_NAME ) {
                        auto f = func->AsNameExpr()->Id();
                        if ( f->Name() == std::string("network_time") ) {
                            network_time_index = c.first;
                            seen = true;
                        }
                    }
                }
            }

            if ( ! seen )
                // Need to generate field dynamically.
                fi->push_back(c);
        }

        if ( fi->empty() ) {
            if ( network_time_index >= 0 )
                op = OP_CONSTRUCT_KNOWN_RECORD_WITH_NT_Vi;
            else
                op = OP_CONSTRUCT_KNOWN_RECORD_V;
        }
        else {
            if ( network_time_index >= 0 )
                op = OP_CONSTRUCT_KNOWN_RECORD_WITH_INITS_AND_NT_Vi;
            else
                op = OP_CONSTRUCT_KNOWN_RECORD_WITH_INITS_V;
            aux->field_inits = std::move(fi);
        }
    }
    else
        op = OP_CONSTRUCT_DIRECT_RECORD_V;

    ZInstI z;

    if ( is_from_rec ) {
        // Map non-from-rec operand to the from-rec equivalent.
        switch ( op ) {
            case OP_CONSTRUCT_KNOWN_RECORD_WITH_NT_Vi: op = OP_CONSTRUCT_KNOWN_RECORD_WITH_NT_FROM_VVi; break;

            case OP_CONSTRUCT_KNOWN_RECORD_V: op = OP_CONSTRUCT_KNOWN_RECORD_FROM_VV; break;

            case OP_CONSTRUCT_KNOWN_RECORD_WITH_INITS_AND_NT_Vi:
                op = OP_CONSTRUCT_KNOWN_RECORD_WITH_INITS_AND_NT_FROM_VVi;
                break;

            case OP_CONSTRUCT_KNOWN_RECORD_WITH_INITS_V:
                op = OP_CONSTRUCT_KNOWN_RECORD_WITH_INITS_FROM_VV;
                break;

                // Note, no case for OP_CONSTRUCT_DIRECT_RECORD_V - shouldn't
                // happen given how we construct ConstructFromRecordExpr's.
            default: reporter->InternalError("bad op in ZAMCompiler::ConstructRecord");
        }

        auto cfr = static_cast<const ConstructFromRecordExpr*>(e);
        auto from_n = cfr->GetOp2()->AsNameExpr();
        if ( network_time_index >= 0 )
            z = GenInst(op, n, from_n, network_time_index);
        else
            z = GenInst(op, n, from_n);

        aux->lhs_map = cfr->LHSMap();
        aux->rhs_map = cfr->RHSMap();

        for ( auto i : aux->lhs_map ) {
            auto& field_t = rt->GetFieldType(i);
            aux->is_managed.push_back(ZVal::IsManagedType(field_t));
        }
    }

    else
        z = network_time_index >= 0 ? GenInst(op, n, network_time_index) : GenInst(op, n);

    z.aux = aux;
    z.SetType(rec_e->GetType());

    auto inst = AddInst(z);

    // If one of the initialization values is an unspecified vector (which
    // in general we can't know until run-time) then we'll need to
    // "concretize" it. We first see whether this is a possibility, since
    // it usually isn't, by counting up how many of the initialized record
    // fields are vectors.

    // First just gather up the types of all the fields, and their location
    // in the target.
    std::vector<std::pair<TypePtr, int>> init_field_types;

    for ( int i = 0; i < z.aux->n; ++i ) {
        auto field_ind = map ? (*map)[i] : i;
        auto& field_t = rt->GetFieldType(field_ind);
        init_field_types.emplace_back(field_t, field_ind);
    }

    if ( is_from_rec )
        // Need to also check the source record.
        for ( auto i : aux->lhs_map ) {
            auto& field_t = rt->GetFieldType(i);
            init_field_types.emplace_back(field_t, i);
        }

    // Now spin through to find the vector fields.

    std::vector<int> vector_fields; // holds indices of the vector fields
    for ( auto& ft : init_field_types )
        if ( ft.first->Tag() == TYPE_VECTOR && ft.first->Yield()->Tag() != TYPE_ANY )
            vector_fields.push_back(ft.second);

    if ( vector_fields.empty() )
        // Common case of no vector fields, we're done.
        return inst;

    // Need to add a separate instruction for concretizing the fields.
    z = GenInst(OP_CONCRETIZE_VECTOR_FIELDS_V, n);
    z.SetType(rec_e->GetType());
    int nf = static_cast<int>(vector_fields.size());
    z.aux = new ZInstAux(nf);
    z.aux->elems_has_slots = false; // we're storing field offsets, not slots
    for ( int i = 0; i < nf; ++i )
        z.aux->Add(i, vector_fields[i]);

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::ConstructVector(const NameExpr* n, const Expr* e) {
    auto con = e->GetOp1()->AsListExpr();

    auto z = GenInst(OP_CONSTRUCT_VECTOR_V, n);
    z.aux = InternalBuildVals(con);
    z.SetType(e->GetType());

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::ArithCoerce(const NameExpr* n, const Expr* e) {
    auto nt = n->GetType();
    auto nt_is_vec = nt->Tag() == TYPE_VECTOR;

    auto op = e->GetOp1();
    auto op_t = op->GetType();
    auto op_is_vec = op_t->Tag() == TYPE_VECTOR;

    auto e_t = e->GetType();
    auto et_is_vec = e_t->Tag() == TYPE_VECTOR;

    if ( nt_is_vec || op_is_vec || et_is_vec ) {
        if ( ! (nt_is_vec && op_is_vec && et_is_vec) )
            reporter->InternalError("vector confusion compiling coercion");

        op_t = op_t->AsVectorType()->Yield();
        e_t = e_t->AsVectorType()->Yield();
    }

    auto targ_it = e_t->InternalType();
    auto op_it = op_t->InternalType();

    if ( op_it == targ_it )
        reporter->InternalError("coercion wasn't folded");

    if ( op->Tag() != EXPR_NAME )
        reporter->InternalError("coercion wasn't folded");

    ZOp a;

    switch ( targ_it ) {
        case TYPE_INTERNAL_DOUBLE: {
            if ( op_it == TYPE_INTERNAL_INT )
                a = nt_is_vec ? OP_COERCE_DI_VEC_VV : OP_COERCE_DI_VV;
            else
                a = nt_is_vec ? OP_COERCE_DU_VEC_VV : OP_COERCE_DU_VV;
            break;
        }

        case TYPE_INTERNAL_INT: {
            if ( op_it == TYPE_INTERNAL_UNSIGNED )
                a = nt_is_vec ? OP_COERCE_IU_VEC_VV : OP_COERCE_IU_VV;
            else
                a = nt_is_vec ? OP_COERCE_ID_VEC_VV : OP_COERCE_ID_VV;
            break;
        }

        case TYPE_INTERNAL_UNSIGNED: {
            if ( op_it == TYPE_INTERNAL_INT )
                a = nt_is_vec ? OP_COERCE_UI_VEC_VV : OP_COERCE_UI_VV;
            else
                a = nt_is_vec ? OP_COERCE_UD_VEC_VV : OP_COERCE_UD_VV;
            break;
        }

        default: reporter->InternalError("bad target internal type in coercion");
    }

    return AddInst(GenInst(a, n, op->AsNameExpr()));
}

const ZAMStmt ZAMCompiler::RecordCoerce(const NameExpr* n, const Expr* e) {
    ASSERT(e->Tag() == EXPR_RECORD_COERCE);
    auto r = static_cast<const RecordCoerceExpr*>(e);
    auto op = r->GetOp1()->AsNameExpr();

    int op_slot = FrameSlot(op);
    auto zop = OP_RECORD_COERCE_VV;
    ZInstI z(zop, Frame1Slot(n, zop), op_slot);

    z.SetType(e->GetType());
    z.op_type = OP_VV;

    auto map = r->Map();
    auto map_size = map.size();
    z.aux = new ZInstAux(map_size);
    z.aux->map = map;

    for ( auto i = 0U; i < map_size; ++i )
        z.aux->Add(i, map[i], nullptr);

    // Mark the integer entries in z.aux as not being frame slots as usual.
    z.aux->elems_has_slots = false;

    if ( pfs->HasSideEffects(SideEffectsOp::CONSTRUCTION, e->GetType()) )
        z.aux->can_change_non_locals = true;

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::TableCoerce(const NameExpr* n, const Expr* e) {
    auto op = e->GetOp1()->AsNameExpr();

    int op_slot = FrameSlot(op);
    auto zop = OP_TABLE_COERCE_VV;
    ZInstI z(zop, Frame1Slot(n, zop), op_slot);
    z.SetType(e->GetType());

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::VectorCoerce(const NameExpr* n, const Expr* e) {
    auto op = e->GetOp1()->AsNameExpr();
    int op_slot = FrameSlot(op);

    auto zop = OP_VECTOR_COERCE_VV;
    ZInstI z(zop, Frame1Slot(n, zop), op_slot);
    z.SetType(e->GetType());

    return AddInst(z);
}

const ZAMStmt ZAMCompiler::Is(const NameExpr* n, const Expr* e) {
    auto is = e->AsIsExpr();
    auto op = e->GetOp1()->AsNameExpr();
    int op_slot = FrameSlot(op);

    ZInstI z(OP_IS_VV, Frame1Slot(n, OP_IS_VV), op_slot);
    z.SetType(is->TestType());
    z.SetType2(op->GetType());

    return AddInst(z);
}

} // namespace zeek::detail
