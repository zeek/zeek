// See the file "COPYING" in the main distribution directory for copyright.

// Optimization-related methods for Expr classes.

#include "zeek/script_opt/Expr.h"

#include "zeek/Desc.h"
#include "zeek/Frame.h"
#include "zeek/Func.h"
#include "zeek/IPAddr.h"
#include "zeek/Overflow.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Stmt.h"
#include "zeek/Traverse.h"
#include "zeek/script_opt/FuncInfo.h"
#include "zeek/script_opt/Inline.h"
#include "zeek/script_opt/Reduce.h"

namespace zeek::detail {

static bool same_singletons(ExprPtr e1, ExprPtr e2);

ConstExpr* Expr::AsConstExpr() {
    CHECK_TAG(tag, EXPR_CONST, "ExprVal::AsConstExpr", expr_name)
    return static_cast<ConstExpr*>(this);
}

const FieldExpr* Expr::AsFieldExpr() const {
    CHECK_TAG(tag, EXPR_FIELD, "ExprVal::AsFieldExpr", expr_name)
    return static_cast<const FieldExpr*>(this);
}

FieldExpr* Expr::AsFieldExpr() {
    CHECK_TAG(tag, EXPR_FIELD, "ExprVal::AsFieldExpr", expr_name)
    return static_cast<FieldExpr*>(this);
}

FieldAssignExpr* Expr::AsFieldAssignExpr() {
    CHECK_TAG(tag, EXPR_FIELD_ASSIGN, "ExprVal::AsFieldAssignExpr", expr_name)
    return static_cast<FieldAssignExpr*>(this);
}

IntrusivePtr<FieldAssignExpr> Expr::AsFieldAssignExprPtr() {
    CHECK_TAG(tag, EXPR_FIELD_ASSIGN, "ExprVal::AsFieldAssignExpr", expr_name)
    return {NewRef{}, static_cast<FieldAssignExpr*>(this)};
}

HasFieldExpr* Expr::AsHasFieldExpr() {
    CHECK_TAG(tag, EXPR_HAS_FIELD, "ExprVal::AsHasFieldExpr", expr_name)
    return static_cast<HasFieldExpr*>(this);
}

const HasFieldExpr* Expr::AsHasFieldExpr() const {
    CHECK_TAG(tag, EXPR_HAS_FIELD, "ExprVal::AsHasFieldExpr", expr_name)
    return static_cast<const HasFieldExpr*>(this);
}

CanConvertExpr* Expr::AsCanConvertExpr() {
    CHECK_TAG(tag, EXPR_CAN_CONVERT, "ExprVal::AsCanConvertExpr", expr_name)
    return static_cast<CanConvertExpr*>(this);
}

const CanConvertExpr* Expr::AsCanConvertExpr() const {
    CHECK_TAG(tag, EXPR_CAN_CONVERT, "ExprVal::AsCanConvertExpr", expr_name)
    return static_cast<const CanConvertExpr*>(this);
}

const IsExpr* Expr::AsIsExpr() const {
    CHECK_TAG(tag, EXPR_IS, "ExprVal::AsIsExpr", expr_name)
    return static_cast<const IsExpr*>(this);
}

CallExpr* Expr::AsCallExpr() {
    CHECK_TAG(tag, EXPR_CALL, "ExprVal::AsCallExpr", expr_name)
    return static_cast<CallExpr*>(this);
}

RefExpr* Expr::AsRefExpr() {
    CHECK_TAG(tag, EXPR_REF, "ExprVal::AsRefExpr", expr_name)
    return static_cast<RefExpr*>(this);
}

LambdaExpr* Expr::AsLambdaExpr() {
    CHECK_TAG(tag, EXPR_LAMBDA, "ExprVal::AsLambdaExpr", expr_name)
    return static_cast<LambdaExpr*>(this);
}

const LambdaExpr* Expr::AsLambdaExpr() const {
    CHECK_TAG(tag, EXPR_LAMBDA, "ExprVal::AsLambdaExpr", expr_name)
    return static_cast<const LambdaExpr*>(this);
}

ExprPtr Expr::GetOp1() const { return nullptr; }
ExprPtr Expr::GetOp2() const { return nullptr; }
ExprPtr Expr::GetOp3() const { return nullptr; }

void Expr::SetOp1(ExprPtr) {}
void Expr::SetOp2(ExprPtr) {}
void Expr::SetOp3(ExprPtr) {}

bool IsSingleton(const Expr* e, Reducer* c) {
    auto tag = e->Tag();
    return (tag == EXPR_NAME && IsReduced(e, c)) || tag == EXPR_CONST;
}

bool IsReducedConditional(const Expr* e, Reducer* c) {
    switch ( e->Tag() ) {
        case EXPR_CONST: return true;

        case EXPR_NAME: return IsReduced(e, c);

        case EXPR_CALL: {
            if ( ! HasReducedOps(e, c) )
                return false;

            return IsZAM_BuiltInCond(static_cast<const CallExpr*>(e));
        }

        case EXPR_IN: {
            auto op1 = e->GetOp1();
            auto t1 = op1->Tag();
            auto op2 = e->GetOp2();

            if ( t1 != EXPR_NAME && t1 != EXPR_CONST && t1 != EXPR_LIST )
                return NonReduced(e);

            if ( op2->GetType()->Tag() != TYPE_TABLE || ! IsSingleton(op2, c) )
                return NonReduced(e);

            if ( t1 == EXPR_LIST ) {
                if ( ! IsReduced(op1.get(), c) )
                    return NonReduced(e);

                auto l1 = op1->AsListExpr();
                auto& l1_e = l1->Exprs();

                if ( l1_e.length() < 1 || l1_e.length() > 2 )
                    return NonReduced(e);
            }

            return true;
        }

        case EXPR_SCRIPT_OPT_BUILTIN: return e->GetType()->Tag() == TYPE_BOOL;

        case EXPR_EQ:
        case EXPR_NE:
        case EXPR_LE:
        case EXPR_GE:
        case EXPR_LT:
        case EXPR_GT:
        case EXPR_CAN_CONVERT:
        case EXPR_HAS_FIELD: return HasReducedOps(e, c);

        default: return false;
    }
}

bool IsReducedFieldAssignment(const Expr* e, Reducer* c) {
    if ( ! IsFieldAssignable(e) )
        return false;

    if ( e->Tag() == EXPR_CONST )
        return true;

    if ( e->Tag() == EXPR_NAME )
        return IsReduced(e, c);

    return HasReducedOps(e, c);
}

bool IsFieldAssignable(const Expr* e) {
    switch ( e->Tag() ) {
        case EXPR_NAME:
        case EXPR_CONST:
        case EXPR_NOT:
        case EXPR_COMPLEMENT:
        case EXPR_POSITIVE:
        case EXPR_NEGATE:
        case EXPR_ADD:
        case EXPR_SUB:
        case EXPR_TIMES:
        case EXPR_DIVIDE:
        case EXPR_MASK:
        case EXPR_MOD:
        case EXPR_AND:
        case EXPR_OR:
        case EXPR_XOR:
        case EXPR_LSHIFT:
        case EXPR_RSHIFT:
        case EXPR_FIELD:
        case EXPR_HAS_FIELD:
        case EXPR_SIZE:
            return true;

            // These would not be hard to add in principle, but at the expense
            // of some added complexity in the templator.  Seems unlikely the
            // actual performance gain would make that worth it.
            // case EXPR_LT:
            // case EXPR_LE:
            // case EXPR_EQ:
            // case EXPR_NE:
            // case EXPR_GE:
            // case EXPR_GT:
            //
            // case EXPR_IN:

            // These could be added if we subsetted them to versions for
            // which we know it's safe to evaluate both operands.  Again
            // likely not worth it.
            // case EXPR_AND_AND:
            // case EXPR_OR_OR:

        default: return false;
    }
}

ExprPtr Expr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    red_stmt = nullptr;
    return ThisPtr();
}

StmtPtr Expr::ReduceToSingletons(Reducer* c) {
    auto op1 = GetOp1();
    auto op2 = GetOp2();
    auto op3 = GetOp3();

    StmtPtr red1_stmt;
    StmtPtr red2_stmt;
    StmtPtr red3_stmt;

    if ( op1 && ! IsSingleton(op1, c) )
        SetOp1(op1->ReduceToSingleton(c, red1_stmt));
    if ( op2 && ! IsSingleton(op2, c) )
        SetOp2(op2->ReduceToSingleton(c, red2_stmt));
    if ( op3 && ! IsSingleton(op3, c) )
        SetOp3(op3->ReduceToSingleton(c, red3_stmt));

    return MergeStmts(this, std::move(red1_stmt), std::move(red2_stmt), std::move(red3_stmt));
}

ExprPtr ReduceToConditional(Expr* e, Reducer* c, StmtPtr& red_stmt) {
    if ( WillTransformInConditional(e, c) ) {
        auto new_me = e->TransformToConditional(c, red_stmt);

        // Now that we've transformed, reduce the result for use in a
        // conditional.
        StmtPtr red_stmt2;
        new_me = ReduceToConditional(new_me.get(), c, red_stmt2);
        red_stmt = MergeStmts(e, std::move(red_stmt), std::move(red_stmt2));

        return new_me;
    }

    switch ( e->Tag() ) {
        case EXPR_CONST: return e->ThisPtr();

        case EXPR_NAME:
            if ( c->Optimizing() )
                return e->ThisPtr();

            return e->Reduce(c, red_stmt);

        case EXPR_CALL: {
            auto ce = static_cast<CallExpr*>(e);
            red_stmt = ce->ReduceToSingletons(c);

            if ( IsZAM_BuiltInCond(ce) )
                return e->ThisPtr();

            StmtPtr red_stmt2;
            auto res = e->Reduce(c, red_stmt2);
            red_stmt = MergeStmts(e, std::move(red_stmt), std::move(red_stmt2));
            return res;
        }

        case EXPR_IN: {
            // This is complicated because there are lots of forms
            // of "in" expressions, and we're only interested in
            // those with 1 or 2 indices, into a table.
            auto op1 = e->GetOp1();
            auto op2 = e->GetOp2();

            if ( c->Optimizing() )
                return e->Reduce(c, red_stmt);

            if ( op2->GetType()->Tag() != TYPE_TABLE )
                // Not a table de-reference.
                return e->Reduce(c, red_stmt);

            if ( op1->Tag() == EXPR_LIST ) {
                auto l1 = op1->AsListExpr();
                auto& l1_e = l1->Exprs();

                if ( l1_e.length() < 1 || l1_e.length() > 2 )
                    // Wrong number of indices.
                    return e->Reduce(c, red_stmt);
            }

            if ( ! IsReduced(op1.get(), c) || ! IsSingleton(op2, c) ) {
                auto red2_stmt = e->ReduceToSingletons(c);
                auto res = ReduceToConditional(e, c, red_stmt);
                red_stmt = MergeStmts(e, std::move(red2_stmt), red_stmt);
                return res;
            }

            return e->ThisPtr();
        }

        case EXPR_NOT:
            if ( e->GetOp1()->Tag() == EXPR_SCRIPT_OPT_BUILTIN ) {
                red_stmt = e->GetOp1()->ReduceToSingletons(c);
                return e->ThisPtr();
            }
            else
                return e->Reduce(c, red_stmt);

        case EXPR_SCRIPT_OPT_BUILTIN:
            if ( e->GetType()->Tag() != TYPE_BOOL )
                return e->Reduce(c, red_stmt);

            // fall through

        case EXPR_EQ:
        case EXPR_NE:
        case EXPR_LE:
        case EXPR_GE:
        case EXPR_LT:
        case EXPR_GT:
            red_stmt = e->ReduceToSingletons(c);

            if ( e->GetOp1()->IsConst() && e->GetOp2()->IsConst() )
            // Fold!
            {
                StmtPtr fold_stmts;
                auto new_me = e->Reduce(c, fold_stmts);
                red_stmt = MergeStmts(e, red_stmt, fold_stmts);

                return new_me;
            }

            return e->ThisPtr();

        case EXPR_CAN_CONVERT:
        case EXPR_HAS_FIELD: red_stmt = e->ReduceToSingletons(c); return e->ThisPtr();

        default: return e->Reduce(c, red_stmt);
    }
}

ExprPtr Expr::TransformToConditional(Reducer* c, StmtPtr& red_stmt) {
    // This shouldn't happen since every expression that can return
    // true for WillTransformInConditional() should implement this
    // method.
    reporter->InternalError("Expr::TransformToConditional called");
}

ExprPtr ReduceToFieldAssignment(Expr* e, Reducer* c, StmtPtr& red_stmt) {
    if ( ! IsFieldAssignable(e) || e->Tag() == EXPR_NAME )
        return e->ReduceToSingleton(c, red_stmt);

    red_stmt = e->ReduceToSingletons(c);

    return e->ThisPtr();
}

ExprPtr AssignToTemporary(Expr* e, ExprPtr target, Reducer* c, StmtPtr& red_stmt) {
    auto result_tmp = c->GenTemporaryExpr(e->GetType(), target);

    auto a_e = make_intrusive<AssignExpr>(result_tmp->MakeLvalue(), target, false, nullptr, nullptr, false);
    a_e->SetLocationInfo(e->GetLocationInfo());
    a_e->SetIsTemp();

    auto a_e_s = with_location_of(make_intrusive<ExprStmt>(a_e), e);
    red_stmt = MergeStmts(e, red_stmt, a_e_s);

    // Important: our result is not result_tmp, but a duplicate of it.
    // This is important because subsequent passes that associate
    // information with Expr's need to not misassociate that
    // information with both the assignment creating the temporary,
    // and the subsequent use of the temporary.
    return result_tmp->Duplicate();
}

ExprPtr AssignToTemporary(Expr* e, Reducer* c, StmtPtr& red_stmt) {
    return AssignToTemporary(e, e->ThisPtr(), c, red_stmt);
}

ExprPtr TransformMe(Expr* e, ExprPtr new_me) {
    if ( new_me == e )
        return new_me;

    new_me->SetLocationInfo(e->GetLocationInfo());

    // Unlike for Stmt's, we assume that new_me has already
    // been reduced, so no need to do so further.
    return new_me;
}

StmtPtr MergeStmts(const Obj* o, StmtPtr s1, StmtPtr s2, StmtPtr s3) {
    int nums = (s1 != nullptr) + (s2 != nullptr) + (s3 != nullptr);

    if ( nums > 1 )
        return with_location_of(make_intrusive<StmtList>(s1, s2, s3), o);
    else if ( s1 )
        return s1;
    else if ( s2 )
        return s2;
    else if ( s3 )
        return s3;
    else
        return nullptr;
}

ValPtr MakeZero(TypeTag t) {
    switch ( t ) {
        case TYPE_BOOL: return val_mgr->False();
        case TYPE_INT: return val_mgr->Int(0);
        case TYPE_COUNT: return val_mgr->Count(0);

        case TYPE_DOUBLE: return make_intrusive<DoubleVal>(0.0);
        case TYPE_TIME: return make_intrusive<TimeVal>(0.0);
        case TYPE_INTERVAL: return make_intrusive<IntervalVal>(0.0, 1.0);

        default: reporter->InternalError("bad call to MakeZero");
    }
}

ConstExprPtr MakeZeroExpr(const Obj* o, TypeTag t) {
    auto z = make_intrusive<ConstExpr>(MakeZero(t));
    z->SetLocationInfo(o->GetLocationInfo());
    return z;
}

ExprPtr NameExpr::Duplicate() { return SetSucc(new NameExpr(id, in_const_init)); }

ExprPtr NameExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    red_stmt = nullptr;

    if ( c->Optimizing() )
        return ThisPtr();

    if ( FoldableGlobal() ) {
        ValPtr v = id->GetVal();
        ASSERT(v);
        return TransformMe(this, make_intrusive<ConstExpr>(v));
    }

    return c->UpdateName({NewRef{}, this});
}

ValPtr NameExpr::FoldVal() const {
    if ( ! id->IsConst() || id->GetAttr(ATTR_REDEF) || id->GetType()->Tag() == TYPE_FUNC )
        return nullptr;

    return id->GetVal();
}

bool NameExpr::FoldableGlobal() const {
    return id->IsGlobal() && id->IsConst() && is_atomic_type(id->GetType()) &&
           // Make sure constant can't be changed on the command line
           // or such.
           ! id->GetAttr(ATTR_REDEF);
}

ExprPtr ConstExpr::Duplicate() { return SetSucc(new ConstExpr(val)); }

ExprPtr UnaryExpr::Inline(Inliner* inl) {
    op = op->Inline(inl);
    return ThisPtr();
}

bool UnaryExpr::HasNoSideEffects() const { return op->HasNoSideEffects(); }

ExprPtr UnaryExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() )
        op = c->UpdateExpr(op, this);

    red_stmt = nullptr;

    if ( ! IsSingleton(op, c) )
        op = op->ReduceToSingleton(c, red_stmt);

    auto op_val = IsAggr(op->GetType()) ? nullptr : op->FoldVal();
    if ( op_val ) {
        auto fold = Fold(op_val.get());
        if ( fold->GetType()->Tag() != TYPE_OPAQUE )
            return TransformMe(this, make_intrusive<ConstExpr>(fold));
    }

    if ( c->Optimizing() )
        return ThisPtr();
    else
        return AssignToTemporary(this, c, red_stmt);
}

ExprPtr BinaryExpr::Inline(Inliner* inl) {
    op1 = op1->Inline(inl);
    op2 = op2->Inline(inl);

    return ThisPtr();
}

bool BinaryExpr::HasNoSideEffects() const { return op1->HasNoSideEffects() && op2->HasNoSideEffects(); }

ExprPtr BinaryExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() ) {
        op1 = c->UpdateExpr(op1, this);
        op2 = c->UpdateExpr(op2, this);
    }

    red_stmt = nullptr;

    if ( ! IsSingleton(op1, c) )
        op1 = op1->ReduceToSingleton(c, red_stmt);

    StmtPtr red2_stmt;
    if ( ! IsSingleton(op2, c) )
        op2 = op2->ReduceToSingleton(c, red2_stmt);

    red_stmt = MergeStmts(this, red_stmt, std::move(red2_stmt));

    auto op1_fold_val = IsAggr(op1->GetType()) ? nullptr : op1->FoldVal();

    if ( ! op1_fold_val && op1->Tag() == EXPR_LIST && op1->AsListExpr()->HasConstantOps() )
        // We can turn the list into a ListVal.
        op1_fold_val = eval_in_isolation(op1);

    auto op2_fold_val = op2->FoldVal();
    if ( op1_fold_val && op2_fold_val ) {
        auto fold = Fold(op1_fold_val.get(), op2_fold_val.get());
        if ( fold->GetType()->Tag() != TYPE_OPAQUE )
            return TransformMe(this, make_intrusive<ConstExpr>(fold));
    }

    if ( c->Optimizing() )
        return ThisPtr();
    else
        return AssignToTemporary(this, c, red_stmt);
}

ExprPtr CloneExpr::Duplicate() {
    // oh the irony
    return SetSucc(new CloneExpr(op->Duplicate()));
}

ExprPtr IncrExpr::Duplicate() { return SetSucc(new IncrExpr(tag, op->Duplicate())); }

bool IncrExpr::HasNoSideEffects() const { return false; }

ExprPtr IncrExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( op->Tag() != EXPR_REF )
        Internal("confusion in IncrExpr::Reduce");

    auto ref_op = op->AsRefExprPtr();
    auto target = ref_op->GetOp1();

    if ( target->Tag() == EXPR_NAME && IsIntegral(target->GetType()->Tag()) ) {
        if ( c->Optimizing() )
            op = c->UpdateExpr(op, this);
        else
            op = op->Reduce(c, red_stmt);

        return ThisPtr();
    }

    // First reduce the target's operands to singletons, so that when
    // we re-use it in the assignment below, it has reduced operands.
    auto init_red_stmt = target->ReduceToSingletons(c);

    // Now reduce it all the way to a single value, to use for the
    // increment.
    auto orig_target = target;
    StmtPtr target_stmt;
    target = target->ReduceToSingleton(c, target_stmt);

    auto incr_const = with_location_of(make_intrusive<ConstExpr>(val_mgr->Count(1)), this);

    ExprPtr incr_expr;

    if ( Tag() == EXPR_INCR )
        incr_expr = with_location_of(make_intrusive<AddExpr>(target, incr_const), this);
    else
        incr_expr = with_location_of(make_intrusive<SubExpr>(target, incr_const), this);

    StmtPtr incr_stmt;
    auto incr_expr2 = incr_expr->Reduce(c, incr_stmt);

    StmtPtr assign_stmt;
    auto rhs = AssignToTemporary(incr_expr2.get(), c, assign_stmt);

    // Build a duplicate version of the original to use as the result.
    if ( orig_target->Tag() == EXPR_NAME )
        orig_target = orig_target->Duplicate();

    else if ( orig_target->Tag() == EXPR_INDEX ) {
        auto dup1 = orig_target->GetOp1()->Duplicate();
        auto dup2 = orig_target->GetOp2()->Duplicate();
        auto index = dup2->AsListExprPtr();
        orig_target = with_location_of(make_intrusive<IndexExpr>(dup1, index), this);
    }

    else if ( orig_target->Tag() == EXPR_FIELD ) {
        auto dup1 = orig_target->GetOp1()->Duplicate();
        auto field_name = orig_target->AsFieldExpr()->FieldName();
        orig_target = with_location_of(make_intrusive<FieldExpr>(dup1, field_name), this);
    }

    else
        reporter->InternalError("confused in IncrExpr::Reduce");

    auto assign = with_location_of(make_intrusive<AssignExpr>(orig_target, rhs, false, nullptr, nullptr, false), this);

    // First reduce it regularly, so it can transform into $= or
    // such as needed.  Then reduce that to a singleton to provide
    // the result for this expression.
    StmtPtr assign_stmt2;
    auto res = assign->Reduce(c, assign_stmt2);
    res = res->ReduceToSingleton(c, red_stmt);
    red_stmt = MergeStmts(this, MergeStmts(this, init_red_stmt, target_stmt),
                          MergeStmts(this, incr_stmt, assign_stmt, assign_stmt2), red_stmt);

    return res;
}

ExprPtr IncrExpr::ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) {
    auto ref_op = op->AsRefExprPtr();
    auto target = ref_op->GetOp1();

    if ( target->Tag() == EXPR_NAME && IsIntegral(target->GetType()->Tag()) ) {
        ExprPtr incr_expr = Duplicate();
        red_stmt = with_location_of(make_intrusive<ExprStmt>(incr_expr), this)->Reduce(c);

        StmtPtr targ_red_stmt;
        auto targ_red = target->Reduce(c, targ_red_stmt);

        red_stmt = MergeStmts(this, red_stmt, targ_red_stmt);

        return targ_red;
    }

    else
        return UnaryExpr::ReduceToSingleton(c, red_stmt);
}

ExprPtr ComplementExpr::Duplicate() { return SetSucc(new ComplementExpr(op->Duplicate())); }


ExprPtr ComplementExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( op->Tag() == EXPR_COMPLEMENT )
        return op->GetOp1()->ReduceToSingleton(c, red_stmt);

    return UnaryExpr::Reduce(c, red_stmt);
}

ExprPtr NotExpr::Duplicate() { return SetSucc(new NotExpr(op->Duplicate())); }


ExprPtr NotExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( op->Tag() == EXPR_NOT )
        return op->GetOp1()->Reduce(c, red_stmt);

    return UnaryExpr::Reduce(c, red_stmt);
}

ExprPtr PosExpr::Duplicate() { return SetSucc(new PosExpr(op->Duplicate())); }


ExprPtr PosExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( op->GetType()->Tag() == TYPE_COUNT )
        // We need to keep the expression because it leads
        // to a coercion from unsigned to signed.
        return UnaryExpr::Reduce(c, red_stmt);

    else
        return op->ReduceToSingleton(c, red_stmt);
}

ExprPtr NegExpr::Duplicate() { return SetSucc(new NegExpr(op->Duplicate())); }


ExprPtr NegExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( op->Tag() == EXPR_NEGATE )
        return op->GetOp1()->ReduceToSingleton(c, red_stmt);

    return UnaryExpr::Reduce(c, red_stmt);
}

ExprPtr SizeExpr::Duplicate() { return SetSucc(new SizeExpr(op->Duplicate())); }

ExprPtr AddExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new AddExpr(op1_d, op2_d));
}


ExprPtr AddExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( op1->IsZero() )
        return op2->ReduceToSingleton(c, red_stmt);

    if ( op2->IsZero() )
        return op1->ReduceToSingleton(c, red_stmt);

    if ( op1->Tag() == EXPR_NEGATE )
        return BuildSub(op2, op1)->ReduceToSingleton(c, red_stmt);

    if ( op2->Tag() == EXPR_NEGATE )
        return BuildSub(op1, op2)->ReduceToSingleton(c, red_stmt);

    return BinaryExpr::Reduce(c, red_stmt);
}

ExprPtr AddExpr::BuildSub(const ExprPtr& op1, const ExprPtr& op2) {
    auto rhs = op2->GetOp1();
    return with_location_of(make_intrusive<SubExpr>(op1, rhs), this);
}

ExprPtr AggrAddDelExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    // In the future, if we use add/delete for list operations or such,
    // then the following becomes germane.
    // if ( type )
    //     return UnaryExpr::Reduce(c, red_stmt);
    if ( c->Optimizing() )
        op = c->UpdateExpr(op, this);

    red_stmt = op->ReduceToSingletons(c);
    return ThisPtr();
}

ExprPtr AggrAddExpr::Duplicate() { return SetSucc(new AggrAddExpr(op->Duplicate())); }

ExprPtr AggrDelExpr::Duplicate() { return SetSucc(new AggrDelExpr(op->Duplicate())); }

ExprPtr AddToExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new AddToExpr(op1_d, op2_d));
}

ExprPtr AddToExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() )
        op2 = c->UpdateExpr(op2, this);

    auto tag = op1->GetType()->Tag();

    switch ( tag ) {
        case TYPE_PATTERN:
        case TYPE_TABLE:
        case TYPE_VECTOR: {
            StmtPtr red_stmt1;
            StmtPtr red_stmt2;

            if ( tag == TYPE_PATTERN && op1->Tag() == EXPR_FIELD )
                red_stmt1 = op1->ReduceToSingletons(c);
            else
                op1 = op1->Reduce(c, red_stmt1);

            auto& t = op1->GetType();
            op2 = op2->ReduceToSingleton(c, red_stmt2);

            red_stmt = MergeStmts(this, red_stmt1, red_stmt2);

            if ( is_vector_elem_append ) {
                auto append = with_location_of(make_intrusive<AppendToExpr>(op1->Duplicate(), op2), this);
                auto append_stmt = with_location_of(make_intrusive<ExprStmt>(append), this);

                red_stmt = MergeStmts(this, red_stmt, append_stmt);

                return op1;
            }

            return ThisPtr();
        }

        default: {
            auto rhs = op1->AsRefExprPtr()->GetOp1();
            auto do_incr = with_location_of(make_intrusive<AddExpr>(rhs->Duplicate(), op2), this);
            auto assign =
                with_location_of(make_intrusive<AssignExpr>(op1, do_incr, false, nullptr, nullptr, false), this);

            return assign->ReduceToSingleton(c, red_stmt);
        }
    }
}

ExprPtr AddToExpr::ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) {
    auto at_stmt = with_location_of(make_intrusive<ExprStmt>(Duplicate()), this);
    red_stmt = at_stmt->Reduce(c);
    return op1;
}

ExprPtr SubExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new SubExpr(op1_d, op2_d));
}


ExprPtr SubExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( op2->IsZero() )
        return op1->ReduceToSingleton(c, red_stmt);

    if ( op2->Tag() == EXPR_NEGATE ) {
        auto rhs = op2->GetOp1();
        auto add = with_location_of(make_intrusive<AddExpr>(op1, rhs), this);
        return add->Reduce(c, red_stmt);
    }

    if ( c->Optimizing() ) { // Allow for alias expansion.
        op1 = c->UpdateExpr(op1, this);
        op2 = c->UpdateExpr(op2, this);
    }

    if ( type->Tag() != TYPE_VECTOR && type->Tag() != TYPE_TABLE && op1->Tag() == EXPR_NAME &&
         op2->Tag() == EXPR_NAME ) {
        auto n1 = op1->AsNameExpr();
        auto n2 = op2->AsNameExpr();
        if ( n1->Id() == n2->Id() ) {
            auto zero = MakeZeroExpr(this, type->Tag());
            return TransformMe(this, zero);
        }
    }

    return BinaryExpr::Reduce(c, red_stmt);
}

ExprPtr RemoveFromExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new RemoveFromExpr(op1_d, op2_d));
}

ExprPtr RemoveFromExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() )
        op2 = c->UpdateExpr(op2, this);

    if ( op1->GetType()->Tag() == TYPE_TABLE ) {
        StmtPtr red_stmt1;
        StmtPtr red_stmt2;

        op1 = op1->Reduce(c, red_stmt1);
        op2 = op2->ReduceToSingleton(c, red_stmt2);

        red_stmt = MergeStmts(this, red_stmt1, red_stmt2);

        return ThisPtr();
    }

    auto lhs = op1->AsRefExprPtr()->GetOp1();
    auto do_decr = with_location_of(make_intrusive<SubExpr>(lhs->Duplicate(), op2), this);
    auto assign = with_location_of(make_intrusive<AssignExpr>(op1, do_decr, false, nullptr, nullptr, false), this);

    return assign->Reduce(c, red_stmt);
}

ExprPtr RemoveFromExpr::ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) {
    auto rf_stmt = with_location_of(make_intrusive<ExprStmt>(Duplicate()), this);
    red_stmt = rf_stmt->Reduce(c);
    return op1;
}

ExprPtr TimesExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new TimesExpr(op1_d, op2_d));
}


ExprPtr TimesExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( op1->IsOne() )
        return op2->ReduceToSingleton(c, red_stmt);

    if ( op2->IsOne() )
        return op1->ReduceToSingleton(c, red_stmt);

    // Optimize integral multiplication by zero ... but not
    // double, due to cases like Inf*0 or NaN*0.
    if ( (op1->IsZero() || op2->IsZero()) && GetType()->Tag() != TYPE_DOUBLE ) {
        if ( op1->IsZero() )
            return c->Fold(op1);
        else
            return c->Fold(op2);
    }

    return BinaryExpr::Reduce(c, red_stmt);
}

ExprPtr DivideExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new DivideExpr(op1_d, op2_d));
}


ExprPtr DivideExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( op2->IsOne() )
        return op1->ReduceToSingleton(c, red_stmt);

    return BinaryExpr::Reduce(c, red_stmt);
}

ExprPtr MaskExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new MaskExpr(op1_d, op2_d));
}

ExprPtr ModExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new ModExpr(op1_d, op2_d));
}

// Helper functions used by BoolExpr.

// Returns true if the given Expr is either of the form "/pat/ in var" or a
// (possibly extended) "||" disjunction of such nodes, for which "var" is
// always the same.  If true, returns the IDPtr corresponding to "var", and
// collects the associated pattern constants in "patterns".
//
// Note that for an initial (non-recursive) call, "id" should be set to
// nullptr, and the caller should have ensured that the starting point is
// a disjunction (since a bare "/pat/ in var" by itself isn't a "cascade"
// and doesn't present a potential optimization opportunity.
static bool is_pattern_cascade(const Expr* e, IDPtr& id, std::vector<ConstExprPtr>& patterns) {
    auto lhs = e->GetOp1();
    auto rhs = e->GetOp2();

    if ( e->Tag() == EXPR_IN ) {
        if ( lhs->Tag() != EXPR_CONST || lhs->GetType()->Tag() != TYPE_PATTERN || rhs->Tag() != EXPR_NAME )
            return false;

        const auto& rhs_id = rhs->AsNameExpr()->IdPtr();

        if ( id && rhs_id != id )
            return false;

        id = rhs_id;
        patterns.push_back(lhs->AsConstExprPtr());

        return true;
    }

    if ( e->Tag() != EXPR_OR_OR )
        return false;

    return is_pattern_cascade(lhs.get(), id, patterns) && is_pattern_cascade(rhs.get(), id, patterns);
}

// Given a set of pattern constants, returns a disjunction that
// includes all of them.
static ExprPtr build_disjunction(std::vector<ConstExprPtr>& patterns, const Obj* obj) {
    ASSERT(patterns.size() > 1);

    ExprPtr e = patterns[0];

    for ( auto& p : patterns )
        e = with_location_of(make_intrusive<BitExpr>(EXPR_OR, e, p), obj);

    return e;
}

ExprPtr BoolExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new BoolExpr(tag, op1_d, op2_d));
}


ExprPtr BoolExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    // First, look for a common idiom of "/foo/ in x || /bar/ in x"
    // and translate it to "(/foo/ | /bar) in x", which is more
    // efficient to match.
    IDPtr common_id = nullptr;
    std::vector<ConstExprPtr> patterns;
    if ( tag == EXPR_OR_OR && is_pattern_cascade(this, common_id, patterns) )
        return TransformToConditional(c, red_stmt);

    // It's either an EXPR_AND_AND or an EXPR_OR_OR.
    bool is_and = (tag == EXPR_AND_AND);

    if ( IsTrue(op1) ) {
        if ( is_and )
            return op2->ReduceToSingleton(c, red_stmt);
        else
            return op1->ReduceToSingleton(c, red_stmt);
    }

    if ( IsFalse(op1) ) {
        if ( is_and )
            return op1->ReduceToSingleton(c, red_stmt);
        else
            return op2->ReduceToSingleton(c, red_stmt);
    }

    if ( op1->HasNoSideEffects() ) {
        if ( IsTrue(op2) ) {
            if ( is_and )
                return op1->ReduceToSingleton(c, red_stmt);
            else
                return op2->ReduceToSingleton(c, red_stmt);
        }

        if ( IsFalse(op2) ) {
            if ( is_and )
                return op2->ReduceToSingleton(c, red_stmt);
            else
                return op1->ReduceToSingleton(c, red_stmt);
        }
    }

    if ( IsVector(op1->GetType()->Tag()) ) {
        if ( c->Optimizing() )
            return ThisPtr();
        else
            return AssignToTemporary(this, c, red_stmt);
    }

    auto else_val = is_and ? val_mgr->False() : val_mgr->True();
    ExprPtr else_e = with_location_of(make_intrusive<ConstExpr>(else_val), this);

    ExprPtr cond;
    if ( is_and )
        cond = with_location_of(make_intrusive<CondExpr>(op1, op2, else_e), this);
    else
        cond = with_location_of(make_intrusive<CondExpr>(op1, else_e, op2), this);

    auto cond_red = cond->ReduceToSingleton(c, red_stmt);
    return TransformMe(this, cond_red);
}

ExprPtr BoolExpr::TransformToConditional(Reducer* c, StmtPtr& red_stmt) {
    // This only happens for pattern cascades.

    // Here in some contexts we're re-doing work that our caller did, but
    // these cascades are quite rare, and re-doing the work keeps the
    // coupling simpler.
    IDPtr common_id = nullptr;
    std::vector<ConstExprPtr> patterns;
    auto is_cascade = is_pattern_cascade(this, common_id, patterns);
    ASSERT(is_cascade);

    auto new_pat = build_disjunction(patterns, this);
    auto new_id = with_location_of(make_intrusive<NameExpr>(common_id), this);
    auto new_node = with_location_of(make_intrusive<InExpr>(new_pat, new_id), this);
    return new_node->Reduce(c, red_stmt);
}

bool BoolExpr::IsTrue(const ExprPtr& e) const {
    if ( ! e->IsConst() )
        return false;

    auto c_e = e->AsConstExpr();
    return c_e->Value()->IsOne();
}

bool BoolExpr::IsFalse(const ExprPtr& e) const {
    if ( ! e->IsConst() )
        return false;

    auto c_e = e->AsConstExpr();
    return c_e->Value()->IsZero();
}

ExprPtr BitExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new BitExpr(tag, op1_d, op2_d));
}


ExprPtr BitExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( ! IsIntegral(GetType()->Tag()) )
        return BinaryExpr::Reduce(c, red_stmt);

    auto zero1 = op1->IsZero();
    auto zero2 = op2->IsZero();

    if ( zero1 && zero2 )
        // No matter the operation, the answer is zero.
        return op1->ReduceToSingleton(c, red_stmt);

    if ( zero1 || zero2 ) {
        ExprPtr& zero_op = zero1 ? op1 : op2;
        ExprPtr& non_zero_op = zero1 ? op2 : op1;

        if ( Tag() == EXPR_AND )
            return zero_op->ReduceToSingleton(c, red_stmt);
        else
            // OR or XOR or LSHIFT or RSHIFT
            return non_zero_op->ReduceToSingleton(c, red_stmt);
    }

    if ( same_singletons(op1, op2) && op1->Tag() == EXPR_NAME ) {
        auto n = op1->AsNameExpr();

        if ( Tag() == EXPR_XOR ) {
            auto zero = with_location_of(make_intrusive<ConstExpr>(val_mgr->Count(0)), this);
            return zero->Reduce(c, red_stmt);
        }

        else
            return op1->ReduceToSingleton(c, red_stmt);
    }

    return BinaryExpr::Reduce(c, red_stmt);
}

static std::map<ExprTag, ExprTag> has_elements_swap_tag = {
    {EXPR_EQ, EXPR_EQ}, {EXPR_NE, EXPR_NE}, {EXPR_LT, EXPR_GT},
    {EXPR_LE, EXPR_GE}, {EXPR_GE, EXPR_LE}, {EXPR_GT, EXPR_LT},
};

static bool IsHasElementsTest(const CmpExpr* e) {
    static std::set<ExprTag> rel_tags = {EXPR_EQ, EXPR_NE, EXPR_LT, EXPR_LE, EXPR_GE, EXPR_GT};

    auto t = e->Tag(); // note, we may invert t below
    if ( ! rel_tags.contains(t) )
        return false;

    auto op1 = e->GetOp1();
    auto op2 = e->GetOp2();

    ASSERT(op1 && op2);

    if ( op1->Tag() != EXPR_SIZE && op2->Tag() != EXPR_SIZE )
        return false;

    if ( ! op1->IsZero() && ! op1->IsOne() && ! op2->IsZero() && ! op2->IsOne() )
        return false;

    if ( op1->Tag() == EXPR_CONST ) {
        t = has_elements_swap_tag[t];
        std::swap(op1, op2);
    }

    auto op1_t = op1->GetOp1()->GetType()->Tag();
    if ( op1_t != TYPE_TABLE && op1_t != TYPE_VECTOR )
        return false;

    static std::map<ExprTag, bool> zero_req = {
        {EXPR_EQ, true}, {EXPR_NE, true}, {EXPR_LT, false}, {EXPR_LE, true}, {EXPR_GE, false}, {EXPR_GT, true},
    };

    return zero_req[t] ? op2->IsZero() : op2->IsOne();
}


ExprPtr CmpExpr::TransformToConditional(Reducer* c, StmtPtr& red_stmt) { return BuildHasElementsTest(); }

ExprPtr CmpExpr::BuildHasElementsTest() const {
    auto t = Tag();
    auto op1 = GetOp1();
    auto op2 = GetOp2();

    if ( op1->Tag() == EXPR_CONST ) {
        t = has_elements_swap_tag[t];
        std::swap(op1, op2);
    }

    ExprPtr he =
        with_location_of(make_intrusive<ScriptOptBuiltinExpr>(ScriptOptBuiltinExpr::HAS_ELEMENTS, op1->GetOp1()), this);

    static std::map<ExprTag, bool> has_elements = {
        {EXPR_EQ, false}, {EXPR_NE, true}, {EXPR_LT, false}, {EXPR_LE, false}, {EXPR_GE, true}, {EXPR_GT, true},
    };

    if ( ! has_elements[t] )
        he = with_location_of(make_intrusive<NotExpr>(he), this);

    return he;
}

ExprPtr EqExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new EqExpr(tag, op1_d, op2_d));
}

ExprPtr EqExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( IsHasElementsTest(this) )
        return BuildHasElementsTest()->Reduce(c, red_stmt);

    if ( GetType()->Tag() == TYPE_BOOL ) {
        if ( same_singletons(op1, op2) ) {
            bool t = Tag() == EXPR_EQ;
            auto res = with_location_of(make_intrusive<ConstExpr>(val_mgr->Bool(t)), this);
            return res->Reduce(c, red_stmt);
        }

        if ( op1->GetType()->Tag() == TYPE_BOOL ) {
            if ( op1->Tag() == EXPR_CONST )
                std::swap(op1, op2);

            if ( op2->Tag() == EXPR_CONST ) {
                bool t = Tag() == EXPR_EQ;
                if ( op2->AsConstExpr()->Value()->IsZero() )
                    t = ! t;
                if ( t )
                    return op1->Reduce(c, red_stmt);

                auto res = with_location_of(make_intrusive<NotExpr>(op1), this);
                return res->Reduce(c, red_stmt);
            }
        }
    }

    return BinaryExpr::Reduce(c, red_stmt);
}

ExprPtr RelExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new RelExpr(tag, op1_d, op2_d));
}

ExprPtr RelExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( IsHasElementsTest(this) )
        return BuildHasElementsTest()->Reduce(c, red_stmt);

    if ( GetType()->Tag() == TYPE_BOOL ) {
        if ( same_singletons(op1, op2) ) {
            bool t = Tag() == EXPR_GE || Tag() == EXPR_LE;
            auto res = with_location_of(make_intrusive<ConstExpr>(val_mgr->Bool(t)), this);
            return res->Reduce(c, red_stmt);
        }

        if ( op1->IsZero() && op2->GetType()->Tag() == TYPE_COUNT && (Tag() == EXPR_LE || Tag() == EXPR_GT) )
            Warn("degenerate comparison");

        if ( op2->IsZero() && op1->GetType()->Tag() == TYPE_COUNT && (Tag() == EXPR_LT || Tag() == EXPR_GE) )
            Warn("degenerate comparison");
    }

    return BinaryExpr::Reduce(c, red_stmt);
}

ExprPtr CondExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    auto op3_d = op3->Duplicate();
    return SetSucc(new CondExpr(op1_d, op2_d, op3_d));
}

ExprPtr CondExpr::Inline(Inliner* inl) {
    op1 = op1->Inline(inl);
    op2 = op2->Inline(inl);
    op3 = op3->Inline(inl);

    return ThisPtr();
}

static bool IsMinOrMax(const CondExpr* e) {
    auto op1 = e->GetOp1();

    switch ( op1->Tag() ) {
        case EXPR_LT:
        case EXPR_LE:
        case EXPR_GE:
        case EXPR_GT: break;

        default: return false;
    }

    auto relop1 = op1->GetOp1();
    auto relop2 = op1->GetOp2();
    auto op2 = e->GetOp2();
    auto op3 = e->GetOp3();

    return (same_expr(relop1, op2) && same_expr(relop2, op3)) || (same_expr(relop1, op3) && same_expr(relop2, op2));
}

static ExprPtr TransformToMinOrMax(const CondExpr* e) {
    auto op1 = e->GetOp1();
    auto relop1 = op1->GetOp1();
    auto relop2 = op1->GetOp2();

    auto is_min = (op1->Tag() == EXPR_LT || op1->Tag() == EXPR_LE);

    if ( same_expr(relop1, e->GetOp3()) )
        is_min = ! is_min;

    auto built_in = is_min ? ScriptOptBuiltinExpr::MINIMUM : ScriptOptBuiltinExpr::MAXIMUM;

    return with_location_of(make_intrusive<ScriptOptBuiltinExpr>(built_in, relop1, relop2), e);
}


ExprPtr CondExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() ) {
        op1 = c->UpdateExpr(op1, this);
        op2 = c->UpdateExpr(op2, this);
        op3 = c->UpdateExpr(op3, this);
    }

    while ( op1->Tag() == EXPR_NOT ) {
        op1 = op1->GetOp1();
        std::swap(op2, op3);
    }

    if ( IsMinOrMax(this) ) {
        auto res = TransformToMinOrMax(this);
        return res->Reduce(c, red_stmt);
    }

    StmtPtr op1_red_stmt;
    op1 = op1->ReduceToSingleton(c, op1_red_stmt);

    if ( op1->IsConst() ) {
        ExprPtr res;
        if ( op1->AsConstExpr()->Value()->IsOne() )
            res = op2->ReduceToSingleton(c, red_stmt);
        else
            res = op3->ReduceToSingleton(c, red_stmt);

        red_stmt = MergeStmts(this, op1_red_stmt, red_stmt);

        return res;
    }

    if ( same_singletons(op2, op3) ) {
        if ( op1->HasNoSideEffects() ) {
            if ( op1->Tag() != EXPR_CONST && op1->Tag() != EXPR_NAME )
                op1 = AssignToTemporary(op1.get(), c, red_stmt);
        }

        red_stmt = MergeStmts(this, op1_red_stmt, red_stmt);

        return op2;
    }

    if ( op2->IsConst() && op3->IsConst() && GetType()->Tag() == TYPE_BOOL ) {
        auto op2_t = op2->IsOne();
        ASSERT(op2_t != op3->IsOne());

        red_stmt = MergeStmts(this, op1_red_stmt, red_stmt);

        if ( op2_t )
            // This is "var ? T : F", which can be replaced by var.
            return op1;

        // Instead we have "var ? F : T".
        return TransformMe(this, make_intrusive<NotExpr>(op1));
    }

    if ( c->Optimizing() )
        return ThisPtr();

    red_stmt = ReduceToSingletons(c);

    StmtPtr assign_stmt;
    auto res = AssignToTemporary(this, c, assign_stmt);

    red_stmt = MergeStmts(this, op1_red_stmt, red_stmt, assign_stmt);

    return TransformMe(this, res);
}

StmtPtr CondExpr::ReduceToSingletons(Reducer* c) {
    StmtPtr red1_stmt;
    if ( ! IsSingleton(op1, c) )
        op1 = op1->ReduceToSingleton(c, red1_stmt);

    StmtPtr red2_stmt;
    if ( ! IsSingleton(op2, c) )
        op2 = op2->ReduceToSingleton(c, red2_stmt);

    StmtPtr red3_stmt;
    if ( ! IsSingleton(op3, c) )
        op3 = op3->ReduceToSingleton(c, red3_stmt);

    if ( IsVector(op1->GetType()->Tag()) ) {
        // In this particular case, it's okay to evaluate op2 and
        // op3 fully ahead of time, because the selector has to be
        // able to choose among them.
        return MergeStmts(this, MergeStmts(this, red1_stmt, red2_stmt), red3_stmt);
    }

    StmtPtr if_else;

    if ( red2_stmt || red3_stmt ) {
        if ( ! red2_stmt )
            red2_stmt = with_location_of(make_intrusive<NullStmt>(), this);
        if ( ! red3_stmt )
            red3_stmt = with_location_of(make_intrusive<NullStmt>(), this);

        if_else = with_location_of(make_intrusive<IfStmt>(op1->Duplicate(), std::move(red2_stmt), std::move(red3_stmt)),
                                   this);
    }

    return MergeStmts(this, red1_stmt, if_else);
}

ExprPtr RefExpr::Duplicate() { return SetSucc(new RefExpr(op->Duplicate())); }

ExprPtr RefExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( op->Tag() == EXPR_NAME )
        op = op->Reduce(c, red_stmt);
    else
        op = AssignToTemporary(this, c, red_stmt);

    return ThisPtr();
}

StmtPtr RefExpr::ReduceToLHS(Reducer* c) {
    if ( op->Tag() == EXPR_NAME ) {
        StmtPtr red_stmt;
        op = op->Reduce(c, red_stmt);
        return red_stmt;
    }

    auto red_stmt1 = op->ReduceToSingletons(c);
    auto op_ref = with_location_of(make_intrusive<RefExpr>(op), this);

    StmtPtr red_stmt2;
    op = AssignToTemporary(this, op_ref, c, red_stmt2);

    return MergeStmts(this, red_stmt1, red_stmt2);
}

ExprPtr AssignExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new AssignExpr(op1_d, op2_d, is_init, val));
}

bool AssignExpr::HasNoSideEffects() const { return false; }

ExprPtr AssignExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    // Yields a fully reduced assignment expression.
    if ( c->Optimizing() ) {
        // Don't update the LHS, it's already in reduced form
        // and it doesn't make sense to expand aliases or such.
        auto orig_op2 = op2;
        op2 = c->UpdateExpr(op2, this);

        if ( op2 != orig_op2 && op2->Tag() == EXPR_CONST && op1->Tag() == EXPR_REF ) {
            auto lhs = op1->GetOp1();
            auto op2_c = cast_intrusive<ConstExpr>(op2);
            if ( lhs->Tag() == EXPR_NAME )
                c->FoldedTo(orig_op2, op2_c);
        }

        return ThisPtr();
    }

    if ( IsTemp() )
        // These are generated for reduced expressions.
        return ThisPtr();

    if ( val ) {
        // These are reduced to the assignment followed by
        // the assignment value.
        auto assign_val = with_location_of(make_intrusive<ConstExpr>(val), this);
        val = nullptr;
        red_stmt = with_location_of(make_intrusive<ExprStmt>(ThisPtr()), this);
        return assign_val;
    }

    auto& t1 = op1->GetType();
    auto& t2 = op2->GetType();

    auto lhs_is_any = t1->Tag() == TYPE_ANY;
    auto rhs_is_any = t2->Tag() == TYPE_ANY;

    StmtPtr rhs_reduce;

    if ( lhs_is_any != rhs_is_any ) {
        auto op2_orig = op2;

        ExprPtr red_rhs = op2->ReduceToSingleton(c, rhs_reduce);

        if ( lhs_is_any ) {
            if ( red_rhs->Tag() == EXPR_CONST )
                op2 = red_rhs;
            else
                op2 = make_intrusive<CoerceToAnyExpr>(red_rhs);
        }
        else
            op2 = make_intrusive<CoerceFromAnyExpr>(red_rhs, t1);

        op2->SetLocationInfo(op2_orig->GetLocationInfo());
    }

    if ( t1->Tag() == TYPE_VECTOR && t1->Yield()->Tag() != TYPE_ANY && t2->Yield() && t2->Yield()->Tag() == TYPE_ANY ) {
        ExprPtr red_rhs = op2->ReduceToSingleton(c, rhs_reduce);
        op2 = with_location_of(make_intrusive<CoerceFromAnyVecExpr>(red_rhs, t1), op2);
    }

    auto lhs_ref = op1->AsRefExprPtr();
    auto lhs_expr = lhs_ref->GetOp1();

    if ( lhs_expr->Tag() == EXPR_INDEX ) {
        auto ind_e = lhs_expr->AsIndexExpr();

        StmtPtr ind1_stmt;
        StmtPtr ind2_stmt;
        StmtPtr rhs_stmt;

        auto ind1_e = ind_e->Op1()->Reduce(c, ind1_stmt);
        auto ind2_e = ind_e->Op2()->Reduce(c, ind2_stmt);
        auto rhs_e = op2->ReduceToSingleton(c, rhs_stmt);

        red_stmt = MergeStmts(this, MergeStmts(this, rhs_reduce, ind1_stmt), ind2_stmt, rhs_stmt);

        auto index_assign = make_intrusive<IndexAssignExpr>(ind1_e, ind2_e, rhs_e);
        return TransformMe(this, index_assign);
    }

    if ( lhs_expr->Tag() == EXPR_FIELD ) {
        auto field_e = lhs_expr->AsFieldExpr();

        StmtPtr lhs_stmt;
        StmtPtr rhs_stmt;

        if ( GetType()->Tag() == TYPE_ANY && op2->GetType()->Tag() != TYPE_ANY )
            op2 = with_location_of(make_intrusive<CoerceToAnyExpr>(op2), op2);

        auto lhs_e = field_e->Op()->Reduce(c, lhs_stmt);
        auto rhs_e = ReduceToFieldAssignment(op2.get(), c, rhs_stmt);

        red_stmt = MergeStmts(this, rhs_reduce, lhs_stmt, rhs_stmt);

        auto field_name = util::copy_string(field_e->FieldName());
        auto field = field_e->Field();
        auto field_assign = make_intrusive<FieldLHSAssignExpr>(lhs_e, rhs_e, field_name, field);

        return TransformMe(this, field_assign);
    }

    if ( lhs_expr->Tag() == EXPR_LIST ) {
        auto lhs_list = lhs_expr->AsListExpr()->Exprs();

        StmtPtr rhs_stmt;
        auto rhs_e = op2->Reduce(c, rhs_stmt);

        auto len = lhs_list.length();
        auto check_stmt = make_intrusive<CheckAnyLenStmt>(rhs_e, len);

        red_stmt = MergeStmts(this, rhs_reduce, rhs_stmt, check_stmt);

        loop_over_list(lhs_list, i) {
            auto rhs_dup = rhs_e->Duplicate();
            auto rhs = with_location_of(make_intrusive<AnyIndexExpr>(rhs_dup, i), this);
            auto lhs = lhs_list[i]->ThisPtr();
            lhs->SetLocationInfo(GetLocationInfo());
            auto assign = make_intrusive<AssignExpr>(lhs, rhs, false, nullptr, nullptr, false);

            auto assign_stmt = with_location_of(make_intrusive<ExprStmt>(assign), this);
            red_stmt = MergeStmts(this, red_stmt, assign_stmt);
        }

        return TransformMe(this, make_intrusive<NopExpr>());
    }

    if ( WillTransform(op2.get(), c) ) {
        StmtPtr xform_stmt;
        StmtPtr lhs_stmt = lhs_ref->ReduceToLHS(c);
        op2 = op2->ReduceToSingleton(c, xform_stmt);
        red_stmt = MergeStmts(this, lhs_stmt, rhs_reduce, xform_stmt);
        return ThisPtr();
    }

    red_stmt = op2->ReduceToSingletons(c);

    if ( op2->HasConstantOps() && op2->Tag() != EXPR_TO_ANY_COERCE )
        op2 = c->Fold(op2);

    // Check once again for transformation, this time made possible
    // because the operands have been reduced.  We don't simply
    // always first reduce the operands, because for expressions
    // like && and ||, that's incorrect.

    if ( WillTransform(op2.get(), c) ) {
        StmtPtr xform_stmt;
        op2 = op2->ReduceToSingleton(c, xform_stmt);
        red_stmt = MergeStmts(this, rhs_reduce, red_stmt, xform_stmt);
        return ThisPtr();
    }

    StmtPtr lhs_stmt = lhs_ref->ReduceToLHS(c);
    StmtPtr rhs_stmt = op2->ReduceToSingletons(c);

    red_stmt = MergeStmts(this, MergeStmts(this, rhs_reduce, red_stmt), lhs_stmt, rhs_stmt);

    return ThisPtr();
}

ExprPtr AssignExpr::ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) {
    // Yields a statement performing the assignment and for the
    // expression the LHS (but turned into an RHS), or the assignment
    // value if present.

    // An initialization assignment has no lvalue, so the invariant below does
    // not hold for it; using one as a value is an error (AssignExpr::Eval).
    if ( is_init ) {
        if ( ! IsError() ) // revisited by later reduction passes
            ExprError("illegal assignment in initialization");
        return ThisPtr();
    }

    if ( op1->Tag() != EXPR_REF )
        Internal("Confusion in AssignExpr::ReduceToSingleton");

    ExprPtr assign_expr = Duplicate();
    auto ae_stmt = with_location_of(make_intrusive<ExprStmt>(assign_expr), this);
    red_stmt = ae_stmt->Reduce(c);

    if ( val )
        return TransformMe(this, make_intrusive<ConstExpr>(val));

    auto lhs = op1->AsRefExprPtr()->GetOp1();
    StmtPtr lhs_stmt;
    auto new_op1 = lhs->ReduceToSingleton(c, lhs_stmt);
    red_stmt = MergeStmts(this, red_stmt, lhs_stmt);

    return new_op1;
}

ExprPtr IndexSliceAssignExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new IndexSliceAssignExpr(op1_d, op2_d, is_init));
}

ExprPtr IndexExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_l = op2->Duplicate()->AsListExprPtr();
    return SetSucc(new IndexExpr(op1_d, op2_l, is_slice, is_inside_when));
}

StmtPtr IndexExpr::ReduceToSingletons(Reducer* c) {
    StmtPtr red1_stmt;
    if ( ! IsSingleton(op1, c) )
        SetOp1(op1->ReduceToSingleton(c, red1_stmt));

    StmtPtr red2_stmt = op2->ReduceToSingletons(c);

    return MergeStmts(this, red1_stmt, std::move(red2_stmt));
}

ExprPtr IndexExprWhen::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_l = op2->Duplicate()->AsListExprPtr();
    return SetSucc(new IndexExprWhen(op1_d, op2_l, is_slice));
}

ExprPtr FieldExpr::Duplicate() { return SetSucc(new FieldExpr(op->Duplicate(), field_name)); }

ExprPtr HasFieldExpr::Duplicate() { return SetSucc(new HasFieldExpr(op->Duplicate(), util::copy_string(field_name))); }

ExprPtr HasFieldExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( ! op->GetType<RecordType>()->FieldHasAttr(field, ATTR_OPTIONAL) ) {
        auto true_constant = make_intrusive<ConstExpr>(val_mgr->True());
        return TransformMe(this, std::move(true_constant));
    }

    return UnaryExpr::Reduce(c, red_stmt);
}

ExprPtr RecordConstructorExpr::Duplicate() {
    auto op_l = op->Duplicate()->AsListExprPtr();

    if ( map ) {
        auto rt = cast_intrusive<RecordType>(type);
        return SetSucc(new RecordConstructorExpr(rt, op_l, false));
    }
    else
        return SetSucc(new RecordConstructorExpr(op_l));
}

ExprPtr RecordConstructorExpr::Inline(Inliner* inl) {
    op = op->Inline(inl)->AsListExprPtr();
    return ThisPtr();
}

ExprPtr RecordConstructorExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( ConstructFromRecordExpr::FindMostCommonRecordSource(op) ) {
        auto cfr = with_location_of(make_intrusive<ConstructFromRecordExpr>(this), this);
        return cfr->Reduce(c, red_stmt);
    }

    red_stmt = ReduceToSingletons(c);

    if ( c->Optimizing() )
        return ThisPtr();
    else
        return AssignToTemporary(this, c, red_stmt);
}

StmtPtr RecordConstructorExpr::ReduceToSingletons(Reducer* c) {
    StmtPtr red_stmt;
    auto& exprs = op->AsListExpr()->Exprs();

    // Could consider merging this code with that for ListExpr::Reduce.
    loop_over_list(exprs, i) {
        auto e_i = exprs[i];
        auto fa_i = e_i->AsFieldAssignExprPtr();
        auto fa_i_rhs = e_i->GetOp1();

        if ( c->Optimizing() ) {
            fa_i->SetOp1(c->UpdateExpr(fa_i_rhs, this));
            continue;
        }

        if ( IsSingleton(fa_i_rhs, c) )
            continue;

        StmtPtr e_stmt;
        auto rhs_red = fa_i_rhs->ReduceToSingleton(c, e_stmt);
        fa_i->SetOp1(rhs_red);

        if ( e_stmt )
            red_stmt = MergeStmts(this, red_stmt, e_stmt);
    }

    return red_stmt;
}

ExprPtr TableConstructorExpr::Duplicate() {
    auto op_l = op->Duplicate()->AsListExprPtr();

    TypePtr t;
    if ( (type && ! type->GetName().empty()) || ! op->AsListExpr()->Exprs().empty() )
        t = type;
    else
        // Use a null type rather than the one inferred, to instruct
        // the constructor to again infer the type.
        t = nullptr;

    return SetSucc(new TableConstructorExpr(op_l, nullptr, t, attrs));
}

ExprPtr TableConstructorExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    red_stmt = ReduceToSingletons(c);

    if ( c->Optimizing() )
        return ThisPtr();
    else
        return AssignToTemporary(this, c, red_stmt);
}

StmtPtr TableConstructorExpr::ReduceToSingletons(Reducer* c) {
    // Need to process the list of initializers directly, as
    // they may be expressed as AssignExpr's, and those get
    // treated quite differently during reduction.
    const auto& exprs = op->AsListExpr()->Exprs();

    StmtPtr red_stmt;

    for ( const auto& expr : exprs ) {
        if ( expr->Tag() == EXPR_ASSIGN ) {
            auto a = expr->AsAssignExpr();
            auto op1 = a->GetOp1();
            auto op2 = a->GetOp2();

            if ( c->Optimizing() ) {
                a->SetOp1(c->UpdateExpr(op1, this));
                a->SetOp2(c->UpdateExpr(op2, this));
                continue;
            }

            StmtPtr red1_stmt;
            StmtPtr red2_stmt;

            a->SetOp1(op1->ReduceToSingleton(c, red1_stmt));
            a->SetOp2(op2->ReduceToSingleton(c, red2_stmt));

            red_stmt = MergeStmts(this, red_stmt, red1_stmt, red2_stmt);
        }

        else
            reporter->InternalError("confused in TableConstructorExpr::Reduce");
    }

    return red_stmt;
}

ExprPtr SetConstructorExpr::Duplicate() {
    auto op_l = op->Duplicate()->AsListExprPtr();

    TypePtr t;
    if ( (type && ! type->GetName().empty()) || ! op->AsListExpr()->Exprs().empty() )
        t = type;
    else
        // Use a null type rather than the one inferred, to instruct
        // the constructor to again infer the type.
        t = nullptr;

    return SetSucc(new SetConstructorExpr(op_l, nullptr, t, attrs));
}

ExprPtr SetConstructorExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    // We rely on the fact that ListExpr's don't change into
    // temporaries.
    red_stmt = nullptr;

    (void)op->Reduce(c, red_stmt);

    if ( c->Optimizing() )
        return ThisPtr();
    else
        return AssignToTemporary(this, c, red_stmt);
}

StmtPtr SetConstructorExpr::ReduceToSingletons(Reducer* c) { return op->ReduceToSingletons(c); }

ExprPtr VectorConstructorExpr::Duplicate() {
    auto op_l = op->Duplicate()->AsListExprPtr();

    if ( op->AsListExpr()->Exprs().empty() )
        return SetSucc(new VectorConstructorExpr(op_l, nullptr));
    else
        return SetSucc(new VectorConstructorExpr(op_l, type));
}

ExprPtr FieldAssignExpr::Duplicate() {
    auto op_dup = op->Duplicate();
    return SetSucc(new FieldAssignExpr(field_name.c_str(), op_dup));
}

ExprPtr FieldAssignExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() ) {
        op = c->UpdateExpr(op, this);
        return ThisPtr();
    }

    red_stmt = nullptr;

    if ( ! IsReduced(op.get(), c) )
        op = op->ReduceToSingleton(c, red_stmt);

    // Doesn't seem worth checking for constant folding.

    return AssignToTemporary(this, c, red_stmt);
}

ExprPtr ArithCoerceExpr::Duplicate() {
    auto op_dup = op->Duplicate();

    TypeTag tag;

    if ( type->Tag() == TYPE_VECTOR )
        tag = type->AsVectorType()->Yield()->Tag();
    else
        tag = type->Tag();

    return SetSucc(new ArithCoerceExpr(op_dup, tag));
}


ExprPtr ArithCoerceExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() )
        op = c->UpdateExpr(op, this);

    red_stmt = nullptr;

    op = op->ReduceToSingleton(c, red_stmt);

    if ( op->Tag() == EXPR_CONST ) {
        const auto& t = GetType();
        auto cv = op->AsConstExpr()->ValuePtr();
        const auto& ct = cv->GetType();

        if ( IsArithmetic(t->Tag()) || IsArithmetic(ct->Tag()) ) {
            if ( auto v = FoldSingleVal(cv, t) )
                return TransformMe(this, make_intrusive<ConstExpr>(v));
            // else there was a coercion error, fall through
        }
    }

    if ( c->Optimizing() )
        return ThisPtr();

    const auto& ot = op->GetType();
    auto bt = ot->InternalType();
    auto tt = type->InternalType();

    if ( ot->Tag() == TYPE_VECTOR ) {
        bt = ot->Yield()->InternalType();
        tt = type->Yield()->InternalType();
    }

    if ( bt == tt )
        // Can drop the conversion.
        return op;

    return AssignToTemporary(this, c, red_stmt);
}

ExprPtr RecordCoerceExpr::Duplicate() {
    auto op_dup = op->Duplicate();
    return SetSucc(new RecordCoerceExpr(op_dup, GetType<RecordType>()));
}


ExprPtr RecordCoerceExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( WillTransform(this, c) ) {
        auto rt = cast_intrusive<RecordType>(type);
        ASSERT(op->Tag() == EXPR_RECORD_CONSTRUCTOR);
        auto rc_op = static_cast<const RecordConstructorExpr*>(op.get());
        auto known_constr = with_location_of(make_intrusive<RecordConstructorExpr>(rt, rc_op->Op()), this);
        auto red_e = known_constr->Reduce(c, red_stmt);
        return TransformMe(this, std::move(red_e));
    }

    return UnaryExpr::Reduce(c, red_stmt);
}

ExprPtr TableCoerceExpr::Duplicate() {
    auto op_dup = op->Duplicate();
    return SetSucc(new TableCoerceExpr(op_dup, GetType<TableType>()));
}

ExprPtr VectorCoerceExpr::Duplicate() {
    auto op_dup = op->Duplicate();
    return SetSucc(new VectorCoerceExpr(op_dup, GetType<VectorType>()));
}


ExprPtr VectorCoerceExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( WillTransform(this, c) ) {
        auto op1_list = op->GetOp1();
        ASSERT(op1_list->Tag() == EXPR_LIST);
        auto empty_list = cast_intrusive<ListExpr>(op1_list);
        auto new_me = with_location_of(make_intrusive<VectorConstructorExpr>(empty_list, type), this);
        auto red_e = new_me->Reduce(c, red_stmt);
        return TransformMe(this, std::move(red_e));
    }

    return UnaryExpr::Reduce(c, red_stmt);
}

ExprPtr ScheduleExpr::Duplicate() {
    auto when_d = when->Duplicate();
    auto event_d = event->Duplicate()->AsEventExprPtr();
    return SetSucc(new ScheduleExpr(when_d, event_d));
}

ExprPtr ScheduleExpr::Inline(Inliner* inl) {
    when = when->Inline(inl);
    event = event->Inline(inl)->AsEventExprPtr();

    return ThisPtr();
}

ExprPtr ScheduleExpr::GetOp1() const { return when; }

// We can't inline the following without moving the definition of
// EventExpr in Expr.h to come before that of ScheduleExpr.  Just
// doing this out-of-line seems cleaner.
ExprPtr ScheduleExpr::GetOp2() const { return event; }

void ScheduleExpr::SetOp1(ExprPtr op) { when = op; }

void ScheduleExpr::SetOp2(ExprPtr op) { event = op->AsEventExprPtr(); }

ExprPtr ScheduleExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() ) {
        when = c->UpdateExpr(when, this);
        auto e = c->UpdateExpr(event, this);
        event = e->AsEventExprPtr();
    }

    red_stmt = nullptr;

    if ( ! IsReduced(when.get(), c) )
        when = when->Reduce(c, red_stmt);

    StmtPtr red2_stmt;
    // We assume that EventExpr won't transform itself fundamentally.
    (void)event->Reduce(c, red2_stmt);

    red_stmt = MergeStmts(this, red_stmt, std::move(red2_stmt));

    return ThisPtr();
}

ExprPtr InExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new InExpr(op1_d, op2_d));
}

ExprPtr InExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( op2->Tag() == EXPR_SET_CONSTRUCTOR && op2->GetOp1()->AsListExpr()->HasConstantOps() )
        op2 = with_location_of(make_intrusive<ConstExpr>(eval_in_isolation(op2)), this);

    return BinaryExpr::Reduce(c, red_stmt);
}

ExprPtr CallExpr::Duplicate() {
    auto func_d = func->Duplicate();
    auto args_d = args->Duplicate()->AsListExprPtr();
    auto func_type = func->GetType();
    auto in_hook = func_type->AsFuncType()->Flavor() == FUNC_FLAVOR_HOOK;

    return SetSucc(new CallExpr(func_d, args_d, in_hook, in_when));
}

ExprPtr CallExpr::Inline(Inliner* inl) {
    // First check our elements.
    func = func->Inline(inl);
    args = cast_intrusive<ListExpr>(args->Inline(inl));

    auto new_me = inl->CheckForInlining({NewRef{}, this});

    if ( ! new_me )
        // All done with inlining.
        return ThisPtr();

    if ( new_me.get() != this )
        return new_me;

    return ThisPtr();
}

static std::map<std::string, ScriptOptBuiltinExpr::SOBuiltInTag> known_funcs = {
    {"id_string", ScriptOptBuiltinExpr::FUNC_ID_STRING}};

static bool AllConstArgs(const CallExpr* e) {
    for ( auto a : e->Args()->Exprs() )
        if ( a->Tag() != EXPR_CONST )
            return false;

    return true;
}

static bool IsFoldableBiF(const CallExpr* e) {
    if ( IsAggr(e->GetType()) )
        return false;

    if ( ! AllConstArgs(e) )
        return false;

    auto func = e->Func();
    if ( func->Tag() != EXPR_NAME )
        return false;

    return is_foldable(func->AsNameExpr()->Id()->Name());
}

static bool CheckForBuiltin(const CallExpr* e) {
    auto func = e->Func();
    if ( func->Tag() != EXPR_NAME )
        return false;

    return known_funcs.contains(func->AsNameExpr()->Id()->Name());
}

static ExprPtr TransformToBuiltin(CallExpr* e) {
    auto kf = known_funcs[e->Func()->AsNameExpr()->Id()->Name()];
    CallExprPtr e_ptr = {NewRef{}, e};
    return with_location_of(make_intrusive<ScriptOptBuiltinExpr>(kf, e_ptr), e);
}

static bool IsEmptyHook(const CallExpr* e) {
    auto func = e->Func();
    if ( func->Tag() != EXPR_NAME )
        return false;

    auto func_id = func->AsNameExpr()->IdPtr();
    auto func_val = func_id->GetVal();

    if ( ! func_val || ! func_id->IsGlobal() )
        return false;

    if ( func_id->GetType()->AsFuncType()->Flavor() != FUNC_FLAVOR_HOOK )
        return false;

    return ! func_val->AsFuncVal()->Get()->HasBodies();
}

ExprPtr CallExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() ) {
        func = c->UpdateExpr(func, this);
        auto e = c->UpdateExpr(args, this);
        args = e->AsListExprPtr();
    }

    red_stmt = nullptr;

    if ( ! IsSingleton(func, c) )
        func = func->ReduceToSingleton(c, red_stmt);

    if ( IsEmptyHook(this) && analysis_options.usage_issues == 0 ) {
        // Reduce the arguments to pick up any side effects they include.
        // However we skip doing this if we're doing usage analysis, because
        // we might remove a conceptual usage of a variable even if in
        // practice it's not used.
        (void)args->Reduce(c, red_stmt);
        return with_location_of(make_intrusive<ConstExpr>(val_mgr->True()), this);
    }

    StmtPtr red2_stmt = args->ReduceToSingletons(c);

    red_stmt = MergeStmts(this, red_stmt, std::move(red2_stmt));

    if ( CheckForBuiltin(this) ) {
        StmtPtr red3_stmt;
        auto res = TransformToBuiltin(this)->Reduce(c, red3_stmt);
        red_stmt = MergeStmts(this, red_stmt, std::move(red3_stmt));
        return res;
    }

    if ( IsFoldableBiF(this) ) {
        auto res = eval_in_isolation(this);
        ASSERT(res);
        return with_location_of(make_intrusive<ConstExpr>(res), this);
    }

    if ( c->Optimizing() || GetType()->Tag() == TYPE_VOID )
        return ThisPtr();
    else
        return AssignToTemporary(this, c, red_stmt);
}

StmtPtr CallExpr::ReduceToSingletons(Reducer* c) {
    StmtPtr func_stmt;

    if ( ! IsSingleton(func, c) )
        func = func->Reduce(c, func_stmt);

    auto args_stmt = args->ReduceToSingletons(c);

    return MergeStmts(this, func_stmt, args_stmt);
}

ExprPtr LambdaExpr::Duplicate() { return SetSucc(new LambdaExpr(this)); }

ExprPtr LambdaExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() )
        return ThisPtr();

    UpdateCaptures(c);

    return AssignToTemporary(this, c, red_stmt);
}

StmtPtr LambdaExpr::ReduceToSingletons(Reducer* c) {
    UpdateCaptures(c);
    return nullptr;
}

void LambdaExpr::UpdateCaptures(Reducer* c) {
    if ( captures ) {
        for ( auto& cp : *captures ) {
            auto& cid = cp.Id();

            if ( ! private_captures.contains(cid) )
                cp.SetID(c->UpdateID(cid));
        }

        c->UpdateIDs(&outer_ids);
    }
}

ExprPtr EventExpr::Duplicate() {
    auto args_d = args->Duplicate()->AsListExprPtr();
    return SetSucc(new EventExpr(name.c_str(), args_d));
}

ExprPtr EventExpr::Inline(Inliner* inl) {
    args = cast_intrusive<ListExpr>(args->Inline(inl));
    return ThisPtr();
}

ExprPtr EventExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() ) {
        auto e = c->UpdateExpr(args, this);
        auto args = e->AsListExprPtr();
        return ThisPtr();
    }

    red_stmt = nullptr;

    if ( ! IsReduced(Args(), c) )
        // We assume that ListExpr won't transform itself fundamentally.
        (void)Args()->Reduce(c, red_stmt);

    return ThisPtr();
}

StmtPtr EventExpr::ReduceToSingletons(Reducer* c) { return args->ReduceToSingletons(c); }

ExprPtr ListExpr::Duplicate() {
    auto new_l = new ListExpr();

    loop_over_list(exprs, i) new_l->Append(exprs[i]->Duplicate());

    return SetSucc(new_l);
}

ExprPtr ListExpr::Inline(Inliner* inl) {
    loop_over_list(exprs, i) {
        auto in_expr = exprs[i]->Inline(inl);
        Unref(exprs[i]);
        exprs[i] = in_expr.release();
    }

    return ThisPtr();
}

ExprPtr ListExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    red_stmt = nullptr;

    loop_over_list(exprs, i) {
        if ( c->Optimizing() ) {
            auto e_i = c->UpdateExpr(exprs[i]->ThisPtr(), this);
            auto old = exprs.replace(i, e_i.release());
            Unref(old);
            continue;
        }

        if ( IsSingleton(exprs[i], c) )
            continue;

        StmtPtr e_stmt;
        auto old = exprs.replace(i, exprs[i]->ReduceToSingleton(c, e_stmt).release());
        Unref(old);

        if ( e_stmt )
            red_stmt = MergeStmts(this, red_stmt, e_stmt);
    }

    return ThisPtr();
}

StmtPtr ListExpr::ReduceToSingletons(Reducer* c) {
    StmtPtr red_stmt;

    loop_over_list(exprs, i) {
        auto& e_i = exprs[i];

        if ( IsSingleton(e_i, c) )
            continue;

        StmtPtr e_stmt;
        auto new_e_i = e_i->ReduceToSingleton(c, e_stmt);
        auto old = exprs.replace(i, new_e_i.release());
        Unref(old);

        if ( e_stmt )
            red_stmt = MergeStmts(this, red_stmt, e_stmt);
    }

    return red_stmt;
}

ExprPtr CanConvertExpr::Duplicate() { return SetSucc(new CanConvertExpr(op->Duplicate(), conversion_type)); }

ExprPtr CastExpr::Duplicate() { return SetSucc(new CastExpr(op->Duplicate(), type)); }

ExprPtr IsExpr::Duplicate() { return SetSucc(new IsExpr(op->Duplicate(), t)); }

InlineExpr::InlineExpr(ScriptFuncPtr arg_sf, ListExprPtr arg_args, std::vector<IDPtr> arg_params,
                       std ::vector<bool> arg_param_is_modified, StmtPtr arg_body, int _frame_offset, TypePtr ret_type)
    : Expr(EXPR_INLINE), sf(std::move(arg_sf)), args(std::move(arg_args)), body(std::move(arg_body)) {
    params = std::move(arg_params);
    param_is_modified = std::move(arg_param_is_modified);
    frame_offset = _frame_offset;
    type = std::move(ret_type);
}

bool InlineExpr::IsPure() const { return args->IsPure() && body->IsPure(); }

ValPtr InlineExpr::Eval(Frame* f) const {
    auto v = eval_list(f, args.get());

    if ( ! v )
        return nullptr;

    int nargs = args->Exprs().length();

    f->Reset(frame_offset + nargs);
    f->AdjustOffset(frame_offset);

    // Assign the arguments.
    for ( auto i = 0; i < nargs; ++i )
        f->SetElement(i, (*v)[i]);

    auto flow = FLOW_NEXT;
    ValPtr result;
    try {
        result = body->Exec(f, flow);
    }

    catch ( InterpreterException& e ) {
        f->AdjustOffset(-frame_offset);
        throw;
    }

    f->AdjustOffset(-frame_offset);

    return result;
}

ExprPtr InlineExpr::Duplicate() {
    auto args_d = args->Duplicate()->AsListExprPtr();
    auto body_d = body->Duplicate();
    return SetSucc(new InlineExpr(sf, args_d, params, param_is_modified, body_d, frame_offset, type));
}

ExprPtr InlineExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    // We have to be careful regarding the order in which we evaluate
    // the various elements that go into inlining the call. First, the
    // arguments need to be reduced in the current scope, not the block
    // we'll create for the inlined code. Second, we need to generate the
    // identifiers for the formal parameters *after* creating that inner
    // block scope, so the variables are distinct to that context. Finally,
    // when done we need to create the return variable within that scope
    // (so it's unique to the inlined instance) even though we'll use it -
    // and possibly other locals from the inlining, via optimization - in
    // the outer scope.

    auto args_list = args->Exprs();
    std::vector<ExprPtr> red_args; // holds the arguments as singletons

    red_stmt = nullptr;

    // Gather up the reduced arguments.
    loop_over_list(args_list, i) {
        StmtPtr arg_red_stmt;
        red_args.emplace_back(args_list[i]->Reduce(c, arg_red_stmt));
        red_stmt = MergeStmts(this, red_stmt, arg_red_stmt);
    }

    // Start the inline block, so the parameters we generate pick up
    // its naming scope.
    c->PushInlineBlock();

    // Generate the parameters and assign them to the reduced arguments.
    loop_over_list(args_list, j) {
        auto assign_stmt = with_location_of(c->GenParam(params[j], red_args[j], param_is_modified[j]), this);
        red_stmt = MergeStmts(this, red_stmt, assign_stmt);
    }

    // Generate the return variable distinct to the inner block.
    auto ret_val = c->GetRetVar(type);
    if ( ret_val )
        ret_val->SetLocationInfo(GetLocationInfo());

    body = body->Reduce(c);
    c->PopInlineBlock();

    auto catch_ret = with_location_of(make_intrusive<CatchReturnStmt>(sf, body, ret_val), this);

    red_stmt = MergeStmts(this, red_stmt, catch_ret);

    return ret_val ? ret_val->Duplicate() : nullptr;
}

TraversalCode InlineExpr::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreExpr(this);
    HANDLE_TC_EXPR_PRE(tc);

    tc = args->Traverse(cb);
    HANDLE_TC_EXPR_PRE(tc);

    tc = body->Traverse(cb);
    HANDLE_TC_EXPR_PRE(tc);

    tc = cb->PostExpr(this);
    HANDLE_TC_EXPR_POST(tc);
}

void InlineExpr::ExprDescribe(ODesc* d) const {
    if ( d->IsReadable() ) {
        d->Add("inline(");
        args->Describe(d);
        d->Add(")(");
        for ( auto& p : params ) {
            if ( &p != &params[0] )
                d->AddSP(",");
            d->Add(p->Name());
        }
        d->Add("){");
        body->Describe(d);
        d->Add("}");
    }
    else {
        args->Describe(d);
        body->Describe(d);
    }
}

AppendToExpr::AppendToExpr(ExprPtr arg_op1, ExprPtr arg_op2)
    : BinaryExpr(EXPR_APPEND_TO, std::move(arg_op1), std::move(arg_op2)) {
    // This is an internal type, so we don't bother with type-checking
    // or coercions, those have already been done before we're created.
    SetType(op1->GetType());
}

ValPtr AppendToExpr::Eval(Frame* f) const {
    auto v1 = op1->Eval(f);

    if ( ! v1 )
        return nullptr;

    auto v2 = op2->Eval(f);

    if ( ! v2 )
        return nullptr;

    VectorVal* vv = v1->AsVectorVal();

    if ( ! vv->Assign(vv->Size(), v2) )
        RuntimeError("type-checking failed in vector append");

    return v1;
}

ExprPtr AppendToExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    return SetSucc(new AppendToExpr(op1_d, op2_d));
}

ExprPtr AppendToExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() ) {
        op1 = c->UpdateExpr(op1, this);
        op2 = c->UpdateExpr(op2, this);
    }

    return ThisPtr();
}

ExprPtr AppendToExpr::ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) {
    auto at_stmt = with_location_of(make_intrusive<ExprStmt>(Duplicate()), this);
    red_stmt = at_stmt->Reduce(c);
    return op1->AsRefExprPtr()->GetOp1();
}

IndexAssignExpr::IndexAssignExpr(ExprPtr arg_op1, ExprPtr arg_op2, ExprPtr arg_op3)
    : BinaryExpr(EXPR_INDEX_ASSIGN, std::move(arg_op1), std::move(arg_op2)) {
    op3 = arg_op3;
    SetType(op3->GetType());
}

ValPtr IndexAssignExpr::Eval(Frame* f) const {
    auto v1 = op1->Eval(f);
    auto v2 = op2->Eval(f);
    auto v3 = op3->Eval(f);

    AssignToIndex(v1, v2, v3);

    return nullptr;
}

ExprPtr IndexAssignExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() ) {
        op1 = c->UpdateExpr(op1, this);
        op2 = c->UpdateExpr(op2, this);
        op3 = c->UpdateExpr(op3, this);
    }

    return ThisPtr();
}

ExprPtr IndexAssignExpr::ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) {
    // Yields a statement performing the assignment and for the
    // expression the LHS (but turned into an RHS).
    if ( op1->Tag() != EXPR_NAME )
        Internal("Confusion in IndexAssignExpr::ReduceToSingleton");

    StmtPtr op1_red_stmt;
    op1 = op1->Reduce(c, op1_red_stmt);

    auto assign_stmt = with_location_of(make_intrusive<ExprStmt>(Duplicate()), this);

    auto index = op2->AsListExprPtr();
    auto res = with_location_of(make_intrusive<IndexExpr>(GetOp1(), index, false), this);
    auto final_res = res->ReduceToSingleton(c, red_stmt);

    red_stmt = MergeStmts(this, op1_red_stmt, assign_stmt, red_stmt);

    return final_res;
}

ExprPtr IndexAssignExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();
    auto op3_d = op3->Duplicate();

    return SetSucc(new IndexAssignExpr(op1_d, op2_d, op3_d));
}

TraversalCode IndexAssignExpr::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreExpr(this);
    HANDLE_TC_EXPR_PRE(tc);

    tc = op1->Traverse(cb);
    HANDLE_TC_EXPR_PRE(tc);

    tc = op2->Traverse(cb);
    HANDLE_TC_EXPR_PRE(tc);

    tc = op3->Traverse(cb);
    HANDLE_TC_EXPR_PRE(tc);

    tc = cb->PostExpr(this);
    HANDLE_TC_EXPR_POST(tc);
}

void IndexAssignExpr::ExprDescribe(ODesc* d) const {
    op1->Describe(d);
    if ( d->IsReadable() )
        d->Add("[");

    op2->Describe(d);
    if ( d->IsReadable() ) {
        d->Add("]");
        d->Add(" []= ");
    }

    op3->Describe(d);
}

FieldLHSAssignExpr::FieldLHSAssignExpr(ExprPtr arg_op1, ExprPtr arg_op2, const char* _field_name, int _field)
    : BinaryExpr(EXPR_FIELD_LHS_ASSIGN, std::move(arg_op1), std::move(arg_op2)) {
    field_name = _field_name;
    field = _field;
    SetType(op2->GetType());
}

ValPtr FieldLHSAssignExpr::Eval(Frame* f) const {
    auto v1 = op1->Eval(f);
    auto v2 = op2->Eval(f);

    if ( v1 && v2 ) {
        RecordVal* r = v1->AsRecordVal();
        r->Assign(field, std::move(v2));
    }

    return nullptr;
}

ExprPtr FieldLHSAssignExpr::Duplicate() {
    auto op1_d = op1->Duplicate();
    auto op2_d = op2->Duplicate();

    return SetSucc(new FieldLHSAssignExpr(op1_d, op2_d, field_name, field));
}

ExprPtr FieldLHSAssignExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() ) {
        op1 = c->UpdateExpr(op1, this);
        op2 = c->UpdateExpr(op2, this);
    }

    return ThisPtr();
}

ExprPtr FieldLHSAssignExpr::ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) {
    // Yields a statement performing the assignment and for the
    // expression the LHS (but turned into an RHS).
    if ( op1->Tag() != EXPR_NAME )
        Internal("Confusion in FieldLHSAssignExpr::ReduceToSingleton");

    StmtPtr op1_red_stmt;
    op1 = op1->Reduce(c, op1_red_stmt);

    auto assign_stmt = with_location_of(make_intrusive<ExprStmt>(Duplicate()), this);

    auto field_res = with_location_of(make_intrusive<FieldExpr>(op1, field_name), this);
    StmtPtr field_res_stmt;
    auto res = field_res->ReduceToSingleton(c, field_res_stmt);

    red_stmt = MergeStmts(this, MergeStmts(this, op1_red_stmt, assign_stmt), red_stmt, field_res_stmt);

    return res;
}

void FieldLHSAssignExpr::ExprDescribe(ODesc* d) const {
    op1->Describe(d);
    if ( d->IsReadable() )
        d->Add("$");

    d->Add(field_name);

    if ( d->IsReadable() )
        d->Add(" $= ");

    op2->Describe(d);
}

// Helper functions.
// This first one mines out of a given statement in an assignment chain the
// variable that occurs as a LHS target, so 'x' for "x$foo = y$bar".
static NameExprPtr get_RFU_LHS_var(const Stmt* s) {
    auto s_e = s->AsExprStmt()->StmtExpr();
    auto var = s_e->GetOp1()->GetOp1()->GetOp1();
    ASSERT(var->Tag() == EXPR_NAME);
    return cast_intrusive<NameExpr>(std::move(var));
}

// This one mines out the RHS, so 'y' for "x$foo = y$bar", or for
// "x$foo = x$foo + y$bar" (which is what "x$foo += y$bar" is at this point).
static NameExprPtr get_RFU_RHS_var(const Stmt* s) {
    auto s_e = s->AsExprStmt()->StmtExpr();
    auto rhs = s_e->GetOp2();

    ExprPtr var;
    if ( rhs->Tag() == EXPR_FIELD )
        var = rhs->GetOp1();
    else
        var = rhs->GetOp2()->GetOp1();

    ASSERT(var->Tag() == EXPR_NAME);
    return cast_intrusive<NameExpr>(std::move(var));
}

RecordFieldUpdatesExpr::RecordFieldUpdatesExpr(ExprTag t, const std::vector<const Stmt*>& stmts,
                                               std::set<const Stmt*>& stmt_pool)
    : BinaryExpr(t, get_RFU_LHS_var(stmts[0]), get_RFU_RHS_var(stmts[0])) {
    // Build up the LHS map (record fields we're assigning/adding) and RHS map
    // (record fields from which we're assigning).
    for ( auto s : stmts ) {
        auto s_e = s->AsExprStmt()->StmtExpr();
        auto lhs = s_e->GetOp1()->GetOp1();
        auto lhs_field = lhs->AsFieldExpr()->Field();

        auto rhs = s_e->GetOp2();
        if ( rhs->Tag() != EXPR_FIELD )
            // It's "x$foo = x$foo + y$bar".
            rhs = rhs->GetOp2();

        auto rhs_field = rhs->AsFieldExpr()->Field();

        lhs_map.push_back(lhs_field);
        rhs_map.push_back(rhs_field);

        // Consistency check that the statement is indeed in the pool,
        // before we remove it.
        ASSERT(stmt_pool.contains(s));
        stmt_pool.erase(s);
    }

    SetType(base_type(TYPE_VOID));
}

RecordFieldUpdatesExpr::RecordFieldUpdatesExpr(ExprTag t, ExprPtr e1, ExprPtr e2, std::vector<int> _lhs_map,
                                               std::vector<int> _rhs_map)
    : BinaryExpr(t, std::move(e1), std::move(e2)) {
    lhs_map = std::move(_lhs_map);
    rhs_map = std::move(_rhs_map);
    SetType(base_type(TYPE_VOID));
}

ValPtr RecordFieldUpdatesExpr::Fold(Val* v1, Val* v2) const {
    auto rv1 = v1->AsRecordVal();
    auto rv2 = v2->AsRecordVal();

    for ( size_t i = 0; i < lhs_map.size(); ++i )
        FoldField(rv1, rv2, i);

    return nullptr;
}

void RecordFieldUpdatesExpr::ExprDescribe(ODesc* d) const {
    op1->Describe(d);
    d->Add(expr_name(tag));
    op2->Describe(d);
}

ExprPtr RecordFieldUpdatesExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() ) {
        op1 = c->UpdateExpr(op1, this);
        op2 = c->UpdateExpr(op2, this);
    }

    red_stmt = nullptr;

    if ( ! IsSingleton(op1, c) )
        op1 = op1->ReduceToSingleton(c, red_stmt);

    StmtPtr red2_stmt;
    if ( ! IsSingleton(op2, c) )
        op2 = op2->ReduceToSingleton(c, red2_stmt);

    red_stmt = MergeStmts(this, red_stmt, std::move(red2_stmt));

    return ThisPtr();
}

ExprPtr AssignRecordFieldsExpr::Duplicate() {
    auto e1 = op1->Duplicate();
    auto e2 = op2->Duplicate();
    return SetSucc(new AssignRecordFieldsExpr(std::move(e1), std::move(e2), lhs_map, rhs_map));
}

void AssignRecordFieldsExpr::FoldField(RecordVal* rv1, RecordVal* rv2, size_t i) const {
    rv1->Assign(lhs_map[i], rv2->GetField(rhs_map[i]));
}

ConstructFromRecordExpr::ConstructFromRecordExpr(const RecordConstructorExpr* orig)
    : AssignRecordFieldsExpr(nullptr, nullptr, {}, {}) {
    tag = EXPR_REC_CONSTRUCT_WITH_REC;
    SetType(orig->GetType());

    // Arguments used in original and final constructor.
    auto& orig_args = orig->Op()->Exprs();
    // The one we'll build up below:
    auto args = with_location_of(make_intrusive<ListExpr>(), orig);

    auto src_id = FindMostCommonRecordSource(orig->Op());
    auto& map = orig->Map();

    for ( size_t i = 0; i < orig_args.size(); ++i ) {
        auto e = orig_args[i];
        auto src = FindRecordSource(e);
        if ( src && src->GetOp1()->AsNameExpr()->IdPtr() == src_id ) {
            // "map" might be nil if we're optimize [$x = foo$bar].
            lhs_map.push_back(map ? (*map)[i] : i);
            rhs_map.push_back(src->Field());
        }
        else
            args->Append({NewRef{}, e});
    }

    auto rt = cast_intrusive<RecordType>(orig->GetType());
    op1 = with_location_of(make_intrusive<RecordConstructorExpr>(std::move(rt), std::move(args), false), orig);
    op2 = with_location_of(make_intrusive<NameExpr>(std::move(src_id)), orig);
}

IDPtr ConstructFromRecordExpr::FindMostCommonRecordSource(const ListExprPtr& exprs) {
    // Maps identifiers to how often they appear in the constructor's
    // arguments as a field reference. Used to find the most common.
    std::unordered_map<IDPtr, int> id_cnt;

    for ( auto e : exprs->Exprs() ) {
        auto src = FindRecordSource(e);
        if ( src ) {
            auto id = src->GetOp1()->AsNameExpr()->IdPtr();
            ++id_cnt[id];
        }
    }

    if ( id_cnt.empty() )
        return nullptr;

    // Return the most common.
    auto max_entry =
        std::ranges::max_element(id_cnt, [](const std::pair<IDPtr, int>& p1, const std::pair<IDPtr, int>& p2) {
            return p1.second < p2.second;
        });
    return max_entry->first;
}

FieldExprPtr ConstructFromRecordExpr::FindRecordSource(const Expr* const_e) {
    // The following cast just saves us from having to define a "const" version
    // of AsFieldAssignExprPtr().
    auto e = const_cast<Expr*>(const_e);
    const auto fa = e->AsFieldAssignExprPtr();
    auto fa_rhs = e->GetOp1();

    if ( fa_rhs->Tag() != EXPR_FIELD )
        return nullptr;

    auto rhs_rec = fa_rhs->GetOp1();
    if ( rhs_rec->Tag() != EXPR_NAME )
        return nullptr;

    return cast_intrusive<FieldExpr>(std::move(fa_rhs));
}

ExprPtr ConstructFromRecordExpr::Duplicate() {
    auto e1 = op1->Duplicate();
    auto e2 = op2->Duplicate();
    return SetSucc(new ConstructFromRecordExpr(std::move(e1), std::move(e2), lhs_map, rhs_map));
}

ExprPtr ConstructFromRecordExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() ) {
        op1 = c->UpdateExpr(op1, this);
        op2 = c->UpdateExpr(op2, this);
    }

    red_stmt = nullptr;

    if ( ! HasReducedOps(op1.get(), c) )
        red_stmt = op1->ReduceToSingletons(c);

    StmtPtr red2_stmt;
    if ( ! IsSingleton(op2, c) )
        op2 = op2->ReduceToSingleton(c, red2_stmt);

    red_stmt = MergeStmts(this, red_stmt, std::move(red2_stmt));

    if ( c->Optimizing() )
        return ThisPtr();
    else
        return AssignToTemporary(this, c, red_stmt);
}

ExprPtr AddRecordFieldsExpr::Duplicate() {
    auto e1 = op1->Duplicate();
    auto e2 = op2->Duplicate();
    return SetSucc(new AddRecordFieldsExpr(std::move(e1), std::move(e2), lhs_map, rhs_map));
}

void AddRecordFieldsExpr::FoldField(RecordVal* rv1, RecordVal* rv2, size_t i) const {
    // The goal here is correctness, not efficiency, since normally this
    // expression only exists temporarily before being compiled to ZAM.
    // Doing it this way saves us from having to switch on the type of the '+'
    // operands.
    auto lhs_val = rv1->GetField(lhs_map[i]);
    auto rhs_val = rv2->GetField(rhs_map[i]);

    auto lhs_const = make_intrusive<ConstExpr>(lhs_val);
    auto rhs_const = make_intrusive<ConstExpr>(rhs_val);

    auto add_expr = make_intrusive<AddExpr>(lhs_const, rhs_const);
    auto sum = eval_in_isolation(add_expr);
    ASSERT(sum);

    rv1->Assign(lhs_map[i], std::move(sum));
}

CoerceToAnyExpr::CoerceToAnyExpr(ExprPtr arg_op) : UnaryExpr(EXPR_TO_ANY_COERCE, std::move(arg_op)) {
    type = base_type(TYPE_ANY);
}

ExprPtr CoerceToAnyExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    if ( c->Optimizing() )
        op = c->UpdateExpr(op, this);

    red_stmt = nullptr;

    if ( ! IsSingleton(op, c) )
        op = op->ReduceToSingleton(c, red_stmt);

    if ( c->Optimizing() )
        return ThisPtr();
    else
        return AssignToTemporary(this, c, red_stmt);
}

ValPtr CoerceToAnyExpr::Fold(Val* v) const { return {NewRef{}, v}; }

ExprPtr CoerceToAnyExpr::Duplicate() { return SetSucc(new CoerceToAnyExpr(op->Duplicate())); }

CoerceFromAnyExpr::CoerceFromAnyExpr(ExprPtr arg_op, TypePtr to_type)
    : UnaryExpr(EXPR_FROM_ANY_COERCE, std::move(arg_op)) {
    type = std::move(to_type);
}

ValPtr CoerceFromAnyExpr::Fold(Val* v) const {
    auto t = GetType()->Tag();
    auto vt = v->GetType()->Tag();

    if ( vt != t && vt != TYPE_ERROR )
        RuntimeError("incompatible \"any\" type");

    return {NewRef{}, v};
}

ExprPtr CoerceFromAnyExpr::Duplicate() { return SetSucc(new CoerceFromAnyExpr(op->Duplicate(), type)); }

CoerceFromAnyVecExpr::CoerceFromAnyVecExpr(ExprPtr arg_op, TypePtr to_type)
    : UnaryExpr(EXPR_FROM_ANY_VEC_COERCE, std::move(arg_op)) {
    type = std::move(to_type);
}

ValPtr CoerceFromAnyVecExpr::Eval(Frame* f) const {
    if ( IsError() )
        return nullptr;

    auto v = op->Eval(f);

    if ( ! v )
        return nullptr;

    auto vv = v->AsVectorVal();
    if ( ! vv->Concretize(type->Yield()) )
        RuntimeError("incompatible \"vector of any\" type");

    return v;
}

ExprPtr CoerceFromAnyVecExpr::Duplicate() { return SetSucc(new CoerceFromAnyVecExpr(op->Duplicate(), type)); }

AnyIndexExpr::AnyIndexExpr(ExprPtr arg_op, int _index) : UnaryExpr(EXPR_ANY_INDEX, std::move(arg_op)) {
    index = _index;
    type = op->GetType();
}

ValPtr AnyIndexExpr::Fold(Val* v) const { return v->AsListVal()->Idx(index); }

ExprPtr AnyIndexExpr::Duplicate() { return SetSucc(new AnyIndexExpr(op->Duplicate(), index)); }

ExprPtr AnyIndexExpr::Reduce(Reducer* c, StmtPtr& red_stmt) { return ThisPtr(); }

void AnyIndexExpr::ExprDescribe(ODesc* d) const {
    if ( d->IsReadable() )
        d->Add("(");

    op->Describe(d);

    if ( d->IsReadable() )
        d->Add(")any [");

    d->Add(index);

    if ( d->IsReadable() )
        d->Add("]");
}

ScriptOptBuiltinExpr::ScriptOptBuiltinExpr(SOBuiltInTag _tag, ExprPtr _arg1, ExprPtr _arg2)
    : Expr(EXPR_SCRIPT_OPT_BUILTIN), tag(_tag), arg1(std::move(_arg1)), arg2(std::move(_arg2)) {
    BuildEvalExpr();
    SetType(eval_expr->GetType());
}

ScriptOptBuiltinExpr::ScriptOptBuiltinExpr(SOBuiltInTag _tag, CallExprPtr _call)
    : Expr(EXPR_SCRIPT_OPT_BUILTIN), tag(_tag), call(std::move(_call)) {
    const auto& args = call->Args()->Exprs();
    ASSERT(args.size() <= 2);

    if ( ! args.empty() ) {
        arg1 = args[0]->Duplicate();
        if ( args.size() > 1 ) {
            arg2 = args[1]->Duplicate();
        }
    }

    BuildEvalExpr();

    SetType(eval_expr->GetType());
}

ValPtr ScriptOptBuiltinExpr::Eval(Frame* f) const { return eval_expr->Eval(f); }

void ScriptOptBuiltinExpr::ExprDescribe(ODesc* d) const {
    switch ( tag ) {
        case MINIMUM: d->Add("ZAM_minimum"); break;
        case MAXIMUM: d->Add("ZAM_maximum"); break;
        case HAS_ELEMENTS: d->Add("ZAM_has_elements"); break;
        case FUNC_ID_STRING: d->Add("ZAM_id_string"); break;
    }

    d->Add("(");
    arg1->Describe(d);

    if ( arg2 ) {
        d->AddSP(",");
        arg2->Describe(d);
    }

    d->Add(")");
}

TraversalCode ScriptOptBuiltinExpr::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreExpr(this);
    HANDLE_TC_EXPR_PRE(tc);

    tc = arg1->Traverse(cb);
    HANDLE_TC_EXPR_PRE(tc);

    if ( arg2 ) {
        tc = arg2->Traverse(cb);
        HANDLE_TC_EXPR_PRE(tc);
    }

    tc = cb->PostExpr(this);
    HANDLE_TC_EXPR_POST(tc);
}

bool ScriptOptBuiltinExpr::IsPure() const { return arg1->IsPure() && (! arg2 || arg2->IsPure()); }

ExprPtr ScriptOptBuiltinExpr::Duplicate() {
    auto new_me = make_intrusive<ScriptOptBuiltinExpr>(tag, arg1, arg2);
    return with_location_of(std::move(new_me), this);
}

ExprPtr ScriptOptBuiltinExpr::Reduce(Reducer* c, StmtPtr& red_stmt) {
    auto orig_arg1 = arg1;
    auto orig_arg2 = arg2;

    if ( c->Optimizing() ) {
        arg1 = c->UpdateExpr(arg1, this);
        if ( arg2 )
            arg2 = c->UpdateExpr(arg2, this);
    }
    else {
        arg1 = arg1->Reduce(c, red_stmt);
        if ( arg2 ) {
            StmtPtr red_stmt2;
            arg2 = arg2->Reduce(c, red_stmt2);
            red_stmt = MergeStmts(this, std::move(red_stmt), std::move(red_stmt2));
        }
    }

    if ( arg1 != orig_arg1 || arg2 != orig_arg2 )
        BuildEvalExpr();

    if ( arg1->IsConst() && (! arg2 || arg2->IsConst()) ) {
        auto res = eval_in_isolation(eval_expr);
        ASSERT(res);
        return with_location_of(make_intrusive<ConstExpr>(res), this);
    }

    if ( c->Optimizing() )
        return ThisPtr();
    else
        return AssignToTemporary(this, c, red_stmt);
}

void ScriptOptBuiltinExpr::BuildEvalExpr() {
    switch ( tag ) {
        case MINIMUM: {
            auto cmp = make_intrusive<RelExpr>(EXPR_LT, arg1, arg2);
            eval_expr = make_intrusive<CondExpr>(cmp, arg1, arg2);
            break;
        }

        case MAXIMUM: {
            auto cmp = make_intrusive<RelExpr>(EXPR_GT, arg1, arg2);
            eval_expr = make_intrusive<CondExpr>(cmp, arg1, arg2);
            break;
        }

        case HAS_ELEMENTS: {
            auto size = make_intrusive<SizeExpr>(arg1);
            auto zero = make_intrusive<ConstExpr>(val_mgr->Count(0));
            eval_expr = make_intrusive<EqExpr>(EXPR_NE, size, zero);
            break;
        }

        case FUNC_ID_STRING: {
            auto args = make_intrusive<ListExpr>();
            if ( arg1 ) {
                args->Append(arg1);
                if ( arg2 )
                    args->Append(arg2);
            }
            eval_expr = make_intrusive<CallExpr>(call->FuncPtr(), args);
            break;
        }
    }

    SetType(eval_expr->GetType());
}

void NopExpr::ExprDescribe(ODesc* d) const {
    if ( d->IsReadable() )
        d->Add("NOP");
}

ValPtr NopExpr::Eval(Frame* /* f */) const { return nullptr; }

ExprPtr NopExpr::Duplicate() { return SetSucc(new NopExpr()); }

TraversalCode NopExpr::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreExpr(this);
    HANDLE_TC_EXPR_PRE(tc);

    tc = cb->PostExpr(this);
    HANDLE_TC_EXPR_POST(tc);
}

static bool same_singletons(ExprPtr e1, ExprPtr e2) {
    auto e1t = e1->Tag();
    auto e2t = e2->Tag();

    if ( (e1t != EXPR_NAME && e1t != EXPR_CONST) || (e2t != EXPR_NAME && e2t != EXPR_CONST) )
        return false;

    if ( e1t != e2t )
        return false;

    if ( e1t == EXPR_CONST ) {
        auto c1 = e1->AsConstExpr()->Value();
        auto c2 = e2->AsConstExpr()->Value();

        if ( ! is_atomic_val(c1) || ! is_atomic_val(c2) )
            return false;

        return same_atomic_val(c1, c2);
    }

    auto i1 = e1->AsNameExpr()->Id();
    auto i2 = e2->AsNameExpr()->Id();

    return i1 == i2;
}


bool WillTransform(const Expr* e, Reducer* c) {
    switch ( e->Tag() ) {
        case EXPR_NAME: return ! IsReduced(e, c);

        case EXPR_INCR:
        case EXPR_DECR: return true;

        case EXPR_COMPLEMENT: return e->GetOp1()->Tag() == EXPR_COMPLEMENT;

        case EXPR_NOT: return e->GetOp1()->Tag() == EXPR_NOT && e->GetOp1()->GetType()->Tag() == TYPE_BOOL;

        case EXPR_POSITIVE: return e->GetOp1()->GetType()->Tag() != TYPE_COUNT;

        case EXPR_NEGATE: return e->GetOp1()->Tag() == EXPR_NEGATE;

        case EXPR_ADD: {
            auto op1 = e->GetOp1();
            auto op2 = e->GetOp2();
            return op1->IsZero() || op2->IsZero() || op1->Tag() == EXPR_NEGATE || op2->Tag() == EXPR_NEGATE;
        }

        case EXPR_SUB: {
            auto op1 = e->GetOp1();
            auto op2 = e->GetOp2();
            auto t = e->GetType()->Tag();
            return op2->IsZero() || op2->Tag() == EXPR_NEGATE ||
                   (t != TYPE_VECTOR && t != TYPE_TABLE && op1->Tag() == EXPR_NAME && op2->Tag() == EXPR_NAME &&
                    op1->AsNameExpr()->Id() == op2->AsNameExpr()->Id());
        }

        case EXPR_ADD_TO:
        case EXPR_REMOVE_FROM: return true;

        case EXPR_TIMES: {
            auto op1 = e->GetOp1();
            auto op2 = e->GetOp2();
            return op1->IsZero() || op2->IsZero() || op1->IsOne() || op2->IsOne();
        }

        case EXPR_DIVIDE: return e->GetOp2()->IsOne();

        case EXPR_AND:
        case EXPR_OR:
        case EXPR_XOR:
        case EXPR_LSHIFT:
        case EXPR_RSHIFT: {
            auto op1 = e->GetOp1();
            auto op2 = e->GetOp2();
            return e->GetType()->Tag() == TYPE_COUNT &&
                   (op1->IsZero() || op2->IsZero() || (same_singletons(op1, op2) && op1->Tag() == EXPR_NAME));
        }

        case EXPR_AND_AND:
        case EXPR_OR_OR: return ! IsVector(e->GetOp1()->GetType()->Tag());

        case EXPR_LT:
        case EXPR_LE:
        case EXPR_EQ:
        case EXPR_NE:
        case EXPR_GE:
        case EXPR_GT:
            if ( IsHasElementsTest(static_cast<const CmpExpr*>(e)) )
                return true;
            return e->GetType()->Tag() == TYPE_BOOL && same_singletons(e->GetOp1(), e->GetOp2());

        case EXPR_COND: return ! HasReducedOps(e, c);

        case EXPR_REF: return e->GetOp1()->Tag() != EXPR_NAME;

        case EXPR_ASSIGN:
        case EXPR_FIELD_ASSIGN: return true;

        case EXPR_ARITH_COERCE: {
            auto op = e->GetOp1();
            if ( op->Tag() != EXPR_CONST )
                return false;
            if ( IsArithmetic(e->GetType()->Tag()) )
                return true;
            return IsArithmetic(op->AsConstExpr()->Value()->GetType()->Tag());
        }

        case EXPR_RECORD_COERCE: return e->GetOp1()->Tag() == EXPR_RECORD_CONSTRUCTOR;

        case EXPR_VECTOR_COERCE: {
            auto op = e->GetOp1();
            return op->Tag() == EXPR_VECTOR_CONSTRUCTOR && op->GetType<VectorType>()->IsUnspecifiedVector();
        }

        case EXPR_CALL: {
            auto ce = static_cast<const CallExpr*>(e);
            return CheckForBuiltin(ce) || IsFoldableBiF(ce) || IsEmptyHook(ce);
        }

        case EXPR_INLINE: return true;

        default: return false;
    }
}

bool WillTransformInConditional(const Expr* e, Reducer* c) {
    switch ( e->Tag() ) {
        case EXPR_OR_OR: {
            IDPtr common_id;
            std::vector<ConstExprPtr> patterns;
            return is_pattern_cascade(e, common_id, patterns);
        }

        case EXPR_LT:
        case EXPR_LE:
        case EXPR_EQ:
        case EXPR_NE:
        case EXPR_GE:
        case EXPR_GT: return WillTransform(e, c);

        default: return false;
    }
}

// For a binary expression whose operands are now both constants, true if
// folding them can't run into trouble.
static bool IsSafeFold(const Expr* e, const ValPtr& v1, const ValPtr& v2) {
    switch ( e->Tag() ) {
        case EXPR_DIVIDE:
        case EXPR_MOD: return ! v2->IsZero();

        case EXPR_MASK: return MaskExpr::GetMask(v2.get()) <= (v1->AsAddr().GetFamily() == IPv4 ? 32 : 128);

        // The only bitwise operation that can potentially have problems is
        // left-shift. Rather than analyzing whether this particular instance
        // is okay, we assume these are rare and just go by the tag.
        case EXPR_LSHIFT: return false;

        default: return true;
    }
}

static bool IsSafeBinarySubstitution(const Expr* parent, const ExprPtr& e, const ValPtr& v) {
    auto op1 = parent->GetOp1();
    auto op2 = parent->GetOp2();

    // It's always safe if we still have a non-constant operand.  If both
    // operands are constant then we check whether the fold is safe.
    if ( e == op1 )
        return op2->IsConst() ? IsSafeFold(parent, v, op2->AsConstExpr()->ValuePtr()) : true;
    if ( e == op2 )
        return op1->IsConst() ? IsSafeFold(parent, op1->AsConstExpr()->ValuePtr(), v) : true;

    // Weird - doesn't match either of our operands. In principle this
    // might happen if we're substituting after doing some reduce logic;
    // decline the substitution to be safe.
    return false;
}

static bool IsSafeArithCoercion(const Expr* parent, const ValPtr& v) {
    const auto& t = parent->GetType();
    // We check for the issues assessed by check_and_promote() that are
    // not due to type clashes.
    const auto& vt = v->GetType();
    TypeTag v_tag = vt->Tag();
    TypeTag t_tag = t->Tag();

    if ( t_tag != TYPE_TIME && ! BothArithmetic(t_tag, v_tag) && max_type(t_tag, v_tag) != t_tag )
        return false;

    InternalTypeTag it = t->InternalType();
    InternalTypeTag vit = vt->InternalType();

    if ( it == TYPE_INTERNAL_INT && (vit == TYPE_INTERNAL_UNSIGNED || vit == TYPE_INTERNAL_DOUBLE) &&
         detail::would_overflow(vt.get(), t.get(), v.get()) )
        return false;

    if ( it == TYPE_INTERNAL_UNSIGNED && (vit == TYPE_INTERNAL_DOUBLE || vit == TYPE_INTERNAL_INT) &&
         detail::would_overflow(vt.get(), t.get(), v.get()) )
        return false;

    return true;
}

bool IsSafeSubstitution(const Expr* parent, const ExprPtr& e, const ValPtr& v) {
    switch ( parent->Tag() ) {
        case EXPR_ARITH_COERCE: return IsSafeArithCoercion(parent, v);

        case EXPR_CAST: return attempt_to_cast_value_to_type(v.get(), parent->GetType().get()) != nullptr;

        // This is a BinaryExpr, but the check below would return false when
        // "e" is not one of op1/op2 (in particular, when it is op3).  Given
        // there's no folding possible for these nodes, substitutions are
        // always safe.
        case EXPR_INDEX_ASSIGN: return true;

        case EXPR_ADD:
        case EXPR_SUB:
        case EXPR_ADD_TO:
        case EXPR_REMOVE_FROM:
        case EXPR_TIMES:
        case EXPR_DIVIDE:
        case EXPR_MASK:
        case EXPR_MOD:
        case EXPR_AND:
        case EXPR_OR:
        case EXPR_XOR:
        case EXPR_LSHIFT:
        case EXPR_RSHIFT:
        case EXPR_AND_AND:
        case EXPR_OR_OR:
        case EXPR_LT:
        case EXPR_LE:
        case EXPR_EQ:
        case EXPR_NE:
        case EXPR_GE:
        case EXPR_GT:
        case EXPR_ASSIGN:
        case EXPR_INDEX:
        case EXPR_IN:
        case EXPR_INDEX_SLICE_ASSIGN:
        case EXPR_APPEND_TO:
        case EXPR_FIELD_LHS_ASSIGN:
        case EXPR_REC_ASSIGN_FIELDS:
        case EXPR_REC_ADD_FIELDS:
        case EXPR_REC_CONSTRUCT_WITH_REC: return IsSafeBinarySubstitution(parent, e, v);

        default: return true;
    }
}

// Helpers for HasReducedOps(), for the expressions whose operands need more
// than a singleton check.

static bool HasReducedRefOps(const Expr* e, Reducer* c) {
    auto op = e->GetOp1();

    switch ( op->Tag() ) {
        case EXPR_NAME: return IsReduced(op.get(), c);

        case EXPR_FIELD: return IsReduced(op->AsFieldExpr()->Op(), c);

        case EXPR_INDEX: {
            auto ind = op->AsIndexExpr();
            return IsReduced(ind->Op1(), c) && IsReduced(ind->Op2(), c);
        }

        case EXPR_LIST: return IsReduced(op.get(), c);

        default: e->Internal("bad operand in HasReducedRefOps");
    }
}

static bool HasReducedIndexOps(const Expr* e, Reducer* c) {
    auto op1 = e->GetOp1();
    auto op2 = e->GetOp2();

    if ( ! IsSingleton(op1, c) )
        return NonReduced(e);

    if ( op2->Tag() == EXPR_LIST )
        return HasReducedOps(op2.get(), c);

    if ( IsSingleton(op2, c) )
        return true;

    return NonReduced(e);
}

static bool HasReducedRecordConstructorOps(const Expr* e, Reducer* c) {
    auto& exprs = static_cast<const RecordConstructorExpr*>(e)->Op()->Exprs();

    loop_over_list(exprs, i) {
        auto e_i = exprs[i];
        if ( ! IsSingleton(e_i->AsFieldAssignExprPtr()->Op(), c) )
            return false;
    }

    return true;
}

static bool HasReducedTableConstructorOps(const Expr* e, Reducer* c) {
    for ( const auto& expr : e->GetOp1()->AsListExpr()->Exprs() ) {
        auto a = expr->AsAssignExpr();
        auto lhs = a->GetOp1();
        auto rhs = a->GetOp2();

        // LHS is a list, not a singleton.
        if ( ! HasReducedOps(lhs.get(), c) )
            return NonReduced(e);

        // RHS might also be a list, if it's a table-of-sets or such.
        if ( rhs->Tag() == EXPR_LIST ) {
            if ( ! HasReducedOps(rhs.get(), c) )
                return NonReduced(e);
        }

        else if ( ! IsSingleton(rhs, c) )
            return NonReduced(e);
    }

    return true;
}

static bool HasReducedCallOps(const Expr* e, Reducer* c) {
    if ( WillTransform(e, c) )
        return false;

    auto ce = static_cast<const CallExpr*>(e);

    if ( ! IsSingleton(ce->Func(), c) )
        return NonReduced(e);

    // We don't use HasReducedOps() on the arguments here because for
    // ListExpr's it has some special-casing that isn't germane for calls.

    for ( const auto& expr : ce->Args()->Exprs() )
        if ( ! IsSingleton(expr, c) )
            return false;

    return true;
}

static bool HasReducedListOps(const Expr* e, Reducer* c) {
    for ( const auto& expr : static_cast<const ListExpr*>(e)->Exprs() ) {
        // Ugly hack for record and complex table constructors.
        if ( expr->Tag() == EXPR_FIELD_ASSIGN || expr->Tag() == EXPR_LIST ) {
            if ( ! HasReducedOps(expr, c) )
                return false;
        }
        else if ( ! IsSingleton(expr, c) )
            return false;
    }

    return true;
}

bool HasReducedOps(const Expr* e, Reducer* c) {
    switch ( e->Tag() ) {
        case EXPR_NAME: return IsReduced(e, c);

        case EXPR_INCR:
        case EXPR_DECR:
        case EXPR_ADD_TO:
        case EXPR_REMOVE_FROM:
        case EXPR_INLINE: return false;

        case EXPR_INDEX_ASSIGN:
        case EXPR_FIELD_LHS_ASSIGN: return true;

        case EXPR_AGGR_ADD:
        case EXPR_AGGR_DEL:
        case EXPR_VECTOR_CONSTRUCTOR: return HasReducedOps(e->GetOp1().get(), c);

        case EXPR_LAMBDA:
        case EXPR_REC_CONSTRUCT_WITH_REC:
        case EXPR_SCRIPT_OPT_BUILTIN: return IsReduced(e, c);

        case EXPR_SET_CONSTRUCTOR: return IsReduced(e->GetOp1().get(), c);

        case EXPR_ASSIGN:
        case EXPR_INDEX_SLICE_ASSIGN: return IsReduced(e->GetOp1().get(), c) && IsSingleton(e->GetOp2(), c);

        case EXPR_IN: return HasReducedOps(e->GetOp1().get(), c) && IsSingleton(e->GetOp2(), c);

        case EXPR_COND: {
            auto op1 = e->GetOp1();
            return ! IsMinOrMax(static_cast<const CondExpr*>(e)) && IsSingleton(op1, c) &&
                   IsSingleton(e->GetOp2(), c) && IsSingleton(e->GetOp3(), c) && ! op1->IsConst();
        }

        case EXPR_SCHEDULE:
            if ( IsSingleton(e->GetOp1(), c) && IsSingleton(e->GetOp2(), c) )
                return true;

            return NonReduced(e);

        case EXPR_REF: return HasReducedRefOps(e, c);
        case EXPR_INDEX: return HasReducedIndexOps(e, c);
        case EXPR_RECORD_CONSTRUCTOR: return HasReducedRecordConstructorOps(e, c);
        case EXPR_TABLE_CONSTRUCTOR: return HasReducedTableConstructorOps(e, c);
        case EXPR_CALL: return HasReducedCallOps(e, c);
        case EXPR_LIST: return HasReducedListOps(e, c);

        // EventExpr exposes its argument list via GetOp1(), but that's not
        // an operand for reduction purposes, so the default below would give
        // the wrong answer.
        case EXPR_EVENT: return true;

        default: {
            // Unary and binary expressions require singleton operands.
            // Anything without operands is trivially reduced.
            auto op1 = e->GetOp1();
            if ( ! op1 )
                return true;

            auto op2 = e->GetOp2();
            return IsSingleton(op1, c) && (! op2 || IsSingleton(op2, c));
        }
    }
}

// Helpers for IsReduced(), for the expressions needing more than a line or two.

static bool IsReducedAddTo(const Expr* e, Reducer* c) {
    auto op1 = e->GetOp1();
    auto op2 = e->GetOp2();
    auto t = op1->GetType();

    switch ( t->Tag() ) {
        case TYPE_PATTERN: return HasReducedOps(op1.get(), c) && IsSingleton(op2, c);

        case TYPE_TABLE: return IsReduced(op1.get(), c) && IsSingleton(op2, c);

        case TYPE_VECTOR:
            if ( IsVector(op2->GetType()->Tag()) && same_type(t, op2->GetType()) )
                return IsReduced(op1.get(), c) && IsSingleton(op2, c);
            break;

        default: break;
    }

    return NonReduced(e);
}

static bool IsReducedAssign(const Expr* e, Reducer* c) {
    auto ae = static_cast<const AssignExpr*>(e);
    auto op1 = e->GetOp1();
    auto op2 = e->GetOp2();

    if ( op2->Tag() == EXPR_ASSIGN )
        // Cascaded assignments are never reduced.
        return false;

    if ( ae->AssignVal() )
        // Initializations of "local" variables in "when" statements
        // are never reduced.
        return false;

    const auto& t1 = op1->GetType();
    const auto& t2 = op2->GetType();

    auto lhs_is_any = t1->Tag() == TYPE_ANY;
    auto rhs_is_any = t2->Tag() == TYPE_ANY;

    if ( lhs_is_any != rhs_is_any && op2->Tag() != EXPR_CONST )
        return NonReduced(e);

    if ( t1->Tag() == TYPE_VECTOR && t1->Yield()->Tag() != TYPE_ANY && t2->Yield() && t2->Yield()->Tag() == TYPE_ANY )
        return NonReduced(e);

    if ( op1->Tag() == EXPR_REF && op2->HasConstantOps() && op2->Tag() != EXPR_TO_ANY_COERCE )
        // We are not reduced because we should instead
        // be folded.
        return NonReduced(e);

    if ( ae->IsTemp() )
        return true;

    if ( ! HasReducedOps(op2.get(), c) )
        return NonReduced(e);

    if ( IsSingleton(op1, c) )
        return true;

    if ( op1->Tag() == EXPR_REF )
        return IsReduced(op1.get(), c);

    return NonReduced(e);
}

static bool IsReducedLambda(const Expr* e, Reducer* c) {
    auto le = static_cast<const LambdaExpr*>(e);
    const auto& captures = le->GetCaptures();

    if ( ! captures )
        return true;

    for ( auto& cp : *captures ) {
        auto& cid = cp.Id();

        if ( ! le->PrivateCaptures().contains(cid) && ! c->ID_IsReduced(cid) )
            return NonReduced(e);
    }

    return true;
}

static bool IsReducedList(const Expr* e, Reducer* c) {
    for ( const auto& expr : static_cast<const ListExpr*>(e)->Exprs() )
        if ( ! IsSingleton(expr, c) ) {
            if ( expr->Tag() != EXPR_LIST || ! IsReduced(expr, c) )
                return NonReduced(expr);
        }

    return true;
}

static bool IsReducedScriptOptBuiltin(const Expr* e, Reducer* c) {
    auto arg1 = e->GetOp1();
    auto arg2 = e->GetOp2();

    if ( ! IsReduced(arg1.get(), c) )
        return NonReduced(arg1.get());

    if ( arg2 && ! IsReduced(arg2.get(), c) )
        return NonReduced(arg2.get());

    if ( arg1->IsConst() && (! arg2 || arg2->IsConst()) )
        return NonReduced(e);

    return true;
}

bool IsReduced(const Expr* e, Reducer* c) {
    switch ( e->Tag() ) {
        case EXPR_NAME: {
            auto ne = static_cast<const NameExpr*>(e);
            if ( ne->FoldableGlobal() )
                return false;

            return c->NameIsReduced(ne);
        }

        // These are created reduced.
        case EXPR_APPEND_TO: return true;

        // Inlined bodies always need further reduction, and don't expose
        // their operands, so the default below wouldn't catch them.
        case EXPR_INLINE: return NonReduced(e);

        case EXPR_AGGR_ADD:
        case EXPR_AGGR_DEL:
        case EXPR_TO_ANY_COERCE:
        case EXPR_REC_ASSIGN_FIELDS:
        case EXPR_REC_ADD_FIELDS: return HasReducedOps(e, c);

        case EXPR_INCR:
        case EXPR_DECR: {
            auto ref_op = e->GetOp1();
            auto target = ref_op->GetOp1();

            if ( target->Tag() != EXPR_NAME || ! IsIntegral(target->GetType()->Tag()) )
                return NonReduced(e);

            return IsReduced(ref_op.get(), c);
        }

        case EXPR_ADD_TO: return IsReducedAddTo(e, c);

        case EXPR_REMOVE_FROM:
            if ( e->GetOp1()->GetType()->Tag() == TYPE_TABLE )
                return IsReduced(e->GetOp1().get(), c) && IsSingleton(e->GetOp2(), c);

            return NonReduced(e);

        case EXPR_LT:
        case EXPR_LE:
        case EXPR_EQ:
        case EXPR_NE:
        case EXPR_GE:
        case EXPR_GT: return IsHasElementsTest(static_cast<const CmpExpr*>(e)) ? NonReduced(e) : true;

        case EXPR_COND: {
            auto op1 = e->GetOp1();
            if ( ! IsVector(op1->GetType()->Tag()) || ! HasReducedOps(e, c) ||
                 same_singletons(e->GetOp2(), e->GetOp3()) )
                return NonReduced(e);

            return true;
        }

        case EXPR_REF:
            if ( e->GetOp1()->Tag() == EXPR_NAME )
                return IsReduced(e->GetOp1().get(), c);

            return NonReduced(e);

        case EXPR_ASSIGN:
        case EXPR_INDEX_SLICE_ASSIGN: return IsReducedAssign(e, c);

        case EXPR_HAS_FIELD: {
            auto hfe = static_cast<const HasFieldExpr*>(e);
            return hfe->GetOp1()->GetType<RecordType>()->FieldHasAttr(hfe->Field(), ATTR_OPTIONAL);
        }

        case EXPR_SCHEDULE: return IsReduced(e->GetOp1().get(), c) && IsReduced(e->GetOp2().get(), c);

        case EXPR_CALL: {
            auto ce = static_cast<const CallExpr*>(e);
            return IsSingleton(ce->Func(), c) && IsReduced(ce->Args(), c) && ! WillTransform(e, c);
        }

        case EXPR_LAMBDA: return IsReducedLambda(e, c);

        case EXPR_EVENT: return IsReduced(static_cast<const EventExpr*>(e)->Args(), c);

        case EXPR_LIST: return IsReducedList(e, c);

        case EXPR_INDEX_ASSIGN:
            // op2 is a ListExpr, not a singleton expression.
            ASSERT(IsSingleton(e->GetOp1(), c) && IsReduced(e->GetOp2().get(), c) && IsSingleton(e->GetOp3(), c));
            return true;

        case EXPR_FIELD_LHS_ASSIGN:
            ASSERT(IsSingleton(e->GetOp1(), c) && IsReducedFieldAssignment(e->GetOp2().get(), c));
            return true;

        case EXPR_REC_CONSTRUCT_WITH_REC: return HasReducedOps(e->GetOp1().get(), c) && IsReduced(e->GetOp2().get(), c);

        case EXPR_SCRIPT_OPT_BUILTIN: return IsReducedScriptOptBuiltin(e, c);

        default:
            // Unary and binary expressions have to say for themselves whether
            // they're reduced; if we get here they haven't, so they aren't.
            // Anything without operands is a singleton, hence reduced.
            return e->GetOp1() ? NonReduced(e) : true;
    }
}


} // namespace zeek::detail
