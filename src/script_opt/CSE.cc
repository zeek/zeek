// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CSE.h"

#include "zeek/script_opt/Expr.h"

namespace zeek::detail {

CSE_ValidityChecker::CSE_ValidityChecker(std::shared_ptr<ProfileFuncs> _pfs, const std::vector<const ID*>& _ids,
                                         const Expr* _start_e, const Expr* _end_e)
    : pfs(std::move(_pfs)), ids(_ids) {
    start_e = _start_e;
    end_e = _end_e;

    // Track whether this is a record assignment, in which case
    // we're attuned to assignments to the same field for the
    // same type of record.
    if ( start_e->Tag() == EXPR_FIELD ) {
        field = start_e->AsFieldExpr()->Field();

        // Track the type of the record, too, so we don't confuse
        // field references to different records that happen to
        // have the same offset as potential aliases.
        field_type = start_e->GetOp1()->GetType();
    }

    else
        field = -1; // flags that there's no relevant field
}

TraversalCode CSE_ValidityChecker::PreStmt(const Stmt* s) {
    auto t = s->Tag();

    if ( t == STMT_WHEN ) {
        // These are too hard to analyze - they result in lambda calls
        // that can affect aggregates, etc.
        is_valid = false;
        return TC_ABORTALL;
    }

    return TC_CONTINUE;
}

TraversalCode CSE_ValidityChecker::PreExpr(const Expr* e) {
    if ( e == start_e ) {
        if ( ! have_start_e ) {
            have_start_e = true;

            // Don't analyze the expression, as it's our starting
            // point and we don't want to conflate its properties
            // with those of any intervening expressions.
            return TC_CONTINUE;
        }
    }

    if ( e == end_e ) {
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
        case EXPR_ASSIGN: {
            auto lhs_ref = e->GetOp1()->AsRefExprPtr();
            auto lhs = lhs_ref->GetOp1()->AsNameExpr();

            if ( CheckID(lhs->Id(), false) )
                return TC_ABORTALL;

            // Note, we don't use CheckAggrMod() because this is a plain
            // assignment.  It might be changing a variable's binding to
            // an aggregate ("aggr_var = new_aggr_val"), but we don't
            // introduce temporaries that are simply aliases of existing
            // variables (e.g., we don't have "<internal>::#8 = aggr_var"),
            // and so there's no concern that the temporary could now be
            // referring to the wrong aggregate.  If instead we have
            // "<internal>::#8 = aggr_var$foo", then a reassignment here
            // to "aggr_var" will already be caught by CheckID().
        } break;

        case EXPR_INDEX_ASSIGN: {
            auto lhs_aggr = e->GetOp1();
            auto lhs_aggr_id = lhs_aggr->AsNameExpr()->Id();

            if ( CheckID(lhs_aggr_id, true) || CheckTableMod(lhs_aggr->GetType()) )
                return TC_ABORTALL;
        } break;

        case EXPR_FIELD_LHS_ASSIGN: {
            auto lhs = e->GetOp1();
            auto lhs_aggr_id = lhs->AsNameExpr()->Id();
            auto lhs_field = static_cast<const FieldLHSAssignExpr*>(e)->Field();

            if ( CheckID(lhs_aggr_id, true) )
                return TC_ABORTALL;
            if ( lhs_field == field && same_type(lhs_aggr_id->GetType(), field_type) ) {
                is_valid = false;
                return TC_ABORTALL;
            }
        } break;

        case EXPR_AGGR_ADD:
        case EXPR_AGGR_DEL: ++in_aggr_mod_expr; break;

        case EXPR_APPEND_TO:
            // This doesn't directly change any identifiers, but does
            // alter an aggregate.
            if ( CheckAggrMod(e->GetType()) )
                return TC_ABORTALL;
            break;

        case EXPR_CALL:
            if ( CheckCall(e->AsCallExpr()) )
                return TC_ABORTALL;
            break;

        case EXPR_TABLE_CONSTRUCTOR:
            // These have EXPR_ASSIGN's in them that don't
            // correspond to actual assignments to variables,
            // so we don't want to traverse them.
            return TC_ABORTSTMT;

        case EXPR_RECORD_COERCE:
        case EXPR_RECORD_CONSTRUCTOR:
        case EXPR_REC_CONSTRUCT_WITH_REC:
            // Note, record coercion behaves like constructors in terms of
            // potentially executing &default functions. In either case,
            // the type of the expression reflects the type we want to analyze
            // for side effects.
            if ( CheckRecordConstructor(e->GetType()) )
                return TC_ABORTALL;
            break;

        case EXPR_INDEX:
        case EXPR_FIELD: {
            // We treat these together because they both have to be checked
            // when inside an "add" or "delete" statement.
            auto aggr = e->GetOp1();
            auto aggr_t = aggr->GetType();

            if ( in_aggr_mod_expr > 0 ) {
                auto aggr_id = aggr->AsNameExpr()->Id();

                if ( CheckID(aggr_id, true) || CheckAggrMod(aggr_t) )
                    return TC_ABORTALL;
            }

            else if ( t == EXPR_INDEX && aggr_t->Tag() == TYPE_TABLE ) {
                if ( CheckTableRef(aggr_t) )
                    return TC_ABORTALL;
            }
        } break;

        default: break;
    }

    return TC_CONTINUE;
}

TraversalCode CSE_ValidityChecker::PostExpr(const Expr* e) {
    if ( have_start_e && (e->Tag() == EXPR_AGGR_ADD || e->Tag() == EXPR_AGGR_DEL) )
        --in_aggr_mod_expr;

    return TC_CONTINUE;
}

bool CSE_ValidityChecker::CheckID(const ID* id, bool ignore_orig) {
    for ( auto i : ids ) {
        if ( ignore_orig && i == ids.front() )
            continue;

        if ( id == i )
            return Invalid(); // reassignment
    }

    return false;
}

bool CSE_ValidityChecker::CheckAggrMod(const TypePtr& t) {
    if ( ! IsAggr(t) )
        return false;

    for ( auto i : ids )
        if ( same_type(t, i->GetType()) )
            return Invalid();

    return false;
}

bool CSE_ValidityChecker::CheckRecordConstructor(const TypePtr& t) {
    if ( t->Tag() != TYPE_RECORD )
        return false;

    return CheckSideEffects(SideEffectsOp::CONSTRUCTION, t);
}

bool CSE_ValidityChecker::CheckTableMod(const TypePtr& t) {
    if ( CheckAggrMod(t) )
        return true;

    if ( t->Tag() != TYPE_TABLE )
        return false;

    return CheckSideEffects(SideEffectsOp::WRITE, t);
}

bool CSE_ValidityChecker::CheckTableRef(const TypePtr& t) { return CheckSideEffects(SideEffectsOp::READ, t); }

bool CSE_ValidityChecker::CheckCall(const CallExpr* c) {
    auto func = c->Func();
    std::string desc;
    if ( func->Tag() != EXPR_NAME )
        // Can't analyze indirect calls.
        return Invalid();

    IDSet non_local_ids;
    TypeSet aggrs;
    bool is_unknown = false;

    auto resolved = pfs->GetCallSideEffects(func->AsNameExpr(), non_local_ids, aggrs, is_unknown);
    ASSERT(resolved);

    if ( is_unknown || CheckSideEffects(non_local_ids, aggrs) )
        return Invalid();

    return false;
}

bool CSE_ValidityChecker::CheckSideEffects(SideEffectsOp::AccessType access, const TypePtr& t) {
    IDSet non_local_ids;
    TypeSet aggrs;

    if ( pfs->GetSideEffects(access, t.get(), non_local_ids, aggrs) )
        return Invalid();

    return CheckSideEffects(non_local_ids, aggrs);
}

bool CSE_ValidityChecker::CheckSideEffects(const IDSet& non_local_ids, const TypeSet& aggrs) {
    if ( non_local_ids.empty() && aggrs.empty() )
        // This is far and away the most common case.
        return false;

    for ( auto i : ids ) {
        for ( auto nli : non_local_ids )
            if ( nli == i )
                return Invalid();

        auto i_t = i->GetType();
        for ( auto a : aggrs )
            if ( same_type(a, i_t.get()) )
                return Invalid();
    }

    return false;
}

} // namespace zeek::detail
