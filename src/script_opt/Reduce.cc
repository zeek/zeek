// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/Reduce.h"

#include "zeek/script_opt/CSE.h"
#include "zeek/script_opt/Expr.h"
#include "zeek/script_opt/StmtOptInfo.h"
#include "zeek/script_opt/TempVar.h"

namespace zeek::detail {

// True if two Val's refer to the same underlying value.  We gauge this
// conservatively (i.e., for complicated values we just return false, even
// if with a lot of work we could establish that they are in fact equivalent.)

static bool same_val(const Val* v1, const Val* v2) {
    if ( is_atomic_val(v1) )
        return same_atomic_val(v1, v2);
    else
        return v1 == v2;
}

static bool same_expr(const Expr* e1, const Expr* e2, bool check_defs);

// Returns true if op1 and op2 represent the same operand. If check_defs
// is true then this factors in the reaching definitions available at
// their usages.

static bool same_op(const Expr* op1, const Expr* op2, bool check_defs) {
    if ( op1 == op2 )
        return true;

    if ( op1->Tag() != op2->Tag() )
        return false;

    if ( op1->Tag() == EXPR_NAME ) {
        // Needs to be both the same identifier and in contexts
        // where the identifier has the same definitions.
        auto op1_n = op1->AsNameExpr();
        auto op2_n = op2->AsNameExpr();

        auto op1_id = op1_n->Id();
        auto op2_id = op2_n->Id();

        if ( op1_id != op2_id )
            return false;

        if ( ! check_defs )
            return true;

        auto e_stmt_1 = op1->GetOptInfo()->stmt_num;
        auto e_stmt_2 = op2->GetOptInfo()->stmt_num;

        auto def_1 = op1_id->GetOptInfo()->DefinitionBefore(e_stmt_1);
        auto def_2 = op2_id->GetOptInfo()->DefinitionBefore(e_stmt_2);

        return def_1 == def_2 && def_1 != NO_DEF;
    }

    if ( op1->Tag() == EXPR_CONST ) {
        auto op1_c = op1->AsConstExpr();
        auto op2_c = op2->AsConstExpr();

        auto op1_v = op1_c->Value();
        auto op2_v = op2_c->Value();

        return same_val(op1_v, op2_v);
    }

    if ( op1->Tag() == EXPR_LIST ) {
        auto op1_l = op1->AsListExpr()->Exprs();
        auto op2_l = op2->AsListExpr()->Exprs();

        if ( op1_l.length() != op2_l.length() )
            return false;

        for ( auto i = 0; i < op1_l.length(); ++i )
            if ( ! same_expr(op1_l[i], op2_l[i], check_defs) )
                return false;

        return true;
    }

    // We only get here if dealing with non-reduced operands.
    auto subop1_1 = op1->GetOp1();
    auto subop1_2 = op2->GetOp1();
    ASSERT(subop1_1 && subop1_2);

    if ( ! same_expr(subop1_1, subop1_2) )
        return false;

    auto subop2_1 = op1->GetOp2();
    auto subop2_2 = op2->GetOp2();
    if ( subop2_1 && ! same_expr(subop2_1, subop2_2) )
        return false;

    auto subop3_1 = op1->GetOp3();
    auto subop3_2 = op2->GetOp3();
    return ! subop3_1 || same_expr(subop3_1, subop3_2);
}

static bool same_op(const ExprPtr& op1, const ExprPtr& op2, bool check_defs) {
    return same_op(op1.get(), op2.get(), check_defs);
}

static bool same_expr(const Expr* e1, const Expr* e2, bool check_defs) {
    if ( e1 == e2 )
        return true;

    if ( e1->Tag() != e2->Tag() )
        return false;

    if ( ! same_type(e1->GetType(), e2->GetType()) )
        return false;

    switch ( e1->Tag() ) {
        case EXPR_NAME:
        case EXPR_CONST: return same_op(e1, e2, check_defs);

        case EXPR_REF: return same_expr(e1->GetOp1(), e2->GetOp1());

        case EXPR_CLONE:
        case EXPR_RECORD_CONSTRUCTOR:
        case EXPR_REC_CONSTRUCT_WITH_REC:
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
            reporter->InternalError("Unexpected tag in Reducer::same_expr");

        case EXPR_ANY_INDEX: {
            auto a1 = static_cast<const AnyIndexExpr*>(e1);
            auto a2 = static_cast<const AnyIndexExpr*>(e2);

            if ( a1->Index() != a2->Index() )
                return false;

            return same_op(a1->GetOp1(), a2->GetOp1(), check_defs);
        }

        case EXPR_FIELD: {
            auto f1 = e1->AsFieldExpr();
            auto f2 = e2->AsFieldExpr();

            if ( f1->Field() != f2->Field() )
                return false;

            return same_op(f1->GetOp1(), f2->GetOp1(), check_defs);
        }

        case EXPR_HAS_FIELD: {
            auto f1 = e1->AsHasFieldExpr();
            auto f2 = e2->AsHasFieldExpr();

            if ( f1->Field() != f2->Field() )
                return false;

            return same_op(f1->GetOp1(), f2->GetOp1(), check_defs);
        }

        case EXPR_LIST: {
            auto l1 = e1->AsListExpr()->Exprs();
            auto l2 = e2->AsListExpr()->Exprs();

            ASSERT(l1.length() == l2.length());

            for ( int i = 0; i < l1.length(); ++i )
                if ( ! same_expr(l1[i], l2[i], check_defs) )
                    return false;

            return true;
        }

        case EXPR_CALL: {
            auto c1 = e1->AsCallExpr();
            auto c2 = e2->AsCallExpr();
            auto f1 = c1->Func();
            auto f2 = c2->Func();

            if ( f1 != f2 )
                return false;

            if ( ! f1->IsPure() )
                return false;

            return same_expr(c1->Args(), c2->Args(), check_defs);
        }

        case EXPR_LAMBDA: return false;

        case EXPR_IS: {
            if ( ! same_op(e1->GetOp1(), e2->GetOp1(), check_defs) )
                return false;

            auto i1 = e1->AsIsExpr();
            auto i2 = e2->AsIsExpr();

            return same_type(i1->TestType(), i2->TestType());
        }

        default:
            if ( ! e1->GetOp1() )
                reporter->InternalError("Bad default in Reducer::same_expr");

            if ( ! same_op(e1->GetOp1(), e2->GetOp1(), check_defs) )
                return false;

            if ( e1->GetOp2() && ! same_op(e1->GetOp2(), e2->GetOp2(), check_defs) )
                return false;

            if ( e1->GetOp3() && ! same_op(e1->GetOp3(), e2->GetOp3(), check_defs) )
                return false;

            return true;
    }
}

bool same_expr(const ExprPtr& e1, const ExprPtr& e2) { return same_expr(e1.get(), e2.get(), false); }

Reducer::Reducer(const ScriptFuncPtr& func, std::shared_ptr<ProfileFunc> _pf, std::shared_ptr<ProfileFuncs> _pfs)
    : pf(std::move(_pf)), pfs(std::move(_pfs)) {
    auto& ft = func->GetType();

    // Track the parameters so we don't remap them.
    int num_params = ft->Params()->NumFields();
    auto& scope_vars = current_scope()->OrderedVars();

    for ( auto i = 0; i < num_params; ++i )
        tracked_ids.insert(scope_vars[i]);

    // Now include any captures.
    if ( ft->GetCaptures() )
        for ( auto& c : *ft->GetCaptures() )
            tracked_ids.insert(c.Id());
}

StmtPtr Reducer::Reduce(StmtPtr s) {
    reduction_root = std::move(s);

    try {
        return reduction_root->Reduce(this);
    } catch ( InterpreterException& e ) {
        /* Already reported. */
        return reduction_root;
    }
}

ExprPtr Reducer::GenTemporaryExpr(const TypePtr& t, ExprPtr rhs) {
    return with_location_of(make_intrusive<NameExpr>(GenTemporary(t, rhs)), rhs);
}

NameExprPtr Reducer::UpdateName(NameExprPtr n) {
    if ( NameIsReduced(n.get()) )
        return n;

    auto ne = make_intrusive<NameExpr>(FindNewLocal(n));

    // This name can be used by follow-on optimization analysis,
    // so need to associate it with its statement.
    BindExprToCurrStmt(ne);

    return ne;
}

bool Reducer::NameIsReduced(const NameExpr* n) { return ID_IsReducedOrTopLevel(n->IdPtr()); }

void Reducer::UpdateIDs(IDPList* ids) {
    for ( auto& id : *ids )
        if ( ! ID_IsReducedOrTopLevel(id) )
            id = UpdateID(id);
}

void Reducer::UpdateIDs(std::vector<IDPtr>& ids) {
    for ( auto& id : ids )
        if ( ! ID_IsReducedOrTopLevel(id) )
            id = UpdateID(id);
}

bool Reducer::IDsAreReduced(const IDPList* ids) const {
    for ( auto& id : *ids )
        if ( ! ID_IsReduced(id) )
            return false;

    return true;
}

bool Reducer::IDsAreReduced(const std::vector<IDPtr>& ids) const {
    for ( const auto& id : ids )
        if ( ! ID_IsReduced(id) )
            return false;

    return true;
}

IDPtr Reducer::UpdateID(IDPtr id) {
    if ( ID_IsReducedOrTopLevel(id) )
        return id;

    return FindNewLocal(id);
}

bool Reducer::ID_IsReducedOrTopLevel(const IDPtr& id) {
    if ( inline_block_level == 0 ) {
        tracked_ids.insert(id);
        return true;
    }

    return ID_IsReduced(id);
}

bool Reducer::ID_IsReduced(const IDPtr& id) const {
    return inline_block_level == 0 || tracked_ids.contains(id) || id->IsGlobal() || IsTemporary(id);
}

StmtPtr Reducer::GenParam(const IDPtr& id, ExprPtr rhs, bool is_modified) {
    auto param = GenInlineBlockName(id);
    param->SetLocationInfo(rhs->GetLocationInfo());
    auto rhs_id = rhs->Tag() == EXPR_NAME ? rhs->AsNameExpr()->IdPtr() : nullptr;

    if ( rhs_id && ! pf->Locals().contains(rhs_id) && ! rhs_id->IsConst() )
        // It's hard to guarantee the RHS won't change during
        // the inline block's execution.
        is_modified = true;

    auto& id_t = id->GetType();
    if ( id_t->Tag() == TYPE_VECTOR && rhs->GetType()->Yield() != id_t->Yield() )
        // Presumably either the identifier or the RHS is a vector-of-any.
        // This means there will essentially be a modification of the RHS
        // due to the need to use (or omit) operations coercing from such
        // vectors.
        is_modified = true;

    if ( ! is_modified ) {
        // Can use a temporary variable, which then supports
        // optimization via alias propagation.
        auto param_id = GenTemporary(id->GetType(), rhs, param->IdPtr());
        auto& tv = ids_to_temps[param_id];

        if ( rhs_id )
            tv->SetAlias(rhs_id);
        else if ( rhs->Tag() == EXPR_CONST )
            tv->SetConst(rhs->AsConstExpr());

        param_temps.insert(param_id);
        param = make_intrusive<NameExpr>(param_id);
        param->SetLocationInfo(rhs->GetLocationInfo());
    }

    auto assign = with_location_of(make_intrusive<AssignExpr>(param, rhs, false, nullptr, nullptr, false), rhs);
    return make_intrusive<ExprStmt>(assign);
}

NameExprPtr Reducer::GenInlineBlockName(const IDPtr& id) {
    // We do this during reduction, not optimization, so no need
    // to associate with curr_stmt.
    return make_intrusive<NameExpr>(GenLocal(id));
}

void Reducer::PushInlineBlock() {
    ++inline_block_level;
    block_locals.emplace_back();
}

void Reducer::PopInlineBlock() {
    --inline_block_level;

    for ( auto& l : block_locals.back() ) {
        auto key = l.first;
        auto prev = l.second;
        if ( prev )
            orig_to_new_locals[key] = prev;
        else
            orig_to_new_locals.erase(key);
    }

    block_locals.pop_back();
}

NameExprPtr Reducer::GetRetVar(TypePtr type) {
    if ( ! type || type->Tag() == TYPE_VOID )
        return nullptr;

    IDPtr ret_id = install_ID("@retvar", "<internal>", false, false);
    ret_id->SetType(std::move(type));
    ret_id->GetOptInfo()->SetTemp();

    ret_vars.insert(ret_id);

    // Track this as a new local *if* we're in the outermost inlining
    // block.  If we're recursively deeper into inlining, then this
    // variable will get mapped to a local anyway, so no need.
    if ( inline_block_level == 1 )
        AddNewLocal(ret_id);

    return GenInlineBlockName(ret_id);
}

ExprPtr Reducer::NewVarUsage(IDPtr var, const Expr* orig) {
    auto var_usage = make_intrusive<NameExpr>(var);
    BindExprToCurrStmt(var_usage);

    return var_usage;
}

void Reducer::BindExprToCurrStmt(const ExprPtr& e) {
    e->GetOptInfo()->stmt_num = curr_stmt->GetOptInfo()->stmt_num;
    e->SetLocationInfo(curr_stmt->GetLocationInfo());
}

void Reducer::BindStmtToCurrStmt(const StmtPtr& s) {
    s->GetOptInfo()->stmt_num = curr_stmt->GetOptInfo()->stmt_num;
    s->SetLocationInfo(curr_stmt->GetLocationInfo());
}

IDPtr Reducer::FindExprTmp(const Expr* rhs, const Expr* a, const std::shared_ptr<const TempVar>& lhs_tmp) {
    for ( const auto& et_i : expr_temps ) {
        if ( et_i->Alias() || ! et_i->IsActive() || et_i == lhs_tmp )
            // This can happen due to re-reduction while
            // optimizing.
            continue;

        auto et_i_expr = et_i->RHS();

        if ( same_expr(rhs, et_i_expr, true) ) {
            // We have an apt candidate.  Make sure its value
            // always makes it here.
            const auto& id = et_i->Id();

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

bool Reducer::ExprValid(const IDPtr& id, const Expr* e1, const Expr* e2) const {
    // First check for whether e1 is already known to itself have side effects.
    // If so, then it's never safe to reuse its associated identifier in lieu
    // of e2.
    std::optional<ExprSideEffects>& e1_se = e1->GetOptInfo()->SideEffects();
    if ( ! e1_se ) {
        bool has_side_effects = false;
        const auto& e1_t = e1->GetType();

        if ( e1_t->Tag() == TYPE_OPAQUE || e1_t->Tag() == TYPE_ANY )
            // These have difficult-to-analyze semantics.
            has_side_effects = true;

        else if ( e1->Tag() == EXPR_INDEX ) {
            auto aggr = e1->GetOp1();
            auto aggr_t = aggr->GetType();

            if ( (pfs->HasSideEffects(SideEffectsOp::READ, aggr_t)) ||
                 (aggr_t->Tag() == TYPE_TABLE && pfs->IsTableWithDefaultAggr(aggr_t.get())) )
                has_side_effects = true;
        }

        else if ( e1->Tag() == EXPR_RECORD_CONSTRUCTOR || e1->Tag() == EXPR_REC_CONSTRUCT_WITH_REC ||
                  e1->Tag() == EXPR_RECORD_COERCE )
            has_side_effects = pfs->HasSideEffects(SideEffectsOp::CONSTRUCTION, e1->GetType());

        e1_se = ExprSideEffects(has_side_effects);
    }

    if ( e1_se->HasSideEffects() ) {
        // We already know that e2 is structurally identical to e1.
        e2->GetOptInfo()->SideEffects() = ExprSideEffects(true);
        return false;
    }

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
    // * Assessment of any record constructors or coercions, or
    //   table references or modifications, for possible invocation of
    //   associated handlers that have side effects.
    //
    // * Assessment of function calls for potential side effects.
    //
    // These latter two are guided by the global profile of the full set
    // of script functions.

    // Tracks which ID's are germane for our analysis.
    std::vector<IDPtr> ids;
    ids.push_back(id);

    // Identify variables involved in the expression.
    CheckIDs(e1->GetOp1(), ids);
    CheckIDs(e1->GetOp2(), ids);
    CheckIDs(e1->GetOp3(), ids);

    if ( e1->Tag() == EXPR_NAME )
        ids.push_back(e1->AsNameExpr()->IdPtr());

    CSE_ValidityChecker vc(pfs, ids, e1, e2);
    reduction_root->Traverse(&vc);

    return vc.IsValid();
}

void Reducer::CheckIDs(const ExprPtr& e, std::vector<IDPtr>& ids) const {
    if ( ! e )
        return;

    if ( e->Tag() == EXPR_LIST ) {
        const auto& e_l = e->AsListExpr()->Exprs();
        for ( auto i = 0; i < e_l.length(); ++i )
            CheckIDs({NewRef{}, e_l[i]}, ids);
    }

    else if ( e->Tag() == EXPR_NAME )
        ids.push_back(e->AsNameExpr()->IdPtr());
}

bool Reducer::IsCSE(const AssignExpr* a, const NameExpr* lhs, const Expr* rhs) {
    const auto& lhs_id = lhs->IdPtr();
    auto lhs_tmp = FindTemporary(lhs_id); // nil if LHS not a temporary
    auto rhs_tmp = FindExprTmp(rhs, a, lhs_tmp);

    ExprPtr new_rhs;
    if ( rhs_tmp ) { // We already have a temporary
        new_rhs = NewVarUsage(rhs_tmp, rhs);
        rhs = new_rhs.get();
    }

    if ( lhs_tmp ) {
        if ( rhs->Tag() == EXPR_CONST ) { // mark temporary as just being a constant
            lhs_tmp->SetConst(rhs->AsConstExpr());
            return true;
        }

        if ( rhs->Tag() == EXPR_NAME ) {
            const auto& rhs_id = rhs->AsNameExpr()->IdPtr();
            auto rhs_tmp_var = FindTemporary(rhs_id);

            if ( rhs_tmp_var ) {
                if ( rhs_tmp_var->Const() )
                    // temporary can be replaced with constant
                    lhs_tmp->SetConst(rhs_tmp_var->Const());
                else
                    lhs_tmp->SetAlias(rhs_id);
                return true;
            }
        }

        expr_temps.emplace_back(lhs_tmp);
    }

    return false;
}

const ConstExpr* Reducer::CheckForConst(const IDPtr& id, int stmt_num) const {
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
    if ( e ) {
        auto ce = constant_exprs.find(e.get());
        if ( ce != constant_exprs.end() )
            e = ce->second;

        if ( e->Tag() == EXPR_CONST )
            return e->AsConstExpr();

        // Follow aliases.
        if ( e->Tag() != EXPR_NAME )
            return nullptr;

        const auto& e_id = e->AsNameExpr()->IdPtr();
        if ( e_id == id )
            // Self-assignment - weird! - but avoid infinite recursion.
            return nullptr;

        return CheckForConst(e->AsNameExpr()->IdPtr(), stmt_num);
    }

    return nullptr;
}

ConstExprPtr Reducer::Fold(ExprPtr e) {
    auto c = make_intrusive<ConstExpr>(eval_in_isolation(e));
    FoldedTo(e, c);
    return c;
}

void Reducer::FoldedTo(ExprPtr e, ConstExprPtr c) {
    c->SetLocationInfo(e->GetLocationInfo());
    om.AddObj(e.get());
    constant_exprs[e.get()] = std::move(c);
    folded_exprs.push_back(std::move(e));
}

ExprPtr Reducer::OptExpr(Expr* e) {
    StmtPtr opt_stmts;
    auto opt_e = e->Reduce(this, opt_stmts);

    if ( opt_stmts )
        reporter->InternalError("Generating new statements while optimizing");

    if ( opt_e->Tag() == EXPR_NAME )
        return UpdateExpr(opt_e);

    return opt_e;
}

ExprPtr Reducer::UpdateExpr(ExprPtr e) {
    if ( e->Tag() != EXPR_NAME )
        return OptExpr(e);

    auto n = e->AsNameExpr();
    const auto& id = n->IdPtr();

    if ( id->IsGlobal() )
        return e;

    auto tmp_var = FindTemporary(id);
    if ( ! tmp_var ) {
        auto stmt_num = e->GetOptInfo()->stmt_num;
        auto is_const = CheckForConst(id, stmt_num);

        if ( is_const ) {
            // Remember this variable as one whose value
            // we used for constant propagation.  That
            // ensures we can subsequently not complain
            // about it being assigned but not used (though
            // we can still omit the assignment).
            constant_vars.insert(id);
            return with_location_of(make_intrusive<ConstExpr>(is_const->ValuePtr()), e);
        }

        return e;
    }

    if ( tmp_var->Const() )
        return with_location_of(make_intrusive<ConstExpr>(tmp_var->Const()->ValuePtr()), e);

    auto alias = tmp_var->Alias();
    if ( alias ) {
        // Make sure that the definitions for the alias here are
        // the same as when the alias was created.
        auto alias_tmp = FindTemporary(alias);

        // Resolve any alias chains.
        while ( alias_tmp && alias_tmp->Alias() ) {
            alias = alias_tmp->Alias();
            alias_tmp = FindTemporary(alias);
        }

        return NewVarUsage(alias, e.get());
    }

    auto rhs = tmp_var->RHS();
    if ( rhs->Tag() != EXPR_CONST )
        return e;

    auto c = rhs->AsConstExpr();
    return with_location_of(make_intrusive<ConstExpr>(c->ValuePtr()), e);
}

StmtPtr Reducer::MergeStmts(const NameExpr* lhs, ExprPtr rhs, const StmtPtr& succ_stmt) {
    // First check for tmp=rhs.
    const auto& lhs_id = lhs->IdPtr();
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

    const auto& a_lhs_var = a_lhs_deref->AsNameExpr()->IdPtr();
    const auto& a_rhs_var = a_rhs->AsNameExpr()->IdPtr();

    if ( a_rhs_var != lhs_id )
        // 2nd statement is var=something else.
        return nullptr;

    if ( a_lhs_var->GetType()->Tag() != a_rhs_var->GetType()->Tag() )
        // This can happen when we generate an assignment
        // specifically to convert to/from an "any" type.
        return nullptr;

    if ( FindTemporary(a_lhs_var) ) {
        // "var" is itself a temporary.  Don't complain, as
        // complex reductions can generate these.  We'll wind
        // up folding the chain once it hits a regular variable.
        return nullptr;
    }

    // Got it.  Mark the original temporary as no longer relevant.
    lhs_tmp->Deactivate();
    auto merge_e = with_location_of(make_intrusive<AssignExpr>(a_lhs_deref, rhs, false, nullptr, nullptr, false), lhs);
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

IDPtr Reducer::GenTemporary(TypePtr t, ExprPtr rhs, IDPtr id) {
    if ( Optimizing() )
        reporter->InternalError("Generating a new temporary while optimizing");

    if ( ! omitted_stmts.empty() )
        reporter->InternalError("Generating a new temporary while pruning statements");

    auto temp = std::make_shared<TempVar>(temps.size(), rhs);

    IDPtr temp_id;
    if ( id )
        temp_id = id;
    else
        temp_id = install_ID(temp->Name(), "<internal>", false, false);

    temp->SetID(temp_id);
    temp_id->SetType(t);

    temps.push_back(temp);

    om.AddObj(temp_id.get());
    ids_to_temps[temp_id] = temp;

    return temp_id;
}

IDPtr Reducer::FindNewLocal(const IDPtr& id) {
    auto mapping = orig_to_new_locals.find(id);

    if ( mapping != orig_to_new_locals.end() )
        return mapping->second;

    return GenLocal(id);
}

void Reducer::AddNewLocal(const IDPtr& l) {
    new_locals.insert(l);
    tracked_ids.insert(l);
}

IDPtr Reducer::GenLocal(const IDPtr& orig) {
    if ( Optimizing() )
        reporter->InternalError("Generating a new local while optimizing");

    if ( ! omitted_stmts.empty() )
        reporter->InternalError("Generating a new local while pruning statements");

    // Make sure the identifier is not being re-re-mapped.
    ASSERT(strchr(orig->Name(), '.') == nullptr);

    char buf[8192];
    int n = new_locals.size();
    snprintf(buf, sizeof buf, "%s.%d", orig->Name(), n);

    IDPtr local_id = install_ID(buf, "<internal>", false, false);
    local_id->SetType(orig->GetType());
    local_id->SetAttrs(orig->GetAttrs());

    if ( orig->IsBlank() )
        local_id->SetBlank();

    if ( orig->GetOptInfo()->IsTemp() )
        local_id->GetOptInfo()->SetTemp();

    IDPtr prev;
    if ( orig_to_new_locals.contains(orig) )
        prev = orig_to_new_locals[orig];

    AddNewLocal(local_id);
    om.AddObj(orig.get());
    orig_to_new_locals[orig] = local_id;

    if ( ! block_locals.empty() && ! ret_vars.contains(orig) )
        block_locals.back()[orig] = prev;

    return local_id;
}

bool Reducer::IsNewLocal(const IDPtr& id) const { return new_locals.contains(id); }

std::shared_ptr<TempVar> Reducer::FindTemporary(const IDPtr& id) const {
    auto tmp = ids_to_temps.find(id);
    if ( tmp == ids_to_temps.end() )
        return nullptr;
    else
        return tmp->second;
}

const Expr* non_reduced_perp;
bool checking_reduction;

bool NonReduced(const Expr* perp) {
    if ( checking_reduction )
        non_reduced_perp = perp;

    return false;
}

} // namespace zeek::detail
