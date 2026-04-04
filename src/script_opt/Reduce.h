// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/script_opt/ObjMgr.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {

class TempVar;

class Reducer {
public:
    Reducer(const ScriptFuncPtr& func, std::shared_ptr<ProfileFunc> pf, std::shared_ptr<ProfileFuncs> pfs);

    StmtPtr Reduce(StmtPtr s);

    void SetReadyToOptimize() { opt_ready = true; }

    void SetCurrStmt(const Stmt* stmt) {
        om.AddObj(stmt);
        curr_stmt = stmt;
    }

    ExprPtr GenTemporaryExpr(const TypePtr& t, ExprPtr rhs);

    NameExprPtr UpdateName(NameExprPtr n);
    bool NameIsReduced(const NameExpr* n);

    void UpdateIDs(IDPList* ids);
    bool IDsAreReduced(const IDPList* ids) const;

    void UpdateIDs(std::vector<IDPtr>& ids);
    bool IDsAreReduced(const std::vector<IDPtr>& ids) const;

    IDPtr UpdateID(IDPtr id);
    bool ID_IsReduced(const IDPtr& id) const;

    // A version of ID_IsReduced() that tracks top-level variables, too.
    bool ID_IsReducedOrTopLevel(const IDPtr& id);

    // This is called *prior* to pushing a new inline block, in order
    // to generate the equivalent of function parameters.  "rhs" is
    // the concrete argument to which the (inline version of the)
    // identifier will be assigned, and "is_modified" is true if the
    // parameter is assigned to in the body of the block.
    //
    // The return value is a statement that performs an assignment
    // to initialize the parameter to the RHS.
    StmtPtr GenParam(const IDPtr& id, ExprPtr rhs, bool is_modified);

    // Returns an expression for referring to an identifier in the
    // context of an inline block.
    NameExprPtr GenInlineBlockName(const IDPtr& id);

    int NumNewLocals() const { return new_locals.size(); }

    // These should be used as a balanced pair to start and end a
    // block being inlined.
    void PushInlineBlock();
    void PopInlineBlock();

    // Returns the name of a temporary for holding the return
    // value of the block, or nil if the type indicates there's
    // no return value. Call before popping the block.
    NameExprPtr GetRetVar(TypePtr type);

    // Whether it's okay to split a statement into two copies for if-else
    // expansion.  We only allow this to a particular depth because
    // beyond that a function body can get too large to analyze.
    bool BifurcationOkay() const { return bifurcation_level <= 12; }
    int BifurcationLevel() const { return bifurcation_level; }

    void PushBifurcation() { ++bifurcation_level; }
    void PopBifurcation() { --bifurcation_level; }

    int NumTemps() const { return temps.size(); }

    // True if this name already reflects the replacement.
    bool IsNewLocal(const NameExpr* n) const { return IsNewLocal(n->IdPtr()); }
    bool IsNewLocal(const IDPtr& id) const;

    bool IsTemporary(const IDPtr& id) const { return FindTemporary(id) != nullptr; }
    bool IsParamTemp(const IDPtr& id) const { return param_temps.contains(id); }

    bool IsConstantVar(const IDPtr& id) const { return constant_vars.contains(id); }

    // True if the Reducer is being used in the context of a second
    // pass over for AST optimization.
    bool Optimizing() const { return ! IsPruning() && opt_ready; }

    // A predicate that indicates whether a given reduction pass
    // is being made to prune unused statements.
    bool IsPruning() const { return ! omitted_stmts.empty(); }

    // A predicate that returns true if the given statement should
    // be removed due to AST optimization.
    bool ShouldOmitStmt(const Stmt* s) const { return omitted_stmts.contains(s); }

    // Provides a replacement for the given statement due to
    // AST optimization, or nil if there's no replacement.
    StmtPtr ReplacementStmt(const StmtPtr& s) const {
        auto repl = replaced_stmts.find(s.get());
        if ( repl == replaced_stmts.end() )
            return nullptr;
        else
            return repl->second;
    }

    // Tells the reducer to prune the given statement during the
    // next reduction pass.
    void AddStmtToOmit(const Stmt* s) {
        om.AddObj(s);
        omitted_stmts.insert(s);
    }

    // Tells the reducer to replace the given statement during the
    // next reduction pass.
    void AddStmtToReplace(const Stmt* s_old, StmtPtr s_new) {
        om.AddObj(s_old);
        replaced_stmts[s_old] = std::move(s_new);
    }

    // Tells the reducer that it can reclaim the storage associated
    // with the omitted statements.
    void ResetAlteredStmts() {
        omitted_stmts.clear();
        replaced_stmts.clear();
    }

    // Given the LHS and RHS of an assignment, returns true if the RHS is
    // a common subexpression (meaning that the current assignment statement
    // should be deleted).  In that case, has the side effect of associating
    // an alias for the LHS with the temporary variable that holds the
    // equivalent RHS; or if the LHS is a local that has no other assignments,
    // and the same for the RHS.
    //
    // Assumes reduction (including alias propagation) has already been applied.

    bool IsCSE(const AssignExpr* a, const NameExpr* lhs, const Expr* rhs);

    // Returns a constant representing folding of the given expression
    // (which must have constant operands).
    ConstExprPtr Fold(ExprPtr e);

    // Notes that the given expression has been folded to the given constant.
    void FoldedTo(ExprPtr orig, ConstExprPtr c);

    // Given an lhs=rhs statement followed by succ_stmt, returns
    // a (new) merge of the two if they're of the form tmp=rhs, var=tmp;
    // otherwise, nil.
    StmtPtr MergeStmts(const NameExpr* lhs, ExprPtr rhs, const StmtPtr& succ_stmt);

    // Update expressions with optimized versions.  They are distinct
    // because the first two (meant for calls in a Stmt reduction
    // context) will also Reduce the expression, whereas the last
    // one (meant for calls in an Expr context) does not, to avoid
    // circularity.
    ExprPtr OptExpr(Expr* e);
    ExprPtr OptExpr(const ExprPtr& e) { return OptExpr(e.get()); }

    // This one for expressions appearing in an Expr context.
    ExprPtr UpdateExpr(ExprPtr e);

protected:
    // Track that the variable "var" will be a replacement for
    // the "orig" expression.  Returns the replacement expression
    // (which is is just a NameExpr referring to "var").
    ExprPtr NewVarUsage(IDPtr var, const Expr* orig);

    void BindExprToCurrStmt(const ExprPtr& e);
    void BindStmtToCurrStmt(const StmtPtr& s);

    // Finds a temporary, if any, whose RHS matches the given "rhs", using
    // the reaching defs associated with the assignment "a".  The context
    // is that "rhs" is currently being assigned to temporary "lhs_tmp"
    // (nil if the assignment isn't to a temporary), and we're wondering
    // whether we can skip that assignment because we already have the
    // exact same value available in a previously assigned temporary.
    IDPtr FindExprTmp(const Expr* rhs, const Expr* a, const std::shared_ptr<const TempVar>& lhs_tmp);

    // Tests whether an expression computed at e1 (and assigned to "id")
    // remains valid for substitution at e2.
    bool ExprValid(const IDPtr& id, const Expr* e1, const Expr* e2) const;

    // Inspects the given expression for identifiers, adding any
    // observed to the given vector.  Assumes reduced form, so only
    // NameExpr's and ListExpr's are of interest - does not traverse
    // into compound expressions.
    void CheckIDs(const ExprPtr& e, std::vector<IDPtr>& ids) const;

    IDPtr GenTemporary(TypePtr t, ExprPtr rhs, IDPtr id = nullptr);
    std::shared_ptr<TempVar> FindTemporary(const IDPtr& id) const;

    // Retrieve the identifier corresponding to the new local for
    // the given expression.  Creates the local if necessary.
    IDPtr FindNewLocal(const IDPtr& id);
    IDPtr FindNewLocal(const NameExprPtr& n) { return FindNewLocal(n->IdPtr()); }

    void AddNewLocal(const IDPtr& l);

    // Generate a new local to use in lieu of the original (seen
    // in an inlined block).  The difference is that the new
    // version has a distinct name and has a correct frame offset
    // for the current function.
    IDPtr GenLocal(const IDPtr& orig);

    // This is the heart of constant propagation.  Given an identifier,
    // if its value is constant at the given location then returns
    // the corresponding ConstExpr with the value.
    const ConstExpr* CheckForConst(const IDPtr& id, int stmt_num) const;

    // Profile associated with the function.
    std::shared_ptr<ProfileFunc> pf;

    // Profile across all script functions - used for optimization decisions.
    std::shared_ptr<ProfileFuncs> pfs;

    // Tracks the temporary variables created during the reduction/
    // optimization process.
    std::vector<std::shared_ptr<TempVar>> temps;

    // Temps for which we've processed their associated expression
    // (and they didn't wind up being aliases).
    std::vector<std::shared_ptr<const TempVar>> expr_temps;

    // Lets us go from an identifier to an associated temporary
    // variable, if it corresponds to one.
    std::unordered_map<IDPtr, std::shared_ptr<TempVar>> ids_to_temps;

    // Identifiers that we're tracking (and don't want to replace).
    IDSet tracked_ids;

    // Local variables created during reduction/optimization.
    IDSet new_locals;

    // Parameters that we're treating as temporaries to facilitate CSE
    // across inlined functions.
    IDSet param_temps;

    // Mapping of original identifiers to new locals.  Used to
    // rename local variables when inlining.
    std::unordered_map<IDPtr, IDPtr> orig_to_new_locals;

    // Tracks expressions we've folded, so that we can recognize them
    // for constant propagation.
    std::unordered_map<const Expr*, ConstExprPtr> constant_exprs;

    // Holds onto those expressions so they don't become invalid
    // due to memory management.
    std::vector<ExprPtr> folded_exprs;

    // Which statements to elide from the AST (because optimization
    // has determined they're no longer needed).
    std::unordered_set<const Stmt*> omitted_stmts;

    // Maps statements to replacements constructed during optimization.
    std::unordered_map<const Stmt*, StmtPtr> replaced_stmts;

    // Tracks return variables we've created.
    IDSet ret_vars;

    // Tracks whether we're inside an inline block, and if so then
    // how deeply.
    int inline_block_level = 0;

    // Tracks locals introduced in the current block, remembering
    // their previous replacement value (per "orig_to_new_locals"),
    // if any.  When we pop the block, we restore the previous mapping.
    std::vector<std::unordered_map<IDPtr, IDPtr>> block_locals;

    // Memory management for AST elements that might change during
    // the reduction/optimization processes.
    ObjMgr om;

    // Tracks how deeply we are in "bifurcation", i.e., duplicating
    // code for if-else cascades.  We need to cap this at a certain
    // depth or else we can get functions whose size blows up
    // exponentially.
    int bifurcation_level = 0;

    // Tracks which (non-temporary) variables had constant
    // values used for constant propagation.
    IDSet constant_vars;

    // Statement at which the current reduction started.
    StmtPtr reduction_root;

    // Statement we're currently working on.
    const Stmt* curr_stmt = nullptr;

    bool opt_ready = false;
};

// Used for debugging, to communicate which expression wasn't
// reduced when we expected them all to be.
extern const Expr* non_reduced_perp;
extern bool checking_reduction;

// Used to report a non-reduced expression.
extern bool NonReduced(const Expr* perp);

// True if e1 and e2 reflect identical expressions, meaning that it's okay
// to use a value computed for one of them in lieu of computing the other.
// (Thus, for example, two record construction expressions are never
// equivalent even if they both specify exactly the same record elements,
// because each invocation of the expression produces a distinct value.)
extern bool same_expr(const ExprPtr& e1, const ExprPtr& e2);

} // namespace zeek::detail
