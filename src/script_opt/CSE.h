// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {

class TempVar;

// Helper class that walks an AST to determine whether it's safe to
// substitute a common subexpression (which at this point is an assignment
// to a variable) created using the assignment expression at position "start_e",
// at the location specified by the expression at position "end_e".
//
// See Reducer::ExprValid for a discussion of what's required for safety.

class CSE_ValidityChecker : public TraversalCallback {
public:
    CSE_ValidityChecker(std::shared_ptr<ProfileFuncs> pfs, const std::vector<const ID*>& ids, const Expr* start_e,
                        const Expr* end_e);

    TraversalCode PreStmt(const Stmt*) override;
    TraversalCode PostStmt(const Stmt*) override;
    TraversalCode PreExpr(const Expr*) override;
    TraversalCode PostExpr(const Expr*) override;

    TraversalCode PreType(const Type* t) override {
        if ( types_seen.contains(t) )
            return TC_ABORTSTMT;
        types_seen.insert(t);
        return TC_CONTINUE;
    }

    // Returns the ultimate verdict re safety.
    bool IsValid() const {
        if ( ! is_valid )
            return false;

        if ( ! have_end_e )
            reporter->InternalError("CSE_ValidityChecker: saw start but not end");
        return true;
    }

protected:
    // Returns true if an assignment involving the given identifier on
    // the LHS is in conflict with the identifiers we're tracking.
    bool CheckID(const ID* id, bool ignore_orig);

    // Returns true if a modification to an aggregate of the given type
    // potentially aliases with one of the identifiers we're tracking.
    bool CheckAggrMod(const TypePtr& t);

    // Returns true if a record constructor/coercion of the given type has
    // side effects and invalides the CSE opportunity.
    bool CheckRecordConstructor(const TypePtr& t);

    // The same for modifications to tables.
    bool CheckTableMod(const TypePtr& t);

    // The same for accessing (reading) tables.
    bool CheckTableRef(const TypePtr& t);

    // The same for the given function call.
    bool CheckCall(const CallExpr* c);

    // True if the given form of access to the given type has side effects.
    bool CheckSideEffects(SideEffectsOp::AccessType access, const TypePtr& t);

    // True if side effects to the given identifiers and aggregates invalidate
    // the CSE opportunity.
    bool CheckSideEffects(const IDSet& non_local_ids, const TypeSet& aggrs);

    // Helper function that marks the CSE opportunity as invalid and returns
    // "true" (used by various methods to signal invalidation).
    bool Invalid() {
        is_valid = false;
        return true;
    }

    // Profile across all script functions.
    std::shared_ptr<ProfileFuncs> pfs;

    // The list of identifiers for which an assignment to one of them
    // renders the CSE unsafe.
    const std::vector<const ID*>& ids;

    // Where in the AST to start our analysis.  This is the initial
    // assignment expression.
    const Expr* start_e;

    // Expression in the AST where we should end our analysis. See discussion
    // in the constructor for the interplay between this and end_s.
    const Expr* end_e;

    // Statement in the AST where we should end our analysis.
    const Stmt* end_s;

    // If what we're analyzing is a record element, then its offset.
    // -1 if not.
    int field;

    // The type of that record element, if any.
    TypePtr field_type;

    // The verdict so far.
    bool is_valid = true;

    // Whether we've encountered the start/end expression in
    // the AST traversal.
    bool have_start_e = false;
    bool have_end_e = false;

    // Whether analyzed expressions occur in the context of an expression
    // that modifies an aggregate ("add" or "delete"), which changes the
    // interpretation of the expressions.
    //
    // A count to allow for nesting.
    int in_aggr_mod_expr = 0;

    // Used to limit traversal of recursive types.
    std::unordered_set<const Type*> types_seen;
};

// Used for debugging, to communicate which expression wasn't
// reduced when we expected them all to be.
extern const Expr* non_reduced_perp;
extern bool checking_reduction;

// Used to report a non-reduced expression.
extern bool NonReduced(const Expr* perp);

} // namespace zeek::detail
