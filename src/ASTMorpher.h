// See the file "COPYING" in the main distribution directory for copyright.

// AST substitution helper threaded through Expr::Duplicate() /
// Stmt::Duplicate() (and also ID's). A caller who wants to rewrite
// selected nodes during a deep-clone subclasses ASTMorpher and overrides
// MorphExpr / MorphStmt / MorphID; each virtual gets a chance to
// substitute a candidate node before the default deep-clone descends into it.
//
// The default virtuals just forward to Duplicate(), the identity morph.
//
// Substituting the ROOT of a Duplicate chain is on the caller: use e.g.
// `root_expr = my_morpher->MorphExpr(root_expr)`.
//
// The morpher is a non-const argument to Duplicate() so that subclasses
// can accumulate state, and a raw pointer to match the Traversal structure.

#pragma once

#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"

namespace zeek {

namespace detail {

class Expr;
class Stmt;
using ExprPtr = IntrusivePtr<Expr>;
using StmtPtr = IntrusivePtr<Stmt>;

class ASTMorpher {
public:
    virtual ~ASTMorpher() = default;

    virtual ExprPtr MorphExpr(const ExprPtr& e);
    virtual StmtPtr MorphStmt(const StmtPtr& s);

    // Called for each ID slot inside a Duplicate override that materially
    // clones the ID reference (rare - most Duplicate sites hold IDs by
    // IntrusivePtr and don't Duplicate them).
    virtual IDPtr MorphID(const IDPtr& id);
};

// Canonical no-op ASTMorpher.
extern ASTMorpher* const identity_am;

} // namespace detail

} // namespace zeek
