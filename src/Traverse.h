// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <unordered_set>

#include "zeek/Scope.h"
#include "zeek/TraverseTypes.h"

namespace zeek {

class Func;
class Type;

namespace detail {

class Stmt;
class Expr;
class ID;
class Attributes;
class Attr;

class TraversalCallback {
public:
    TraversalCallback() { current_scope = nullptr; }
    virtual ~TraversalCallback() {}

    virtual TraversalCode PreFunction(const Func*) { return TC_CONTINUE; }
    virtual TraversalCode PostFunction(const Func*) { return TC_CONTINUE; }

    virtual TraversalCode PreStmt(const Stmt*) { return TC_CONTINUE; }
    virtual TraversalCode PostStmt(const Stmt*) { return TC_CONTINUE; }

    virtual TraversalCode PreExpr(const Expr*) { return TC_CONTINUE; }
    virtual TraversalCode PostExpr(const Expr*) { return TC_CONTINUE; }

    virtual TraversalCode PreID(const ID*) { return TC_CONTINUE; }
    virtual TraversalCode PostID(const ID*) { return TC_CONTINUE; }

    virtual TraversalCode PreTypedef(const ID*) { return TC_CONTINUE; }
    virtual TraversalCode PostTypedef(const ID*) { return TC_CONTINUE; }

    virtual TraversalCode PreDecl(const ID*) { return TC_CONTINUE; }
    virtual TraversalCode PostDecl(const ID*) { return TC_CONTINUE; }

    // A caution regarding using the next two: when traversing types,
    // there's a possibility of encountering a (directly or indirectly)
    // recursive record.  So you'll need some way of avoiding that,
    // such as remembering which types have already been traversed
    // and skipping via TC_ABORTSTMT when seen again.
    virtual TraversalCode PreType(const Type*) { return TC_CONTINUE; }
    virtual TraversalCode PostType(const Type*) { return TC_CONTINUE; }

    virtual TraversalCode PreAttrs(const Attributes*) { return TC_CONTINUE; }
    virtual TraversalCode PostAttrs(const Attributes*) { return TC_CONTINUE; }

    virtual TraversalCode PreAttr(const Attr*) { return TC_CONTINUE; }
    virtual TraversalCode PostAttr(const Attr*) { return TC_CONTINUE; }

    ScopePtr current_scope;
};


using TraversalCallbackPtr = std::shared_ptr<TraversalCallback>;

/**
 * A delegating TraversalCallback with implicit traversal of types
 * and attributes in its PreID() default implementation. Further,
 * individual types in the traversed AST will be visited just once
 * through PreType() and PostType().
 *
 * Could think about adding a Traversal policy to make certain things
 * configurable, like visiting a type more than once during the
 * full traversal.
 */
class DelegatingTraversalCallback : public TraversalCallback {
public:
    explicit DelegatingTraversalCallback(TraversalCallbackPtr cb) : cb(std::move(cb)){};
    ~DelegatingTraversalCallback() {}

    TraversalCode PreFunction(const Func* f) override { return cb->PreFunction(f); }
    TraversalCode PostFunction(const Func* f) override { return cb->PostFunction(f); }

    TraversalCode PreStmt(const Stmt* s) override { return cb->PreStmt(s); }
    TraversalCode PostStmt(const Stmt* s) override { return cb->PostStmt(s); }

    TraversalCode PreExpr(const Expr* e) override { return cb->PreExpr(e); }
    TraversalCode PostExpr(const Expr* e) override { return cb->PostExpr(e); }

    TraversalCode PreID(const ID* id) override;
    TraversalCode PostID(const ID* id) override { return cb->PostID(id); }

    TraversalCode PreTypedef(const ID* id) override { return cb->PreTypedef(id); }
    TraversalCode PostTypedef(const ID* id) override { return cb->PostTypedef(id); }

    TraversalCode PreDecl(const ID* id) override { return cb->PreDecl(id); }
    TraversalCode PostDecl(const ID* id) override { return cb->PostDecl(id); }

    TraversalCode PreType(const Type* t) override;
    TraversalCode PostType(const Type* t) override;

    TraversalCode PreAttrs(const Attributes* attrs) override { return cb->PreAttrs(attrs); }
    TraversalCode PostAttrs(const Attributes* attrs) override { return cb->PostAttrs(attrs); }

    TraversalCode PreAttr(const Attr* attr) override { return cb->PreAttr(attr); }
    TraversalCode PostAttr(const Attr* attr) override { return cb->PostAttr(attr); }

protected:
    TraversalCallbackPtr cb;
    std::unordered_set<const Type*> visited_types_pre;
    std::unordered_set<const Type*> visited_types_post;
};

TraversalCode traverse_all(TraversalCallback* cb);

} // namespace detail
} // namespace zeek
