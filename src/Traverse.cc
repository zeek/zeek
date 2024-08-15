// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Traverse.h"

#include "zeek/ID.h"
#include "zeek/Scope.h"
#include "zeek/StmtBase.h"
#include "zeek/TraverseTypes.h"
#include "zeek/Type.h"
#include "zeek/input.h"

namespace zeek::detail {

TraversalCode traverse_all(TraversalCallback* cb) {
    if ( ! global_scope() )
        return TC_CONTINUE;

    if ( ! stmts )
        // May be null when parsing fails.
        return TC_CONTINUE;

    cb->current_scope = global_scope();

    TraversalCode tc = global_scope()->Traverse(cb);

    HANDLE_TC_STMT_PRE(tc);
    tc = stmts->Traverse(cb);
    HANDLE_TC_STMT_POST(tc);
}

TraversalCode DelegatingTraversalCallback::PreType(const Type* t) {
    if ( visited_types_pre.count(t) > 0 )
        return TC_ABORTSTMT;

    visited_types_pre.insert(t);

    return cb->PreType(t);
}

TraversalCode DelegatingTraversalCallback::PostType(const Type* t) {
    if ( visited_types_post.count(t) > 0 )
        return TC_ABORTSTMT;

    visited_types_post.insert(t);

    return cb->PostType(t);
}

TraversalCode DelegatingTraversalCallback::PreID(const ID* id) {
    auto tc = cb->PreID(id);
    HANDLE_TC_STMT_PRE(tc);

    // Traverse the ID's type, this isn't done by ID's
    // Traversal() implementation.
    tc = id->GetType()->Traverse(this);
    HANDLE_TC_STMT_PRE(tc);

    // Visit the ID's attributes, too.
    if ( auto& attrs = id->GetAttrs() )
        tc = attrs->Traverse(this);

    return tc;
}

} // namespace zeek::detail
