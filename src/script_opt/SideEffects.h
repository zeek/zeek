// See the file "COPYING" in the main distribution directory for copyright.

// Analyses regarding operations where non-locals or aggregates can be modified
// indirectly, in support of ensuring that after such an operation, script
// optimization doesn't use a stale version of the non-local/aggregate.

#pragma once

#include "zeek/ID.h"

namespace zeek::detail {

// Describes an operation for which some forms of access can lead to state
// modifications.
class SideEffectsOp {
public:
    enum AccessType { NONE, CALL, CONSTRUCTION, READ, WRITE };

    // Type can be left off for CALL access.
    SideEffectsOp(AccessType at = NONE, const Type* t = nullptr) : access(at), type(t) {}

    auto GetAccessType() const { return access; }
    const Type* GetType() const { return type; }

    void SetUnknownChanges() { has_unknown_changes = true; }
    bool HasUnknownChanges() const { return has_unknown_changes; }

    void AddModNonGlobal(IDSet ids) { mod_non_locals.insert(ids.begin(), ids.end()); }
    void AddModAggrs(TypeSet types) { mod_aggrs.insert(types.begin(), types.end()); }

    const auto& ModNonLocals() const { return mod_non_locals; }
    const auto& ModAggrs() const { return mod_aggrs; }

private:
    AccessType access;
    const Type* type; // type for which some operations alter state

    IDSet mod_non_locals;
    TypeSet mod_aggrs;

    bool has_unknown_changes = false;
};

} // namespace zeek::detail
