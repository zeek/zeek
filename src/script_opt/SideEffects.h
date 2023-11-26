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
    // ### remove NONE?
    enum AccessType { NONE, READ, WRITE };

    // SideEffectsOp() : access(NONE), type(nullptr) {}
    SideEffectsOp(AccessType at, const Type* t) : access(at), type(t) {}

    auto GetAccessType() const { return access; }
    bool NoSideEffects() const { return access == NONE; }
    bool OnReadAccess() const { return access == READ; }
    bool OnWriteAccess() const { return access == WRITE; }

    const Type* GetType() const { return type; }

    void SetUnknownChanges() { has_unknown_changes = true; }
    bool HasUnknownChanges() const { return has_unknown_changes; }

    void AddModNonGlobal(std::unordered_set<const ID*> ids) { mod_non_locals.insert(ids.begin(), ids.end()); }
    void AddModAggrs(std::unordered_set<const Type*> types) { mod_aggrs.insert(types.begin(), types.end()); }

    const auto& ModNonLocals() const { return mod_non_locals; }
    const auto& ModAggrs() const { return mod_aggrs; }

private:
    AccessType access;
    const Type* type;         // type for which some operations alter state

    std::unordered_set<const ID*> mod_non_locals;
    std::unordered_set<const Type*> mod_aggrs;

    bool has_unknown_changes = false;
};

} // namespace zeek::detail
