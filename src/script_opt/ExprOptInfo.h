// See the file "COPYING" in the main distribution directory for copyright.

// Auxiliary information associated with expressions to aid script
// optimization.

#pragma once

namespace zeek::detail {

// Class for tracking whether a given expression has side effects. Currently,
// we just need to know whether Yes-it-does or No-it-doesn't, so the structure
// is very simple.

class ExprSideEffects {
public:
    ExprSideEffects(bool _has_side_effects) : has_side_effects(_has_side_effects) {}

    bool HasSideEffects() const { return has_side_effects; }

protected:
    bool has_side_effects;
};

class ExprOptInfo {
public:
    // The AST number of the statement in which this expression
    // appears.
    int stmt_num = -1; // -1 = not assigned yet

    auto& SideEffects() { return side_effects; }

protected:
    // This optional value missing means "we haven't yet determined the
    // side effects".
    std::optional<ExprSideEffects> side_effects;
};

} // namespace zeek::detail
