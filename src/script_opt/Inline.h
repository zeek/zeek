// See the file "COPYING" in the main distribution directory for copyright.

// Class that manages the process of (recursively) inlining function bodies.

#pragma once

#include <unordered_set>

#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/Scope.h"

namespace zeek::detail {

class FuncInfo;
class ProfileFunc;

class Inliner {
public:
    // First argument is a collection of information about *all* of
    // the script functions.  Second argument states whether to report
    // recursive functions (of interest as they're not in-lineable).
    Inliner(std::vector<FuncInfo>& _funcs, bool _report_recursive)
        : funcs(_funcs), report_recursive(_report_recursive) {
        Analyze();
    }

    // Either returns the original CallExpr if it's not inline-able;
    // or an InlineExpr if it is; or nil if further inlining should stop.
    ExprPtr CheckForInlining(CallExprPtr c);

    // True if every instance of the function was inlined.
    bool WasFullyInlined(const Func* f) { return did_inline.contains(f) && ! skipped_inlining.contains(f); }

protected:
    // Driver routine that analyzes all of the script functions and
    // recursively inlines eligible ones.
    void Analyze();

    // Maps an event handler body to its corresponding FuncInfo.  For the
    // latter we use a cursor rather than a direct reference or pointer
    // because the collection of FuncInfo's are maintained in a vector and
    // can wind up moving around in memory.
    using BodyInfo = std::unordered_map<const Stmt*, size_t>;

    // Goes through all the event handlers and coalesces those with
    // multiple bodies into a single "alternative" body.
    void CoalesceEventHandlers();

    // For a given event handler, collection of bodies, and associated
    // function information, creates a new FuncInfo entry reflecting an
    // alternative body for the event handler with all of the bodies
    // coalesced into a single new body.
    void CoalesceEventHandlers(ScriptFuncPtr sf, const std::vector<Func::Body>& bodies, const BodyInfo& body_to_info);

    // Recursively inlines any calls associated with the given function.
    void InlineFunction(FuncInfo* f);

    // Performs common functionality prior to inlining a call body.
    void PreInline(StmtOptInfo* oi, size_t frame_size);

    // Performs common functionality that comes after inlining a call body.
    void PostInline(StmtOptInfo* oi, ScriptFuncPtr f);

    // Inlines the given body using the given arguments.
    ExprPtr DoInline(ScriptFuncPtr sf, StmtPtr body, ListExprPtr args, ScopePtr scope, const ProfileFunc* pf);

    // Information about all of the functions (and events/hooks) in
    // the full set of scripts.
    std::vector<FuncInfo>& funcs;

    // Functions that we've determined to be suitable for inlining, and
    // their associated profiles.
    std::unordered_map<const Func*, const ProfileFunc*> inline_ables;

    // Functions that we inlined.
    std::unordered_set<const Func*> did_inline;

    // Functions that we didn't fully inline, so require separate
    // compilation.
    std::unordered_set<const Func*> skipped_inlining;

    // As we do inlining for a given function, this tracks the
    // largest frame size of any inlined function.
    int max_inlined_frame_size;

    // The size of the frame of the currently-being-inlined function,
    // prior to increasing it to accommodate inlining.
    int curr_frame_size;

    // The number of statements and expressions in the function being
    // inlined.  Dynamically updated as the inlining proceeds.  Used
    // to cap inlining complexity.
    int num_stmts;
    int num_exprs;

    // Whether to generate a report about functions either directly and
    // indirectly recursive.
    bool report_recursive;
};

} // namespace zeek::detail
