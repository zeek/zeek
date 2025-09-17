// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// Base class for Zeek statements.  We maintain it separately from
// the bulk of Stmt.h to allow Expr.h to include it, necessary for
// Expr.h to use StmtPtr.

#include "zeek/IntrusivePtr.h"
#include "zeek/Obj.h"
#include "zeek/StmtEnums.h"
#include "zeek/TraverseTypes.h"
#include "zeek/util.h"

namespace zeek {

class Val;
using ValPtr = IntrusivePtr<Val>;

namespace run_state {
extern double network_time;
}

namespace detail {

class CompositeHash;
class Frame;

class AssertStmt;
class CatchReturnStmt;
class ExprStmt;
class ForStmt;
class IfStmt;
class InitStmt;
class NullStmt;
class PrintStmt;
class ReturnStmt;
class StmtList;
class SwitchStmt;
class WhenStmt;
class WhileStmt;

class EventExpr;
class ListExpr;

using EventExprPtr = IntrusivePtr<EventExpr>;
using ListExprPtr = IntrusivePtr<ListExpr>;

class Inliner;
class Reducer;

class Stmt;
using StmtPtr = IntrusivePtr<Stmt>;

class StmtOptInfo;

class Stmt : public Obj {
public:
    StmtTag Tag() const { return tag; }

    ~Stmt() override;

    virtual ValPtr Exec(Frame* f, StmtFlowType& flow) = 0;

    Stmt* Ref() {
        zeek::Ref(this);
        return this;
    }
    StmtPtr ThisPtr() { return {NewRef{}, this}; }

    // True if the statement has no side effects, false otherwise.
    virtual bool IsPure() const;

    StmtList* AsStmtList();
    const StmtList* AsStmtList() const;

    ForStmt* AsForStmt();
    const ForStmt* AsForStmt() const;

    const ExprStmt* AsExprStmt() const;
    const PrintStmt* AsPrintStmt() const;
    const InitStmt* AsInitStmt() const;
    const CatchReturnStmt* AsCatchReturnStmt() const;
    const ReturnStmt* AsReturnStmt() const;
    const IfStmt* AsIfStmt() const;
    const WhileStmt* AsWhileStmt() const;
    const WhenStmt* AsWhenStmt() const;
    const SwitchStmt* AsSwitchStmt() const;
    const NullStmt* AsNullStmt() const;
    const AssertStmt* AsAssertStmt() const;

    void RegisterAccess() const {
        last_access = run_state::network_time;
        access_count++;
    }
    void AccessStats(ODesc* d) const;
    uint32_t GetAccessCount() const { return access_count; }

    void Describe(ODesc* d) const final;

    virtual void IncrBPCount() { ++breakpoint_count; }
    virtual void DecrBPCount();

    virtual unsigned int BPCount() const { return breakpoint_count; }

    virtual TraversalCode Traverse(TraversalCallback* cb) const = 0;

    // Returns a duplicate of the statement so that modifications
    // can be made to statements from inlining function bodies - or
    // to the originals - without affecting other instances.
    //
    // It's tempting to think that there are some statements that
    // are safe to share across multiple functions and could just
    // return references to themselves - but since we associate
    // information for script optimization with individual statements
    // nodes, even these need to be duplicated.
    virtual StmtPtr Duplicate() = 0;

    // Recursively traverses the AST to inline eligible function calls.
    virtual void Inline(Inliner* inl) {}

    // True if the statement is in reduced form.
    virtual bool IsReduced(Reducer* c) const;

    // Returns a reduced version of the statement, as managed by
    // the given Reducer.
    StmtPtr Reduce(Reducer* c);
    virtual StmtPtr DoReduce(Reducer* c) { return ThisPtr(); }

    // True if there's definitely no control flow past the statement.
    // The argument governs whether to ignore "break" statements, given
    // they mean two different things depending on whether they're in
    // a loop or a switch.  Also, if we want to know whether flow reaches
    // the *end* of a loop, then we also want to ignore break's, as
    // in that case, they do lead to flow reaching the end.
    virtual bool NoFlowAfter(bool ignore_break) const { return false; }

    // True if the statement could potentially execute a return. This is
    // used by script optimization to track confluence inside catch-return
    // blocks. Here, ignore_break is false if we're analyzing a coalesced
    // hook body.
    virtual bool CouldReturn(bool ignore_break) const { return false; }

    // A convenience function for taking a newly-created Stmt,
    // making it point to us as the successor, and returning it.
    //
    // Takes a Stmt* rather than a StmtPtr to de-clutter the calling
    // code, which is always passing in "new XyzStmt(...)".  This
    // call, as a convenient side effect, transforms that bare pointer
    // into a StmtPtr.
    virtual StmtPtr SetSucc(Stmt* succ) {
        succ->SetLocationInfo(GetLocationInfo());
        return {AdoptRef{}, succ};
    }

    // Access script optimization information associated with
    // this statement.
    StmtOptInfo* GetOptInfo() const { return opt_info; }

    // Returns the number of statements created since the last reset.
    static int GetNumStmts() { return num_stmts; }

    // Clears the number of statements created.
    static void ResetNumStmts() { num_stmts = 0; }

protected:
    explicit Stmt(StmtTag arg_tag);

    // Helper function called after reductions to perform canonical
    // actions.
    StmtPtr TransformMe(StmtPtr new_me, Reducer* c);

    void AddTag(ODesc* d) const;
    virtual void StmtDescribe(ODesc* d) const;
    void DescribeDone(ODesc* d) const;

    StmtTag tag;
    int breakpoint_count; // how many breakpoints on this statement

    // FIXME: Learn the exact semantics of mutable.
    mutable double last_access;    // time of last execution
    mutable uint32_t access_count; // number of executions

    // Information associated with the Stmt for purposes of
    // script optimization.
    StmtOptInfo* opt_info;

    // Number of statements created thus far.
    static int num_stmts;
};

} // namespace detail
} // namespace zeek
