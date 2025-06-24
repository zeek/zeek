// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// Zeek statements.

#include "zeek/Dict.h"
#include "zeek/Expr.h"
#include "zeek/ID.h"
#include "zeek/StmtBase.h"
#include "zeek/Type.h"
#include "zeek/ZeekList.h"

namespace zeek::detail {

class CompositeHash;
class NameExpr;
using NameExprPtr = IntrusivePtr<zeek::detail::NameExpr>;

class ZAMCompiler; // for "friend" declarations

class ExprListStmt : public Stmt {
public:
    ~ExprListStmt() override;

    const ListExpr* ExprList() const { return l.get(); }
    const ListExprPtr& ExprListPtr() const { return l; }

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    void Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

protected:
    ExprListStmt(StmtTag t, ListExprPtr arg_l);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;
    virtual ValPtr DoExec(std::vector<ValPtr> vals, StmtFlowType& flow) = 0;

    void StmtDescribe(ODesc* d) const override;

    ListExprPtr l;

    // Optimization-related:

    // Returns a new version of the original derived object
    // based on the given list of singleton expressions.
    virtual StmtPtr DoSubclassReduce(ListExprPtr singletons, Reducer* c) = 0;
};

class PrintStmt final : public ExprListStmt {
public:
    template<typename L>
    explicit PrintStmt(L&& l) : ExprListStmt(STMT_PRINT, std::forward<L>(l)) {}

    // Optimization-related:
    StmtPtr Duplicate() override;

protected:
    ValPtr DoExec(std::vector<ValPtr> vals, StmtFlowType& flow) override;

    // Optimization-related:
    StmtPtr DoSubclassReduce(ListExprPtr singletons, Reducer* c) override;
};

extern void do_print_stmt(const std::vector<ValPtr>& vals);

class ExprStmt : public Stmt {
public:
    explicit ExprStmt(ExprPtr e);
    ~ExprStmt() override;

    // This constructor is only meant for internal use, but it's
    // not protected since ExprPtr's mask the actual caller,
    // not allowing us to use "friend" for protected access.
    ExprStmt(StmtTag t, ExprPtr e);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    const Expr* StmtExpr() const { return e.get(); }
    ExprPtr StmtExprPtr() const;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    StmtPtr Duplicate() override;
    void Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

protected:
    virtual ValPtr DoExec(Frame* f, Val* v, StmtFlowType& flow);

    bool IsPure() const override;

    ExprPtr e;
};

class IfStmt final : public ExprStmt {
public:
    IfStmt(ExprPtr test, StmtPtr s1, StmtPtr s2);
    ~IfStmt() override;

    const Stmt* TrueBranch() const { return s1.get(); }
    const Stmt* FalseBranch() const { return s2.get(); }

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    StmtPtr Duplicate() override;
    void Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

    bool NoFlowAfter(bool ignore_break) const override;
    bool CouldReturn(bool ignore_break) const override;

protected:
    ValPtr DoExec(Frame* f, Val* v, StmtFlowType& flow) override;
    bool IsPure() const override;

    bool IsMinMaxConstruct() const;
    StmtPtr ConvertToMinMaxConstruct();

    StmtPtr s1;
    StmtPtr s2;
};

class Case final : public Obj {
public:
    Case(ListExprPtr c, IDPList* types, StmtPtr arg_s);
    ~Case() override;

    const ListExpr* ExprCases() const { return expr_cases.get(); }
    ListExpr* ExprCases() { return expr_cases.get(); }

    const IDPList* TypeCases() const { return type_cases; }
    IDPList* TypeCases() { return type_cases; }

    const Stmt* Body() const { return s.get(); }
    Stmt* Body() { return s.get(); }

    void UpdateBody(StmtPtr new_body) { s = std::move(new_body); }

    void Describe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const;

    // Optimization-related:
    IntrusivePtr<Case> Duplicate();

protected:
    ListExprPtr expr_cases;
    IDPList* type_cases;
    StmtPtr s;
};

using case_list = PList<Case>;

class SwitchStmt final : public ExprStmt {
public:
    SwitchStmt(ExprPtr index, case_list* cases);
    ~SwitchStmt() override;

    const case_list* Cases() const { return cases; }
    bool HasDefault() const { return default_case_idx != -1; }

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    StmtPtr Duplicate() override;
    void Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

    bool NoFlowAfter(bool ignore_break) const override;
    bool CouldReturn(bool ignore_break) const override;

protected:
    friend class ZAMCompiler;
    friend class CPPCompile;

    int DefaultCaseIndex() const { return default_case_idx; }
    const auto& ValueMap() const { return case_label_value_map; }
    const std::vector<std::pair<ID*, int>>* TypeMap() const { return &case_label_type_list; }
    const CompositeHash* CompHash() const { return comp_hash; }

    ValPtr DoExec(Frame* f, Val* v, StmtFlowType& flow) override;
    bool IsPure() const override;

    // Initialize composite hash and case label map.
    void Init();

    // Adds entries in case_label_value_map and case_label_hash_map
    // for the given value to associate it with the given index in
    // the cases list.  If the entry already exists, returns false,
    // else returns true.
    bool AddCaseLabelValueMapping(const Val* v, int idx);

    // Adds an entry in case_label_type_map for the given type (w/ ID) to
    // associate it with the given index in the cases list.  If an entry
    // for the type already exists, returns false; else returns true.
    bool AddCaseLabelTypeMapping(ID* t, int idx);

    // Returns index of a case label that matches the value, or
    // default_case_idx if no case label matches (which may be -1 if
    // there's no default label). The second tuple element is the ID of
    // the matching type-based case if it defines one.
    std::pair<int, ID*> FindCaseLabelMatch(const Val* v) const;

    case_list* cases = nullptr;
    int default_case_idx = -1;
    CompositeHash* comp_hash = nullptr;
    std::unordered_map<const Val*, int> case_label_value_map;
    PDict<int> case_label_hash_map;
    std::vector<std::pair<ID*, int>> case_label_type_list;
};

class EventStmt final : public ExprStmt {
public:
    explicit EventStmt(EventExprPtr e);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    StmtPtr Duplicate() override;

    StmtPtr DoReduce(Reducer* c) override;

protected:
    EventExprPtr event_expr;
};

class WhileStmt final : public Stmt {
public:
    WhileStmt(ExprPtr loop_condition, StmtPtr body);
    ~WhileStmt() override;

    bool IsPure() const override;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    StmtPtr Duplicate() override;
    void Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

    const ExprPtr& Condition() const { return loop_condition; }
    StmtPtr CondPredStmt() const { return loop_cond_pred_stmt; }
    const StmtPtr& Body() const { return body; }
    const StmtPtr& ConditionAsStmt() const { return stmt_loop_condition; }

    // Note, no need for a NoFlowAfter method because the loop might
    // execute zero times, so it's always the default of "false".
    // However, we do need to check for potential returns.
    bool CouldReturn(bool ignore_break) const override;

protected:
    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    ExprPtr loop_condition;
    StmtPtr body;

    // Optimization-related member variables.

    // When in reduced form, the following holds a statement (which
    // might be a block) that's a *predecessor* necessary for evaluating
    // the loop's conditional.
    StmtPtr loop_cond_pred_stmt = nullptr;

    // When reducing, we create a *statement* associated with
    // evaluating the reduced conditional, as well as the reduced
    // expression.  This turns out to be useful in propagating RDs/UDs.
    StmtPtr stmt_loop_condition = nullptr;
};

class ForStmt final : public ExprStmt {
public:
    ForStmt(IDPList* loop_vars, ExprPtr loop_expr);
    // Special constructor for key value for loop.
    ForStmt(IDPList* loop_vars, ExprPtr loop_expr, IDPtr val_var);
    ~ForStmt() override;

    void AddBody(StmtPtr arg_body) { body = std::move(arg_body); }

    const IDPList* LoopVars() const { return loop_vars; }
    IDPtr ValueVar() const { return value_var; }
    const Expr* LoopExpr() const { return e.get(); }
    const Stmt* LoopBody() const { return body.get(); }

    bool IsPure() const override;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    StmtPtr Duplicate() override;
    void Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

    // Note, no need for a NoFlowAfter method because the loop might
    // execute zero times, so it's always the default of "false".
    // However, we do need to check for potential returns.
    bool CouldReturn(bool ignore_break) const override;

protected:
    ValPtr DoExec(Frame* f, Val* v, StmtFlowType& flow) override;

    IDPList* loop_vars;
    StmtPtr body;
    // Stores the value variable being used for a key value for loop.
    // Always set to nullptr unless special constructor is called.
    IDPtr value_var;
};

class NextStmt final : public Stmt {
public:
    NextStmt() : Stmt(STMT_NEXT) {}

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;
    bool IsPure() const override;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    StmtPtr Duplicate() override { return SetSucc(new NextStmt()); }

    bool NoFlowAfter(bool ignore_break) const override { return true; }

protected:
};

class BreakStmt final : public Stmt {
public:
    BreakStmt() : Stmt(STMT_BREAK) {}

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;
    bool IsPure() const override;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    StmtPtr Duplicate() override { return SetSucc(new BreakStmt()); }

    bool NoFlowAfter(bool ignore_break) const override { return ! ignore_break; }
    bool CouldReturn(bool ignore_break) const override { return ! ignore_break; }

protected:
};

class FallthroughStmt final : public Stmt {
public:
    FallthroughStmt() : Stmt(STMT_FALLTHROUGH) {}

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;
    bool IsPure() const override;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    StmtPtr Duplicate() override { return SetSucc(new FallthroughStmt()); }

protected:
};

class ReturnStmt final : public ExprStmt {
public:
    explicit ReturnStmt(ExprPtr e);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    void StmtDescribe(ODesc* d) const override;

    // Optimization-related:
    StmtPtr Duplicate() override;

    // Constructor used internally, for when we've already done
    // all of the type-checking.
    ReturnStmt(ExprPtr e, bool ignored);

    // Optimization-related:
    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

    bool NoFlowAfter(bool ignore_break) const override { return true; }
    bool CouldReturn(bool ignore_break) const override { return true; }
};

class StmtList : public Stmt {
public:
    StmtList();
    ~StmtList() override = default;

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    const auto& Stmts() const { return stmts; }
    auto& Stmts() { return stmts; }

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    StmtPtr Duplicate() override;
    void Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

    bool NoFlowAfter(bool ignore_break) const override;
    bool CouldReturn(bool ignore_break) const override;

    // Idioms commonly used in reduction.
    StmtList(StmtPtr s1, StmtPtr s2);
    StmtList(StmtPtr s1, StmtPtr s2, StmtPtr s3);

protected:
    bool IsPure() const override;

    std::vector<StmtPtr> stmts;

    // Optimization-related:
    bool ReduceStmt(unsigned int& s_i, std::vector<StmtPtr>& f_stmts, Reducer* c);

    void ResetStmts(std::vector<StmtPtr> new_stmts) { stmts = std::move(new_stmts); }
};

class InitStmt final : public Stmt {
public:
    explicit InitStmt(std::vector<IDPtr> arg_inits);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    const std::vector<IDPtr>& Inits() const { return inits; }

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    StmtPtr Duplicate() override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

protected:
    std::vector<IDPtr> inits;
};

class NullStmt final : public Stmt {
public:
    NullStmt(bool arg_is_directive = false);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;
    bool IsPure() const override;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    StmtPtr Duplicate() override { return SetSucc(new NullStmt()); }

    // Returns true if this NullStmt represents a directive (@if..., @else, @endif)
    bool IsDirective() const { return is_directive; };

private:
    bool is_directive;
};

class AssertStmt final : public ExprStmt {
public:
    explicit AssertStmt(ExprPtr cond, ExprPtr msg = nullptr);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    const auto& CondDesc() const { return cond_desc; }
    const auto& Msg() const { return msg; }
    const auto& MsgSetupStmt() const { return msg_setup_stmt; }

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    StmtPtr Duplicate() override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

private:
    std::string cond_desc;
    ExprPtr msg;

    // Statement to execute before evaluating "msg". Only used for script
    // optimization.
    StmtPtr msg_setup_stmt;
};

// Helper function for reporting on asserts that either failed, or should
// be processed regardless due to the presence of a "assertion_result" hook.
//
// If "cond" is false, throws an InterpreterException after reporting.
extern void report_assert(bool cond, std::string_view cond_desc, StringValPtr msg_val, const Location* loc);

// A helper class for tracking all of the information associated with
// a "when" statement, and constructing the necessary components in support
// of lambda-style captures.
class WhenInfo {
public:
    // Takes ownership of the CaptureList.
    WhenInfo(ExprPtr cond, FuncType::CaptureList* cl, bool is_return);

    // Used for duplication to support inlining.
    WhenInfo(const WhenInfo* orig);

    // Constructor used by script optimization to create a stub.
    WhenInfo(bool is_return);

    ~WhenInfo() { delete cl; }

    void AddBody(StmtPtr arg_s) { s = std::move(arg_s); }

    void AddTimeout(ExprPtr arg_timeout, StmtPtr arg_timeout_s) {
        timeout = std::move(arg_timeout);
        timeout_s = std::move(arg_timeout_s);
    }

    // Complete construction of the associated internals, including
    // the (complex) lambda used to access the different elements of
    // the statement.  The optional argument is only for generating
    // error messages.
    void Build(StmtPtr ws = nullptr);

    // This is available after a call to Build().
    const LambdaExprPtr& Lambda() const { return lambda; }

    // Instantiate a new instance, either by evaluating the associated
    // lambda, or directly using the given function value (for compiled
    // code).
    void Instantiate(Frame* f);
    void Instantiate(ValPtr func);

    // Return the original components used to construct the "when".
    const ExprPtr& OrigCond() const { return cond; }
    const StmtPtr& OrigBody() const { return s; }
    const ExprPtr& OrigTimeout() const { return timeout; }
    const StmtPtr& OrigTimeoutStmt() const { return timeout_s; }

    // Return different invocations of a lambda that manages the captures.
    ExprPtr Cond();
    StmtPtr WhenBody();
    StmtPtr TimeoutStmt();

    ExprPtr TimeoutExpr() const { return timeout; }
    void SetTimeoutExpr(ExprPtr e) { timeout = std::move(e); }
    double TimeoutVal(Frame* f);

    FuncType::CaptureList* Captures() { return cl; }

    bool IsReturn() const { return is_return; }

    // The locals and globals used in the conditional expression
    // (other than newly introduced locals), necessary for registering
    // the associated triggers for when their values change.
    const auto& WhenExprLocals() const { return when_expr_locals; }
    const auto& WhenExprGlobals() const { return when_expr_globals; }

    // The locals introduced in the conditional expression.
    const auto& WhenNewLocals() const { return when_new_locals; }

    // Used for script optimization when in-lining needs to revise
    // identifiers.
    bool HasUnreducedIDs(Reducer* c) const;
    void UpdateIDs(Reducer* c);

private:
    // Profile the original AST elements to extract things like
    // globals and locals used.
    void BuildProfile();

    // Build those elements we'll need for invoking our lambda.
    void BuildInvokeElems();

    ExprPtr cond;
    StmtPtr s;
    StmtPtr timeout_s;
    ExprPtr timeout;
    FuncType::CaptureList* cl = nullptr;

    bool is_return = false;

    // The name of parameter passed to the lambda, and the corresponding
    // identifier.
    std::string lambda_param_id;
    IDPtr param_id;

    // The expression for constructing the lambda, and its type.
    LambdaExprPtr lambda;
    FuncTypePtr lambda_ft;

    // The current instance of the lambda.  Created by Instantiate(),
    // for immediate use via calls to Cond() etc.
    ExprPtr curr_lambda;

    // Arguments to use when calling the lambda to either evaluate
    // the conditional, or execute the body or the timeout statement.
    ListExprPtr invoke_cond;
    ListExprPtr invoke_s;
    ListExprPtr invoke_timeout;

    // Helper expressions for calling the lambda / testing within it.
    ConstExprPtr one_const;
    ConstExprPtr two_const;
    ConstExprPtr three_const;

    std::vector<IDPtr> when_expr_locals;
    IDSet when_expr_globals;

    // Locals introduced via "local" in the "when" clause itself.
    IDSet when_new_locals;
};

class WhenStmt final : public Stmt {
public:
    WhenStmt(std::shared_ptr<WhenInfo> wi);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;
    bool IsPure() const override;

    ExprPtr Cond() const { return wi->Cond(); }
    StmtPtr Body() const { return wi->WhenBody(); }
    ExprPtr TimeoutExpr() const { return wi->TimeoutExpr(); }
    StmtPtr TimeoutBody() const { return wi->TimeoutStmt(); }
    bool IsReturn() const { return wi->IsReturn(); }

    auto Info() const { return wi; }

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

    // Optimization-related:
    StmtPtr Duplicate() override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

private:
    std::shared_ptr<WhenInfo> wi;
};

// Internal statement used for inlining.  Executes a block and stops
// the propagation of any "return" inside the block.  Generated in
// an already-reduced state.
class CatchReturnStmt : public Stmt {
public:
    explicit CatchReturnStmt(ScriptFuncPtr sf, StmtPtr block, NameExprPtr ret_var);

    const ScriptFuncPtr& Func() const { return sf; }
    StmtPtr Block() const { return block; }

    // This returns a bare pointer rather than a NameExprPtr only
    // because we don't want to have to include Expr.h in this header.
    const NameExpr* RetVar() const { return ret_var.get(); }

    // The assignment statement this statement transformed into,
    // or nil if it hasn't (the common case).
    StmtPtr AssignStmt() const { return assign_stmt; }

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    bool IsPure() const override;

    // Even though these objects are generated in reduced form, we still
    // have a reduction method to support the subsequent optimizer pass.
    StmtPtr DoReduce(Reducer* c) override;

    // Note, no need for a NoFlowAfter() method because anything that
    // has "NoFlowAfter" inside the body still gets caught and we
    // continue afterwards.  Same goes for CouldReturn().

    StmtPtr Duplicate() override;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
    // The inlined function.
    ScriptFuncPtr sf;

    // The inlined function body.
    StmtPtr block;

    // Expression that holds the return value.  Only used for compiling.
    NameExprPtr ret_var;

    // If this statement transformed into an assignment, that
    // corresponding statement.
    StmtPtr assign_stmt;
};

// Statement that makes sure at run-time that an "any" type has the
// correct number of (list) entries to enable sub-assigning to it via
// statements like "[a, b, c] = x;".  Generated in an already-reduced state.
class CheckAnyLenStmt : public ExprStmt {
public:
    explicit CheckAnyLenStmt(ExprPtr e, int expected_len);

    int ExpectedLen() const { return expected_len; }

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    StmtPtr Duplicate() override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

    void StmtDescribe(ODesc* d) const override;

protected:
    int expected_len;
};

// Statement that calls a std::function. These can be added to a Func body
// to directly all a C++ method.
class StdFunctionStmt : public Stmt {
public:
    StdFunctionStmt(std::function<void(const zeek::Args&, StmtFlowType&)> f)
        : Stmt(STMT_STD_FUNCTION), func(std::move(f)) {}

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    StmtPtr Duplicate() override {
        reporter->Error("Duplicate() on StdFunctionStmt not implemented");
        return {zeek::NewRef{}, this};
    }

    TraversalCode Traverse(TraversalCallback* cb) const override { return TC_CONTINUE; }

private:
    std::function<void(const zeek::Args&, StmtFlowType&)> func;
};

} // namespace zeek::detail
