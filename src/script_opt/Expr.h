#include "zeek/Expr.h"

namespace zeek::detail {
class IndexAssignExpr;

class InlineExpr : public Expr {
public:
    InlineExpr(ScriptFuncPtr sf, ListExprPtr arg_args, std::vector<IDPtr> params, std::vector<bool> param_is_modified,
               StmtPtr body, int frame_offset, TypePtr ret_type);

    bool IsPure() const override;

    const ScriptFuncPtr& Func() const { return sf; }
    ListExprPtr Args() const { return args; }
    StmtPtr Body() const { return body; }

    ValPtr Eval(Frame* f) const override;

    ExprPtr Duplicate() override;

    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override { return false; }
    bool WillTransform(Reducer* c) const override { return true; }
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
    void ExprDescribe(ODesc* d) const override;

    std::vector<IDPtr> params;
    std::vector<bool> param_is_modified;
    int frame_offset;
    ScriptFuncPtr sf;
    ListExprPtr args;
    StmtPtr body;
};

// A companion to AddToExpr that's for vector-append, instantiated during
// the reduction process.
class AppendToExpr : public BinaryExpr {
public:
    AppendToExpr(ExprPtr op1, ExprPtr op2);
    ValPtr Eval(Frame* f) const override;

    ExprPtr Duplicate() override;

    bool IsPure() const override { return false; }
    bool IsReduced(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) override;
};

// An internal class for reduced form.
class IndexAssignExpr : public BinaryExpr {
public:
    // "op1[op2] = op3", all reduced.
    IndexAssignExpr(ExprPtr op1, ExprPtr op2, ExprPtr op3);

    ValPtr Eval(Frame* f) const override;

    ExprPtr Duplicate() override;

    bool IsPure() const override { return false; }
    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) override;

    ExprPtr GetOp3() const override final { return op3; }
    void SetOp3(ExprPtr _op) override final { op3 = std::move(_op); }

    TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
    void ExprDescribe(ODesc* d) const override;

    ExprPtr op3; // assignment RHS
};

// An internal class for reduced form.
class FieldLHSAssignExpr : public BinaryExpr {
public:
    // "op1$field = RHS", where RHS is reduced with respect to
    // ReduceToFieldAssignment().
    FieldLHSAssignExpr(ExprPtr op1, ExprPtr op2, const char* field_name, int field);

    const char* FieldName() const { return field_name; }
    int Field() const { return field; }

    ValPtr Eval(Frame* f) const override;

    ExprPtr Duplicate() override;

    bool IsPure() const override { return false; }
    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) override;

protected:
    void ExprDescribe(ODesc* d) const override;

    const char* field_name;
    int field;
};

// ... and for conversion from a "vector of any" type.
class CoerceFromAnyVecExpr : public UnaryExpr {
public:
    // to_type is yield type, not VectorType.
    CoerceFromAnyVecExpr(ExprPtr op, TypePtr to_type);

    // Can't use UnaryExpr's Eval() because it will do folding
    // over the individual vector elements.
    ValPtr Eval(Frame* f) const override;

protected:
    ExprPtr Duplicate() override;
};

// Expression used to explicitly capture [a, b, c, ...] = x assignments.
class AnyIndexExpr : public UnaryExpr {
public:
    AnyIndexExpr(ExprPtr op, int index);

    int Index() const { return index; }

protected:
    ValPtr Fold(Val* v) const override;

    void ExprDescribe(ODesc* d) const override;

    ExprPtr Duplicate() override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

    int index;
};

// Used internally for optimization, when a placeholder is needed.
class NopExpr : public Expr {
public:
    explicit NopExpr() : Expr(EXPR_NOP) {}

    ValPtr Eval(Frame* f) const override;

    ExprPtr Duplicate() override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
    void ExprDescribe(ODesc* d) const override;
};

};
