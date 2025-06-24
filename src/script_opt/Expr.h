// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Expr.h"

namespace zeek::detail {

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

    ExprPtr GetOp3() const final { return op3; }
    void SetOp3(ExprPtr _op) final { op3 = std::move(_op); }

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

// Base class for updating a number of record fields from fields in
// another record.
class RecordFieldUpdatesExpr : public BinaryExpr {
public:
    const auto& LHSMap() const { return lhs_map; }
    const auto& RHSMap() const { return rhs_map; }

    // Only needed if we're transforming-but-not-compiling.
    ValPtr Fold(Val* v1, Val* v2) const override;

    bool IsPure() const override { return false; }
    bool IsReduced(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
    RecordFieldUpdatesExpr(ExprTag t, const std::vector<const Stmt*>& stmts, std::set<const Stmt*>& stmt_pool);
    RecordFieldUpdatesExpr(ExprTag t, ExprPtr e1, ExprPtr e2, std::vector<int> _lhs_map, std::vector<int> _rhs_map);

    // Apply the operation for the given index 'i' from rv2 to rv1.
    // Does not return a value since we're modifying rv1 in-place.
    virtual void FoldField(RecordVal* rv1, RecordVal* rv2, size_t i) const = 0;

    void ExprDescribe(ODesc* d) const override;

    std::vector<int> lhs_map;
    std::vector<int> rhs_map;
};

// Assign a bunch of record fields en masse from fields in another record.
class AssignRecordFieldsExpr : public RecordFieldUpdatesExpr {
public:
    AssignRecordFieldsExpr(const std::vector<const Stmt*>& stmts, std::set<const Stmt*>& stmt_pool)
        : RecordFieldUpdatesExpr(EXPR_REC_ASSIGN_FIELDS, stmts, stmt_pool) {}

    ExprPtr Duplicate() override;

protected:
    // Used for duplicating.
    AssignRecordFieldsExpr(ExprPtr e1, ExprPtr e2, std::vector<int> _lhs_map, std::vector<int> _rhs_map)
        : RecordFieldUpdatesExpr(EXPR_REC_ASSIGN_FIELDS, std::move(e1), std::move(e2), std::move(_lhs_map),
                                 std::move(_rhs_map)) {}

    void FoldField(RecordVal* rv1, RecordVal* rv2, size_t i) const override;
};

// Construct a record with some of the fields taken directly from another
// record. After full construction, the  first operand is the base constructor
// (a subset of the original) and the second is the source record being used
// for some of the initialization.
using FieldExprPtr = IntrusivePtr<FieldExpr>;
class ConstructFromRecordExpr : public AssignRecordFieldsExpr {
public:
    ConstructFromRecordExpr(const RecordConstructorExpr* orig);

    // Helper function that finds the most common source value.
    // Returns its identifier, or nil if there is no "$field = x$y"
    // to leverage.
    static IDPtr FindMostCommonRecordSource(const ListExprPtr& exprs);

    ExprPtr Duplicate() override;

    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
    ConstructFromRecordExpr(ExprPtr e1, ExprPtr e2, std::vector<int> _lhs_map, std::vector<int> _rhs_map)
        : AssignRecordFieldsExpr(std::move(e1), std::move(e2), std::move(_lhs_map), std::move(_rhs_map)) {
        tag = EXPR_REC_CONSTRUCT_WITH_REC;
    }

    // Helper function that for a given "$field = x$y" returns the
    // "x$y" node, or nil if that's not the nature of the expression.
    static FieldExprPtr FindRecordSource(const Expr* e);
};

// Add en masse fields from one record to fields in another record.
// We could add additional such expressions for other common operations
// like "x$foo -= y$bar", but in practice these are quite rare.
class AddRecordFieldsExpr : public RecordFieldUpdatesExpr {
public:
    AddRecordFieldsExpr(const std::vector<const Stmt*>& stmts, std::set<const Stmt*>& stmt_pool)
        : RecordFieldUpdatesExpr(EXPR_REC_ADD_FIELDS, stmts, stmt_pool) {}

    ExprPtr Duplicate() override;

protected:
    AddRecordFieldsExpr(ExprPtr e1, ExprPtr e2, std::vector<int> _lhs_map, std::vector<int> _rhs_map)
        : RecordFieldUpdatesExpr(EXPR_REC_ADD_FIELDS, std::move(e1), std::move(e2), std::move(_lhs_map),
                                 std::move(_rhs_map)) {}

    void FoldField(RecordVal* rv1, RecordVal* rv2, size_t i) const override;
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

class ScriptOptBuiltinExpr : public Expr {
public:
    enum SOBuiltInTag : uint8_t {
        MINIMUM,
        MAXIMUM,
        HAS_ELEMENTS,
        FUNC_ID_STRING,
    };

    ScriptOptBuiltinExpr(SOBuiltInTag tag, ExprPtr arg1, ExprPtr arg2 = nullptr);
    ScriptOptBuiltinExpr(SOBuiltInTag tag, CallExprPtr call);

    auto Tag() const { return tag; }

    ExprPtr GetOp1() const final { return arg1; }
    ExprPtr GetOp2() const final { return arg2; }

    void SetOp1(ExprPtr op) final { arg1 = std::move(op); }
    void SetOp2(ExprPtr op) final { arg2 = std::move(op); }

    ValPtr Eval(Frame* f) const override;

protected:
    void ExprDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;
    bool IsPure() const override;

    // Optimization-related:
    ExprPtr Duplicate() override;
    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override { return IsReduced(c); }
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

    void BuildEvalExpr();

    SOBuiltInTag tag;
    ExprPtr arg1;
    ExprPtr arg2;
    ExprPtr eval_expr;
    CallExprPtr call;
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

}; // namespace zeek::detail
