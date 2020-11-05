// See the file "COPYING" in the main distribution directory for copyright.

// Expr subclasses and associated functions associated with script
// optimization.

class InlineExpr : public Expr {
public:
	InlineExpr(ListExprPtr arg_args, IDPList* params, StmtPtr body,
			int frame_offset, TypePtr ret_type);

	bool IsPure() const override;

	ListExprPtr Args() const	{ return args; }
	StmtPtr Body() const		{ return body; }

	ValPtr Eval(Frame* f) const override;

	ExprPtr Duplicate() override;

	bool WillTransform(Reducer* c) const override	{ return true; }
	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override	{ return false; }
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	void ExprDescribe(ODesc* d) const override;

	IDPList* params;
	int frame_offset;
	ListExprPtr args;
	StmtPtr body;
};

// A companion to AddToExpr that's for vector-append, instantiated during
// the reduction process.
class AppendToExpr : public BinaryExpr {
public:
	AppendToExpr(ExprPtr op1, ExprPtr op2);
	ValPtr Eval(Frame* f) const override;

	bool IsReduced(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

	ExprPtr Duplicate() override;
};

// An internal class for reduced form.
class IndexAssignExpr : public BinaryExpr {
public:
	// "op1[op2] = op3", all reduced.
	IndexAssignExpr(ExprPtr op1, ExprPtr op2, ExprPtr op3);

	ValPtr Eval(Frame* f) const override;

	ExprPtr Duplicate() override;

	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) override;

	ExprPtr GetOp3() const override final	{ return op3; }
	void SetOp3(ExprPtr _op) override final { op3 = _op; }

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	void ExprDescribe(ODesc* d) const override;

	ExprPtr op3;	// assignment RHS
};

// An internal class for reduced form.
class FieldLHSAssignExpr : public BinaryExpr {
public:
	// "op1$field = RHS", where RHS is reduced with respect to
	// ReduceToFieldAssignment().
	FieldLHSAssignExpr(ExprPtr op1, ExprPtr op2, const char* field_name,
				int field);

	const char* FieldName() const	{ return field_name; }
	int Field() const		{ return field; }

	ValPtr Eval(Frame* f) const override;

	ExprPtr Duplicate() override;

	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) override;

protected:
	void ExprDescribe(ODesc* d) const override;

	const char* field_name;
	int field;
};

class CoerceToAnyExpr : public UnaryExpr {
public:
	CoerceToAnyExpr(ExprPtr op);

protected:
	ValPtr Fold(Val* v) const override;

	ExprPtr Duplicate() override;
};

class CoerceFromAnyExpr : public UnaryExpr {
public:
	CoerceFromAnyExpr(ExprPtr op, TypePtr to_type);

protected:
	ValPtr Fold(Val* v) const override;

	ExprPtr Duplicate() override;
};

// Any internal call used for [a, b, c, ...] = x assignments.
class AnyIndexExpr : public UnaryExpr {
public:
	AnyIndexExpr(ExprPtr op, int index);

	int Index() const	{ return index; }

protected:
	ValPtr Fold(Val* v) const override;

	void ExprDescribe(ODesc* d) const override;

	ExprPtr Duplicate() override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

	int index;
};

// Used internally for optimization.
class NopExpr : public Expr {
public:
	explicit NopExpr() : Expr(EXPR_NOP) { }

	ValPtr Eval(Frame* f) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	void ExprDescribe(ODesc* d) const override;
};

// Assigns v1[v2] = v3.  Returns an error message, or nullptr on success.
extern const char* assign_to_index(ValPtr v1, ValPtr v2, ValPtr v3);
