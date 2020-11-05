// See the file "COPYING" in the main distribution directory for copyright.

// Stmt subclasses and associated functions associated with script
// optimization.

// Internal statement used for inlining.  Executes a block and stops
// the propagation of any "return" inside the block.  Generated in
// an already-reduced state.
class NameExpr;
class CatchReturnStmt : public Stmt {
public:
	explicit CatchReturnStmt(StmtPtr block, IntrusivePtr<NameExpr> ret_var);

	StmtPtr Block() const	{ return block; }

	// This returns a bare pointer rather than an IntrusivePtr only
	// because we don't want to have to include Expr.h in this header.
	const NameExpr* RetVar() const		{ return ret_var.get(); }

	// The assignment statement this statement transformed into,
	// or nil if it hasn't (the common case).
	StmtPtr AssignStmt() const	{ return assign_stmt; }

	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;

	bool IsPure() const override;

	// Even though these objects are generated in reduced form, we still
	// have a reduction method to support the optimizer pass.
	StmtPtr DoReduce(Reducer* c) override;

	// Note, no need for a NoFlowAfter method because anything that
	// has "NoFlowAfter" inside the body still gets caught and we
	// continue afterwards.

	StmtPtr Duplicate() override;

	void StmtDescribe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	StmtPtr block;

	// Expression that holds the return value.  Only used for
	// compiling.
	IntrusivePtr<NameExpr> ret_var;

	// If this statement transformed into an assignment, that
	// corresponding statement.
	StmtPtr assign_stmt;
};

// Statement that makes sure at run-time that an "any" type has the
// correct number of (list) entries to enable sub-assigning to it.
// Generated in an already-reduced state.
class CheckAnyLenStmt : public ExprStmt {
public:
	explicit CheckAnyLenStmt(ExprPtr e, int expected_len);

	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;

	StmtPtr Duplicate() override;

	bool IsReduced(Reducer* c) const override;
	StmtPtr DoReduce(Reducer* c) override;

	void StmtDescribe(ODesc* d) const override;

protected:
	int expected_len;
};
