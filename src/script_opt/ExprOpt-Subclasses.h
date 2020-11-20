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

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	void ExprDescribe(ODesc* d) const override;

	IDPList* params;
	int frame_offset;
	ListExprPtr args;
	StmtPtr body;
};
