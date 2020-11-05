// See the file "COPYING" in the main distribution directory for copyright.

// Public Expr methods associated with script optimization.
//
// We can't effectively factor these out into a separate class to
// include via multiple inheritance, because in general they rely
// on other Expr methods or member variables, so to do so we'd
// have to (1) make all of the methods virtual, and (2) still
// include (re-)definitions for them in Expr.h, defeating most
// of the benefits of using a separate class.

	// Returns a duplicate of the expression.  For atomic expressions
	// that can be safely shared across multiple function bodies
	// (due to inline-ing), and that won't have Reaching Definitions
	// tied to an individual copy, we can return just a reference, per the
	// default here.
	virtual ExprPtr Duplicate()		{ return ThisPtr(); }

	// Recursively traverses the AST to inline eligible function calls.
	virtual ExprPtr Inline(Inliner* inl)	{ return ThisPtr(); }

	// True if the expression can serve as an operand to a reduced
	// expression.
	bool IsSingleton(Reducer* r) const
		{
		return (tag == EXPR_NAME && IsReduced(r)) || tag == EXPR_CONST;
		}

	// True if the expression has no side effects, false otherwise.
	virtual bool HasNoSideEffects() const	{ return IsPure(); }

	// True if the expression is in fully reduced form: a singleton
	// or an assignment to an operator with singleton operands.
	virtual bool IsReduced(Reducer* c) const;

	// True if the expression's operands are singletons.
	virtual bool HasReducedOps(Reducer* c) const;

	bool HasConstantOps() const
		{
		return GetOp1() && GetOp1()->IsConst() &&
			(! GetOp2() ||
			 (GetOp2()->IsConst() &&
			  (! GetOp3() || GetOp3()->IsConst())));
		}

	// True if the expression is reduced to a form that can be
	// used in a conditional.
	bool IsReducedConditional(Reducer* c) const;

	// True if the expression is reduced to a form that can be
	// used in a field assignment.
	bool IsReducedFieldAssignment(Reducer* c) const;
	bool IsFieldAssignable(const Expr* e) const;

	// True if the expression will transform to one of another type
	// upon reduction, for non-constant operands.  "Transform" means
	// something beyond assignment to a temporary.  Necessary so that
	// we know to fully reduce such expressions if they're the RHS
	// of an assignment.
	virtual bool WillTransform(Reducer* c) const	{ return false; }

	// The same, but for the expression used in a conditional context.
	virtual bool WillTransformInConditional(Reducer* c) const
		{ return false; }

	// Returns the current expression transformed into "new_me".
	// Takes a bare pointer for "new_me" since often it's newly
	// allocated.
	ExprPtr TransformMe(Expr* new_me, Reducer* c, StmtPtr& red_stmt);
	ExprPtr TransformMe(ExprPtr new_me, Reducer* c, StmtPtr& red_stmt)
		{ return TransformMe(new_me.get(), c, red_stmt); }

	// Returns a set of predecessor statements in red_stmt (which might
	// be nil if no reduction necessary), and the reduced version of
	// the expression, suitable for replacing previous uses.  The
	// second version always yields a singleton suitable for use
	// as an operand.  The first version does this too except
	// for assignment statements; thus, its form is not guarantee
	// suitable for use as an operand.
	virtual ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt);
	virtual ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt)
		{ return Reduce(c, red_stmt); }

	// Reduces the expression to one whose operands are singletons.
	// Returns a predecessor statement(list), if any.
	virtual StmtPtr ReduceToSingletons(Reducer* c);

	// Reduces the expression to one that can appear as a conditional.
	ExprPtr ReduceToConditional(Reducer* c, StmtPtr& red_stmt);

	// Reduces the expression to one that can appear as a field
	// assignment.
	ExprPtr ReduceToFieldAssignment(Reducer* c, StmtPtr& red_stmt);

	// Helper function for factoring out index-based assignment.
	void AssignToIndex(ValPtr v1, ValPtr v2, ValPtr v3) const;

	// Returns a new expression corresponding to a temporary
	// that's been assigned to the given expression via red_stmt.
	ExprPtr AssignToTemporary(ExprPtr e, Reducer* c, StmtPtr& red_stmt);
	// Same but for this expression.
	ExprPtr AssignToTemporary(Reducer* c, StmtPtr& red_stmt)
		{ return AssignToTemporary(ThisPtr(), c, red_stmt); }

	// If the expression always evaluates to the same value, returns
	// that value.  Otherwise, returns nullptr.
	virtual ValPtr FoldVal() const	{ return nullptr; }

	ValPtr MakeZero(TypeTag t) const;
	ConstExprPtr MakeZeroExpr(TypeTag t) const;

	// Returns the expressions operands, or nil if it doesn't
	// have one.
	virtual ExprPtr GetOp1() const;
	virtual ExprPtr GetOp2() const;
	virtual ExprPtr GetOp3() const;

	// Sets the operands to new values.
	virtual void SetOp1(ExprPtr new_op);
	virtual void SetOp2(ExprPtr new_op);
	virtual void SetOp3(ExprPtr new_op);

	// Helper function to reduce boring code runs.
	StmtPtr MergeStmts(StmtPtr s1, StmtPtr s2, StmtPtr s3 = nullptr) const;

	// Access to the original expression from which this one is derived,
	// or this one if we don't have an original.  Returns a bare pointer
	// rather than an ExprPtr to emphasize that the access is read-only.
	const Expr* Original() const
		{ return original ? original->Original() : this; }

	// Designate the given Expr node as the original for this one.
	void SetOriginal(ExprPtr _orig)
		{
		if ( ! original )
			original = std::move(_orig);
		}

	// A convenience function for taking a newly-created Expr,
	// making it point to us as the successor, and returning it.
	//
	// Takes an Expr* rather than a ExprPtr to de-clutter the calling
	// code, which is always passing in "new XyzExpr(...)".  This
	// call, as a convenient side effect, transforms that bare pointer
	// into an ExprPtr.
	virtual ExprPtr SetSucc(Expr* succ)
		{
		succ->SetOriginal(ThisPtr());
		if ( IsParen() )
			succ->MarkParen();
		return {AdoptRef{}, succ};
		}
