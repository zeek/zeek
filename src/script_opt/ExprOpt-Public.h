// See the file "COPYING" in the main distribution directory for copyright.

// Public Expr methods associated with script optimization.
//
// We can't effectively factor these out into a separate class to
// include via multiple inheritance, because in general they rely
// on other Expr methods or member variables, so to do so we'd
// have to (1) make all of the methods virtual, and (2) still
// include (re-)definitions for them in Expr.h, defeating most
// of the benefits of using a separate class.

	// Returns a duplicate of the expression.
	virtual ExprPtr Duplicate() = 0;

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
