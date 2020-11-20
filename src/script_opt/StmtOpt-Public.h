// See the file "COPYING" in the main distribution directory for copyright.

// Stmt methods and member varibles associated with script optimization.
// See script_opt/ExprOpt-public.h for why these aren't factored into a
// separate class.

	// Returns a duplicate of the statement.
	virtual StmtPtr Duplicate() = 0;

	// Recursively traverses the AST to inline eligible function calls.
	virtual void Inline(Inliner* inl)	{ }

	// Access to the original statement from which this one is derived,
	// or this one if we don't have an original.  Returns a bare pointer
	// rather than a StmtPtr to emphasize that the access is read-only.
	const Stmt* Original() const
		{ return original ? original->Original() : this; }

	// Designate the given Stmt node as the original for this one.
	void SetOriginal(StmtPtr _orig)
		{
		if ( ! original )
			original = std::move(_orig);
		}

	// A convenience function for taking a newly-created Stmt,
	// making it point to us as the successor, and returning it.
	//
	// Takes a Stmt* rather than a StmtPtr to de-clutter the calling
	// code, which is always passing in "new XyzStmt(...)".  This
	// call, as a convenient side effect, transforms that bare pointer
	// into a StmtPtr.
	virtual StmtPtr SetSucc(Stmt* succ)
		{
		succ->SetOriginal({NewRef{}, this});
		return {AdoptRef{}, succ};
		}
