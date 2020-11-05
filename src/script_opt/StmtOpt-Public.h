// See the file "COPYING" in the main distribution directory for copyright.

// Stmt methods and member varibles associated with script optimization.
// See script_opt/ExprOpt-public.h for why these aren't factored into a
// separate class.

	// Returns a duplicate of the statement so that modifications
	// can be made to statements from inlining function bodies - or
	// to the originals - without affecting other instances.
	//
	// It's tempting to think that there are some statements that
	// are safe to share across multiple functions and could just
	// return references to themselves - but since we associate
	// information such as reaching-defs with statements, even these
	// need to be duplicated.
	virtual StmtPtr Duplicate() = 0;

	// Recursively traverses the AST to inline eligible function calls.
	virtual void Inline(Inliner* inl)	{ }

	// True if the statement is in reduced form.
	virtual bool IsReduced(Reducer* c) const;

	// Returns a reduced version of the statement, as managed by
	// the given Reducer.
	StmtPtr Reduce(Reducer* c);
	virtual StmtPtr DoReduce(Reducer* c)	{ return ThisPtr(); }

	// True if there's definitely no control flow past the statement.
	// The argument governs whether to ignore "break" statements, given
	// they mean two different things depending on whether they're in
	// a loop or a switch.  Also, if we want to know whether flow reaches
	// the *end* of a loop, then we also want to ignore break's, as
	// in that case, they do lead to flow reaching the end.
	virtual bool NoFlowAfter(bool ignore_break) const
		{ return false; }

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
