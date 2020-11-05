// See the file "COPYING" in the main distribution directory for copyright.

// Private (protected) Stmt methods and member varibles associated
// with script optimization.  See script_opt/ExprOpt-public.h for
// why these aren't factored into a separate class.
//
// Right now, this file is small, but it will grow as we expand into
// other forms of script optimization.

	// The original statement from which this statement was
	// derived, if any.  Used as an aid for generating meaningful
	// and correctly-localized error messages.
	StmtPtr original = nullptr;

	// Helper function called after reductions to perform canonical
	// actions.  Takes a bare pointer for new_me because usually
	// it's been newly new'd, so this keeps down code clutter.
	StmtPtr TransformMe(Stmt* new_me, Reducer* c);
