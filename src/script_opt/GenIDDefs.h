// See the file "COPYING" in the main distribution directory for copyright.

// Class for generating identifier definition information by traversing
// a function body's AST.

#pragma once

#include "zeek/script_opt/IDOptInfo.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {

class GenIDDefs : public TraversalCallback {
public:
	GenIDDefs(std::shared_ptr<ProfileFunc> _pf, const Func* f,
	          ScopePtr scope, StmtPtr body);

private:
	// Traverses the given function body, using the first two
	// arguments for context.
	void TraverseFunction(const Func* f, ScopePtr scope, StmtPtr body);

	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PostStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;
	TraversalCode PostExpr(const Expr*) override;

	// Analyzes the target of an assignment.  Returns true if the LHS
	// was an expression for which we can track it as a definition
	// (e.g., assignments to variables, but not to elements of
	// aggregates).  "rhs" gives the expression used for simple direct
	// assignments.
	bool CheckLHS(const ExprPtr& lhs, const ExprPtr& rhs = nullptr);

	// True if the given expression directly represents an aggregate.
	bool IsAggr(const ExprPtr& e) const	{ return IsAggr(e.get()); }
	bool IsAggr(const Expr* e) const;

	// If -u is active, checks for whether the given identifier present
	// in the given expression is undefined at that point.
	void CheckVarUsage(const Expr* e, const ID* id);

	// Begin a new confluence block with the given statement.
	void StartConfluenceBlock(const Stmt* s);

	// Finish up the current confluence block.  If no_orig_flow is true,
	// then there's no control flow from the origin (the statement that
	// starts the block).
	void EndConfluenceBlock(bool no_orig_flow = false);

	// Note branches from the given "from" statement back up to the
	// beginning of, or just past, the "to" statement.  If "close_all"
	// is true then the nature of the branch is that it terminates
	// all pending confluence blocks.
	void BranchBackTo(const Stmt* from, const Stmt* to, bool close_all);
	void BranchBeyond(const Stmt* from, const Stmt* to, bool close_all);

	// These search back through the active confluence blocks looking
	// for either the innermost loop, or the innermost block for which
	// a "break" would target going beyond that block.
	const Stmt* FindLoop();
	const Stmt* FindBreakTarget();

	// Note that the given statement executes a "return" (which could
	// instead be an outer "break" for a hook).
	void ReturnAt(const Stmt* s);

	// Tracks that the given identifier is defined at the current
	// statement in the current confluence block.  'e' is the
	// expression used to define the identifier, for simple direct
	// assignments.
	void TrackID(const IDPtr& id, const ExprPtr& e = nullptr)
		{ TrackID(id.get(), e); }
	void TrackID(const ID* id, const ExprPtr& e = nullptr);

	// Profile for the function.  Currently, all we actually need from
	// this is the list of globals and locals.
	std::shared_ptr<ProfileFunc> pf;

	// Whether the Func is an event/hook/function.  We currently only
	// need to know whether it's a hook, so we correctly interpret an
	// outer "break" in that context.
	FunctionFlavor func_flavor;

	// The statement we are currently traversing.
	const Stmt* curr_stmt = nullptr;

	// Used to number Stmt objects found during AST traversal.
	int stmt_num;

	// A stack of confluence blocks, with the innermost at the top/back.
	std::vector<const Stmt*> confluence_blocks;

	// Index into confluence_blocks of "barrier" blocks that
	// represent unavoidable confluence blocks (no branching
	// out of them).  These include the outermost block and
	// any catch-return blocks.  We track these because
	// (1) there's no need for an IDOptInfo to track previously
	// unseen confluence regions outer to those, and (2) they
	// can get quite deep due when inlining, so there are savings
	// to avoid having to track outer to them.
	std::vector<int> barrier_blocks;

	// The following is parallel to confluence_blocks except
	// the front entry tracks identifiers at the outermost
	// (non-confluence) scope.  Thus, to index it for a given
	// confluence block i, we need to use i+1.
	std::vector<std::unordered_set<const ID*>> modified_IDs;

	// If non-zero, indicates we should suspend any generation
	// of usage errors.  A counter rather than a boolean because
	// such situations might nest.
	int suppress_usage = 0;
};

} // zeek::detail
