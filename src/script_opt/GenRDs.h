// See the file "COPYING" in the main distribution directory for copyright.

// Class for generating Reaching Definitions by traversing a function
// body's AST.

#pragma once

#include <memory>

#include "zeek/script_opt/ReachingDefs.h"
#include "zeek/script_opt/DefSetsMgr.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {


// Helper class that tracks definitions gathered in a block that either
// need to be propagated to the beginning of the block or to the end.
// Used for RD propagation due to altered control flow (next/break/fallthrough).
// Managed as a stack (vector) to deal with nested loops, switches, etc.
// Only applies to gathering maximum RDs.
class BlockDefs {
public:
	BlockDefs(bool _is_case)
		{ is_case = _is_case; }

	void AddPreRDs(RDPtr RDs)	{ pre_RDs.push_back(std::move(RDs)); }
	void AddPostRDs(RDPtr RDs)	{ post_RDs.push_back(std::move(RDs)); }
	void AddFutureRDs(RDPtr RDs)	{ future_RDs.push_back(std::move(RDs)); }

	const std::vector<RDPtr>& PreRDs() const	{ return pre_RDs; }
	const std::vector<RDPtr>& PostRDs() const	{ return post_RDs; }
	const std::vector<RDPtr>& FutureRDs() const	{ return future_RDs; }

	void Clear()
		{ pre_RDs.clear(); post_RDs.clear(); future_RDs.clear(); }

	bool IsCase() const	{ return is_case; }

private:
	std::vector<RDPtr> pre_RDs;
	std::vector<RDPtr> post_RDs;
	std::vector<RDPtr> future_RDs;	// RDs for next case block

	// Whether this block is for a switch case.  If not,
	// it's for a loop body.
	bool is_case;
};


class RD_Decorate : public TraversalCallback {
public:
	RD_Decorate(std::shared_ptr<ProfileFunc> _pf, const Func* f,
	            ScopePtr scope, StmtPtr body);

	const DefSetsMgr* GetDefSetsMgr() const	{ return &mgr; }

private:
	// Traverses the given function body, using the first two
	// arguments for context.
	void TraverseFunction(const Func* f, ScopePtr scope, StmtPtr body);

	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PostStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;
	TraversalCode PostExpr(const Expr*) override;

	// The following implement various types of "confluence", i.e.,
	// situations in which control flow merges from multiple possible
	// paths to a given point.
	void TraverseSwitch(const SwitchStmt* sw);
	void DoIfStmtConfluence(const IfStmt* i);
	void DoLoopConfluence(const Stmt* s, const Stmt* top, const Stmt* body);

	// Analyzes the target of an assignment.  Returns true if the LHS
	// was an expression for which we can track it as a definition
	// (e.g., assignments to variables or record fields, but not to
	// table or vector elements).
	bool CheckLHS(const Expr* lhs, const Expr* a);

	// True if the given expression directly represents an aggregate.
	bool IsAggr(const Expr* e) const;

	// Checks for whether the given identifier present in the given
	// expression is undefined at that point, per the associated RDs.
	// If check_fields is true, then we check the fields of records
	// in addition to the record itself.
	void CheckVar(const Expr* e, const ID* id, bool check_fields);

	// The following enable tracking of either identifiers or
	// record fields before/after the given definition point.
	void CreateInitPreDef(const ID* id, DefinitionPoint dp);
	void CreateInitPostDef(const ID* id, DefinitionPoint dp,
				bool assume_full, const Expr* rhs);
	void CreateInitPostDef(std::shared_ptr<DefinitionItem> di,
				DefinitionPoint dp, bool assume_full,
				const Expr* rhs);
	void CreateInitDef(std::shared_ptr<DefinitionItem> di,
				DefinitionPoint dp, bool is_pre,
				bool assume_full, const Expr* rhs);

	// Helper functions for generating RDs associated with record
	// fields.
	void CreateRecordRDs(std::shared_ptr<DefinitionItem> di,
				DefinitionPoint dp, bool assume_full,
				const DefinitionItem* rhs_di)
		{ CreateRecordRDs(std::move(di), dp, false, assume_full, rhs_di); }
	void CreateRecordRDs(std::shared_ptr<DefinitionItem> di,
				DefinitionPoint dp, bool is_pre,
				bool assume_full, const DefinitionItem* rhs_di);
	void CheckRecordRDs(std::shared_ptr<DefinitionItem> di,
					DefinitionPoint dp,
					const RDPtr& pre_rds, const Obj* o);

	void CreateEmptyPostRDs(const Stmt* s);

	// Helper function for tracking block definitions, i.e., those
	// associated with loops or switches.  We always track the
	// maximal "pre" RDs for the given statement.  If is_pre is
	// true, then we track them as RDs to propagate to the beginning
	// of the block.  Otherwise, they are to propagate to the end
	// of the block; and, if is_future is true, then also to the
	// beginning of the next block (used for "fallthrough" switch
	// blocks).
	//
	// is_case specifies whether we are adding definitions associated
	// with a switch case.
	void AddBlockDefs(const Stmt* s,
				bool is_pre, bool is_future, bool is_case);

	// Profile for the function.  Currently, all we actually need from
	// this is the list of globals.
	std::shared_ptr<ProfileFunc> pf;

	// Whether the Func is an event/hook/function.  We currently only
	// need to know whether it's a hook, so we correctly interpret an
	// outer "break" in that context.
	FunctionFlavor func_flavor;

	// Manager for the associated pre/post minimal/maximal RDs.
	DefSetsMgr mgr;

	// A stack of definitions associated with (potentially nested) loop
	// and switch blocks.
	std::vector<std::unique_ptr<BlockDefs>> block_defs;
};

} // zeek::detail
