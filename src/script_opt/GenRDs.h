// See the file "COPYING" in the main distribution directory for copyright.

// Class for generating Reaching Definitions by traversing a function
// body's AST.

#pragma once

#include "zeek/script_opt/ReachingDefs.h"
#include "zeek/script_opt/DefSetsMgr.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {


// Helper class that tracks definitions gathered in a block that either
// need to be propagated to the beginning of the block or to the end.
class BlockDefs;

class RD_Decorate : public TraversalCallback {
public:
	RD_Decorate(const ProfileFunc* _pf) : pf(_pf)
		{ }

	// Traverses the given function body, using the first two
	// arguments for context.  "scope" is a Scope* rather than
	// a ScopePtr because the various scope management functions
	// (e.g., push_existing_scope(), current_scope()) traffic in
	// Scope*'s.
	void TraverseFunction(const Func* f, Scope* scope, StmtPtr body);

	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PostStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;
	TraversalCode PostExpr(const Expr*) override;

	const DefSetsMgr* GetDefSetsMgr() const	{ return &mgr; }

private:
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
	const ProfileFunc* pf;

	// Whether the Func is an event/hook/function.  We currently only
	// need to know whether it's a hook, so we correctly interpret an
	// outer "break" in that context.
	FunctionFlavor func_flavor;

	// Manager for the associated pre/post minimal/maximal RDs.
	DefSetsMgr mgr;

	// A stack of definitions associated with (potentially nested) loop
	// and switch blocks.
	std::vector<BlockDefs*> block_defs;
};

} // zeek::detail
