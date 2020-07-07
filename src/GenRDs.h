// See the file "COPYING" in the main distribution directory for copyright.

// Classes for generating Reaching Definitions.

#pragma once

#include "ReachingDefs.h"
#include "DefSetsMgr.h"
#include "ProfileFunc.h"


// Helper class that tracks definitions gathered in a block that either
// need to be propagated to the beginning of the block or to the end.
struct BlockDefs;

class RD_Decorate : public TraversalCallback {
public:
	RD_Decorate(const ProfileFunc* pf);

	void TraverseFunction(const Func*, Scope* scope,
				IntrusivePtr<Stmt> body);

	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PostStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;
	TraversalCode PostExpr(const Expr*) override;

	void TrackInits(const Func* f, const id_list* inits);

	const DefSetsMgr* GetDefSetsMgr() const	{ return &mgr; }

protected:
	void TraverseSwitch(const SwitchStmt* sw);
	void DoIfStmtConfluence(const IfStmt* i);
	void DoLoopConfluence(const Stmt* s, const Stmt* top, const Stmt* body);
	bool CheckLHS(const Expr* lhs, const Expr* a);

	bool IsAggr(const Expr* e) const;

	void CreateInitPreDef(const ID* id, DefinitionPoint dp);

	void CreateInitPostDef(const ID* id, DefinitionPoint dp,
				bool assume_full, const Expr* rhs);

	void CreateInitPostDef(DefinitionItem* di, DefinitionPoint dp,
				bool assume_full, const Expr* rhs);

	void CreateInitDef(DefinitionItem* di, DefinitionPoint dp, bool is_pre,
				bool assume_full, const Expr* rhs);

	void CreateRecordRDs(DefinitionItem* di, DefinitionPoint dp,
				bool assume_full, const DefinitionItem* rhs_di)
		{ CreateRecordRDs(di, dp, false, assume_full, rhs_di); }
	void CreateRecordRDs(DefinitionItem* di, DefinitionPoint dp, bool is_pre,
				bool assume_full, const DefinitionItem* rhs_di);

	void CheckRecordRDs(DefinitionItem* di, DefinitionPoint dp,
					const RD_ptr& pre_rds, const BroObj* o);

	void CreateEmptyPostRDs(const Stmt* s);
	void AddBlockDefs(const Stmt* s,
				bool is_pre, bool is_future, bool is_case);

	const ProfileFunc* pf;
	function_flavor func_flavor;
	DefSetsMgr mgr;
	vector<BlockDefs*> block_defs;
};
