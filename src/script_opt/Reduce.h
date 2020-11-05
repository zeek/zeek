// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "IntrusivePtr.h"

#ifdef NOT_YET
#include "DefSetsMgr.h"
#endif

namespace zeek::detail {

class Expr;
class TempVar;
class ProfileFunc;

class Reducer {
public:
	Reducer(Scope* s);
	~Reducer();

	StmtPtr Reduce(StmtPtr s)
		{
#ifdef NOT_YET
		reduction_root = s;
#endif
		return s->Reduce(this);
		}

#ifdef NOT_YET
	const DefSetsMgr* GetDefSetsMgr() const	{ return mgr; }
	void SetDefSetsMgr(const DefSetsMgr* _mgr)	{ mgr = _mgr; }
#endif

	ExprPtr GenTemporaryExpr(const TypePtr& t, ExprPtr rhs);

	NameExpr* UpdateName(NameExpr* n);
	bool NameIsReduced(const NameExpr* n) const;

	void UpdateIDs(IDPList* ids);
	bool IDsAreReduced(const IDPList* ids) const;

	void UpdateIDs(std::vector<IDPtr>& ids);
	bool IDsAreReduced(const std::vector<IDPtr>& ids) const;

	IDPtr UpdateID(IDPtr id);
	bool ID_IsReduced(const IDPtr& id) const
		{ return ID_IsReduced(id.get()); }
	bool ID_IsReduced(const ID* id) const;

	// This is called *prior* to pushing a new inline block, in
	// order to generate the equivalent of function parameters.
	NameExprPtr GenInlineBlockName(ID* id);

	int NumNewLocals() const	{ return new_locals.size(); }

	// Returns the name of a temporary for holding the return
	// value of the block, or nil if the type indicates there's
	// o return value.
	NameExprPtr PushInlineBlock(TypePtr type);
	void PopInlineBlock();

	// Whether it's okay to split a statement into two copies for if-else
	// expansion.  We only allow this to a particular depth because
	// beyond that a function body can get too large to analyze.
	bool BifurcationOkay() const	{ return bifurcation_level <= 12; }
	int BifurcationLevel() const	{ return bifurcation_level; }

	void PushBifurcation()		{ ++bifurcation_level; }
	void PopBifurcation()		{ --bifurcation_level; }

	int NumTemps() const		{ return temps.length(); }

	// True if this name already reflects the replacement.
	bool IsNewLocal(const NameExpr* n) const
		{ return IsNewLocal(n->Id()); }
	bool IsNewLocal(const ID* id) const;

	bool IsTemporary(const ID* id) const
		{ return FindTemporary(id) != nullptr; }

#ifdef NOT_YET
	bool Optimizing() const	
		{ return ! IsPruning() && mgr != nullptr; }

	bool IsPruning() const		{ return omitted_stmts.size() > 0; }
	bool ShouldOmitStmt(const Stmt* s) const
		{ return omitted_stmts.find(s) != omitted_stmts.end(); }

	bool IsConstantVar(const ID* id) const
		{ return constant_vars.find(id) != constant_vars.end(); }

	Stmt* ReplacementStmt(const Stmt* s) const
		{
		auto repl = replaced_stmts.find(s);
		if ( repl == replaced_stmts.end() )
			return nullptr;
		else
			return repl->second;
		}

	// Tells the reducer to prune the given statement during the
	// next reduction pass.
	void AddStmtToOmit(const Stmt* s)	{ omitted_stmts.insert(s); }

	// Tells the reducer to replace the given statement during the
	// next reduction pass.
	void AddStmtToReplace(const Stmt* s_old, Stmt* s_new)
		{ replaced_stmts[s_old] = s_new; }

	// Tells the reducer that it can reclaim the storage associated
	// with the omitted statements.
	void ResetAlteredStmts()	
		{
		omitted_stmts.clear();
		replaced_stmts.clear();
		}

	// Tests whether an expression computed at e1 remains valid for
	// substitution at e2.
	bool ExprValid(const ID* id, const Expr* e1, const Expr* e2) const;

	// Given the LHS and RHS of an assignment, returns true
	// if the RHS is a common subexpression (meaning that the
	// current assignment statement should be deleted).  In
	// that case, has the side effect of associating an alias
	// for the LHS with the temporary holding the equivalent RHS.
	//
	// Assumes reduction (including alias propagation) has
	// already been applied.
	bool IsCSE(const AssignExpr* a, const NameExpr* lhs, const Expr* rhs);

	// Given an lhs=rhs statement followed by succ_stmt, returns
	// a (new) merge of the two if they're of the form tmp=rhs, var=tmp;
	// otherwise, nil.
	Stmt* MergeStmts(const NameExpr* lhs, ExprPtr rhs, Stmt* succ_stmt);

	ExprPtr OptExpr(ExprPtr e);
	ExprPtr UpdateExpr(ExprPtr e);
#else
	bool Optimizing() const	{ return false; }
#endif // NOT_YET

	const Scope* FuncScope() const	{ return scope; }

protected:
	bool SameVal(const Val* v1, const Val* v2) const;

#ifdef NOT_YET
	ExprPtr NewVarUsage(IDPtr var, const DefPoints* dps, const Expr* orig);

	const DefPoints* GetDefPoints(const NameExpr* var);
	const DefPoints* FindDefPoints(const NameExpr* var) const;
	void SetDefPoints(const NameExpr* var, const DefPoints* dps);

	// Returns true if op1 and op2 represent the same operand, given
	// the reaching definitions available at their usages (e1 and e2).
	bool SameOp(const Expr* op1, const Expr* op2);
	bool SameOp(const ExprPtr& op1, const ExprPtr& op2)
		{ return SameOp(op1.get(), op2.get()); }

	bool SameExpr(const Expr* e1, const Expr* e2);

	IDPtr FindExprTmp(const Expr* rhs, const Expr* a,
					const TempVar* lhs_tmp);

	void TrackExprReplacement(const Expr* orig, const Expr* e);

	// This is the heart of constant propagation.  Given an identifier
	// and a set of definition points for it, if its value is constant
	// then returns the corresponding ConstExpr with the value.
	const ConstExpr* CheckForConst(const IDPtr& id,
					const DefPoints* dps) const;

	const BroObj* GetRDLookupObj(const Expr* e) const;
#endif

	IDPtr GenTemporary(const TypePtr& t, ExprPtr rhs);
	TempVar* FindTemporary(const ID* id) const;

	// Retrieve the identifier corresponding to the new local for
	// the given expression.  Creates the local if necessary.
	IDPtr FindNewLocal(ID* id);
	IDPtr FindNewLocal(const NameExpr* n)
		{ return FindNewLocal(n->Id()); }

	// Generate a new local to use in lieu of the original (seen
	// in an inlined block).  The difference is that the new
	// version has a distinct name and has a correct frame offset
	// for the current function.
	IDPtr GenLocal(ID* orig);

	Scope* scope;
	PList<TempVar> temps;

	// Temps for which we've processed their associated expression
	// (and they didn't wind up being aliases).
	PList<TempVar> expr_temps;

	// Let's us go from an identifier to an associated temporary
	// variable, if it corresponds to one.
	std::unordered_map<const ID*, TempVar*> ids_to_temps;

	std::unordered_set<ID*> new_locals;
	std::unordered_map<const ID*, IDPtr> orig_to_new_locals;

	// Tracks whether we're inside an inline block, and if so then
	// how deeply.
	int inline_block_level = 0;

	// Tracks how deeply we are in "bifurcation", i.e., duplicating
	// code for if-else cascades.  We need to cap this at a certain
	// depth or else we can get functions whose size blows up
	// exponentially.
	int bifurcation_level = 0;

#ifdef NOT_YET
	// Tracks which (non-temporary) variables had constant
	// values used for constant propagation.
	std::unordered_set<const ID*> constant_vars;

	// For a new expression we've created, map it to the expression
	// it's replacing.  This allows us to locate the RDs associated
	// with the usage.
	std::unordered_map<const Expr*, const Expr*> new_expr_to_orig;

	std::unordered_set<const Stmt*> omitted_stmts;
	std::unordered_map<const Stmt*, Stmt*> replaced_stmts;

	// Statement at which the current reduction started.
	StmtPtr reduction_root = nullptr;

	// For a given usage of a variable's value, return the definition
	// points associated with its use at that point.  We use this
	// both as a cache (populating it every time we do a more
	// laborious lookup), and proactively when creating new
	// references to variables.
	std::unordered_map<const NameExpr*, const DefPoints*> var_usage_to_DPs;

	const DefSetsMgr* mgr = nullptr;
#endif
};

#ifdef NOT_YET
extern bool same_DPs(const DefPoints* dp1, const DefPoints* dp2);
#endif

// Used for debugging, to communicate which expression wasn't
// reduced when we expected them all to be.
extern const Expr* non_reduced_perp;
extern bool checking_reduction;

// Used to report a non-reduced expression.
extern bool NonReduced(const Expr* perp);

} // zeek::detail
