// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Scope.h"
#include "zeek/Expr.h"
#include "zeek/Stmt.h"
#include "zeek/script_opt/DefSetsMgr.h"

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
		return s->Reduce(this);
		}

	const DefSetsMgr* GetDefSetsMgr() const		{ return mgr; }
	void SetDefSetsMgr(const DefSetsMgr* _mgr)	{ mgr = _mgr; }

	ExprPtr GenTemporaryExpr(const TypePtr& t, ExprPtr rhs);

	NameExprPtr UpdateName(NameExprPtr n);
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
	NameExprPtr GenInlineBlockName(IDPtr id);

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

	bool IsConstantVar(const ID* id) const
		{ return constant_vars.find(id) != constant_vars.end(); }

	// True if the Reducer is being used in the context of a second
	// pass over for AST optimization.
	bool Optimizing() const
		{ return ! IsPruning() && mgr != nullptr; }

	// A predicate that indicates whether a given reduction pass
	// is being made to prune unused statements.
	bool IsPruning() const		{ return omitted_stmts.size() > 0; }

	// A predicate that returns true if the given statement should
	// be removed due to AST optimization.
	bool ShouldOmitStmt(const Stmt* s) const
		{ return omitted_stmts.find(s) != omitted_stmts.end(); }

	// Provides a replacement for the given statement due to
	// AST optimization, or nil if there's no replacement.
	StmtPtr ReplacementStmt(const StmtPtr& s) const
		{
		auto repl = replaced_stmts.find(s.get());
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
	void AddStmtToReplace(const Stmt* s_old, StmtPtr s_new)
		{ replaced_stmts[s_old] = std::move(s_new); }

	// Tells the reducer that it can reclaim the storage associated
	// with the omitted statements.
	void ResetAlteredStmts()
		{
		omitted_stmts.clear();
		replaced_stmts.clear();
		}

	// NOT YET IMPLEMENTED, SO CURRENTLY A STUB:
	// Given the LHS and RHS of an assignment, returns true
	// if the RHS is a common subexpression (meaning that the
	// current assignment statement should be deleted).  In
	// that case, has the side effect of associating an alias
	// for the LHS with the temporary holding the equivalent RHS.
	//
	// Assumes reduction (including alias propagation) has
	// already been applied.
	bool IsCSE(const AssignExpr* a, const NameExpr* lhs, const Expr* rhs)
		{ return false; }

	// Given an lhs=rhs statement followed by succ_stmt, returns
	// a (new) merge of the two if they're of the form tmp=rhs, var=tmp;
	// otherwise, nil.
	StmtPtr MergeStmts(const NameExpr* lhs, ExprPtr rhs, Stmt* succ_stmt);

	// The following two methods will, in the future, update expressions
	// with optimized versions.  They are distinct because the first
	// one (meant for calls in a Stmt reduction context) will also Reduce
	// the expression, whereas the second one (meant for calls in an Expr
	// context) does not, to avoid circularity.
	//
	// For now, they are stubs.
	//
	// These two are used for use in optimizing expressions that appear in
	// a Stmt context.
	ExprPtr OptExpr(Expr* e)	{ return {NewRef{}, e}; }
	ExprPtr OptExpr(ExprPtr e)	{ return e; }
	// This one for expressions appearing in an Expr context.
	ExprPtr UpdateExpr(ExprPtr e)	{ return e; }

	const Scope* FuncScope() const	{ return scope; }

protected:
	bool SameVal(const Val* v1, const Val* v2) const;

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

	// Track that we're replacing instances of "orig" with a new
	// expression.  This allows us to locate the RDs associated
	// with "orig" in the context of the new expression, without
	// requiring an additional RD propagation pass.
	void TrackExprReplacement(const Expr* orig, const Expr* e);

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

	std::unordered_set<const Stmt*> omitted_stmts;
	std::unordered_map<const Stmt*, StmtPtr> replaced_stmts;

	// Tracks whether we're inside an inline block, and if so then
	// how deeply.
	int inline_block_level = 0;

	// Tracks how deeply we are in "bifurcation", i.e., duplicating
	// code for if-else cascades.  We need to cap this at a certain
	// depth or else we can get functions whose size blows up
	// exponentially.
	int bifurcation_level = 0;

	// Tracks which (non-temporary) variables had constant
	// values used for constant propagation.
	std::unordered_set<const ID*> constant_vars;

	// For a new expression we've created, map it to the expression
	// it's replacing.  This allows us to locate the RDs associated
	// with the usage.
	std::unordered_map<const Expr*, const Expr*> new_expr_to_orig;

	const DefSetsMgr* mgr = nullptr;
};

// Used for debugging, to communicate which expression wasn't
// reduced when we expected them all to be.
extern const Expr* non_reduced_perp;
extern bool checking_reduction;

// Used to report a non-reduced expression.
extern bool NonReduced(const Expr* perp);

} // zeek::detail
